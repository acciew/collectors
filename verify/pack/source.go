package pack

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"go.acciew.io/collector/verify/internal/logio"
	"go.acciew.io/collector/verify/internal/text"
)

// Limits bound what a pack may expand to and hold. The zero value of a field
// means its default.
type Limits struct {
	// MaxEntries is the most files and folders in the pack. Default 10,000.
	MaxEntries int
	// MaxFileBytes is the most one file may expand to. Default 2 GiB.
	MaxFileBytes int64
	// MaxTotalBytes is the most the whole pack may expand to. Default 8 GiB.
	MaxTotalBytes int64
	// MaxRatio is the most an archive entry may expand to, as a multiple of its
	// compressed size, once it is past a megabyte. Default 500.
	MaxRatio int
	// MaxLineBytes is the longest line of a log. Default 64 MiB.
	MaxLineBytes int
}

func (l Limits) withDefaults() Limits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = 10_000
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 2 << 30
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = 8 << 30
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = 500
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = logio.DefaultMaxLineBytes
	}
	return l
}

// ratioFloor is the size under which an entry's ratio means nothing.
const ratioFloor = 1 << 20

// maxDocBytes bounds the documents that are read whole: the manifest, the list
// of digests, the campaign file and the anchors.
const maxDocBytes = 64 << 20

// entry is a file of the pack.
type entry struct {
	path string
}

// source is where a pack is: a folder or an archive.
type source interface {
	// list names the files, in order of path. What cannot be a file of a pack is
	// returned as findings and left out; what a folder holds because an operating
	// system put it there is returned as notes, and left out. An error is a limit
	// or a failure to read at all.
	list(lim Limits) (files []entry, findings, notes []Finding, err error)
	open(path string) (io.ReadCloser, error)
}

func limitError(format string, args ...any) *Error {
	return &Error{Reason: ReasonLimit, msg: fmt.Sprintf(format, args...)}
}

func notReadable(err error, format string, args ...any) *Error {
	return &Error{Reason: ReasonUnreadable, msg: fmt.Sprintf(format, args...), err: err}
}

// ---- a folder

type dirSource struct {
	root *os.Root
}

func openDir(dir string) (*dirSource, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, notReadable(err, "%s cannot be opened: %s", text.Show(dir), text.Plain(err))
	}
	return &dirSource{root: root}, nil
}

func (d *dirSource) close() { _ = d.root.Close() }

func (d *dirSource) list(lim Limits) ([]entry, []Finding, []Finding, error) {
	var out []entry
	var findings, notes []Finding
	var seen int
	var total int64
	err := fs.WalkDir(d.root.FS(), ".", func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		if seen++; seen > lim.MaxEntries {
			return limitError("the folder holds more than %d files and folders, which is more than a pack does", lim.MaxEntries)
		}
		if leftBySystem(path.Base(p), de.IsDir()) {
			notes = append(notes, Finding{Reason: ReasonNote, Path: p,
				Message: "is what an operating system leaves in a folder, and is not part of the pack; check the archive as it was handed over"})
			if de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := checkPath(p); err != nil {
			findings = append(findings, nameFinding(p, err))
			if de.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case de.IsDir():
			return nil
		case !de.Type().IsRegular():
			findings = append(findings, Finding{Reason: ReasonNotPlain, Path: p,
				Message: "is a link or another kind of file that is not a plain file, and is not followed"})
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return notReadable(err, "%s cannot be read: %s", text.Show(p), text.Plain(err))
		}
		if total += info.Size(); info.Size() > lim.MaxFileBytes {
			return limitError("%s is %d bytes, and a file of a pack may be %d at most", text.Show(p), info.Size(), lim.MaxFileBytes)
		}
		if total > lim.MaxTotalBytes {
			return limitError("the folder holds more than %d bytes, which is more than a pack does", lim.MaxTotalBytes)
		}
		out = append(out, entry{path: p})
		return nil
	})
	if err != nil {
		var pe *Error
		if errors.As(err, &pe) {
			return nil, nil, nil, pe
		}
		return nil, nil, nil, notReadable(err, "the folder cannot be read: %s", text.Plain(err))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, findings, notes, nil
}

// leftBySystem says whether a name in a folder is one an operating system puts
// there when a folder is opened or an archive is unpacked: the Finder's .DS_Store
// and AppleDouble files (._name) and __MACOSX folder, and Windows' Thumbs.db and
// desktop.ini.
func leftBySystem(base string, isDir bool) bool {
	if isDir {
		return base == "__MACOSX"
	}
	return base == ".DS_Store" || base == "Thumbs.db" || base == "desktop.ini" || strings.HasPrefix(base, "._")
}

func (d *dirSource) open(p string) (io.ReadCloser, error) {
	f, err := logio.OpenPlain(d.root, p)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// ---- an archive

type zipSource struct {
	files   map[string]*zip.File // by name; the first of a name that is repeated
	ordered []*zip.File          // as the archive gives them
}

func openZip(r io.ReaderAt, size int64) (*zipSource, error) {
	zr, err := zip.NewReader(r, size)
	// An archive with a name that climbs is still read: every name is judged here,
	// and an entry with a bad one is named and never opened.
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, notReadable(err, "this is not a ZIP archive that can be read: %s", text.Plain(err))
	}
	if err := checkLocalHeaders(r, size, zr.File); err != nil {
		return nil, err
	}
	z := &zipSource{files: map[string]*zip.File{}, ordered: zr.File}
	for _, f := range zr.File {
		if _, again := z.files[f.Name]; !again {
			z.files[f.Name] = f
		}
	}
	return z, nil
}

func (z *zipSource) list(lim Limits) ([]entry, []Finding, []Finding, error) {
	var out []entry
	var findings []Finding
	named := map[string]bool{}
	var total uint64
	var n int
	for _, f := range z.ordered {
		if n++; n > lim.MaxEntries {
			return nil, nil, nil, limitError("the archive holds more than %d entries, which is more than a pack does", lim.MaxEntries)
		}
		// A folder is an entry whose name ends in a slash, as archive/zip's own Open
		// has it. Mode bits that say folder on a name with no slash do not make it
		// one: it is a file that is not plain, and is named, not skipped.
		name := f.Name
		isDir := strings.HasSuffix(name, "/")
		if isDir {
			name = name[:len(name)-1]
		}
		if err := checkPath(name); err != nil {
			findings = append(findings, nameFinding(f.Name, err))
			continue
		}
		if isDir {
			if f.UncompressedSize64 > 0 {
				findings = append(findings, Finding{Reason: ReasonNotPlain, Path: name,
					Message: "is a folder entry that carries data, and is not read"})
			}
			continue
		}
		if named[name] {
			findings = append(findings, Finding{Reason: ReasonDuplicate, Path: name,
				Message: "is in the archive more than once, and only the first is read"})
			continue
		}
		named[name] = true
		if mode := f.Mode(); !mode.IsRegular() {
			findings = append(findings, Finding{Reason: ReasonNotPlain, Path: name,
				Message: "is a link or another kind of entry that is not a plain file, and is not followed"})
			continue
		}
		size := f.UncompressedSize64
		if !within(size, lim.MaxFileBytes) {
			return nil, nil, nil, limitError("%s expands to %d bytes, and a file of a pack may be %d at most", text.Show(name), size, lim.MaxFileBytes)
		}
		if total += size; !within(total, lim.MaxTotalBytes) {
			return nil, nil, nil, limitError("the archive expands to more than %d bytes, which is more than a pack does", lim.MaxTotalBytes)
		}
		if size > ratioFloor && f.CompressedSize64 > 0 && !within(size/f.CompressedSize64, int64(lim.MaxRatio)) {
			return nil, nil, nil, limitError("%s expands to %d bytes from %d, more than %d times its size, which no file of a pack does",
				text.Show(name), size, f.CompressedSize64, lim.MaxRatio)
		}
		out = append(out, entry{path: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, findings, nil, nil
}

func (z *zipSource) open(p string) (io.ReadCloser, error) {
	f, ok := z.files[p]
	if !ok {
		return nil, notReadable(fs.ErrNotExist, "%s is not there", text.Show(p))
	}
	rc, err := f.Open()
	if err != nil {
		return nil, notReadable(err, "%s cannot be opened: %s", text.Show(p), text.Plain(err))
	}
	return rc, nil
}

func nameFinding(p string, err error) Finding {
	return Finding{Reason: ReasonName, Path: p, Message: err.Error() + ", so it is not read"}
}

// ---- reading what is in the pack

// reader reads files of a pack with their size and digest, within the limits.
type reader struct {
	src   source
	lim   Limits
	total int64
}

// result is what was found of a file: how much of it there is and its digest.
type result struct {
	size int64
	sum  string
	err  error
}

// read opens a file, hands it to each if that is not nil, and reads whatever each
// did not, so that the digest and size are those of the whole file. A file that
// expands past the limits ends the checking.
func (r *reader) read(path string, each func(io.Reader) error) (result, error) {
	rc, err := r.src.open(path)
	if err != nil {
		return result{err: err}, nil
	}
	defer rc.Close()
	h := sha256.New()
	counted := &countingReader{r: io.LimitReader(rc, r.lim.MaxFileBytes+1), tee: h}
	var eachErr error
	if each != nil {
		eachErr = each(counted)
	}
	if _, err := io.Copy(io.Discard, counted); err != nil && counted.err == nil {
		counted.err = err
	}
	r.total += counted.n
	switch {
	case counted.n > r.lim.MaxFileBytes:
		return result{}, limitError("%s expands past %d bytes, and a file of a pack may be %d at most", text.Show(path), r.lim.MaxFileBytes, r.lim.MaxFileBytes)
	case r.total > r.lim.MaxTotalBytes:
		return result{}, limitError("the pack expands past %d bytes, which is more than a pack does", r.lim.MaxTotalBytes)
	}
	res := result{size: counted.n, sum: hex.EncodeToString(h.Sum(nil))}
	if counted.err != nil {
		res.err = notReadable(counted.err, "%s cannot be read: %s", text.Show(path), text.Plain(counted.err))
	}
	if eachErr != nil && res.err == nil {
		res.err = eachErr
	}
	return res, nil
}

// readAll reads a document whole, if it is no larger than documents are.
func (r *reader) readAll(path string) ([]byte, result, error) {
	var body []byte
	res, err := r.read(path, func(in io.Reader) error {
		var err error
		body, err = io.ReadAll(io.LimitReader(in, maxDocBytes+1))
		return err
	})
	if err != nil {
		return nil, res, err
	}
	if len(body) > maxDocBytes {
		return nil, res, limitError("%s is longer than %d bytes, which no document of a pack is", text.Show(path), maxDocBytes)
	}
	return body, res, nil
}

// countingReader counts what passes, feeds it to a hash, and remembers the first
// error that was not the end.
type countingReader struct {
	r   io.Reader
	tee io.Writer
	n   int64
	err error
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n += int64(n)
		_, _ = c.tee.Write(p[:n])
	}
	if err != nil && !errors.Is(err, io.EOF) && c.err == nil {
		c.err = err
	}
	return n, err
}

// within says whether a size from a header is no more than a limit.
func within(n uint64, limit int64) bool {
	return limit >= 0 && n <= uint64(limit)
}
