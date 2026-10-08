package collection

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"unicode/utf8"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/internal/text"
)

// DefaultMaxLineBytes is the longest line a log may have unless Limits says
// otherwise. A line is a whole collection, so it is long; it is bounded so that
// a file that is not a log cannot be read into memory whole.
const DefaultMaxLineBytes = 64 << 20

// Limits bounds what a reader will take in. The zero value means the defaults.
type Limits struct {
	MaxLineBytes int
}

// Summary is what a verification found.
type Summary struct {
	Entries int
	// Head is the chain value of the last entry, empty for a log of nothing.
	Head string
}

// Reason says which rule a log broke. The chain's own faults carry the chain
// package's reasons.
type Reason string

// The reasons this package reports. They are stable: a caller may switch on them.
const (
	// ReasonName: the name is not one a log can have.
	ReasonName Reason = "name"
	// ReasonUnreadable: a file is missing, is not a plain file, or cannot be read.
	// It says nothing about whether the log is intact.
	ReasonUnreadable Reason = "unreadable"
	// ReasonLine: a line is not an entry in the one form entries are written in.
	ReasonLine Reason = "line"
	// ReasonDigest: an entry's run does not match the digest the entry carries.
	ReasonDigest Reason = "digest"
)

// Error is a fault in a collection log that is not about the chain. Its text
// says what disagrees and where, and nothing about who changed what.
type Error struct {
	Reason Reason
	// Line is the line of the file the fault is on, or 0.
	Line int
	// Sequence is the entry the fault is at, when the line could be read.
	Sequence uint64
	msg      string
	err      error
}

func (e *Error) Error() string { return e.msg }
func (e *Error) Unwrap() error { return e.err }

// ReasonOf is the reason code of a fault from this package or from chain, or ""
// for any other error.
func ReasonOf(err error) string {
	var own *Error
	if errors.As(err, &own) {
		return string(own.Reason)
	}
	var link *chain.Error
	if errors.As(err, &link) {
		return string(link.Reason)
	}
	return ""
}

func lineFault(line int, format string, args ...any) *Error {
	return &Error{Reason: ReasonLine, Line: line, msg: fmt.Sprintf("line %d ", line) + fmt.Sprintf(format, args...)}
}

func unreadable(err error, format string, args ...any) *Error {
	return &Error{Reason: ReasonUnreadable, msg: fmt.Sprintf(format, args...), err: err}
}

// Verify checks the log "<name>.jsonl" and its anchor "<name>.head" in a
// directory against themselves: every line is an entry in the one form, every
// entry's digest is that of its run, the chain holds, and the anchor names the
// last entry.
//
// It shows that the files agree with each other. It does not show who wrote them
// or when, and whoever holds both a log and its anchor can rewrite both.
func Verify(dir, name string) (Summary, error) {
	if err := checkName(name); err != nil {
		return Summary{}, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Summary{}, unreadable(err, "%s cannot be opened: %s", show(dir), text.Plain(err))
	}
	defer root.Close()

	log, err := openPlain(root, name+".jsonl")
	if err != nil {
		return Summary{}, err
	}
	defer log.Close()

	var head io.Reader
	switch f, err := openPlain(root, name+".head"); {
	case errors.Is(err, fs.ErrNotExist):
		// Left nil: a log with entries and no anchor is a fault of the chain's.
	case err != nil:
		return Summary{}, err
	default:
		defer f.Close()
		head = f
	}
	return VerifyReaders(name, log, head, Limits{})
}

// VerifyReaders is Verify for a log and an anchor that are not files in a
// directory. A nil head means there is no anchor.
//
// The anchor is read first, so that a format this verifier does not know, or no
// anchor at all, is said before the log is read. What is kept while the log is
// read is the entry before the one in hand and, for the anchor, the last entry
// and the one it names: nothing that grows with the length of the log.
func VerifyReaders(name string, log, head io.Reader, limits Limits) (Summary, error) {
	var anchor *chain.Anchor
	if head != nil {
		a, err := chain.ReadAnchor(head)
		if err != nil {
			return Summary{}, fmt.Errorf("%s: %w", show(name+".head"), err)
		}
		anchor = &a
	}
	check := chain.NewAnchorCheck(anchor)

	var count int
	position := uint64(1)
	previous := ""
	var anchorFault error
	err := Read(log, limits, func(line int, e Entry) error {
		if Digest(e.Run) != e.Digest {
			return &Error{Reason: ReasonDigest, Line: line, Sequence: e.Sequence,
				msg: fmt.Sprintf("line %d, entry %d: the record does not match its digest", line, e.Sequence)}
		}
		if err := chain.CheckEntry(position, previous, e.Entry); err != nil {
			return err
		}
		if anchorFault = check.Add(e.Entry); anchorFault != nil {
			return errStop
		}
		count++
		position++
		previous = e.Chain
		return nil
	})
	switch {
	case anchorFault != nil:
		return Summary{}, fmt.Errorf("%s: %w", show(name), anchorFault)
	case err != nil:
		return Summary{}, fmt.Errorf("%s: %w", show(name+".jsonl"), err)
	}
	if err := check.Done(); err != nil {
		return Summary{}, fmt.Errorf("%s: %w", show(name), err)
	}
	return Summary{Entries: count, Head: previous}, nil
}

// errStop ends a Read whose reason is kept elsewhere.
var errStop = errors.New("stop reading")

// Read reads the lines of a log as entries, strictly, and hands each to visit
// with its line number. It checks neither digests nor the chain; those are
// Verify's. A line that is not an entry in the one form entries are written in
// ends the reading with a fault, and so does a line longer than the limit: a
// collection silently skipped is the one thing a reader must not do.
func Read(r io.Reader, limits Limits, visit func(line int, e Entry) error) error {
	limit := limits.MaxLineBytes
	if limit <= 0 {
		limit = DefaultMaxLineBytes
	}
	lines := &lineReader{br: bufio.NewReaderSize(r, 64<<10), limit: limit}
	for n := 1; ; n++ {
		raw, err := lines.next()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, errTooLong):
			return lineFault(n, "is longer than %d bytes, which this reader will not take in", limit)
		case errors.Is(err, errNoNewline):
			return lineFault(n, "does not end in a line feed: the log was cut short, or was written by something else")
		case err != nil:
			return unreadable(err, "the log cannot be read: %s", text.Plain(err))
		}
		e, err := decodeLine(raw)
		if err != nil {
			return lineFault(n, "%v", err)
		}
		if err := visit(n, e); err != nil {
			return err
		}
	}
}

// decodeLine reads a line as an entry and refuses it unless it is exactly what
// writing that entry produces. Go reads a repeated member by the last, a member
// in any case, and a missing or null one as zero; other readers do not, so only
// the one form is read, and there is one reading.
func decodeLine(raw []byte) (Entry, error) {
	if len(raw) == 0 {
		return Entry{}, errors.New("is empty")
	}
	if !utf8.Valid(raw) {
		return Entry{}, errors.New("is not valid UTF-8")
	}
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Entry{}, fmt.Errorf("is not an entry: %w", err)
	}
	if again, err := json.Marshal(e); err != nil || !bytes.Equal(again, raw) {
		return Entry{}, errors.New("is not in the one form an entry is written in: " +
			"a repeated, missing or unknown member, a member in another order, case or spelling, " +
			"other spacing, a value of another kind, or a time written another way")
	}
	return e, nil
}

var (
	errTooLong   = errors.New("line too long")
	errNoNewline = errors.New("no line feed at the end")
)

// lineReader reads lines of bounded length without ever holding more than a
// line and a buffer.
type lineReader struct {
	br    *bufio.Reader
	limit int
	buf   []byte
}

// next returns the next line without its line feed, valid until the next call.
// It returns io.EOF only at the end of a line, errNoNewline if the input ends in
// the middle of one, and errTooLong at the first byte past the bound.
func (l *lineReader) next() ([]byte, error) {
	l.buf = l.buf[:0]
	for {
		chunk, err := l.br.ReadSlice('\n')
		l.buf = append(l.buf, chunk...)
		switch {
		case err == nil:
			if len(l.buf)-1 > l.limit {
				return nil, errTooLong
			}
			return l.buf[:len(l.buf)-1], nil
		case len(l.buf) > l.limit:
			return nil, errTooLong
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(l.buf) == 0 {
				return nil, io.EOF
			}
			return nil, errNoNewline
		default:
			return nil, err
		}
	}
}

// checkName refuses a name that would not stay inside the directory.
func checkName(name string) error {
	switch {
	case name == "":
		return &Error{Reason: ReasonName, msg: "a log has to have a name"}
	case len(name) > 128:
		return &Error{Reason: ReasonName, msg: fmt.Sprintf("the name is too long (%d bytes, and 128 is the most)", len(name))}
	case name == "." || name == ".." || strings.ContainsAny(name, `/\`+"\x00"):
		return &Error{Reason: ReasonName, msg: fmt.Sprintf("%s is not a usable name", show(name))}
	}
	return nil
}

// openPlain opens a plain file inside root. A link, a directory or a device is
// refused rather than followed, and not opened, so that nothing waits on it.
func openPlain(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, unreadable(err, "%s is not there", show(name))
		}
		return nil, unreadable(err, "%s cannot be read: %s", show(name), text.Plain(err))
	}
	if !info.Mode().IsRegular() {
		return nil, unreadable(nil, "%s is not a plain file: a link, a directory or a device is not followed", show(name))
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, unreadable(err, "%s cannot be opened: %s", show(name), text.Plain(err))
	}
	return f, nil
}

// show renders a name taken from outside for a message.
func show(s string) string { return text.Show(s) }
