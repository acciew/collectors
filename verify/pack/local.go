package pack

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"go.acciew.io/collector/verify/internal/text"
)

// An archive says what each of its files is twice: in the central directory at
// its end, and in a header before the file's data. archive/zip goes by the
// central directory for the name, the method and the sizes, and by the local
// header only for where the data starts. A program that unpacks by the local
// header gets another file than the one that was checked, so this verifier reads
// the central directory again, itself, to compare, and refuses an archive in
// which the two disagree. The central directory is the authority; an archive that
// needs the other is not read.

const (
	sigCentral  = 0x02014b50
	sigLocal    = 0x04034b50
	sigEOCD     = 0x06054b50
	sigEOCD64   = 0x06064b50
	sigLocator  = 0x07064b50
	flagLater   = 0x8 // sizes and digest follow the data
	zip64Marker = 0xFFFFFFFF
)

// central is what the central directory says of one entry, and where its local
// header is.
type central struct {
	name         []byte
	flags        uint16
	method       uint16
	crc          uint32
	compressed   uint64
	uncompressed uint64
	offset       uint64
}

var errDirectory = errors.New("the central directory of the archive cannot be read")

// checkLocalHeaders compares each entry's local header with the central
// directory. files are the entries archive/zip read, in the order it read them.
func checkLocalHeaders(r io.ReaderAt, size int64, files []*zip.File) error {
	entries, base, err := readCentral(r, size)
	if err != nil {
		return notReadable(err, "this is not a ZIP archive that can be read: %s", text.Plain(err))
	}
	if len(entries) != len(files) {
		return notReadable(nil, "the central directory of the archive lists %d entries and the archive reads as %d: it is not read", len(entries), len(files))
	}
	for i, c := range entries {
		f := files[i]
		if string(c.name) != f.Name {
			return notReadable(nil, "entry %d of the archive is named differently by two readings of its central directory: it is not read", i+1)
		}
		if err := compareLocal(r, size, base, c); err != nil {
			return notReadable(nil, "the local header of %s disagrees with the central directory (%v): "+
				"the central directory is what is checked, so the archive is not read", text.Show(f.Name), err)
		}
	}
	return nil
}

func compareLocal(r io.ReaderAt, size, base int64, c central) error {
	off := base + int64(c.offset) //nolint:gosec // an offset in a file that was read
	if c.offset > uint64(size) || off < 0 || off+30 > size {
		return errors.New("it starts past the end of the archive")
	}
	var h [30]byte
	if _, err := r.ReadAt(h[:], off); err != nil {
		return fmt.Errorf("it cannot be read: %w", err)
	}
	le := binary.LittleEndian
	if le.Uint32(h[0:]) != sigLocal {
		return errors.New("there is no local header where the central directory puts it")
	}
	flags, method := le.Uint16(h[6:]), le.Uint16(h[8:])
	nameLen := int(le.Uint16(h[26:]))
	name := make([]byte, nameLen)
	if _, err := r.ReadAt(name, off+30); err != nil {
		return fmt.Errorf("the name cannot be read: %w", err)
	}
	switch {
	case !bytes.Equal(name, c.name):
		return errors.New("it gives another name")
	case method != c.method:
		return errors.New("it gives another method")
	case flags&flagLater != 0:
		return nil // the sizes and the digest are after the data, and the central directory has them
	}
	if crc := le.Uint32(h[14:]); crc != c.crc {
		return errors.New("it gives another digest")
	}
	if cs := le.Uint32(h[18:]); cs != zip64Marker && uint64(cs) != c.compressed {
		return errors.New("it gives another compressed size")
	}
	if us := le.Uint32(h[22:]); us != zip64Marker && uint64(us) != c.uncompressed {
		return errors.New("it gives another size")
	}
	return nil
}

// readCentral reads the central directory of the archive, with its ZIP64 forms,
// and returns its entries and how far the archive's start is from the start of
// the file (a program that is also an archive has a prefix).
func readCentral(r io.ReaderAt, size int64) ([]central, int64, error) {
	const eocdLen = 22
	tailLen := min(size, eocdLen+0xFFFF)
	if tailLen < eocdLen {
		return nil, 0, errDirectory
	}
	tail := make([]byte, tailLen)
	if _, err := r.ReadAt(tail, size-tailLen); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	le := binary.LittleEndian
	at := -1
	for i := len(tail) - eocdLen; i >= 0; i-- {
		if le.Uint32(tail[i:]) == sigEOCD && i+eocdLen+int(le.Uint16(tail[i+20:])) <= len(tail) {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, 0, errDirectory
	}
	eocdOffset := size - tailLen + int64(at)
	e := tail[at:]
	count, cdSize, cdOffset := uint64(le.Uint16(e[10:])), uint64(le.Uint32(e[12:])), uint64(le.Uint32(e[16:]))
	dirEnd := eocdOffset
	if le.Uint16(e[10:]) == 0xFFFF || le.Uint32(e[12:]) == zip64Marker || le.Uint32(e[16:]) == zip64Marker {
		var loc [20]byte
		if eocdOffset < 20 {
			return nil, 0, errDirectory
		}
		if _, err := r.ReadAt(loc[:], eocdOffset-20); err != nil || le.Uint32(loc[0:]) != sigLocator {
			return nil, 0, errDirectory
		}
		o64 := le.Uint64(loc[8:])
		if !within(o64, size) {
			return nil, 0, errDirectory
		}
		var rec [56]byte
		if _, err := r.ReadAt(rec[:], int64(o64)); err != nil || le.Uint32(rec[0:]) != sigEOCD64 { //nolint:gosec // bounded by the size just above
			return nil, 0, errDirectory
		}
		count, cdSize, cdOffset = le.Uint64(rec[32:]), le.Uint64(rec[40:]), le.Uint64(rec[48:])
		dirEnd = int64(o64) //nolint:gosec // bounded by the size just above
	}
	if cdSize > 64<<20 || !within(cdSize, size) {
		return nil, 0, errors.New("the central directory is larger than any archive of a pack has")
	}
	base := dirEnd - int64(cdSize) - int64(cdOffset) //nolint:gosec // both bounded by the size of the archive
	if base < 0 {
		return nil, 0, errDirectory
	}
	dir := make([]byte, cdSize)
	if _, err := r.ReadAt(dir, base+int64(cdOffset)); err != nil { //nolint:gosec // bounded as above
		return nil, 0, errDirectory
	}
	var out []central
	for uint64(len(out)) < count {
		if len(dir) < 46 || le.Uint32(dir) != sigCentral {
			return nil, 0, errDirectory
		}
		c := central{
			flags: le.Uint16(dir[8:]), method: le.Uint16(dir[10:]), crc: le.Uint32(dir[16:]),
			compressed: uint64(le.Uint32(dir[20:])), uncompressed: uint64(le.Uint32(dir[24:])), offset: uint64(le.Uint32(dir[42:])),
		}
		nameLen, extraLen, commentLen := int(le.Uint16(dir[28:])), int(le.Uint16(dir[30:])), int(le.Uint16(dir[32:]))
		if len(dir) < 46+nameLen+extraLen+commentLen {
			return nil, 0, errDirectory
		}
		c.name = dir[46 : 46+nameLen]
		wide(dir[46+nameLen:46+nameLen+extraLen], &c, le.Uint32(dir[20:]) == zip64Marker, le.Uint32(dir[24:]) == zip64Marker, le.Uint32(dir[42:]) == zip64Marker)
		out = append(out, c)
		dir = dir[46+nameLen+extraLen+commentLen:]
	}
	return out, base, nil
}

// wide reads the ZIP64 extra field of an entry, which holds the 8-byte forms of
// the fields whose 4-byte forms are all ones, in this order: the size, the
// compressed size, the offset.
func wide(extra []byte, c *central, wantSize, wantCompressed, wantOffset bool) {
	le := binary.LittleEndian
	for len(extra) >= 4 {
		id, n := le.Uint16(extra), int(le.Uint16(extra[2:]))
		if 4+n > len(extra) {
			return
		}
		if id == 1 {
			data := extra[4 : 4+n]
			for _, field := range []struct {
				want bool
				into *uint64
			}{{wantSize, &c.uncompressed}, {wantCompressed, &c.compressed}, {wantOffset, &c.offset}} {
				if field.want && len(data) >= 8 {
					*field.into = le.Uint64(data)
					data = data[8:]
				}
			}
			return
		}
		extra = extra[4+n:]
	}
}
