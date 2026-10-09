// Package logio is what the readers of the exported logs share: the faults they
// name, the bounded reading of lines, the opening of a plain file, and the
// order in which a log is checked.
//
// A log is a file of JSON lines with an anchor beside it. What differs between
// kinds of log is what is on a line and what its digest is taken over; that is
// handed in as a function, so that the order of checks, the bounds and the
// messages are written once.
package logio

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/internal/jsonobj"
	"go.acciew.io/collector/verify/internal/text"
)

// DefaultMaxLineBytes is the longest line a log may have unless Limits says
// otherwise. A line is a whole record, so it is long; it is bounded so that a
// file that is not a log cannot be read into memory whole.
const DefaultMaxLineBytes = 64 << 20

// Limits bounds what a reader will take in. The zero value means the defaults.
type Limits struct {
	MaxLineBytes int
}

func (l Limits) lineBytes() int {
	if l.MaxLineBytes <= 0 {
		return DefaultMaxLineBytes
	}
	return l.MaxLineBytes
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

// The reasons the readers report. They are stable: a caller may switch on them.
const (
	// ReasonName: the name is not one a log can have.
	ReasonName Reason = "name"
	// ReasonUnreadable: a file is missing, is not a plain file, or cannot be read.
	// It says nothing about whether the log is intact.
	ReasonUnreadable Reason = "unreadable"
	// ReasonLine: a line is not an entry in the one form entries are written in.
	ReasonLine Reason = "line"
	// ReasonDigest: an entry's content does not match the digest the entry carries.
	ReasonDigest Reason = "digest"
	// ReasonEvent: an entry's body is not an event.
	ReasonEvent Reason = "event"
	// ReasonLimit: a line is longer than the bound. It says nothing about the log.
	ReasonLimit Reason = "limit"
	// ReasonUnknownMember: a line holds a member this verifier does not know. It
	// says nothing about the log: the file may be newer than the verifier.
	ReasonUnknownMember Reason = "unknown-member"
)

// Error is a fault in a log that is not about the chain. Its text says what
// disagrees and where, and nothing about who changed what.
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

// ReasonOf is the reason code of a fault from a reader or from chain, or "" for
// any other error.
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

// Faultf makes a fault with a reason, a line and an entry.
func Faultf(reason Reason, line int, sequence uint64, format string, args ...any) *Error {
	return &Error{Reason: reason, Line: line, Sequence: sequence, msg: fmt.Sprintf(format, args...)}
}

// LineFault makes a fault in a line, whose message begins with the line's number.
func LineFault(line int, format string, args ...any) *Error {
	return &Error{Reason: ReasonLine, Line: line, msg: fmt.Sprintf("line %d ", line) + fmt.Sprintf(format, args...)}
}

// LineError makes the fault of a line that could not be read as an entry: a member
// the verifier does not know is said to be that, in words that are not the
// decoder's, and anything else is a line that is not in the form.
func LineError(line int, err error) *Error {
	if name, ok := jsonobj.UnknownMember(err); ok {
		return Faultf(ReasonUnknownMember, line, 0, "line %d holds a member %s that this verifier does not know: the file may be newer than this verifier",
			line, text.Quote(name))
	}
	return LineFault(line, "%v", err)
}

// Unreadable makes a fault in reading, which carries the error that caused it.
func Unreadable(err error, format string, args ...any) *Error {
	return &Error{Reason: ReasonUnreadable, msg: fmt.Sprintf(format, args...), err: err}
}

// Show renders a name taken from outside for a message.
func Show(s string) string { return text.Show(s) }

// ReadLines hands each line of r to visit, without its line feed, valid until
// the next. A line past the limit ends the reading with a fault and is not
// skipped, and so does input that stops in the middle of a line.
func ReadLines(r io.Reader, limits Limits, visit func(line int, raw []byte) error) error {
	limit := limits.lineBytes()
	lines := &lineReader{br: bufio.NewReaderSize(r, 64<<10), limit: limit}
	for n := 1; ; n++ {
		raw, err := lines.next()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, errTooLong):
			return Faultf(ReasonLimit, n, 0, "line %d is longer than %d bytes, which this reader will not take in", n, limit)
		case errors.Is(err, errNoNewline):
			return LineFault(n, "does not end in a line feed: the log was cut short, or was written by something else")
		case err != nil:
			return Unreadable(err, "the log cannot be read: %s", text.Plain(err))
		}
		if err := visit(n, raw); err != nil {
			return err
		}
	}
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

// errStop ends a ReadLines whose reason is kept elsewhere.
var errStop = errors.New("stop reading")

// Run checks a log and its anchor. The anchor is read first, so that a format
// this verifier does not know, or no anchor at all, is said before the log is
// read. Each line is handed to decode, which reads it as an entry of its kind
// and checks what only that kind knows (the digest of the content); Run then
// checks the entry's place in the chain and against the anchor. accepted, if
// not nil, is called once an entry has passed everything.
//
// What is kept while the log is read is the chain value of the entry before the
// one in hand and, for the anchor, the last entry and the one it names: nothing
// that grows with the length of the log. A nil head means there is no anchor.
func Run(name string, log, head io.Reader, limits Limits,
	decode func(line int, raw []byte) (chain.Entry, error), accepted func()) (Summary, error) {
	var anchor *chain.Anchor
	if head != nil {
		a, err := chain.ReadAnchor(head)
		if err != nil {
			return Summary{}, fmt.Errorf("%s: %w", Show(name+".head"), err)
		}
		anchor = &a
	}
	check := chain.NewAnchorCheck(anchor)

	var count int
	position := uint64(1)
	previous := ""
	var anchorFault error
	err := ReadLines(log, limits, func(line int, raw []byte) error {
		e, err := decode(line, raw)
		if err != nil {
			return err
		}
		if err := chain.CheckEntry(position, previous, e); err != nil {
			return err
		}
		if anchorFault = check.Add(e); anchorFault != nil {
			return errStop
		}
		if accepted != nil {
			accepted()
		}
		count++
		position++
		previous = e.Chain
		return nil
	})
	switch {
	case anchorFault != nil:
		return Summary{}, fmt.Errorf("%s: %w", Show(name), anchorFault)
	case err != nil:
		return Summary{}, fmt.Errorf("%s: %w", Show(name+".jsonl"), err)
	}
	if err := check.Done(); err != nil {
		return Summary{}, fmt.Errorf("%s: %w", Show(name), err)
	}
	return Summary{Entries: count, Head: previous}, nil
}

// VerifyDir opens the log "<name>.jsonl" and its anchor "<name>.head" in a
// directory and hands them to verify. Nothing outside the directory is opened,
// and a link, a directory or a device is refused and not followed.
func VerifyDir(dir, name string, verify func(name string, log, head io.Reader) (Summary, error)) (Summary, error) {
	if err := CheckName(name); err != nil {
		return Summary{}, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Summary{}, Unreadable(err, "%s cannot be opened: %s", Show(dir), text.Plain(err))
	}
	defer root.Close()

	log, err := OpenPlain(root, name+".jsonl")
	if err != nil {
		return Summary{}, err
	}
	defer log.Close()

	var head io.Reader
	switch f, err := OpenPlain(root, name+".head"); {
	case errors.Is(err, fs.ErrNotExist):
		// Left nil: a log with entries and no anchor is a fault of the chain's.
	case err != nil:
		return Summary{}, err
	default:
		defer f.Close()
		head = f
	}
	return verify(name, log, head)
}

// CheckName refuses a name that would not stay inside the directory.
func CheckName(name string) error {
	switch {
	case name == "":
		return Faultf(ReasonName, 0, 0, "a log has to have a name")
	case len(name) > 128:
		return Faultf(ReasonName, 0, 0, "the name is too long (%d bytes, and 128 is the most)", len(name))
	case name == "." || name == ".." || strings.ContainsAny(name, `/\`+"\x00"):
		return Faultf(ReasonName, 0, 0, "%s is not a usable name", Show(name))
	}
	return nil
}

// OpenPlain opens a plain file inside root. A link, a directory or a device is
// refused rather than followed, and not opened, so that nothing waits on it. A
// file that is not there is an error for which errors.Is(err, fs.ErrNotExist).
func OpenPlain(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Unreadable(err, "%s is not there", Show(name))
		}
		return nil, Unreadable(err, "%s cannot be read: %s", Show(name), text.Plain(err))
	}
	if !info.Mode().IsRegular() {
		return nil, Unreadable(nil, "%s is not a plain file: a link, a directory or a device is not followed", Show(name))
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, Unreadable(err, "%s cannot be opened: %s", Show(name), text.Plain(err))
	}
	return f, nil
}
