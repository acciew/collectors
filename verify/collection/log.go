package collection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/internal/logio"
)

// DefaultMaxLineBytes is the longest line a log may have unless Limits says
// otherwise. A line is a whole collection, so it is long; it is bounded so that
// a file that is not a log cannot be read into memory whole.
const DefaultMaxLineBytes = logio.DefaultMaxLineBytes

// Limits bounds what a reader will take in. The zero value means the defaults.
type Limits = logio.Limits

// Summary is what a verification found.
type Summary = logio.Summary

// Reason says which rule a log broke. The chain's own faults carry the chain
// package's reasons.
type Reason = logio.Reason

// The reasons this package reports. They are stable: a caller may switch on them.
const (
	// ReasonName: the name is not one a log can have.
	ReasonName = logio.ReasonName
	// ReasonUnreadable: a file is missing, is not a plain file, or cannot be read.
	// It says nothing about whether the log is intact.
	ReasonUnreadable = logio.ReasonUnreadable
	// ReasonLine: a line is not an entry in the one form entries are written in.
	ReasonLine = logio.ReasonLine
	// ReasonDigest: an entry's run does not match the digest the entry carries.
	ReasonDigest = logio.ReasonDigest
)

// Error is a fault in a collection log that is not about the chain. Its text
// says what disagrees and where, and nothing about who changed what.
type Error = logio.Error

// ReasonOf is the reason code of a fault from this package or from chain, or ""
// for any other error.
func ReasonOf(err error) string { return logio.ReasonOf(err) }

// Verify checks the log "<name>.jsonl" and its anchor "<name>.head" in a
// directory against themselves: every line is an entry in the one form, every
// entry's digest is that of its run, the chain holds, and the anchor names the
// last entry.
//
// It shows that the files agree with each other. It does not show who wrote them
// or when, and whoever holds both a log and its anchor can rewrite both.
func Verify(dir, name string) (Summary, error) {
	return logio.VerifyDir(dir, name, func(name string, log, head io.Reader) (Summary, error) {
		return VerifyReaders(name, log, head, Limits{})
	})
}

// VerifyReaders is Verify for a log and an anchor that are not files in a
// directory. A nil head means there is no anchor.
//
// The anchor is read first, so that a format this verifier does not know, or no
// anchor at all, is said before the log is read. What is kept while the log is
// read is the entry before the one in hand and, for the anchor, the last entry
// and the one it names: nothing that grows with the length of the log.
func VerifyReaders(name string, log, head io.Reader, limits Limits) (Summary, error) {
	return logio.Run(name, log, head, limits, func(line int, raw []byte) (chain.Entry, error) {
		e, err := decodeLine(raw)
		if err != nil {
			return chain.Entry{}, logio.LineFault(line, "%v", err)
		}
		if Digest(e.Run) != e.Digest {
			return chain.Entry{}, logio.Faultf(logio.ReasonDigest, line, e.Sequence,
				"line %d, entry %d: the record does not match its digest", line, e.Sequence)
		}
		return e.Entry, nil
	}, nil)
}

// Read reads the lines of a log as entries, strictly, and hands each to visit
// with its line number. It checks neither digests nor the chain; those are
// Verify's. A line that is not an entry in the one form entries are written in
// ends the reading with a fault, and so does a line longer than the limit: a
// collection silently skipped is the one thing a reader must not do.
func Read(r io.Reader, limits Limits, visit func(line int, e Entry) error) error {
	return logio.ReadLines(r, limits, func(line int, raw []byte) error {
		e, err := decodeLine(raw)
		if err != nil {
			return logio.LineFault(line, "%v", err)
		}
		return visit(line, e)
	})
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
