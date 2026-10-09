// Package chain checks the hash chain over the entries of an evidence log, and
// the anchor that names the last of them.
//
// Each entry carries a chain value that covers its own position, time and
// digest and the chain value of the entry before it, so changing an early entry
// breaks every link after it. A chain cannot see its own tail being cut, so the
// last entry is also named in a second file, the anchor.
//
// What agreement shows is that the files are consistent with each other. It
// does not show who wrote them or when, and whoever holds both files can
// rewrite both.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Entry is the part of a log line the chain covers: where the entry sits, when
// it was recorded, the digest of what it holds, and the links.
type Entry struct {
	// Sequence starts at 1.
	Sequence   uint64    `json:"sequence"`
	RecordedAt time.Time `json:"recorded_at"`
	// Digest is the digest of the entry's content. The chain treats it as an
	// opaque string; the package that knows the content checks it.
	Digest string `json:"digest"`
	// Previous is the chain value of the entry before this one, empty for the first.
	Previous string `json:"previous"`
	Chain    string `json:"chain"`
}

// Reason says which rule a log broke.
type Reason string

// The reasons a check can fail. They are stable: a caller may switch on them.
const (
	// ReasonSequence: an entry is not where its number says. Entries are
	// missing, repeated or out of order.
	ReasonSequence Reason = "sequence"
	// ReasonLink: an entry does not name the entry before it.
	ReasonLink Reason = "link"
	// ReasonValue: an entry's chain value is not the one its fields give.
	ReasonValue Reason = "chain-value"
	// ReasonAnchorMissing: the log has entries and no anchor.
	ReasonAnchorMissing Reason = "anchor-missing"
	// ReasonEntriesMissing: there is an anchor and no entries.
	ReasonEntriesMissing Reason = "entries-missing"
	// ReasonTailCut: the anchor names an entry beyond the end of the log.
	ReasonTailCut Reason = "tail-cut"
	// ReasonAnchorStale: the anchor names an entry before the end of the log.
	ReasonAnchorStale Reason = "anchor-stale"
	// ReasonAnchorMismatch: the anchor and the log name different chain values
	// for the same entry.
	ReasonAnchorMismatch Reason = "anchor-mismatch"
	// ReasonUnreadable: the anchor is not a file this verifier can read.
	ReasonUnreadable Reason = "unreadable"
	// ReasonFormat: the anchor is in a format this verifier does not know.
	ReasonFormat Reason = "format"
	// ReasonUnknownMember: the anchor holds a member this verifier does not know,
	// which may be one a later revision of the format added.
	ReasonUnknownMember Reason = "unknown-member"
)

// Error is what a failed check returns. Its text says that the files disagree
// and where, and nothing about who changed them or why.
type Error struct {
	Reason Reason
	// Sequence is the entry the fault is at, or 0 when it is about the log
	// as a whole.
	Sequence uint64
	msg      string
}

func (e *Error) Error() string { return "chain: " + e.msg }

func fault(r Reason, sequence uint64, format string, args ...any) *Error {
	return &Error{Reason: r, Sequence: sequence, msg: fmt.Sprintf(format, args...)}
}

// Value is the chain value of one entry: the hex SHA-256 of
//
//	"<sequence>\n<recorded_at>\n<digest>\n<previous>"
//
// where sequence is in decimal and recorded_at is the instant in UTC as
// RFC 3339 with the fraction Go prints (no trailing zeros, none when zero).
func Value(sequence uint64, recordedAt time.Time, digest, previous string) string {
	preimage := strconv.FormatUint(sequence, 10) + "\n" +
		recordedAt.UTC().Format(time.RFC3339Nano) + "\n" + digest + "\n" + previous
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:])
}

// Check verifies the links of a sequence of entries, oldest first: numbered
// from 1 without gaps, the first with nothing before it, each naming the chain
// value of the one before, each chain value the one its fields give.
//
// It cannot see entries cut off the end; CheckAnchor does.
func Check(entries []Entry) error {
	previous := ""
	for i, e := range entries {
		if err := CheckEntry(uint64(i+1), previous, e); err != nil {
			return err
		}
		previous = e.Chain
	}
	return nil
}

// CheckEntry verifies one entry that is at the given position (counting from 1)
// and follows the entry whose chain value is previous, which is empty for the
// first. It is Check for a reader that does not hold the whole log.
func CheckEntry(position uint64, previous string, e Entry) error {
	if e.Sequence != position {
		return fault(ReasonSequence, e.Sequence,
			"entry %d is in position %d: entries are missing, repeated or out of order", e.Sequence, position)
	}
	if e.Previous != previous {
		return fault(ReasonLink, e.Sequence,
			"entry %d links to %s, but the entry before it is %s", e.Sequence, short(e.Previous), short(previous))
	}
	if got := Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous); got != e.Chain {
		return fault(ReasonValue, e.Sequence, "entry %d: the chain value does not cover this entry", e.Sequence)
	}
	return nil
}

// short renders a value taken from a file for a message: quoted, so that a
// control or direction character cannot reach a terminal, and cut, so that a
// long line cannot fill one.
func short(s string) string {
	if s == "" {
		return "nothing"
	}
	const keep = 12
	cut := s
	n := 0
	for i := range s {
		if n == keep {
			cut = s[:i]
			break
		}
		n++
	}
	return strconv.Quote(cut)
}
