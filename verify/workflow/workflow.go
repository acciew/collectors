package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/internal/jsonobj"
	"go.acciew.io/collector/verify/internal/logio"
	"go.acciew.io/collector/verify/internal/text"
)

// DefaultMaxLineBytes is the longest line a log may have unless Limits says
// otherwise. It is bounded so that a file that is not a log cannot be read into
// memory whole.
const DefaultMaxLineBytes = logio.DefaultMaxLineBytes

// Limits bounds what a reader will take in. The zero value means the defaults.
type Limits = logio.Limits

// Summary is what a verification found.
type Summary = logio.Summary

// Error is a fault in a workflow log that is not about the chain. Its text says
// what disagrees and where, and nothing about who changed what.
type Error = logio.Error

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
	// ReasonDigest: an entry's body is not the one its digest is of.
	ReasonDigest = logio.ReasonDigest
	// ReasonEvent: an entry's body is not an event.
	ReasonEvent = logio.ReasonEvent
	// ReasonLimit: a line is longer than the bound. It says nothing about the log.
	ReasonLimit = logio.ReasonLimit
	// ReasonUnknownMember: a line, or an event, holds a member this verifier does not
	// know, which may be one a later revision of the format added. It says nothing
	// about the log.
	ReasonUnknownMember = logio.ReasonUnknownMember
)

// ReasonOf is the reason code of a fault from this package or from chain, or ""
// for any other error.
func ReasonOf(err error) string { return logio.ReasonOf(err) }

// Entry is one line of a workflow log: where it sits in the chain, and the event
// as the text its digest was taken over.
type Entry struct {
	chain.Entry
	// Body is the event, byte for byte.
	Body json.RawMessage `json:"body"`
}

// Digest is the SHA-256 of a body, as lowercase hexadecimal. It is taken over the
// bytes of the body as they stand in the line.
func Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Event is what a body says: what happened, who did it, and the rest. Data is
// the text of the "data" member, nil when there is none; it is left as written,
// and which of its members mean anything depends on the type.
type Event struct {
	Type  string
	Actor string
	Data  json.RawMessage
}

// ParseEvent reads a body as an event, exactly: an object with the members
// "type" and "actor", both non-empty strings, and "data", an object, if it has
// one. Another member, a repeated one, or one in another case is refused, so that
// the body has one reading.
func ParseEvent(body []byte) (Event, error) {
	members, err := jsonobj.Members(body)
	if err != nil {
		return Event{}, fmt.Errorf("the body %w", err)
	}
	var ev Event
	for _, f := range []struct {
		name string
		into *string
	}{{"type", &ev.Type}, {"actor", &ev.Actor}} {
		raw, ok := members[f.name]
		if !ok {
			return Event{}, fmt.Errorf("the body does not say its %s", f.name)
		}
		v, err := jsonobj.String(raw)
		if err != nil || v == "" {
			return Event{}, fmt.Errorf("the %s of the body is not a non-empty string", f.name)
		}
		*f.into = v
	}
	if raw, ok := members["data"]; ok {
		if _, err := jsonobj.Members(raw); err != nil {
			return Event{}, fmt.Errorf("the data of the body %w", err)
		}
		ev.Data = raw
	}
	// A member beyond these is not a disagreement: it may be one a later revision of
	// the format added. It is said last, after the body has been found to be an event.
	for _, name := range sortedNames(members) {
		switch name {
		case "type", "actor", "data":
		default:
			return Event{}, &unknownMember{name: name}
		}
	}
	return ev, nil
}

func sortedNames(m map[string]json.RawMessage) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// unknownMember is an event with a member this verifier does not know.
type unknownMember struct{ name string }

func (u *unknownMember) Error() string {
	return fmt.Sprintf("the body holds a member %s that this verifier does not know: the file may be newer than this verifier", text.Quote(u.name))
}

// Options say how a log is verified.
type Options struct {
	Limits Limits
	// Entry, if not nil, is called with each entry once it has passed every
	// check, in order. Nothing it is given is true of the log until the
	// verification as a whole has returned without a fault.
	Entry func(e Entry, ev Event)
}

// Verify checks the log "<name>.jsonl" and its anchor "<name>.head" in a
// directory against themselves: every line is an entry in the one form, every
// digest is that of its body, every body is an event, the chain holds, and the
// anchor names the last entry.
//
// It shows that the files agree with each other. It does not show who wrote them
// or when, and whoever holds both a log and its anchor can rewrite both.
func Verify(dir, name string) (Summary, error) { return VerifyDir(dir, name, Limits{}) }

// VerifyDir is Verify with limits.
func VerifyDir(dir, name string, limits Limits) (Summary, error) {
	return logio.VerifyDir(dir, name, func(name string, log, head io.Reader) (Summary, error) {
		return VerifyReaders(name, log, head, limits)
	})
}

// VerifyReaders is Verify for a log and an anchor that are not files in a
// directory. A nil head means there is no anchor.
func VerifyReaders(name string, log, head io.Reader, limits Limits) (Summary, error) {
	return VerifyWith(name, log, head, Options{Limits: limits})
}

// VerifyWith is VerifyReaders with options.
//
// The anchor is read first, so that a format this verifier does not know, or no
// anchor at all, is said before the log is read. What is kept while the log is
// read is the entry before the one in hand and, for the anchor, the last entry
// and the one it names: nothing that grows with the length of the log.
func VerifyWith(name string, log, head io.Reader, opts Options) (Summary, error) {
	var current Entry
	var event Event
	var accepted func()
	if opts.Entry != nil {
		accepted = func() { opts.Entry(current, event) }
	}
	return logio.Run(name, log, head, opts.Limits, func(line int, raw []byte) (chain.Entry, error) {
		e, err := decodeLine(raw)
		if err != nil {
			return chain.Entry{}, logio.LineError(line, err)
		}
		if Digest(e.Body) != e.Digest {
			return chain.Entry{}, logio.Faultf(logio.ReasonDigest, line, e.Sequence,
				"line %d, entry %d: the event does not match its digest", line, e.Sequence)
		}
		ev, err := ParseEvent(e.Body)
		if err != nil {
			reason := logio.ReasonEvent
			var unknown *unknownMember
			if errors.As(err, &unknown) {
				reason = logio.ReasonUnknownMember
			}
			return chain.Entry{}, logio.Faultf(reason, line, e.Sequence, "line %d, entry %d: %v", line, e.Sequence, err)
		}
		current, event = e, ev
		return e.Entry, nil
	}, accepted)
}

// Read reads the lines of a log as entries, strictly, and hands each to visit
// with its line number. It checks neither digests, nor events, nor the chain;
// those are Verify's.
func Read(r io.Reader, limits Limits, visit func(line int, e Entry) error) error {
	return logio.ReadLines(r, limits, func(line int, raw []byte) error {
		e, err := decodeLine(raw)
		if err != nil {
			return logio.LineError(line, err)
		}
		return visit(line, e)
	})
}

// decodeLine reads a line as an entry and refuses it unless it is exactly what
// writing that entry produces: members in their order, no spaces, the time in
// UTC, and the body as compact JSON with <, >, & and U+2028 and U+2029 in its
// strings written as escapes. Go reads a repeated member by the last and a member
// in any case; other readers do not, so only the one form is read.
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
	e.RecordedAt = e.RecordedAt.UTC()
	if again, err := json.Marshal(e); err != nil || !bytes.Equal(again, raw) {
		return Entry{}, errors.New("is not in the one form an entry is written in: " +
			"a repeated, missing or unknown member, a member in another order, case or spelling, " +
			"other spacing in the line or the body, the time in another zone or written another way, " +
			"or markup in the body that is not written as escapes")
	}
	return e, nil
}
