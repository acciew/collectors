package chain

import (
	"bytes"
	"encoding/json"
	"io"

	"go.acciew.io/collector/verify/internal/text"
)

// AnchorFormat is the one anchor format this verifier reads.
const AnchorFormat = 1

// maxAnchor is far above the size of a real anchor, and small enough that a
// file that is not one is refused before it is parsed.
const maxAnchor = 1 << 10

// Anchor names the last entry of a log, kept in a second file beside it.
// It is written as one line of JSON in exactly this field order.
type Anchor struct {
	Format   int    `json:"format"`
	Sequence uint64 `json:"sequence"`
	Chain    string `json:"chain"`
}

// ReadAnchor reads an anchor file. It refuses anything but the one form an
// anchor is written in: a format it does not know, a field it does not know,
// a repeated field, another spelling or another spacing, and anything after
// the object but one final newline.
//
// The format is read before anything else is judged, so an anchor from a newer
// format is reported as one this verifier does not know and never as altered.
func ReadAnchor(r io.Reader) (Anchor, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxAnchor+1))
	if err != nil {
		return Anchor{}, fault(ReasonUnreadable, 0, "the anchor cannot be read: %s", text.Plain(err))
	}
	if len(raw) > maxAnchor {
		return Anchor{}, fault(ReasonUnreadable, 0, "the anchor is longer than an anchor of format %d may be (%d bytes)", AnchorFormat, maxAnchor)
	}
	body := bytes.TrimSuffix(raw, []byte("\n"))

	var head struct {
		Format json.RawMessage `json:"format"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return Anchor{}, fault(ReasonUnreadable, 0, "the anchor is not readable: %v", err)
	}
	if string(head.Format) != "1" {
		return Anchor{}, formatFault(head.Format)
	}

	var a Anchor
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return Anchor{}, fault(ReasonUnreadable, 0, "the anchor is not in a form this verifier reads: %v", err)
	}
	if again, err := json.Marshal(a); err != nil || !bytes.Equal(again, body) {
		return Anchor{}, fault(ReasonUnreadable, 0,
			"the anchor is not in the form anchors are written in: a repeated field, another spelling, or other spacing")
	}
	return a, nil
}

func formatFault(raw json.RawMessage) *Error {
	if len(raw) == 0 {
		return fault(ReasonFormat, 0,
			"the anchor does not say which format it is in, so it is not a format this verifier knows (it reads format %d)",
			AnchorFormat)
	}
	return fault(ReasonFormat, 0,
		"the anchor says format %s, which is not a format this verifier knows (it reads format %d): "+
			"a newer verifier may read it, and this one cannot say whether it holds together",
		short(string(raw)), AnchorFormat)
}

// CheckAnchor compares an anchor with the entries it should name the end of.
// A nil anchor means there was no anchor file. Run Check first: this reads the
// last entry's own fields and trusts them.
//
// An empty log and no anchor agree. Anything else that is not the last entry
// named exactly is a fault, told apart by how it differs.
func CheckAnchor(entries []Entry, a *Anchor) error {
	check := NewAnchorCheck(a)
	for _, e := range entries {
		if err := check.Add(e); err != nil {
			return err
		}
	}
	return check.Done()
}

// AnchorCheck is CheckAnchor for a reader that does not hold the log. It keeps
// the last entry and the chain value at the position the anchor names, so what
// it holds does not grow with the log.
type AnchorCheck struct {
	anchor *Anchor
	count  uint64
	last   Entry
	// at is the chain value of the entry at the position the anchor names, and
	// seen says there was one.
	at   string
	seen bool
}

// NewAnchorCheck starts a check against an anchor, or against the absence of
// one if the anchor is nil.
func NewAnchorCheck(a *Anchor) *AnchorCheck { return &AnchorCheck{anchor: a} }

// Add takes the next entry, in order. With no anchor it fails at the first one:
// a log with entries and no anchor needs no more of the log to be said.
func (c *AnchorCheck) Add(e Entry) error {
	if c.anchor == nil {
		return fault(ReasonAnchorMissing, 0, "the log has entries and no anchor: one of the two was removed")
	}
	c.count++
	c.last = e
	if c.count == c.anchor.Sequence {
		c.at, c.seen = e.Chain, true
	}
	return nil
}

// Done gives the verdict once the last entry has been added.
func (c *AnchorCheck) Done() error {
	a := c.anchor
	if a == nil {
		return nil
	}
	if c.count == 0 {
		return fault(ReasonEntriesMissing, a.Sequence,
			"the anchor names entry %d and the log has no entries: one of the two was removed", a.Sequence)
	}
	last := c.last
	switch {
	case a.Sequence > last.Sequence:
		return fault(ReasonTailCut, last.Sequence,
			"the log ends at entry %d and the anchor names entry %d: entries were removed from the end, "+
				"or the anchor belongs to a longer log", last.Sequence, a.Sequence)
	case a.Sequence == last.Sequence && a.Chain == last.Chain:
		return nil
	case a.Sequence < last.Sequence && c.seen && c.at == a.Chain:
		return fault(ReasonAnchorStale, a.Sequence,
			"the log ends at entry %d and the anchor names entry %d, which is in the log: "+
				"the anchor is behind it", last.Sequence, a.Sequence)
	case !c.seen:
		noun := "entries"
		if c.count == 1 {
			noun = "entry"
		}
		return fault(ReasonAnchorMismatch, a.Sequence,
			"the log has %d %s, numbered from 1, and the anchor names entry %d", c.count, noun, a.Sequence)
	}
	return fault(ReasonAnchorMismatch, a.Sequence,
		"entry %d is %s in the log and %s in the anchor", a.Sequence, short(c.at), short(a.Chain))
}
