package collection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Canonical renders a run in the one form its digest is taken over.
//
// One line of JSON, members in the order below, strings escaped as the
// specification's Strings section says, the start time as an RFC 3339 instant in
// UTC, scopes by id and observations in a fixed order. Enumerations are numbers,
// never words. It is written here by hand and not by encoding/json: a digest is
// a fact about the specification, and must not move with the escaping rules of a
// library version.
func Canonical(r Run) []byte {
	b := make([]byte, 0, 512)
	b = append(b, `{"source":`...)
	b = appendString(b, r.Source)
	b = append(b, `,"started_at":`...)
	b = appendString(b, r.StartedAt.UTC().Format(time.RFC3339Nano))
	b = append(b, `,"whole":`...)
	b = strconv.AppendBool(b, r.Whole)
	b = append(b, `,"verdict":`...)
	b = strconv.AppendInt(b, int64(r.Verdict), 10)
	b = append(b, `,"cause":`...)
	b = strconv.AppendInt(b, int64(r.Cause), 10)

	b = append(b, `,"scopes":`...)
	scopes := make([]piece, 0, len(r.Scopes))
	for _, s := range r.Scopes {
		scopes = append(scopes, piece{key: s.ID, text: appendScope(nil, s)})
	}
	b = appendOrdered(b, scopes)

	c := r.Counts
	b = append(b, `,"counts":{"identities":`...)
	b = strconv.AppendInt(b, c.Identities, 10)
	b = append(b, `,"groupings":`...)
	b = strconv.AppendInt(b, c.Groupings, 10)
	b = append(b, `,"entitlements":`...)
	b = strconv.AppendInt(b, c.Entitlements, 10)
	b = append(b, `,"resources":`...)
	b = strconv.AppendInt(b, c.Resources, 10)
	b = append(b, `,"grants":`...)
	b = strconv.AppendInt(b, c.Grants, 10)
	b = append(b, `,"referenced":`...)
	b = strconv.AppendInt(b, c.Referenced, 10)

	b = append(b, `},"observed":`...)
	grants := make([]piece, 0, len(r.Observed))
	for _, g := range r.Observed {
		grants = append(grants, renderGrant(g))
	}
	b = appendOrdered(b, grants)
	return append(b, '}')
}

// Digest is the SHA-256 of the canonical form, as lowercase hexadecimal.
func Digest(r Run) string {
	sum := sha256.Sum256(Canonical(r))
	return hex.EncodeToString(sum[:])
}

// piece is one element of a list that is put in order: the text it is first
// ordered by, and its own rendering, which orders elements whose keys are equal.
// Equal renderings are the same element, so the order is total.
type piece struct {
	key  string
	text []byte
}

// appendOrdered writes a list of elements in order, or null if there are none.
func appendOrdered(b []byte, items []piece) []byte {
	if len(items) == 0 {
		return append(b, "null"...)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].key != items[j].key {
			return items[i].key < items[j].key
		}
		return bytes.Compare(items[i].text, items[j].text) < 0
	})
	b = append(b, '[')
	for i, it := range items {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, it.text...)
	}
	return append(b, ']')
}

func appendScope(b []byte, s Scope) []byte {
	b = append(b, `{"id":`...)
	b = appendString(b, s.ID)
	b = append(b, `,"status":`...)
	b = strconv.AppendInt(b, int64(s.Status), 10)
	b = append(b, `,"reason":`...)
	b = appendString(b, s.Reason)
	b = append(b, `,"activity_available":`...)
	b = strconv.AppendBool(b, s.ActivityAvailable)
	if s.ActivityUndetermined {
		b = append(b, `,"activity_undetermined":true`...)
	}
	return append(b, '}')
}

// renderGrant renders a grant and works out the text it is first ordered by:
// subject, entitlement, route and fidelity, each ended by a NUL so that one part
// cannot run into the next.
func renderGrant(g Grant) piece {
	identity, entitlement := g.Identity.String(), g.Entitlement.String()
	via := make([]string, 0, len(g.Via))
	for _, k := range g.Via {
		via = append(via, k.String())
	}
	b := append([]byte(nil), `{"identity":`...)
	b = appendString(b, identity)
	b = append(b, `,"entitlement":`...)
	b = appendString(b, entitlement)
	b = append(b, `,"fidelity":`...)
	b = strconv.AppendInt(b, int64(g.Fidelity), 10)
	b = append(b, `,"via":`...)
	if len(via) == 0 {
		b = append(b, "null"...)
	} else {
		b = append(b, '[')
		for i, v := range via {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, v)
		}
		b = append(b, ']')
	}
	b = append(b, '}')
	key := identity + "\x00" + entitlement + "\x00" + strings.Join(via, ">") + "\x00" + strconv.Itoa(int(g.Fidelity))
	return piece{key: key, text: b}
}

const hexDigits = "0123456789abcdef"

// appendString writes a string as the Strings section of the specification
// says: the escapes of Go's encoding/json with its HTML escaping, spelled out
// here so that they are the same under any version of it.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				b = append(b, '\\', c)
			case c == '\b':
				b = append(b, '\\', 'b')
			case c == '\f':
				b = append(b, '\\', 'f')
			case c == '\n':
				b = append(b, '\\', 'n')
			case c == '\r':
				b = append(b, '\\', 'r')
			case c == '\t':
				b = append(b, '\\', 't')
			case c < 0x20 || c == '<' || c == '>' || c == '&':
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			default:
				b = append(b, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// One for each byte that is not part of a valid sequence. A real
			// U+FFFD, which is three bytes, is written as itself.
			b = append(b, `\ufffd`...)
		case r == '\u2028' || r == '\u2029':
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
		default:
			b = append(b, s[i:i+size]...)
		}
		i += size
	}
	return append(b, '"')
}
