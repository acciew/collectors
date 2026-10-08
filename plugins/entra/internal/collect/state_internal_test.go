package collect

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// A cut that lands inside a character leaves bytes that are not text, and a
// message that is not text cannot be sent. This holds the cut to the boundary,
// for every length it could land on.
func TestClipCutsOnACharacterBoundaryWhereverTheLimitFalls(t *testing.T) {
	for _, unit := range []string{"経", "é", "😀", "a"} {
		text := strings.Repeat(unit, 400)
		for n := 1; n < 40; n++ {
			got := clip(text, n)
			if !utf8.ValidString(got) {
				t.Fatalf("clip(%q x400, %d) = %q is not valid UTF-8", unit, n, got)
			}
			if len(strings.TrimSuffix(got, "...")) > n {
				t.Fatalf("clip(%q x400, %d) kept %d bytes", unit, n, len(got))
			}
		}
	}
	if got := clip("short", 100); got != "short" {
		t.Errorf("clip changed text that fits: %q", got)
	}
}

// And text that was never valid is made so, not passed on.
func TestClipMakesInvalidTextValid(t *testing.T) {
	got := clip("a name \xff\xfe with bad bytes", 100)
	if !utf8.ValidString(got) || strings.IndexByte(got, 0xff) >= 0 || strings.IndexByte(got, 0xfe) >= 0 {
		t.Errorf("clip passed invalid bytes on: %q", got)
	}
	st := &state{}
	st.problem("k", errors.New("bad \xff name"))
	if len(st.problems) != 1 || !utf8.ValidString(st.problems[0].Text) {
		t.Errorf("a problem carried invalid text: %+v", st.problems)
	}
}

// LowerLimits shrinks what one read may take and hold, so that a test need not
// make a hundred thousand pages or ten thousand members to reach them. A
// negative number leaves a limit as it is. The function it returns puts them
// back.
func LowerLimits(readPages, groupMembers, allMembers int) (restore func()) {
	r, g, a := readCeiling, maxCachedMembers, maxCachedTotal
	if readPages >= 0 {
		readCeiling = readPages
	}
	if groupMembers >= 0 {
		maxCachedMembers = groupMembers
	}
	if allMembers >= 0 {
		maxCachedTotal = allMembers
	}
	return func() { readCeiling, maxCachedMembers, maxCachedTotal = r, g, a }
}

// LowerEventLimit is the most events a stream may send and the number held back
// from records for the events that end it, for a test.
func LowerEventLimit(limit, held int) (restore func()) {
	l, h := eventLimit, eventHeld
	eventLimit, eventHeld = limit, held
	return func() { eventLimit, eventHeld = l, h }
}

// LowerByteLimit is the most bytes of events a stream may send and the number
// held back from records for the events that end it, for a test.
func LowerByteLimit(limit, held int) (restore func()) {
	l, h := byteLimit, byteHeld
	byteLimit, byteHeld = limit, held
	return func() { byteLimit, byteHeld = l, h }
}
