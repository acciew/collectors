package chain_test

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/iotest"

	"go.acciew.io/collector/verify/chain"
)

func anchorOf(t testing.TB, i int) *chain.Anchor {
	t.Helper()
	e := log(t)[i]
	return &chain.Anchor{Format: 1, Sequence: e.Sequence, Chain: e.Chain}
}

func reason(t testing.TB, err error) chain.Reason {
	t.Helper()
	var fault *chain.Error
	if !errors.As(err, &fault) {
		t.Fatalf("error = %v, want a *chain.Error", err)
	}
	return fault.Reason
}

func TestAnAnchorNamingTheLastEntryAgrees(t *testing.T) {
	if err := chain.CheckAnchor(log(t), anchorOf(t, 2)); err != nil {
		t.Errorf("CheckAnchor: %v", err)
	}
	if err := chain.CheckAnchor(nil, nil); err != nil {
		t.Errorf("no log and no anchor: %v", err)
	}
}

func TestCheckAnchorTellsTheWaysItCanDisagreeApart(t *testing.T) {
	cases := []struct {
		name    string
		entries []chain.Entry
		anchor  *chain.Anchor
		want    chain.Reason
	}{
		{"entries cut off the end", log(t)[:2], anchorOf(t, 2), chain.ReasonTailCut},
		{"all entries gone, anchor left", nil, anchorOf(t, 2), chain.ReasonEntriesMissing},
		{"anchor removed", log(t), nil, chain.ReasonAnchorMissing},
		{"anchor behind the log", log(t), anchorOf(t, 1), chain.ReasonAnchorStale},
		{"the last entry named by a different chain value", log(t),
			&chain.Anchor{Format: 1, Sequence: 3, Chain: c1}, chain.ReasonAnchorMismatch},
		{"an earlier entry named by a chain value the log does not hold", log(t),
			&chain.Anchor{Format: 1, Sequence: 2, Chain: c3}, chain.ReasonAnchorMismatch},
		{"an anchor at sequence 0", log(t),
			&chain.Anchor{Format: 1, Sequence: 0, Chain: ""}, chain.ReasonAnchorMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := chain.CheckAnchor(tc.entries, tc.anchor)
			if err == nil {
				t.Fatal("agreed")
			}
			if got := reason(t, err); got != tc.want {
				t.Errorf("reason = %s, want %s (%v)", got, tc.want, err)
			}
		})
	}
}

// A log and an anchor that disagree can be told apart from one another only by
// which side is ahead; the message says which.
func TestTheMessagesSayWhichSideIsAhead(t *testing.T) {
	cut := chain.CheckAnchor(log(t)[:2], anchorOf(t, 2))
	if cut == nil || !strings.Contains(cut.Error(), "log ends at entry 2") || !strings.Contains(cut.Error(), "names entry 3") {
		t.Errorf("tail cut: %v", cut)
	}
	stale := chain.CheckAnchor(log(t), anchorOf(t, 1))
	if stale == nil || !strings.Contains(stale.Error(), "log ends at entry 3") || !strings.Contains(stale.Error(), "names entry 2") {
		t.Errorf("stale: %v", stale)
	}
}

func TestAnAnchorIsReadBackAsWritten(t *testing.T) {
	line := `{"format":1,"sequence":3,"chain":"` + c3 + `"}`
	for _, in := range []string{line, line + "\n"} {
		a, err := chain.ReadAnchor(strings.NewReader(in))
		if err != nil {
			t.Fatalf("ReadAnchor(%q): %v", in, err)
		}
		if a != (chain.Anchor{Format: 1, Sequence: 3, Chain: c3}) {
			t.Errorf("anchor = %+v", a)
		}
	}
}

func TestAnAnchorInAFormatThisVerifierDoesNotKnowIsNotCalledAltered(t *testing.T) {
	cases := map[string]string{
		"format 2":                      `{"format":2,"sequence":3,"chain":"` + c3 + `"}`,
		"format 2 with other fields":    `{"format":2,"seq":3,"head":{"n":"` + c3 + `"}}`,
		"no format at all":              `{"sequence":3,"chain":"` + c3 + `"}`,
		"the format as a string":        `{"format":"1","sequence":3,"chain":"` + c3 + `"}`,
		"the format as 1.0":             `{"format":1.0,"sequence":3,"chain":"` + c3 + `"}`,
		"the format as null":            `{"format":null,"sequence":3,"chain":"` + c3 + `"}`,
		"format 0":                      `{"format":0,"sequence":3,"chain":"` + c3 + `"}`,
		"a file written before formats": `{"sequence":3,"chain":"` + c3 + `"}` + "\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := chain.ReadAnchor(strings.NewReader(in))
			if err == nil {
				t.Fatal("read")
			}
			if got := reason(t, err); got != chain.ReasonFormat {
				t.Errorf("reason = %s, want %s (%v)", got, chain.ReasonFormat, err)
			}
			if !strings.Contains(err.Error(), "not a format this verifier knows") {
				t.Errorf("%q does not say the format is not known", err)
			}
			for _, word := range []string{"altered", "tamper", "changed"} {
				if strings.Contains(err.Error(), word) {
					t.Errorf("%q: a format this verifier does not know is not evidence of a change", err)
				}
			}
		})
	}
}

func TestAnAnchorThatIsNotInTheFormItIsWrittenInIsRefused(t *testing.T) {
	good := `{"format":1,"sequence":3,"chain":"` + c3 + `"}`
	cases := map[string]string{
		"an unknown field":        `{"format":1,"sequence":3,"chain":"` + c3 + `","note":"x"}`,
		"an unknown field first":  `{"note":"x","format":1,"sequence":3,"chain":"` + c3 + `"}`,
		"a repeated field":        `{"format":1,"sequence":2,"sequence":3,"chain":"` + c3 + `"}`,
		"a repeated format":       `{"format":2,"format":1,"sequence":3,"chain":"` + c3 + `"}`,
		"a field in another case": `{"format":1,"Sequence":3,"chain":"` + c3 + `"}`,
		"fields in another order": `{"sequence":3,"format":1,"chain":"` + c3 + `"}`,
		"spaces":                  `{"format": 1, "sequence": 3, "chain": "` + c3 + `"}`,
		"a missing field":         `{"format":1,"chain":"` + c3 + `"}`,
		"a negative sequence":     `{"format":1,"sequence":-3,"chain":"` + c3 + `"}`,
		"a fractional sequence":   `{"format":1,"sequence":3.5,"chain":"` + c3 + `"}`,
		"a string sequence":       `{"format":1,"sequence":"3","chain":"` + c3 + `"}`,
		"a number chain":          `{"format":1,"sequence":3,"chain":7}`,
		"an array":                `[1,3]`,
		"a second object":         good + good,
		"a second line":           good + "\n" + good,
		"text after the object":   good + " x",
		"two final newlines":      good + "\n\n",
		"a carriage return":       good + "\r\n",
		"not JSON":                `format=1`,
		"nothing":                 ``,
		"an unterminated object":  `{"format":1,"sequence":3`,
		"an escaped spelling":     `{"format":1,"sequence":3,"chain":"\u0039` + c3[1:] + `"}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := chain.ReadAnchor(strings.NewReader(in))
			if err == nil {
				t.Fatalf("read %q", in)
			}
			if got := reason(t, err); got != chain.ReasonUnreadable && got != chain.ReasonFormat {
				t.Errorf("reason = %s (%v)", got, err)
			}
		})
	}
}

func TestAnUnknownFieldIsNamed(t *testing.T) {
	_, err := chain.ReadAnchor(strings.NewReader(`{"format":1,"sequence":3,"chain":"` + c3 + `","extra":1}`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "extra"`) {
		t.Errorf("error = %v, want one naming the unknown field", err)
	}
	if reason(t, err) != chain.ReasonUnreadable {
		t.Errorf("reason = %s", reason(t, err))
	}
}

func TestAnAnchorTooLargeToBeOneIsRefusedUnparsed(t *testing.T) {
	big := `{"format":1,"sequence":3,"chain":"` + strings.Repeat("a", 2000) + `"}`
	_, err := chain.ReadAnchor(strings.NewReader(big))
	if err == nil || reason(t, err) != chain.ReasonUnreadable {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "longer than an anchor of format 1 may be (1024 bytes)") {
		t.Errorf("error = %q: it does not say the size is what was refused", err)
	}
	// Exactly the limit is not too large: a valid anchor padded to 1024 bytes is
	// refused for its form and not for its size.
	edge := `{"format":1,"sequence":3,"chain":"` + strings.Repeat("a", 1024-len(`{"format":1,"sequence":3,"chain":""}`)) + `"}`
	if len(edge) != 1024 {
		t.Fatalf("test anchor is %d bytes", len(edge))
	}
	if _, err := chain.ReadAnchor(strings.NewReader(edge)); err != nil {
		t.Errorf("an anchor of exactly 1024 bytes: %v", err)
	}
}

// A file that is too long is refused for its length, and says nothing about
// formats: it may be an anchor of a format this verifier has never heard of.
func TestAnOversizeAnchorOfAnotherFormatIsOnlyCalledOversize(t *testing.T) {
	big := `{"format":2,"note":"` + strings.Repeat("a", 2000) + `"}`
	_, err := chain.ReadAnchor(strings.NewReader(big))
	if err == nil {
		t.Fatal("read")
	}
	if strings.Contains(err.Error(), "no anchor is") || strings.Contains(err.Error(), "format 2") {
		t.Errorf("error = %q: it claims something about formats it does not know", err)
	}
	if !strings.Contains(err.Error(), "longer than an anchor of format 1 may be") {
		t.Errorf("error = %q", err)
	}
}

func TestTheRangeOfAnAnchorsSequenceIsAnUnsigned64BitInteger(t *testing.T) {
	read := func(n string) (chain.Anchor, error) {
		return chain.ReadAnchor(strings.NewReader(`{"format":1,"sequence":` + n + `,"chain":"` + c3 + `"}`))
	}
	if a, err := read("18446744073709551615"); err != nil || a.Sequence != 1<<64-1 {
		t.Errorf("2^64-1: %+v, %v", a, err)
	}
	for _, n := range []string{"18446744073709551616", "99999999999999999999999"} {
		_, err := read(n)
		if err == nil || reason(t, err) != chain.ReasonUnreadable {
			t.Errorf("sequence %s: error = %v", n, err)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestAnAnchorThatCannotBeReadIsUnreadable(t *testing.T) {
	_, err := chain.ReadAnchor(failingReader{})
	if err == nil || reason(t, err) != chain.ReasonUnreadable {
		t.Errorf("error = %v", err)
	}
}

// What the anchor says about the format is quoted from the file, so it is
// shortened and escaped like every other value taken from one.
func TestTheFormatTheFileClaimsIsQuoted(t *testing.T) {
	const rlo = "\xe2\x80\xae" // U+202E, right-to-left override
	_, err := chain.ReadAnchor(strings.NewReader(`{"format":"` + rlo + `[2J` + strings.Repeat("x", 300) + `"}`))
	if err == nil {
		t.Fatal("read")
	}
	if strings.Contains(err.Error(), rlo) || len(err.Error()) > 400 {
		t.Errorf("message = %q", err)
	}
}

// CheckAnchor trusts the entries it is given, so a caller that skipped Check
// gets a fault and not an index out of range.
func TestCheckAnchorDoesNotTrustSequenceNumbersToIndex(t *testing.T) {
	entries := []chain.Entry{{Sequence: 5, Chain: c1}}
	err := chain.CheckAnchor(entries, &chain.Anchor{Format: 1, Sequence: 3, Chain: c1})
	if err == nil || reason(t, err) != chain.ReasonAnchorMismatch {
		t.Errorf("error = %v", err)
	}
}

// Both sides must be told apart in the message: an anchor that names entry 0
// against a log of three is not "nothing and nothing".
func TestAnAnchorNamingNoEntryAtAllSaysWhatEachSideHolds(t *testing.T) {
	err := chain.CheckAnchor(log(t), &chain.Anchor{Format: 1, Sequence: 0, Chain: ""})
	if err == nil || reason(t, err) != chain.ReasonAnchorMismatch {
		t.Fatalf("error = %v", err)
	}
	for _, want := range []string{"the log has 3 entries", "the anchor names entry 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "nothing") {
		t.Errorf("error = %q: both sides read as nothing", err)
	}
}

// A reader over a file fails with the file's path in its error. The path came
// from outside and is not printed raw.
func TestAReadErrorDoesNotPrintThePathItCarries(t *testing.T) {
	fail := &fs.PathError{Op: "read", Path: "/tmp/a\x1b[2Jb\xe2\x80\xaec", Err: errors.New("input/output error")}
	_, err := chain.ReadAnchor(iotest.ErrReader(fail))
	if err == nil || reason(t, err) != chain.ReasonUnreadable {
		t.Fatalf("error = %v", err)
	}
	if strings.ContainsAny(err.Error(), "\x1b") || strings.Contains(err.Error(), "\xe2\x80\xae") || strings.Contains(err.Error(), "/tmp/a") {
		t.Errorf("error = %q", err)
	}
	if !strings.Contains(err.Error(), "input/output error") {
		t.Errorf("error = %q: it does not say what failed", err)
	}
}

// A reader that streams a log judges the anchor holding two entries and not the
// log; the verdicts are those of CheckAnchor.
func TestAnAnchorCheckGivesTheVerdictsOfCheckAnchorEntryByEntry(t *testing.T) {
	entries := log(t)
	cases := map[string]*chain.Anchor{
		"on the last entry":   anchorOf(t, 2),
		"behind the log":      anchorOf(t, 1),
		"past the log":        {Format: 1, Sequence: 4, Chain: c3},
		"another chain value": {Format: 1, Sequence: 2, Chain: c3},
		"at sequence 0":       {Format: 1},
		"no anchor":           nil,
	}
	for name, anchor := range cases {
		t.Run(name, func(t *testing.T) {
			check := chain.NewAnchorCheck(anchor)
			var streamed error
			for _, e := range entries {
				if streamed = check.Add(e); streamed != nil {
					break
				}
			}
			if streamed == nil {
				streamed = check.Done()
			}
			whole := chain.CheckAnchor(entries, anchor)
			if (streamed == nil) != (whole == nil) || (whole != nil && reason(t, streamed) != reason(t, whole)) {
				t.Errorf("streamed = %v, whole = %v", streamed, whole)
			}
		})
	}
}

func TestWithNoAnchorTheFirstEntryIsEnoughToSayThereIsNone(t *testing.T) {
	check := chain.NewAnchorCheck(nil)
	if err := check.Done(); err != nil {
		t.Errorf("a log of nothing and no anchor: %v", err)
	}
	err := check.Add(log(t)[0])
	if err == nil || reason(t, err) != chain.ReasonAnchorMissing {
		t.Errorf("error = %v", err)
	}
}

func TestTheCountOfEntriesAgreesInNumber(t *testing.T) {
	one := chain.CheckAnchor(log(t)[:1], &chain.Anchor{Format: 1, Sequence: 0})
	if one == nil || !strings.Contains(one.Error(), "the log has 1 entry,") {
		t.Errorf("one entry: %v", one)
	}
	three := chain.CheckAnchor(log(t), &chain.Anchor{Format: 1, Sequence: 0})
	if three == nil || !strings.Contains(three.Error(), "the log has 3 entries,") {
		t.Errorf("three entries: %v", three)
	}
}
