package collection_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/collection"
)

// testdata/good.jsonl is three collections written by a separate
// implementation of the digest and the chain, testdata/gen/fixture.py, which
// shares no code with this package and is run by a test below. It holds an empty collection with null lists, a
// partial one with a name containing < and &, non-ASCII ids, an unrecognised
// enum value and key type, a route of two keys, a scope whose activity could not
// be determined and a time with a fraction, and a third with nine fractional digits.
const (
	d1 = "f296b2e6af7c14b0335950c51077dc627f073aa8172fd2ffb0a979b07185bf20"
	d2 = "a319fd1c8fda3eb8f631a2f26aa131801e3ee875a16848b2dabf6e0ed658fd25"
	d3 = "e9595a0f9ad8f0493be666548e008f5d13e004a1873d47484ca5768a3adabb06"
	c1 = "6b0f653e62fe00ee67511a11a52f6465c7affdae4775093f30867199b58ee0c4"
	c2 = "f809155c2b9d4971c05ab0cf4cbde5f06112e014340b21882c476f5308676373"
	c3 = "253b941f286f85c0a76ef200de1441ccd50bc767adba17be29ddd9fe2eeeec6f"
)

func readTestdata(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func good(t testing.TB) (log, head string) {
	t.Helper()
	return readTestdata(t, "good.jsonl"), readTestdata(t, "good.head")
}

func lines(log string) []string { return strings.SplitAfter(log, "\n")[:strings.Count(log, "\n")] }

func put(t testing.TB, dir, name string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func verify(t testing.TB, log, head string) (collection.Summary, error) {
	t.Helper()
	dir := t.TempDir()
	put(t, dir, "x.jsonl", log)
	if head != "" {
		put(t, dir, "x.head", head)
	}
	return collection.Verify(dir, "x")
}

func replaceOnce(t testing.TB, s, old, replacement string) string {
	t.Helper()
	if strings.Count(s, old) != 1 {
		t.Fatalf("the fixture has %d of %q, the test wants exactly one", strings.Count(s, old), old)
	}
	return strings.Replace(s, old, replacement, 1)
}

// want says what a verification must report: the reason, and the line or the
// entry it is found at.
type want struct {
	reason string
	line   int    // for a fault in a line
	entry  uint64 // for a fault in the chain
}

func check(t *testing.T, err error, w want) {
	t.Helper()
	if err == nil {
		t.Fatalf("verified; want %q", w.reason)
	}
	if got := collection.ReasonOf(err); got != w.reason {
		t.Errorf("reason = %q, want %q (%v)", got, w.reason, err)
	}
	var line *collection.Error
	if errors.As(err, &line) && w.line != 0 && line.Line != w.line {
		t.Errorf("fault is at line %d, want %d (%v)", line.Line, w.line, err)
	}
	var link *chain.Error
	if errors.As(err, &link) && w.entry != 0 && link.Sequence != w.entry {
		t.Errorf("fault is at entry %d, want %d (%v)", link.Sequence, w.entry, err)
	}
	for _, word := range []string{"tamper", "forged", "attack"} {
		if strings.Contains(strings.ToLower(err.Error()), word) {
			t.Errorf("%q says more than the files can show", err)
		}
	}
}

func TestAnUntouchedLogVerifiesAndSaysWhatItHolds(t *testing.T) {
	log, head := good(t)
	got, err := verify(t, log, head)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Entries != 3 || got.Head != c3 {
		t.Errorf("summary = %+v, want 3 entries ending at %s", got, c3)
	}
}

// The digests in the fixture were written by another implementation. Reading
// them back and computing them here is what shows the two agree, for the cases
// the golden digest does not reach.
func TestTheDigestsAnotherImplementationWroteAreTheOnesThisComputes(t *testing.T) {
	log, _ := good(t)
	var got []string
	err := collection.Read(strings.NewReader(log), collection.Limits{}, func(line int, e collection.Entry) error {
		if d := collection.Digest(e.Run); d != e.Digest {
			t.Errorf("line %d: Digest = %s, the other implementation wrote %s", line, d, e.Digest)
		}
		got = append(got, e.Digest)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != d1+","+d2+","+d3 {
		t.Errorf("digests = %v", got)
	}
}

func TestEntriesAreReadAsTheyAreWritten(t *testing.T) {
	log, _ := good(t)
	var entries []collection.Entry
	if err := collection.Read(strings.NewReader(log), collection.Limits{}, func(_ int, e collection.Entry) error {
		entries = append(entries, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e := entries[1]
	if e.Sequence != 2 || e.Previous != c1 || e.Chain != c2 || !e.RecordedAt.Equal(time.Date(2026, 3, 2, 8, 30, 10, 250_000_000, time.UTC)) {
		t.Errorf("entry = %+v", e.Entry)
	}
	if e.Run.Source != "alpha" || e.Run.Verdict != 2 || e.Run.Cause != 77 || len(e.Run.Scopes) != 2 || len(e.Run.Observed) != 5 {
		t.Errorf("run = %+v", e.Run)
	}
	if !e.Run.Scopes[1].ActivityUndetermined || e.Run.Scopes[1].Reason != "token expired" {
		t.Errorf("scope = %+v", e.Run.Scopes[1])
	}
	if got := e.Run.Observed[0].Identity.String(); got != "ops<&>/identity/zoë" {
		t.Errorf("identity = %q", got)
	}
}

func TestAChangeToTheFilesIsNamed(t *testing.T) {
	log, head := good(t)
	ls := lines(log)
	join := func(parts ...string) string { return strings.Join(parts, "") }

	// An entry rewritten the way somebody who also knows the rules would: the
	// record, its digest and its own chain value all changed, the rest left.
	rewritten := func(fixChain bool) string {
		var e collection.Entry
		if err := json.Unmarshal([]byte(ls[1]), &e); err != nil {
			t.Fatal(err)
		}
		e.Run.Counts.Identities = 9
		e.Digest = collection.Digest(e.Run)
		if fixChain {
			e.Chain = chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous)
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return string(b) + "\n"
	}

	cases := []struct {
		name      string
		log, head string
		w         want
	}{
		{"a byte of a record edited", replaceOnce(t, log, `"identities":3`, `"identities":9`), head,
			want{reason: "digest", line: 2}},
		{"a digest edited", replaceOnce(t, log, d2, d3), head, want{reason: "digest", line: 2}},
		{"a time edited", replaceOnce(t, log, `"recorded_at":"2026-03-02T08:30:10.25Z"`, `"recorded_at":"2026-03-02T08:30:11.25Z"`), head,
			want{reason: "chain-value", entry: 2}},
		{"a record and its digest edited", join(ls[0], rewritten(false), ls[2]), head, want{reason: "chain-value", entry: 2}},
		{"a record, its digest and its chain value edited", join(ls[0], rewritten(true), ls[2]), head,
			want{reason: "link", entry: 3}},
		{"an entry removed from the middle", join(ls[0], ls[2]), head, want{reason: "sequence", entry: 3}},
		{"the first entry removed", join(ls[1], ls[2]), head, want{reason: "sequence", entry: 2}},
		{"two entries swapped", join(ls[0], ls[2], ls[1]), head, want{reason: "sequence", entry: 3}},
		{"an entry repeated", join(ls[0], ls[1], ls[1], ls[2]), head, want{reason: "sequence", entry: 2}},
		{"the last entry cut off", join(ls[0], ls[1]), head, want{reason: "tail-cut"}},
		{"every entry cut off", "", head, want{reason: "entries-missing"}},
		{"the anchor removed", log, "", want{reason: "anchor-missing"}},
		{"the anchor behind the log", log, `{"format":1,"sequence":2,"chain":"` + c2 + `"}`, want{reason: "anchor-stale"}},
		{"the anchor of another log", log, `{"format":1,"sequence":3,"chain":"` + c1 + `"}`, want{reason: "anchor-mismatch"}},
		{"an anchor in format 2", log, `{"format":2,"sequence":3,"chain":"` + c3 + `"}`, want{reason: "format"}},
		{"an anchor from before formats", log, `{"sequence":3,"chain":"` + c3 + `"}`, want{reason: "format"}},
		{"an anchor with a field it does not know", log, `{"format":1,"sequence":3,"chain":"` + c3 + `","at":1}`, want{reason: "unreadable"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(t, tc.log, tc.head)
			check(t, err, tc.w)
		})
	}
}

// Nothing a single party holds can show this, and the specification says so:
// whoever can rewrite the log and its anchor together leaves nothing to find.
func TestACutLogWithItsAnchorMovedToMatchVerifies(t *testing.T) {
	log, _ := good(t)
	ls := lines(log)
	got, err := verify(t, ls[0]+ls[1], `{"format":1,"sequence":2,"chain":"`+c2+`"}`)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Entries != 2 || got.Head != c2 {
		t.Errorf("summary = %+v", got)
	}
}

func TestALogOfNothingAndNoAnchorAgree(t *testing.T) {
	got, err := verify(t, "", "")
	if err != nil || got.Entries != 0 || got.Head != "" {
		t.Errorf("Verify = %+v, %v", got, err)
	}
}

func TestALineMustBeExactlyTheFormItIsWrittenIn(t *testing.T) {
	log, head := good(t)
	ls := lines(log)
	bs := "\\"
	at2 := func(old, replacement string) string {
		return ls[0] + replaceOnce(t, ls[1], old, replacement) + ls[2]
	}
	cases := []struct {
		name string
		log  string
	}{
		{"an unknown member", at2(`"sequence":2,`, `"sequence":2,"note":"x",`)},
		{"an unknown member of the run", at2(`"run":{`, `"run":{"extra":1,`)},
		{"an unknown member of a key", at2(`{"scope":"ops\u003c\u0026\u003e","type":2,"id":"root"}`,
			`{"scope":"ops\u003c\u0026\u003e","type":2,"id":"root","x":1}`)},
		{"an unknown member of a scope", at2(`"status":9,`, `"status":9,"x":true,`)},
		{"not JSON", ls[0] + "{ this is not an entry\n" + ls[2]},
		{"an empty line", ls[0] + "\n" + ls[1] + ls[2]},
		{"a blank line at the end", log + "\n"},
		{"no final line feed", strings.TrimSuffix(log, "\n")},
		{"a carriage return", ls[0] + strings.TrimSuffix(ls[1], "\n") + "\r\n" + ls[2]},
		{"leading space", ls[0] + " " + ls[1] + ls[2]},
		{"a repeated member", at2(`"sequence":2,`, `"sequence":2,"sequence":2,`)},
		{"a repeated member with another value", at2(`"sequence":2,`, `"sequence":7,"sequence":2,`)},
		{"a member in another case", at2(`"source":"alpha"`, `"Source":"alpha"`)},
		{"a member spelled with a long s", at2(`"source":"alpha"`, "\"\xc5\xbfource\":\"alpha\"")},
		{"a null for a value", at2(`"whole":false`, `"whole":null`)},
		{"a missing member", at2(`"cause":77,`, ``)},
		{"members in another order", at2(`"sequence":2,"recorded_at":"2026-03-02T08:30:10.25Z",`, `"recorded_at":"2026-03-02T08:30:10.25Z","sequence":2,`)},
		{"spacing", at2(`"sequence":2`, `"sequence": 2`)},
		{"an escape where a plain character would do", at2(`"source":"alpha"`, `"source":"alph`+bs+`u0061"`)},
		{"an empty reason written out", at2(`"status":1,"activity_available"`, `"status":1,"reason":"","activity_available"`)},
		{"an empty route written out", ls[0] + ls[1] + replaceOnce(t, ls[2], `"fidelity":2}]`, `"fidelity":2,"via":[]}]`)},
		{"a number with a fraction", at2(`"identities":3`, `"identities":3.0`)},
		{"a number with an exponent", at2(`"identities":3`, `"identities":3e0`)},
		{"a number too large", at2(`"verdict":2`, `"verdict":4294967296`)},
		{"a negative sequence", at2(`"sequence":2`, `"sequence":-2`)},
		{"a sequence past 64 bits", at2(`"sequence":2`, `"sequence":18446744073709551616`)},
		{"a string for a number", at2(`"identities":3`, `"identities":"3"`)},
		{"a time with a comma", at2(`10.25Z`, `10,25Z`)},
		{"a time with a trailing zero", at2(`10.25Z`, `10.250Z`)},
		{"a time with a zero offset written out", at2(`2026-03-02T08:30:10.25Z`, `2026-03-02T08:30:10.25+00:00`)},
		{"a time in lower case", at2(`2026-03-02T08:30:10.25Z`, `2026-03-02t08:30:10.25z`)},
		{"an invalid byte in a string", at2(`"source":"alpha"`, "\"source\":\"alph\xff\"")},
		{"a second object on the line", strings.TrimSuffix(ls[0], "\n") + ls[0] + ls[1] + ls[2]},
		{"an array", "[1]\n"},
		{"a bare string", "\"x\"\n"},
		{"a line of nothing but a null", "null\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(t, tc.log, head)
			if err == nil {
				t.Fatal("verified")
			}
			if got := collection.ReasonOf(err); got != "line" {
				t.Errorf("reason = %q, want line (%v)", got, err)
			}
		})
	}
}

func TestAFaultInALineSaysWhichLine(t *testing.T) {
	log, head := good(t)
	ls := lines(log)
	_, err := verify(t, ls[0]+ls[1]+"{ this is not an entry\n", head)
	check(t, err, want{reason: "line", line: 3})
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("%v does not name the line", err)
	}
}

func TestAnUnknownMemberIsNamed(t *testing.T) {
	log, head := good(t)
	_, err := verify(t, replaceOnce(t, log, `"run":{"source":"alpha","started_at":"2026-03-01T00:00:00Z"`,
		`"run":{"extra":1,"source":"alpha","started_at":"2026-03-01T00:00:00Z"`), head)
	if err == nil || !strings.Contains(err.Error(), `unknown field "extra"`) {
		t.Errorf("error = %v", err)
	}
}

func TestALineLongerThanTheLimitIsRefusedNotSkipped(t *testing.T) {
	log, head := good(t)
	ls := lines(log)
	limit := len(ls[1]) - 1 // the longest line, without its line feed
	dir := t.TempDir()
	put(t, dir, "x.jsonl", log)
	put(t, dir, "x.head", head)

	open := func(l collection.Limits) error {
		f, err := os.Open(filepath.Join(dir, "x.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h, err := os.Open(filepath.Join(dir, "x.head"))
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		_, err = collection.VerifyReaders("x", f, h, l)
		return err
	}
	if err := open(collection.Limits{MaxLineBytes: limit}); err != nil {
		t.Errorf("a line exactly as long as the limit: %v", err)
	}
	err := open(collection.Limits{MaxLineBytes: limit - 1})
	check(t, err, want{reason: "line", line: 2})
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("error = %v", err)
	}
	if err := open(collection.Limits{}); err != nil {
		t.Errorf("the zero limits mean the default: %v", err)
	}
}

// A line is read in pieces; a collection of a few thousand grants is longer than
// any one piece, and a reader that hands back a byte at a time must reach the
// same verdict.
func TestALongLineIsReadWholeHoweverItArrives(t *testing.T) {
	r := run()
	for i := range 3000 {
		r.Observed = append(r.Observed, collection.Grant{
			Identity:    collection.Key{Scope: "s", Type: 1, ID: "user-" + strings.Repeat("x", i%7) + string(rune('a'+i%26))},
			Entitlement: collection.Key{Scope: "s", Type: 3, ID: "role"},
			Fidelity:    1 + int32(i%3),
			Via:         []collection.Key{{Scope: "s", Type: 2, ID: "g" + string(rune('a'+i%5))}},
		})
	}
	log, head := build(t, []collection.Run{run(), r})
	if len(lines(log)[1]) < 200_000 {
		t.Fatalf("the long line is only %d bytes", len(lines(log)[1]))
	}
	got, err := collection.VerifyReaders("x", strings.NewReader(log), strings.NewReader(head), collection.Limits{})
	if err != nil || got.Entries != 2 {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	got, err = collection.VerifyReaders("x", iotest.OneByteReader(strings.NewReader(log)), strings.NewReader(head), collection.Limits{})
	if err != nil || got.Entries != 2 {
		t.Fatalf("a reader that returns one byte at a time: %+v, %v", got, err)
	}
}

func TestAReaderThatFailsIsUnreadableNotAlteredAndNotAPass(t *testing.T) {
	log, head := good(t)
	boom := errors.New("disk on fire")
	failing := io.MultiReader(strings.NewReader(lines(log)[0]), iotest.ErrReader(boom))
	_, err := collection.VerifyReaders("x", failing, strings.NewReader(head), collection.Limits{})
	check(t, err, want{reason: "unreadable"})
	if !errors.Is(err, boom) {
		t.Errorf("%v does not carry the reader's own error", err)
	}
	_, err = collection.VerifyReaders("x", strings.NewReader(log), iotest.ErrReader(boom), collection.Limits{})
	check(t, err, want{reason: "unreadable"})
}

// A reader over a file fails with the file's path in its error. The path came
// from outside and is not printed raw.
func TestAReadErrorDoesNotPrintThePathItCarries(t *testing.T) {
	log, head := good(t)
	odd := "/tmp/a\x1b[2Jb\xe2\x80\xaec"
	fail := &fs.PathError{Op: "read", Path: odd, Err: errors.New("input/output error")}
	_, err := collection.VerifyReaders("x", io.MultiReader(strings.NewReader(lines(log)[0]), iotest.ErrReader(fail)),
		strings.NewReader(head), collection.Limits{})
	check(t, err, want{reason: "unreadable"})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b") || strings.Contains(err.Error(), "\xe2\x80\xae") || strings.Contains(err.Error(), "/tmp/a") {
		t.Errorf("error = %q", err)
	}
	if !strings.Contains(err.Error(), "input/output error") {
		t.Errorf("error = %q: it does not say what failed", err)
	}
	if !errors.Is(err, fail) {
		t.Errorf("%v does not carry the reader's own error", err)
	}
}

func TestAMissingAnchorIsAnAbsentReader(t *testing.T) {
	log, _ := good(t)
	_, err := collection.VerifyReaders("x", strings.NewReader(log), nil, collection.Limits{})
	check(t, err, want{reason: "anchor-missing"})
}

func TestNamesThatCouldLeaveTheDirectoryAreRefused(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "../x", "a\x00b", strings.Repeat("n", 129)} {
		_, err := collection.Verify(dir, name)
		if err == nil || collection.ReasonOf(err) != "name" {
			t.Errorf("name %q: error = %v", name, err)
		}
	}
	// A name that is long but not too long, and one with characters a file
	// manager would show, are names.
	log, head := good(t)
	for _, name := range []string{strings.Repeat("n", 128), "acme keycloak", "a.b-c_d", "é"} {
		put(t, dir, name+".jsonl", log)
		put(t, dir, name+".head", head)
		if _, err := collection.Verify(dir, name); err != nil {
			t.Errorf("name %q: %v", name, err)
		}
	}
}

func TestWhatIsNotAPlainFileIsRefused(t *testing.T) {
	log, head := good(t)

	t.Run("no directory", func(t *testing.T) {
		_, err := collection.Verify(filepath.Join(t.TempDir(), "nowhere"), "x")
		check(t, err, want{reason: "unreadable"})
	})
	t.Run("no log", func(t *testing.T) {
		dir := t.TempDir()
		put(t, dir, "x.head", head)
		_, err := collection.Verify(dir, "x")
		check(t, err, want{reason: "unreadable"})
	})
	t.Run("a directory where the log should be", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "x.jsonl"), 0o700); err != nil {
			t.Fatal(err)
		}
		put(t, dir, "x.head", head)
		_, err := collection.Verify(dir, "x")
		check(t, err, want{reason: "unreadable"})
	})
	t.Run("a directory where the anchor should be", func(t *testing.T) {
		dir := t.TempDir()
		put(t, dir, "x.jsonl", log)
		if err := os.Mkdir(filepath.Join(dir, "x.head"), 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := collection.Verify(dir, "x")
		check(t, err, want{reason: "unreadable"})
	})
	t.Run("a link to a log", func(t *testing.T) {
		dir, other := t.TempDir(), t.TempDir()
		put(t, other, "real.jsonl", log)
		put(t, dir, "x.head", head)
		if err := os.Symlink(filepath.Join(other, "real.jsonl"), filepath.Join(dir, "x.jsonl")); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		_, err := collection.Verify(dir, "x")
		check(t, err, want{reason: "unreadable"})
	})
	t.Run("a link to an anchor", func(t *testing.T) {
		dir, other := t.TempDir(), t.TempDir()
		put(t, dir, "x.jsonl", log)
		put(t, other, "real.head", head)
		if err := os.Symlink(filepath.Join(other, "real.head"), filepath.Join(dir, "x.head")); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		_, err := collection.Verify(dir, "x")
		check(t, err, want{reason: "unreadable"})
	})
}

func TestReasonOfNamesTheFaultAndNothingElse(t *testing.T) {
	if got := collection.ReasonOf(errors.New("anything")); got != "" {
		t.Errorf("ReasonOf(other) = %q", got)
	}
	if got := collection.ReasonOf(nil); got != "" {
		t.Errorf("ReasonOf(nil) = %q", got)
	}
}

// build writes runs as a log the way a writer would, using this package's own
// digest and the chain's own value. The primitives are pinned by the golden
// tests above and in the chain package, so this is for shapes, not for values.
func build(t testing.TB, runs []collection.Run) (log, head string) {
	t.Helper()
	var out bytes.Buffer
	previous := ""
	for i, r := range runs {
		e := collection.Entry{
			Entry: chain.Entry{
				Sequence:   uint64(i + 1),
				RecordedAt: when.Add(time.Duration(i) * time.Second),
				Digest:     collection.Digest(r),
				Previous:   previous,
			},
			Run: r,
		}
		e.Chain = chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous)
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(line)
		out.WriteByte('\n')
		previous = e.Chain
	}
	h, err := json.Marshal(chain.Anchor{Format: chain.AnchorFormat, Sequence: uint64(len(runs)), Chain: previous})
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), string(h)
}

// What a writer produces for a run, in the form a line takes, verifies: the
// shapes the fixture does not reach (a run with nothing in it, empty lists) too.
func TestRunsAsAWriterWouldWriteThemVerify(t *testing.T) {
	runs := []collection.Run{
		{},
		{Scopes: []collection.Scope{}, Observed: []collection.Grant{}},
		run(),
		{Source: "a<b", StartedAt: time.Date(2026, 1, 1, 3, 0, 0, 1, time.FixedZone("", 3*60*60)), Whole: true},
	}
	log, head := build(t, runs)
	got, err := verify(t, log, head)
	if err != nil || got.Entries != 4 {
		t.Fatalf("Verify = %+v, %v\n%s", got, err, log)
	}
}

func TestAnInvalidByteIsNamedAsSuch(t *testing.T) {
	log, head := good(t)
	_, err := verify(t, strings.Replace(log, `"source":"alpha"`, "\"source\":\"alph\xff\"", 1), head)
	if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Errorf("error = %v", err)
	}
}

func TestInputWithNoLineFeedInItIsBoundedToo(t *testing.T) {
	_, err := collection.VerifyReaders("x", strings.NewReader(strings.Repeat("a", 5000)), nil, collection.Limits{MaxLineBytes: 100})
	check(t, err, want{reason: "line", line: 1})
	if err == nil || !strings.Contains(err.Error(), "longer than 100 bytes") {
		t.Errorf("error = %v", err)
	}
}

// A name goes into a message, and it came from outside: nothing in it may reach a
// terminal as a control or direction character.
func TestANameIsQuotedWhenItHoldsWhatATerminalWouldObey(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a\nb", "a\x1b[2Jb", "a\xe2\x80\xaeb", "a\xffb"} {
		_, err := collection.Verify(dir, name)
		if err == nil {
			t.Fatalf("name %q verified", name)
		}
		if strings.ContainsAny(err.Error(), "\n\x1b") || strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "\xe2\x80\xae") {
			t.Errorf("name %q reached the message raw: %q", name, err.Error())
		}
	}
}

// The anchor says whether the format is known, and whether there is one at all,
// before any entry is read: a log of ten gigabytes is not read to find out.
func TestTheAnchorIsReadBeforeTheLog(t *testing.T) {
	untouched := readerFunc(func([]byte) (int, error) {
		t.Error("the log was read before the anchor was judged")
		return 0, io.EOF
	})
	_, err := collection.VerifyReaders("x", untouched, strings.NewReader(`{"format":2,"sequence":3,"chain":"`+c3+`"}`), collection.Limits{})
	check(t, err, want{reason: "format"})
	_, err = collection.VerifyReaders("x", untouched, strings.NewReader(`{ nonsense`), collection.Limits{})
	check(t, err, want{reason: "unreadable"})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// With no anchor the first entry already settles it.
func TestNoAnchorIsSettledAtTheFirstEntry(t *testing.T) {
	log, _ := good(t)
	rest := iotest.ErrReader(errors.New("read past the first entry"))
	_, err := collection.VerifyReaders("x", io.MultiReader(strings.NewReader(lines(log)[0]), rest), nil, collection.Limits{})
	check(t, err, want{reason: "anchor-missing"})
	// A first entry that is itself wrong is reported as that.
	_, err = collection.VerifyReaders("x", strings.NewReader("{ not an entry\n"), nil, collection.Limits{})
	check(t, err, want{reason: "line", line: 1})
}

// genLog is a log of minimal entries that exists only as it is read.
type genLog struct {
	n, i     int
	digest   string
	previous string
	buf      []byte
	onLine   func(i int)
}

func (g *genLog) Read(p []byte) (int, error) {
	for len(g.buf) == 0 {
		if g.i == g.n {
			return 0, io.EOF
		}
		g.i++
		e := collection.Entry{Entry: chain.Entry{
			Sequence: uint64(g.i), RecordedAt: when.Add(time.Duration(g.i) * time.Second),
			Digest: g.digest, Previous: g.previous,
		}}
		e.Chain = chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous)
		line, err := json.Marshal(e)
		if err != nil {
			return 0, err
		}
		g.buf = append(append(g.buf[:0], line...), '\n')
		g.previous = e.Chain
		if g.onLine != nil {
			g.onLine(g.i)
		}
	}
	n := copy(p, g.buf)
	g.buf = g.buf[n:]
	return n, nil
}

func lastChain(n int, digest string) string {
	previous := ""
	for i := 1; i <= n; i++ {
		previous = chain.Value(uint64(i), when.Add(time.Duration(i)*time.Second), digest, previous)
	}
	return previous
}

// A log of any length is checked holding no more than a line, the entry before
// it, and the one entry the anchor names. What the verifier keeps is measured
// with the live heap, after a collection, partway through and at the end of a log
// that exists only as it is read.
func TestMemoryDoesNotGrowWithTheLengthOfTheLog(t *testing.T) {
	const n, every = 20_000, 4_000
	digest := collection.Digest(collection.Run{})
	head, err := json.Marshal(chain.Anchor{Format: chain.AnchorFormat, Sequence: n, Chain: lastChain(n, digest)})
	if err != nil {
		t.Fatal(err)
	}
	var live []uint64
	g := &genLog{n: n, digest: digest, onLine: func(i int) {
		if i%every == 0 {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			live = append(live, m.HeapAlloc)
		}
	}}
	got, err := collection.VerifyReaders("x", g, bytes.NewReader(head), collection.Limits{})
	if err != nil || got.Entries != n {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	if len(live) != n/every {
		t.Fatalf("measured %d times", len(live))
	}
	// Keeping a chain entry for each line would hold some 270 bytes a line:
	// about four megabytes more at the end than at the first measure.
	if growth := int64(live[len(live)-1]) - int64(live[0]); growth > 1<<20 {
		t.Errorf("the live heap grew by %d bytes between line %d and line %d: the verifier is keeping the log", growth, every, n)
	}
}

// Any anchor and the entry it names can be anywhere in a log; the verdicts of
// an anchor that is behind or ahead do not depend on keeping the log.
func TestTheVerdictsOnTheAnchorHoldWithoutKeepingTheLog(t *testing.T) {
	digest := collection.Digest(collection.Run{})
	anchor := func(seq int, chainValue string) io.Reader {
		b, _ := json.Marshal(chain.Anchor{Format: 1, Sequence: uint64(seq), Chain: chainValue})
		return bytes.NewReader(b)
	}
	run := func(n int, a io.Reader) error {
		_, err := collection.VerifyReaders("x", &genLog{n: n, digest: digest}, a, collection.Limits{})
		return err
	}
	if err := run(50, anchor(50, lastChain(50, digest))); err != nil {
		t.Errorf("an anchor on the last entry: %v", err)
	}
	check(t, run(50, anchor(40, lastChain(40, digest))), want{reason: "anchor-stale"})
	check(t, run(50, anchor(40, lastChain(41, digest))), want{reason: "anchor-mismatch"})
	check(t, run(50, anchor(60, lastChain(60, digest))), want{reason: "tail-cut"})
	check(t, run(50, anchor(50, lastChain(49, digest))), want{reason: "anchor-mismatch"})
	check(t, run(0, anchor(1, lastChain(1, digest))), want{reason: "entries-missing"})
	if err := run(0, nil); err != nil {
		t.Errorf("nothing and no anchor: %v", err)
	}
}

// A path came from outside; it is shown quoted when it has anything in it a
// terminal would obey, and never repeated raw by the error that names it.
func TestNoPathReachesAMessageRaw(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file names with control characters are not made on Windows")
	}
	odd := "a\x1b[2Jb\xe2\x80\xaec"
	clean := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("verified")
		}
		if strings.ContainsAny(err.Error(), "\x1b") || strings.Contains(err.Error(), "\xe2\x80\xae") {
			t.Errorf("a raw path reached the message: %q", err.Error())
		}
	}
	base := t.TempDir()

	t.Run("a directory that is not there", func(t *testing.T) {
		_, err := collection.Verify(filepath.Join(base, odd), "x")
		clean(t, err)
		if !strings.Contains(err.Error(), "no such file") {
			t.Errorf("error = %q: it does not say what failed", err)
		}
	})
	t.Run("a log that cannot be opened", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root opens anything")
		}
		log, head := good(t)
		dir := filepath.Join(base, odd+"2")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		put(t, dir, "x.jsonl", log)
		put(t, dir, "x.head", head)
		if err := os.Chmod(filepath.Join(dir, "x.jsonl"), 0); err != nil {
			t.Fatal(err)
		}
		_, err := collection.Verify(dir, "x")
		clean(t, err)
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("error = %q: it does not say what failed", err)
		}
	})
}

// The generator is a second implementation of the format, written from the
// specification. Its output must be the committed fixture byte for byte, and
// the digests this file expects for ties must be the ones it prints.
func TestTheFixtureIsWhatTheSeparateGeneratorWrites(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	script := filepath.Join("testdata", "gen", "fixture.py")
	out := t.TempDir()
	if b, err := exec.Command(python, script, out).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	for _, name := range []string{"good.jsonl", "good.head"} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != readTestdata(t, name) {
			t.Errorf("%s: the generator writes something other than the committed file", name)
		}
	}
	vectors, err := exec.Command(python, script, "--vectors").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, vectors)
	}
	for _, d := range []string{tieGrantsDigest, tieScopesDigest} {
		if !strings.Contains(string(vectors), d) {
			t.Errorf("the generator does not print the digest %s", d)
		}
	}
}

// When several faults coexist the one named is the first of: the anchor's form
// and format, the first entry in the file that fails its line, digest or chain
// checks, and then what the anchor says. With no anchor the first entry that
// passes names it, so an entry is judged as an entry before it is judged against
// an anchor that is not there.
func TestWhichFaultIsNamedWhenSeveralCoexist(t *testing.T) {
	log, _ := good(t)
	ls := lines(log)
	format2 := `{"format":2,"sequence":3,"chain":"` + c3 + `"}`
	cases := []struct {
		name      string
		log, head string
		w         want
	}{
		{"no anchor, and the first entry's chain value is wrong",
			replaceOnce(t, ls[0], c1, c2) + ls[1] + ls[2], "", want{reason: "chain-value", entry: 1}},
		{"no anchor, and the first entry's record is wrong",
			replaceOnce(t, ls[0], d1, d2) + ls[1] + ls[2], "", want{reason: "digest", line: 1}},
		{"no anchor, and the first line is not an entry",
			"{ not an entry\n" + ls[1] + ls[2], "", want{reason: "line", line: 1}},
		{"no anchor, and a link broken at the third entry",
			ls[0] + ls[1] + replaceOnce(t, ls[2], c2, c1), "", want{reason: "anchor-missing"}},
		{"a format this verifier does not know, and a line that is not an entry",
			ls[0] + "{ not an entry\n" + ls[2], format2, want{reason: "format"}},
		{"a format this verifier does not know, and a log that is cut", ls[0] + ls[1], format2, want{reason: "format"}},
		{"an anchor behind the log, and a fault in the log",
			ls[0] + ls[1] + replaceOnce(t, ls[2], d3, d1), `{"format":1,"sequence":2,"chain":"` + c2 + `"}`,
			want{reason: "digest", line: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(t, tc.log, tc.head)
			check(t, err, tc.w)
		})
	}
}
