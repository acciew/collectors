package workflow_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/workflow"
)

// testdata/good.jsonl is five events written by a separate implementation of the
// log and its chain, testdata/gen/fixture.py, which shares no code with this
// package and is run by a test below. The bodies hold markup written as escapes,
// nested data, a number past 2^53, U+2028 written as an escape and non-ASCII.
const (
	d1 = "eced2aa288415d40918b78ed356717eeb5578991756990d32889b724232ea053"
	d2 = "3d4352b338588fc79707251daa2ee999b8072a8d19ed8f171d0fbaacda026c3e"
	d4 = "d32f00bf41f72e204e39de101342f3117e38e5f749e215c8ae6126a0d5ff2137"
	c1 = "f14d723a934dc1ca7cb4924961dba37d91c82e7cacd5148ca157556414e302fa"
	c2 = "5186f8546c8ae4bbff7c4fbbef68e51dcd8d9a376b8615b80468d9edca66ec19"
	c3 = "1112f3d1f72e444dac4f7e440f7de59c5002e58ac8b5b5321d3b918b2873d068"
	c4 = "62872803f05bb8e8c98d74ff75f068419b05d7d32d158a2d31596eb1ce30affd"
	c5 = "333a942b6f9c6c55ac50132e16b99ea4bab1a042dc0cd17d37e58f7939fb5e7b"
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

func put(t testing.TB, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func verify(t testing.TB, log, head string) (workflow.Summary, error) {
	t.Helper()
	dir := t.TempDir()
	put(t, dir, "x.jsonl", log)
	if head != "" {
		put(t, dir, "x.head", head)
	}
	return workflow.Verify(dir, "x")
}

func replaceOnce(t testing.TB, s, old, replacement string) string {
	t.Helper()
	if strings.Count(s, old) != 1 {
		t.Fatalf("the fixture has %d of %q, the test wants exactly one", strings.Count(s, old), old)
	}
	return strings.Replace(s, old, replacement, 1)
}

type want struct {
	reason string
	line   int
	entry  uint64
}

func check(t *testing.T, err error, w want) {
	t.Helper()
	if err == nil {
		t.Fatalf("verified; want %q", w.reason)
	}
	if got := workflow.ReasonOf(err); got != w.reason {
		t.Errorf("reason = %q, want %q (%v)", got, w.reason, err)
	}
	var fault *workflow.Error
	if errors.As(err, &fault) && w.line != 0 && fault.Line != w.line {
		t.Errorf("fault is at line %d, want %d (%v)", fault.Line, w.line, err)
	}
	var link *chain.Error
	if errors.As(err, &link) && w.entry != 0 && link.Sequence != w.entry {
		t.Errorf("fault is at entry %d, want %d (%v)", link.Sequence, w.entry, err)
	}
	for _, word := range []string{"forged", "attack"} {
		if strings.Contains(strings.ToLower(err.Error()), word) {
			t.Errorf("%q says more than the files can show", err)
		}
	}
}

// build writes bodies as a log the way the service does, by hand: the line is
// spelled out, the digest is the SHA-256 of the body's text, and the chain value
// is the chain package's, which its own tests pin.
func build(t testing.TB, bodies ...string) (log, head string) {
	t.Helper()
	var out strings.Builder
	previous := ""
	at := time.Date(2026, 10, 6, 12, 0, 0, 123456000, time.UTC)
	for i, body := range bodies {
		sum := sha256.Sum256([]byte(body))
		digest := hex.EncodeToString(sum[:])
		seq := uint64(i + 1)
		when := at.Add(time.Duration(i) * time.Second)
		value := chain.Value(seq, when, digest, previous)
		fmt.Fprintf(&out, `{"sequence":%d,"recorded_at":%q,"digest":%q,"previous":%q,"chain":%q,"body":%s}`+"\n",
			seq, when.Format(time.RFC3339Nano), digest, previous, value, body)
		previous = value
	}
	return out.String(), fmt.Sprintf(`{"format":1,"sequence":%d,"chain":%q}`, len(bodies), previous)
}

const (
	created = `{"type":"example.created","actor":"system","data":{"name":"Acme Co"}}`
	locked  = `{"type":"campaign.locked","actor":"admin:1","data":{"digest":"abc","items":3}}`
	decided = `{"type":"example.decided","actor":"reviewer:r@example.com","data":{"verb":"approve"}}`
)

func TestAnUntouchedChainVerifiesAndSaysWhatItHolds(t *testing.T) {
	log, head := good(t)
	got, err := verify(t, log, head)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Entries != 5 || got.Head != c5 {
		t.Errorf("summary = %+v, want 5 entries ending at %s", got, c5)
	}
}

func TestAChainBuiltByHandVerifies(t *testing.T) {
	log, head := build(t, created, locked, decided)
	got, err := verify(t, log, head)
	if err != nil || got.Entries != 3 {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
}

// The digest is the SHA-256 of the body's text as it stands in the line, so a
// number past 2^53, and a character written as an escape, are not touched. The
// value was made with `printf '%s' '<the body>' | shasum -a 256`.
func TestTheDigestIsTheSHA256OfTheBodyBytes(t *testing.T) {
	body := `{"type":"pack.built","actor":"admin:1"}`
	if got := workflow.Digest([]byte(body)); got != "b3b19a7a0bdb041196b600216458e41d097d59dc5ef8ac730589fd9c0d5c3510" {
		t.Errorf("Digest = %s", got)
	}
	log, _ := good(t)
	var seen []string
	if err := workflow.Read(strings.NewReader(log), workflow.Limits{}, func(_ int, e workflow.Entry) error {
		seen = append(seen, workflow.Digest(e.Body))
		if workflow.Digest(e.Body) != e.Digest {
			t.Errorf("entry %d: Digest = %s, the other implementation wrote %s", e.Sequence, workflow.Digest(e.Body), e.Digest)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 || seen[0] != d1 || seen[1] != d2 || seen[3] != d4 {
		t.Errorf("digests = %v", seen)
	}
}

func TestEntriesAreReadAsEventsWithTheirBodyUntouched(t *testing.T) {
	log, _ := good(t)
	var entries []workflow.Entry
	if err := workflow.Read(strings.NewReader(log), workflow.Limits{}, func(_ int, e workflow.Entry) error {
		entries = append(entries, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entries[3].Body), `"big":9007199254740993`) || !strings.Contains(string(entries[0].Body), `Acme \u003c\u0026\u003e Co`) {
		t.Errorf("a body was changed on the way in: %s", entries[3].Body)
	}
	ev, err := workflow.ParseEvent(entries[3].Body)
	if err != nil || ev.Type != "example.decided" || ev.Actor != "reviewer:r@example.com" || !strings.Contains(string(ev.Data), `"verb":"approve"`) {
		t.Errorf("event = %+v, %v", ev, err)
	}
	ev, err = workflow.ParseEvent(entries[4].Body)
	if err != nil || ev.Type != "pack.built" || ev.Data != nil {
		t.Errorf("an event with no data: %+v, %v", ev, err)
	}
	if !entries[2].RecordedAt.Equal(time.Date(2026, 10, 6, 12, 0, 2, 500_000_000, time.UTC)) {
		t.Errorf("recorded_at = %v", entries[2].RecordedAt)
	}
}

func TestAChangeToTheFilesIsNamed(t *testing.T) {
	log, head := good(t)
	ls := lines(log)
	join := func(parts ...string) string { return strings.Join(parts, "") }
	cases := []struct {
		name      string
		log, head string
		w         want
	}{
		{"an event rewritten", replaceOnce(t, log, `"verb":"approve"`, `"verb":"reject" `), head, want{reason: "line", line: 4}},
		{"an event rewritten with its bytes kept in form", replaceOnce(t, log, `"verb":"approve"`, `"verb":"reject"`), head, want{reason: "digest", line: 4}},
		{"a digest changed", replaceOnce(t, log, d2, strings.Repeat("0", 64)), head, want{reason: "digest", line: 2}},
		{"a time changed", replaceOnce(t, log, "12:00:01.123456Z", "12:00:09.123456Z"), head, want{reason: "chain-value", entry: 2}},
		{"an entry removed from the middle", join(ls[0], ls[2], ls[3], ls[4]), head, want{reason: "sequence", entry: 3}},
		{"the last entry removed", join(ls[0], ls[1], ls[2], ls[3]), head, want{reason: "tail-cut"}},
		{"the first entry removed", join(ls[1], ls[2], ls[3], ls[4]), head, want{reason: "sequence", entry: 2}},
		{"the anchor removed", log, "", want{reason: "anchor-missing"}},
		{"entries reordered", join(ls[1], ls[0], ls[2], ls[3], ls[4]), head, want{reason: "sequence", entry: 2}},
		{"an entry repeated", join(ls[0], ls[1], ls[1], ls[2], ls[3], ls[4]), head, want{reason: "sequence", entry: 2}},
		{"an anchor behind the log", log, `{"format":1,"sequence":4,"chain":"` + c4 + `"}`, want{reason: "anchor-stale"}},
		{"an anchor naming another link", log, `{"format":1,"sequence":5,"chain":"` + strings.Repeat("0", 64) + `"}`, want{reason: "anchor-mismatch"}},
		{"an anchor in format 2", log, `{"format":2,"sequence":5,"chain":"` + c5 + `"}`, want{reason: "format"}},
		{"an anchor from before formats", log, `{"sequence":5,"chain":"` + c5 + `"}`, want{reason: "format"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(t, tc.log, tc.head)
			check(t, err, tc.w)
		})
	}
}

// An event that holds < or & is written with an escape and digested with it. An
// escape added or removed on the way into a file would change the digest, so a
// body in the other form is refused as a line and not read as a different event.
func TestAnEventWithMarkupInItKeepsItsDigestThroughTheFile(t *testing.T) {
	log, head := build(t, `{"type":"example.created","actor":"system","data":{"name":"Acme `+"\\"+`u003c`+"\\"+`u0026`+"\\"+`u003e Co"}}`)
	if _, err := verify(t, log, head); err != nil {
		t.Errorf("an event with markup in it: %v", err)
	}
	raw, rawHead := build(t, `{"type":"example.created","actor":"system","data":{"name":"Acme <&> Co"}}`)
	_, err := verify(t, raw, rawHead)
	check(t, err, want{reason: "line", line: 1})
}

func TestALineMustBeExactlyTheFormItIsWrittenIn(t *testing.T) {
	log, head := good(t)
	ls := lines(log)
	at2 := func(old, replacement string) string {
		return ls[0] + replaceOnce(t, ls[1], old, replacement) + strings.Join(ls[2:], "")
	}
	cases := map[string]string{
		"a second body before the real one": at2(`{"sequence":2,`, `{"body":{"type":"forged","actor":"system"},"sequence":2,`),
		"a member in other case":            at2(`"body":`, `"Body":`),
		"a member nobody asked for":         at2(`"chain":`, `"note":"approved by the CEO","chain":`),
		"windows line endings":              strings.ReplaceAll(log, "\n", "\r\n"),
		"spaces between members":            at2(`"recorded_at":"2026-10-06T12:00:01.123456Z",`, `"recorded_at": "2026-10-06T12:00:01.123456Z",`),
		"the same time in another zone":     at2("12:00:01.123456Z", "14:00:01.123456+02:00"),
		"the time with a trailing zero":     at2("12:00:01.123456Z", "12:00:01.1234560Z"),
		"no final newline":                  strings.TrimSuffix(log, "\n"),
		"an empty line":                     ls[0] + "\n" + strings.Join(ls[1:], ""),
		"spaces inside the body":            at2(`"type":"campaign.locked",`, `"type": "campaign.locked",`),
		"a body with a literal ampersand":   at2(`"campaign":"c-1"`, `"campaign":"c&1"`),
		"a body with U+2028 spelled out":    at2(`"campaign":"c-1"`, "\"campaign\":\"c\xe2\x80\xa81\""),
		"an invalid byte in the body":       at2(`"campaign":"c-1"`, "\"campaign\":\"c\xff1\""),
		"a sequence past 64 bits":           at2(`"sequence":2,`, `"sequence":18446744073709551616,`),
		"a repeated member":                 at2(`"previous":"`+c1+`",`, `"previous":"`+c1+`","previous":"`+c1+`",`),
		"a null for a member":               at2(`"previous":"`+c1+`",`, `"previous":null,`),
		"a missing member":                  at2(`"previous":"`+c1+`",`, ``),
		"a body that is not JSON":           at2(`"body":{`, `"body":{{`),
		"a line that is not an entry":       ls[0] + "{ this is not an entry\n" + strings.Join(ls[2:], ""),
		"an array":                          "[1]\n",
		"a null":                            "null\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := verify(t, in, head)
			if err == nil {
				t.Fatal("verified")
			}
			if got := workflow.ReasonOf(err); got != "line" {
				t.Errorf("reason = %q, want line (%v)", got, err)
			}
		})
	}
}

func TestAnAnchorMustBeTheFormAnchorsAreWrittenIn(t *testing.T) {
	log, _ := good(t)
	for name, head := range map[string]string{
		"an extra member":   `{"format":1,"sequence":5,"chain":"` + c5 + `","note":"x"}`,
		"members in a case": `{"Format":1,"Sequence":5,"Chain":"` + c5 + `"}`,
		"spaces around it":  ` {"format":1,"sequence":5,"chain":"` + c5 + `"} `,
		"spaces inside it":  `{"format": 1,"sequence":5,"chain":"` + c5 + `"}`,
		"another order":     `{"sequence":5,"format":1,"chain":"` + c5 + `"}`,
		"two lines":         `{"format":1,"sequence":5,"chain":"` + c5 + `"}` + "\n" + `{"format":1,"sequence":5,"chain":"` + c5 + `"}`,
	} {
		if _, err := verify(t, log, head); err == nil {
			t.Errorf("an anchor with %s verified", name)
		}
	}
	// A newline at the end is what text tools add, and says nothing.
	if _, err := verify(t, log, `{"format":1,"sequence":5,"chain":"`+c5+`"}`+"\n"); err != nil {
		t.Errorf("an anchor with a newline at the end: %v", err)
	}
}

// An entry swapped for another whose own digest and chain value are recomputed
// still leaves the entry after it pointing at the old one.
func TestAnEntryReplacedWithItsOwnFiguresRecomputedStillBreaksTheLink(t *testing.T) {
	genuine, _ := build(t, created, locked, decided)
	forged, _ := build(t, created, `{"type":"example.decided","actor":"reviewer:x@example.com","data":{"verb":"reject"}}`)
	r, f := lines(genuine), lines(forged)
	_, err := verify(t, r[0]+f[1]+r[2], `{"format":1,"sequence":3,"chain":"`+lastChain(t, r[2])+`"}`)
	check(t, err, want{reason: "link", entry: 3})
}

func lastChain(t testing.TB, line string) string {
	t.Helper()
	var e workflow.Entry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	return e.Chain
}

// Every digest and chain value right, and still not an event.
func TestABodyThatIsNotAnEventDoesNotVerify(t *testing.T) {
	cases := map[string]string{
		"an object that is not an event": `{"foo":1}`,
		"an array":                       `[1]`,
		"a string":                       `"x"`,
		"a null":                         `null`,
		"a number":                       `1`,
		"no type":                        `{"actor":"system"}`,
		"no actor":                       `{"type":"x"}`,
		"an empty type":                  `{"type":"","actor":"system"}`,
		"an empty actor":                 `{"type":"x","actor":""}`,
		"a type that is not a string":    `{"type":1,"actor":"system"}`,
		"an actor that is null":          `{"type":"x","actor":null}`,
		"a member nobody asked for":      `{"type":"x","actor":"system","note":"y"}`,
		"a member in other case":         `{"Type":"x","actor":"system"}`,
		"a repeated member":              `{"type":"a","type":"b","actor":"system"}`,
		"a repeated member, spelled out": `{"type":"a","t` + "\\" + `u0079pe":"b","actor":"system"}`,
		"data that is a list":            `{"type":"x","actor":"system","data":[1]}`,
		"data that is null":              `{"type":"x","actor":"system","data":null}`,
		"data that is a string":          `{"type":"x","actor":"system","data":"y"}`,
		"data with a repeated member":    `{"type":"x","actor":"system","data":{"k":1,"k":2}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			log, head := build(t, created, body)
			_, err := verify(t, log, head)
			check(t, err, want{reason: "event", line: 2})
		})
	}
}

func TestAnEventOfAnyTypeIsChainedWhateverItHolds(t *testing.T) {
	log, head := build(t,
		`{"type":"something.new","actor":"robot:1","data":{"anything":[1,2,{"x":null}],"deep":{"er":{"and":"deeper"}}}}`,
		`{"type":"a.b.c","actor":"x"}`)
	if got, err := verify(t, log, head); err != nil || got.Entries != 2 {
		t.Errorf("Verify = %+v, %v", got, err)
	}
}

func TestAnAnchorThatIsAFolderIsNotSaidToBeRemoved(t *testing.T) {
	log, _ := good(t)
	dir := t.TempDir()
	put(t, dir, "x.jsonl", log)
	if err := os.Mkdir(filepath.Join(dir, "x.head"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := workflow.Verify(dir, "x")
	if err == nil || strings.Contains(err.Error(), "removed") || workflow.ReasonOf(err) != "unreadable" {
		t.Errorf("an anchor that is a folder: %v", err)
	}
}

func TestVerifyNamesWhatIsMissingAndWhatIsNotALog(t *testing.T) {
	if _, err := workflow.Verify(t.TempDir(), "acme"); err == nil || !strings.Contains(err.Error(), "acme") || workflow.ReasonOf(err) != "unreadable" {
		t.Errorf("verifying what is not there: %v", err)
	}
	_, err := verify(t, "not json\n", "")
	check(t, err, want{reason: "line", line: 1})
	for _, name := range []string{"", "..", "a/b", `a\b`, "a\x00b", strings.Repeat("a", 129)} {
		if _, err := workflow.Verify(t.TempDir(), name); err == nil || workflow.ReasonOf(err) != "name" {
			t.Errorf("name %q: %v", name, err)
		}
	}
}

// When several faults coexist the one named is the first of: the anchor's form
// and format, then for each entry in the file its line, its digest, its body as
// an event and its place in the chain, and then what the anchor says.
func TestWhichFaultIsNamedWhenSeveralCoexist(t *testing.T) {
	log, _ := good(t)
	ls := lines(log)
	notEvent := badLogs(t, `{"foo":1}`)
	cases := []struct {
		name      string
		log, head string
		w         want
	}{
		{"a bad digest and a body that is not an event", notEvent.badDigest, "", want{reason: "digest", line: 1}},
		{"a body that is not an event and a bad chain value", notEvent.badChain, "", want{reason: "event", line: 1}},
		{"no anchor, and the first entry's chain value wrong", replaceOnce(t, ls[0], c1, c2) + strings.Join(ls[1:], ""), "", want{reason: "chain-value", entry: 1}},
		{"no anchor, and a link broken at the third entry", ls[0] + ls[1] + replaceOnce(t, ls[2], c2, c1) + ls[3] + ls[4], "", want{reason: "anchor-missing"}},
		{"a format not known, and a line that is not an entry", ls[0] + "{ x\n", `{"format":2,"sequence":5,"chain":"` + c5 + `"}`, want{reason: "format"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verify(t, tc.log, tc.head)
			check(t, err, tc.w)
		})
	}
}

type notEventLogs struct{ badDigest, badChain string }

// badLogs makes a one-entry log with a body, once with a wrong digest and once
// with a wrong chain value.
func badLogs(t testing.TB, body string) notEventLogs {
	t.Helper()
	log, _ := build(t, body)
	var e workflow.Entry
	if err := json.Unmarshal([]byte(strings.TrimSuffix(log, "\n")), &e); err != nil {
		t.Fatal(err)
	}
	return notEventLogs{
		badDigest: replaceOnce(t, log, e.Digest, strings.Repeat("0", 64)),
		badChain:  replaceOnce(t, log, e.Chain, strings.Repeat("0", 64)),
	}
}

func TestTheCallbackSeesEachEntryOnceItHasPassedEverything(t *testing.T) {
	log, head := good(t)
	var seen []string
	opts := workflow.Options{Entry: func(e workflow.Entry, ev workflow.Event) {
		seen = append(seen, fmt.Sprintf("%d:%s", e.Sequence, ev.Type))
	}}
	if _, err := workflow.VerifyWith("x", strings.NewReader(log), strings.NewReader(head), opts); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(seen, " "); got != "1:example.created 2:campaign.locked 3:collection.completed 4:example.decided 5:pack.built" {
		t.Errorf("seen = %s", got)
	}

	// Entries before the fault were seen; the entry with the fault was not.
	seen = nil
	ls := lines(log)
	broken := ls[0] + ls[1] + replaceOnce(t, ls[2], c2, c1) + ls[3] + ls[4]
	_, err := workflow.VerifyWith("x", strings.NewReader(broken), strings.NewReader(head), opts)
	check(t, err, want{reason: "link", entry: 3})
	if got := strings.Join(seen, " "); got != "1:example.created 2:campaign.locked" {
		t.Errorf("seen = %s", got)
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestTheAnchorIsReadBeforeTheLog(t *testing.T) {
	untouched := readerFunc(func([]byte) (int, error) {
		t.Error("the log was read before the anchor was judged")
		return 0, io.EOF
	})
	_, err := workflow.VerifyReaders("x", untouched, strings.NewReader(`{"format":2,"sequence":3,"chain":"`+c3+`"}`), workflow.Limits{})
	check(t, err, want{reason: "format"})
}

func TestALongLineIsReadWholeHoweverItArrives(t *testing.T) {
	big := `{"type":"x","actor":"system","data":{"list":[` + strings.Repeat(`{"k":"vvvvvvvvvvvvvvvvvvvvvvvvvvvv"},`, 9000) + `{"k":"end"}]}}`
	log, head := build(t, created, big)
	if len(lines(log)[1]) < 200_000 {
		t.Fatalf("the long line is only %d bytes", len(lines(log)[1]))
	}
	for name, r := range map[string]io.Reader{"whole": strings.NewReader(log), "a byte at a time": iotest.OneByteReader(strings.NewReader(log))} {
		got, err := workflow.VerifyReaders("x", r, strings.NewReader(head), workflow.Limits{})
		if err != nil || got.Entries != 2 {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	_, err := workflow.VerifyReaders("x", strings.NewReader(log), strings.NewReader(head), workflow.Limits{MaxLineBytes: 1000})
	check(t, err, want{reason: "line", line: 2})
}

// The standard library stops at ten thousand levels of nesting, so a body that
// goes deeper is refused as a line and does not use the stack up.
func TestABodyNestedBeyondTheLimitIsRefused(t *testing.T) {
	deep := `{"type":"x","actor":"system","data":{"a":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}}`
	log, head := build(t, deep)
	_, err := verify(t, log, head)
	check(t, err, want{reason: "line", line: 1})
}

func TestAReaderThatFailsIsUnreadable(t *testing.T) {
	log, head := good(t)
	boom := errors.New("disk on fire")
	_, err := workflow.VerifyReaders("x", io.MultiReader(strings.NewReader(lines(log)[0]), iotest.ErrReader(boom)), strings.NewReader(head), workflow.Limits{})
	check(t, err, want{reason: "unreadable"})
	if !errors.Is(err, boom) {
		t.Errorf("%v does not carry the reader's own error", err)
	}
}

// A chain of any length is checked holding no more than a line, the entry before
// it and the one the anchor names.
func TestMemoryDoesNotGrowWithTheLengthOfTheChain(t *testing.T) {
	const n, every = 20_000, 4_000
	body := `{"type":"x","actor":"system"}`
	sum := sha256.Sum256([]byte(body))
	digest := hex.EncodeToString(sum[:])
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	last := ""
	for i := 1; i <= n; i++ {
		last = chain.Value(uint64(i), at.Add(time.Duration(i)*time.Second), digest, last)
	}
	head := fmt.Sprintf(`{"format":1,"sequence":%d,"chain":%q}`, n, last)

	var live []uint64
	i, previous := 0, ""
	var pending []byte
	src := readerFunc(func(p []byte) (int, error) {
		for len(pending) == 0 {
			if i == n {
				return 0, io.EOF
			}
			i++
			when := at.Add(time.Duration(i) * time.Second)
			value := chain.Value(uint64(i), when, digest, previous)
			pending = []byte(fmt.Sprintf(`{"sequence":%d,"recorded_at":%q,"digest":%q,"previous":%q,"chain":%q,"body":%s}`+"\n",
				i, when.Format(time.RFC3339Nano), digest, previous, value, body))
			previous = value
			if i%every == 0 {
				runtime.GC()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				live = append(live, m.HeapAlloc)
			}
		}
		c := copy(p, pending)
		pending = pending[c:]
		return c, nil
	})
	got, err := workflow.VerifyReaders("x", src, strings.NewReader(head), workflow.Limits{})
	if err != nil || got.Entries != n {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	if growth := int64(live[len(live)-1]) - int64(live[0]); growth > 1<<20 {
		t.Errorf("the live heap grew by %d bytes over the chain: the verifier is keeping it", growth)
	}
}

// The generator is a second implementation of the format, written from the
// specification. Its output must be the committed fixture byte for byte.
func TestTheFixtureIsWhatTheSeparateGeneratorWrites(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	out := t.TempDir()
	if b, err := exec.Command(python, filepath.Join("testdata", "gen", "fixture.py"), out).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	for _, name := range []string{"good.jsonl", "good.head"} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte(readTestdata(t, name))) {
			t.Errorf("%s: the generator writes something other than the committed file", name)
		}
	}
}

// The bound is on the line without its line feed: a line of exactly the limit is
// taken, and one byte more is not.
func TestALineOfExactlyTheLimitIsTakenAndOneByteMoreIsNot(t *testing.T) {
	log, head := build(t, created)
	n := len(strings.TrimSuffix(log, "\n"))
	if _, err := workflow.VerifyReaders("x", strings.NewReader(log), strings.NewReader(head), workflow.Limits{MaxLineBytes: n}); err != nil {
		t.Errorf("a line of exactly %d bytes with a limit of %d: %v", n, n, err)
	}
	_, err := workflow.VerifyReaders("x", strings.NewReader(log), strings.NewReader(head), workflow.Limits{MaxLineBytes: n - 1})
	check(t, err, want{reason: "line", line: 1})
	// And a final line with no line feed, past the limit, is refused for its length.
	_, err = workflow.VerifyReaders("x", strings.NewReader(strings.TrimSuffix(log, "\n")), strings.NewReader(head), workflow.Limits{MaxLineBytes: n - 1})
	check(t, err, want{reason: "line", line: 1})
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("error = %v: it does not say the line is too long", err)
	}
}

// With no anchor an entry is not accepted: the callback must not see an entry of
// a log that is then said to have no anchor.
func TestTheCallbackNeverSeesAnEntryOfALogWithNoAnchor(t *testing.T) {
	log, _ := build(t, created, locked)
	var seen int
	_, err := workflow.VerifyWith("x", strings.NewReader(log), nil, workflow.Options{Entry: func(workflow.Entry, workflow.Event) { seen++ }})
	check(t, err, want{reason: "anchor-missing"})
	if seen != 0 {
		t.Errorf("the callback saw %d entries of a log with no anchor", seen)
	}
}
