package vectors_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/collection"
	"go.acciew.io/collector/verify/vectors"
	"go.acciew.io/collector/verify/workflow"
)

var update = flag.Bool("update", false, "write the vectors this makes to candidates/, for review; they are never written over cases/")

// The vectors are made here, from the two logs written by the separate Python
// implementation under collection/testdata/gen and workflow/testdata/gen and from
// the builders below. What a verifier must say of each is written out by hand, in
// this file, and is not taken from the verifier.
//
// The test fails if what is made differs from what is committed in cases/. To
// change a vector: change it here, run `go test ./vectors -update`, read the
// difference between candidates/ and cases/, and move what is intended.

type vcase struct {
	name  string
	kind  vectors.Kind
	files map[string][]byte
	base  string // the name of the case this is a change to, if it is one

	verified bool
	reason   string
	findings []string
	errCode  string
	digests  []string
	chains   []string
	note     string
}

func read(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyFiles(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func lines(s string) []string {
	return strings.SplitAfter(s, "\n")[:strings.Count(s, "\n")]
}

func replaceOnce(t testing.TB, s, old, replacement string) string {
	t.Helper()
	if strings.Count(s, old) != 1 {
		t.Fatalf("%d of %q, wanted one", strings.Count(s, old), old)
	}
	return strings.Replace(s, old, replacement, 1)
}

// ---- logs

func logFiles(log, head string) map[string][]byte {
	files := map[string][]byte{"x.jsonl": []byte(log)}
	if head != "" {
		files["x.head"] = []byte(head)
	}
	return files
}

func anchor(seq int, value string) string {
	return fmt.Sprintf(`{"format":1,"sequence":%d,"chain":%q}`, seq, value)
}

var epoch = time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

// collectionLog writes runs as a collection log.
func collectionLog(t testing.TB, runs ...collection.Run) (log, head string) {
	t.Helper()
	var out strings.Builder
	previous := ""
	for i, r := range runs {
		e := collection.Entry{Entry: chain.Entry{
			Sequence: uint64(i + 1), RecordedAt: epoch.Add(time.Duration(i) * time.Hour),
			Digest: collection.Digest(r), Previous: previous,
		}, Run: r}
		e.Chain = chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous)
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(line)
		out.WriteByte('\n')
		previous = e.Chain
	}
	return out.String(), anchor(len(runs), previous)
}

// workflowLog writes bodies, as the text they are digested over, as a workflow log.
func workflowLog(bodies ...string) (log, head string) {
	var out strings.Builder
	previous := ""
	for i, body := range bodies {
		seq := uint64(i + 1)
		at := epoch.Add(2*time.Hour + time.Duration(i)*time.Second)
		digest := workflow.Digest([]byte(body))
		value := chain.Value(seq, at, digest, previous)
		fmt.Fprintf(&out, `{"sequence":%d,"recorded_at":%q,"digest":%q,"previous":%q,"chain":%q,"body":%s}`+"\n",
			seq, at.Format(time.RFC3339Nano), digest, previous, value, body)
		previous = value
	}
	return out.String(), anchor(len(bodies), previous)
}

func event(typ, actor string, data map[string]any) string {
	type ev struct {
		Type  string         `json:"type"`
		Actor string         `json:"actor"`
		Data  map[string]any `json:"data,omitempty"`
	}
	b, err := json.Marshal(ev{typ, actor, data})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ---- the cases

const (
	// The digests the separate implementation wrote for collection/good.
	g1 = "f296b2e6af7c14b0335950c51077dc627f073aa8172fd2ffb0a979b07185bf20"
	g2 = "a319fd1c8fda3eb8f631a2f26aa131801e3ee875a16848b2dabf6e0ed658fd25"
	g3 = "e9595a0f9ad8f0493be666548e008f5d13e004a1873d47484ca5768a3adabb06"

	// The chain values the separate implementation wrote for collection/good and workflow/good.
	cc1 = "6b0f653e62fe00ee67511a11a52f6465c7affdae4775093f30867199b58ee0c4"
	cc2 = "f809155c2b9d4971c05ab0cf4cbde5f06112e014340b21882c476f5308676373"
	cc3 = "253b941f286f85c0a76ef200de1441ccd50bc767adba17be29ddd9fe2eeeec6f"
	wc1 = "f14d723a934dc1ca7cb4924961dba37d91c82e7cacd5148ca157556414e302fa"
	wc2 = "5186f8546c8ae4bbff7c4fbbef68e51dcd8d9a376b8615b80468d9edca66ec19"
	wc3 = "1112f3d1f72e444dac4f7e440f7de59c5002e58ac8b5b5321d3b918b2873d068"
	wc4 = "62872803f05bb8e8c98d74ff75f068419b05d7d32d158a2d31596eb1ce30affd"
	wc5 = "333a942b6f9c6c55ac50132e16b99ea4bab1a042dc0cd17d37e58f7939fb5e7b"

	// Digests worked out outside Go: collection/testdata/gen/fixture.py --vectors,
	// and the same script's canonical form for the run in collection/escapes.
	tieGrantsDigest = "da7234b611b6b9b15ffe0e6e5fb298a7d926258b5f29cb11911b181bc0af7b73"
	tieScopesDigest = "615ac6461ef671e2f5f3da10420d6e7597190f9a3ae1aaf09a2526142e298aee"
	escapesDigest   = "9740639db4697583fdd6ef6051fde39a04c4ecebf4d1ab35989468866efc3d1d"

	// The digests the separate implementation wrote for workflow/good.
	w1 = "eced2aa288415d40918b78ed356717eeb5578991756990d32889b724232ea053"
	w2 = "3d4352b338588fc79707251daa2ee999b8072a8d19ed8f171d0fbaacda026c3e"
	w3 = "2b42dbbbf295c82eb7d4f8e6101a19167ffac5f23ce8678280c6d5b55235bfa3"
	w4 = "d32f00bf41f72e204e39de101342f3117e38e5f749e215c8ae6126a0d5ff2137"
	w5 = "b3b19a7a0bdb041196b600216458e41d097d59dc5ef8ac730589fd9c0d5c3510"
)

func generate(t testing.TB) []vcase {
	t.Helper()
	var out []vcase
	add := func(c vcase) { out = append(out, c) }

	// -- collection logs
	colLog := string(read(t, "../collection/testdata/good.jsonl"))
	colHead := string(read(t, "../collection/testdata/good.head"))
	col := func(name, note, reason string, log, head string, digests []string) {
		files := logFiles(log, head)
		add(vcase{name: "collection/" + name, kind: vectors.Collection, files: files, base: "collection/good",
			verified: reason == "", reason: reason, digests: digests, note: note})
	}
	add(vcase{name: "collection/good", kind: vectors.Collection, files: logFiles(colLog, colHead), verified: true,
		digests: []string{g1, g2, g3},
		note:    "Three collections written by a separate implementation: an empty one with null lists; one with routes, an enum value and a key type with no name, a name with <, > and &, non-ASCII ids, a scope whose activity is undetermined and a time with a fraction; and one with nine fractional digits."})
	cl := lines(colLog)
	col("byte-changed", "A count in the second record changed. Its digest no longer matches.", "digest",
		replaceOnce(t, colLog, `"identities":3`, `"identities":9`), colHead, nil)
	col("entry-cut-middle", "The second entry removed. The third is at the second position.", "sequence",
		cl[0]+cl[2], colHead, []string{g1, g3})
	col("entries-reordered", "The second and third entries swapped.", "sequence", cl[0]+cl[2]+cl[1], colHead, []string{g1, g3, g2})
	col("tail-cut", "The last entry removed and the anchor left as it was.", "tail-cut", cl[0]+cl[1], colHead, []string{g1, g2})
	col("tail-cut-with-anchor", "The last entry removed and the anchor made to name the second. Nothing a single party holds can show this.", "",
		cl[0]+cl[1], anchor(2, "f809155c2b9d4971c05ab0cf4cbde5f06112e014340b21882c476f5308676373"), []string{g1, g2})
	col("anchor-behind", "An anchor that names the second entry of a log of three.", "anchor-stale",
		colLog, anchor(2, "f809155c2b9d4971c05ab0cf4cbde5f06112e014340b21882c476f5308676373"), []string{g1, g2, g3})
	col("anchor-of-another-log", "An anchor that names the right position and another chain value.", "anchor-mismatch",
		colLog, anchor(3, strings.Repeat("0", 64)), []string{g1, g2, g3})
	col("anchor-removed", "No anchor.", "anchor-missing", colLog, "", []string{g1, g2, g3})
	col("anchor-format-2", "An anchor in a format this verifier does not know. It is not called altered.", "format",
		colLog, `{"format":2,"sequence":3,"chain":"253b941f286f85c0a76ef200de1441ccd50bc767adba17be29ddd9fe2eeeec6f"}`, []string{g1, g2, g3})
	col("anchor-without-format", "An anchor from before formats.", "format",
		colLog, `{"sequence":3,"chain":"253b941f286f85c0a76ef200de1441ccd50bc767adba17be29ddd9fe2eeeec6f"}`, []string{g1, g2, g3})
	zeros := strings.Repeat("0", 64)
	col("previous-edited", "The second entry's previous changed to another value and everything else left right: it no longer names the entry before it.", "link",
		replaceOnce(t, colLog, `"previous":"`+cc1+`"`, `"previous":"`+zeros+`"`), colHead, []string{g1, g2, g3})
	col("chain-value-edited", "The second entry's chain value changed to another value and everything else left right: it is not the value its fields give. A verifier that reads the chain member instead of computing it passes this.", "chain-value",
		replaceOnce(t, colLog, `"chain":"`+cc2+`"`, `"chain":"`+zeros+`"`), colHead, []string{g1, g2, g3})
	col("anchor-without-entries", "An anchor, and a log with nothing in it.", "entries-missing", "", colHead, nil)
	col("unknown-field", "A member of a line that the format does not have. It may be one a later revision added, so the verifier says it is older than the file and not that anything disagrees.", "unknown-member",
		replaceOnce(t, colLog, `{"sequence":2,`, `{"note":"x","sequence":2,`), colHead, nil)
	col("repeated-member", "A member written twice, which one reader takes by the first and another by the last.", "line",
		replaceOnce(t, colLog, `"sequence":2,`, `"sequence":2,"sequence":2,`), colHead, nil)
	col("no-final-line-feed", "The last line cut short of its line feed.", "line", strings.TrimSuffix(colLog, "\n"), colHead, nil)

	tieAB, tieBA := tieRuns()
	tl := func(r collection.Run) (string, string) { return collectionLog(t, r) }
	la, ha := tl(tieAB.grants)
	lb, hb := tl(tieBA.grants)
	add(vcase{name: "collection/tie-grants-ab", kind: vectors.Collection, files: logFiles(la, ha), verified: true, digests: []string{tieGrantsDigest},
		note: "Two grants whose ordering text is equal (a route through one key whose id holds '>', and through two keys), in one order."})
	add(vcase{name: "collection/tie-grants-ba", kind: vectors.Collection, files: logFiles(lb, hb), verified: true, digests: []string{tieGrantsDigest},
		note: "The same two grants in the other order: the same digest."})
	ls1, hs1 := tl(tieAB.scopes)
	ls2, hs2 := tl(tieBA.scopes)
	add(vcase{name: "collection/tie-scopes-ab", kind: vectors.Collection, files: logFiles(ls1, hs1), verified: true, digests: []string{tieScopesDigest},
		note: "Two scopes with one id, in one order."})
	add(vcase{name: "collection/tie-scopes-ba", kind: vectors.Collection, files: logFiles(ls2, hs2), verified: true, digests: []string{tieScopesDigest},
		note: "The same two scopes in the other order: the same digest."})

	le, he := collectionLog(t, escapesRun())
	add(vcase{name: "collection/escapes", kind: vectors.Collection, files: logFiles(le, he), verified: true, digests: []string{escapesDigest},
		note: "A name with every character that needs an escape: backspace and form feed, line feed, carriage return, tab, U+0001, DEL, U+2028 and U+2029, <, > and &, a quote, a backslash, a slash, non-ASCII and a real U+FFFD."})

	// -- workflow logs
	wfLog := string(read(t, "../workflow/testdata/good.jsonl"))
	wfHead := string(read(t, "../workflow/testdata/good.head"))
	wf := func(name, note, reason string, log, head string, digests []string) {
		add(vcase{name: "workflow/" + name, kind: vectors.Workflow, files: logFiles(log, head), base: "workflow/good",
			verified: reason == "", reason: reason, digests: digests, note: note})
	}
	add(vcase{name: "workflow/good", kind: vectors.Workflow, files: logFiles(wfLog, wfHead), verified: true,
		digests: []string{w1, w2, w3, w4, w5},
		note:    "Five events written by a separate implementation: markup written as escapes, nested data, a number past 2^53 kept as written, U+2028 as an escape, non-ASCII and an event with no data."})
	wl := lines(wfLog)
	wfD := []string{w1, w2, w3, w4, w5}
	wfC := wfD
	wf("event-rewritten", "A word of the fourth event changed to another of the same length. Its digest no longer matches.", "digest",
		replaceOnce(t, wfLog, `"verb":"approve"`, `"verb":"approvf"`), wfHead, nil)
	wf("event-cut-middle", "The third event removed.", "sequence", wl[0]+wl[1]+wl[3]+wl[4], wfHead, nil)
	wf("events-reordered", "The first two events swapped.", "sequence", wl[1]+wl[0]+wl[2]+wl[3]+wl[4], wfHead, nil)
	wf("tail-cut", "The last event removed and the anchor left as it was.", "tail-cut", wl[0]+wl[1]+wl[2]+wl[3], wfHead, wfC[:4])
	wf("anchor-behind", "An anchor that names the fourth event of five.", "anchor-stale", wfLog,
		anchor(4, "62872803f05bb8e8c98d74ff75f068419b05d7d32d158a2d31596eb1ce30affd"), wfC)
	wf("anchor-removed", "No anchor.", "anchor-missing", wfLog, "", wfC)
	wf("anchor-format-2", "An anchor in a format this verifier does not know.", "format", wfLog,
		`{"format":2,"sequence":5,"chain":"333a942b6f9c6c55ac50132e16b99ea4bab1a042dc0cd17d37e58f7939fb5e7b"}`, wfC)
	wf("chain-value-edited", "The second event's chain value changed to another value and everything else left right.", "chain-value",
		replaceOnce(t, wfLog, `"chain":"`+wc2+`"`, `"chain":"`+zeros+`"`), wfHead, wfD)
	wf("unknown-field", "A member of a line that the format does not have. It may be one a later revision added, so the verifier says it is older than the file and not that anything disagrees.", "unknown-member",
		replaceOnce(t, wfLog, `"chain":"5186f8546c8ae4bbff7c4fbbef68e51dcd8d9a376b8615b80468d9edca66ec19"`,
			`"note":"x","chain":"5186f8546c8ae4bbff7c4fbbef68e51dcd8d9a376b8615b80468d9edca66ec19"`), wfHead, nil)
	wf("time-in-another-zone", "The first time written with an offset instead of Z.", "line",
		replaceOnce(t, wfLog, "2026-10-06T12:00:00.123456Z", "2026-10-06T14:00:00.123456+02:00"), wfHead, nil)
	wf("spaces-in-body", "A space in a body, which would not change what it says and does change its bytes.", "line",
		replaceOnce(t, wfLog, `"type":"pack.built"`, `"type": "pack.built"`), wfHead, nil)

	notEvent, notEventHead := workflowLog(`{"foo":1}`)
	add(vcase{name: "workflow/body-not-an-event", kind: vectors.Workflow, files: logFiles(notEvent, notEventHead), verified: false, reason: "event",
		digests: []string{workflow.Digest([]byte(`{"foo":1}`))}, note: "Every digest and chain value right, and the body is not an event."})
	repeated := `{"type":"a.b","type":"c.d","actor":"system"}`
	repLog, repHead := workflowLog(repeated)
	add(vcase{name: "workflow/repeated-member-in-body", kind: vectors.Workflow, files: logFiles(repLog, repHead), verified: false, reason: "event",
		digests: []string{workflow.Digest([]byte(repeated))}, note: "An event with 'type' twice."})
	markup, markupHead := workflowLog(`{"type":"a.b","actor":"system","data":{"name":"<&>"}}`)
	add(vcase{name: "workflow/markup-not-escaped", kind: vectors.Workflow, files: logFiles(markup, markupHead), verified: false, reason: "line",
		note: "A body with < and & written as themselves, where a body writes them as escapes."})
	unknownType, unknownTypeHead := workflowLog(`{"type":"something.new","actor":"robot:1","data":{"anything":[1,2,{"x":null}]}}`)
	add(vcase{name: "workflow/unknown-type", kind: vectors.Workflow, files: logFiles(unknownType, unknownTypeHead), verified: true,
		digests: []string{workflow.Digest([]byte(`{"type":"something.new","actor":"robot:1","data":{"anything":[1,2,{"x":null}]}}`))},
		note:    "A type this verifier has never heard of is chained like any other."})

	// The chain values a verifier computes, which for the logs that parse are those the
	// separate implementation wrote, whichever member of the log was changed.
	chains := map[string][]string{
		"collection/good": {cc1, cc2, cc3}, "collection/byte-changed": {cc1, cc2, cc3}, "collection/entry-cut-middle": {cc1, cc3},
		"collection/entries-reordered": {cc1, cc3, cc2}, "collection/tail-cut": {cc1, cc2}, "collection/tail-cut-with-anchor": {cc1, cc2},
		"collection/anchor-behind": {cc1, cc2, cc3}, "collection/anchor-of-another-log": {cc1, cc2, cc3}, "collection/anchor-removed": {cc1, cc2, cc3},
		"collection/anchor-format-2": {cc1, cc2, cc3}, "collection/anchor-without-format": {cc1, cc2, cc3}, "collection/chain-value-edited": {cc1, cc2, cc3},
		"workflow/good": {wc1, wc2, wc3, wc4, wc5}, "workflow/event-rewritten": {wc1, wc2, wc3, wc4, wc5}, "workflow/event-cut-middle": {wc1, wc2, wc4, wc5},
		"workflow/events-reordered": {wc2, wc1, wc3, wc4, wc5}, "workflow/tail-cut": {wc1, wc2, wc3, wc4}, "workflow/anchor-behind": {wc1, wc2, wc3, wc4, wc5},
		"workflow/anchor-removed": {wc1, wc2, wc3, wc4, wc5}, "workflow/anchor-format-2": {wc1, wc2, wc3, wc4, wc5}, "workflow/chain-value-edited": {wc1, wc2, wc3, wc4, wc5},
	}
	for i := range out {
		out[i].chains = chains[out[i].name]
	}

	// -- packs
	out = append(out, packCases(t, colLog, colHead)...)
	return out
}

type tie struct{ grants, scopes collection.Run }

// tieRuns are the runs of the tie vectors, in the two orders.
func tieRuns() (ab, ba tie) {
	id := collection.Key{Scope: "s", Type: 1, ID: "a"}
	ent := collection.Key{Scope: "s", Type: 3, ID: "x"}
	joined := collection.Grant{Identity: id, Entitlement: ent, Fidelity: 1, Via: []collection.Key{{Scope: "s", Type: 2, ID: "g>s/grouping/h"}}}
	separate := collection.Grant{Identity: id, Entitlement: ent, Fidelity: 1, Via: []collection.Key{{Scope: "s", Type: 2, ID: "g"}, {Scope: "s", Type: 2, ID: "h"}}}
	one := collection.Scope{ID: "s", Status: 1, ActivityAvailable: true}
	two := collection.Scope{ID: "s", Status: 2}
	empty := collection.Run{StartedAt: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)}
	mk := func(g []collection.Grant, s []collection.Scope) tie {
		a, b := empty, empty
		a.Observed, b.Scopes = g, s
		return tie{grants: a, scopes: b}
	}
	return mk([]collection.Grant{joined, separate}, []collection.Scope{one, two}), mk([]collection.Grant{separate, joined}, []collection.Scope{two, one})
}

// escapesRun is a run with a name full of what needs an escape. The digest above was
// worked out by the Python implementation from the same text.
func escapesRun() collection.Run {
	name := "a<b>&c\b\f\n\r\t\x01\x7f\xe2\x80\xa8\xe2\x80\xa9\xc3\xa9\xef\xbf\xbd\"\\/"
	return collection.Run{
		Source: name, StartedAt: time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC), Whole: true, Verdict: 1,
		Scopes:   []collection.Scope{{ID: name, Status: 1, Reason: name, ActivityAvailable: true}},
		Counts:   collection.Counts{Identities: 1, Entitlements: 1, Grants: 1},
		Observed: []collection.Grant{{Identity: collection.Key{Scope: "s", Type: 1, ID: name}, Entitlement: collection.Key{Scope: "s", Type: 3, ID: "e"}, Fidelity: 1}},
	}
}

// ---- writing and comparing

type tree map[string][]byte

// emit turns the cases into files: case.json and the files of each, which for a
// case that is a change to another are the files that differ.
func emit(t testing.TB, cases []vcase) tree {
	t.Helper()
	byName := map[string]vcase{}
	for _, c := range cases {
		byName[c.name] = c
	}
	out := tree{}
	for _, c := range cases {
		files, deleted := c.files, []string(nil)
		if c.base != "" {
			base, ok := byName[c.base]
			if !ok {
				t.Fatalf("%s: no base %s", c.name, c.base)
			}
			files = map[string][]byte{}
			for p, body := range c.files {
				if old, same := base.files[p]; !same || !bytes.Equal(old, body) {
					files[p] = body
				}
			}
			for p := range base.files {
				if _, kept := c.files[p]; !kept {
					deleted = append(deleted, p)
				}
			}
			sort.Strings(deleted)
		}
		spec := struct {
			Kind     vectors.Kind `json:"kind"`
			Base     string       `json:"base,omitempty"`
			Delete   []string     `json:"delete,omitempty"`
			Verified bool         `json:"verified"`
			Reason   string       `json:"reason,omitempty"`
			Findings []string     `json:"findings,omitempty"`
			Error    string       `json:"error,omitempty"`
			Digests  []string     `json:"digests,omitempty"`
			Chains   []string     `json:"chains,omitempty"`
			Note     string       `json:"note"`
		}{c.kind, c.base, deleted, c.verified, c.reason, c.findings, c.errCode, c.digests, c.chains, c.note}
		var raw bytes.Buffer
		enc := json.NewEncoder(&raw)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(spec); err != nil {
			t.Fatal(err)
		}
		out[c.name+"/case.json"] = raw.Bytes()
		for p, body := range files {
			out[c.name+"/files/"+p] = body
		}
	}
	return out
}

func readTree(t testing.TB, root string) tree {
	t.Helper()
	out := tree{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || filepath.Base(p) == "README.md" {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = read(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheCasesAreWhatTheyAreMadeFrom(t *testing.T) {
	made := emit(t, generate(t))
	if *update {
		if err := os.RemoveAll("candidates"); err != nil {
			t.Fatal(err)
		}
		for p, body := range made {
			path := filepath.Join("candidates", filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Fatalf("%d files written to candidates/. Read the difference with cases/ and move what is intended; nothing under cases/ was changed", len(made))
	}
	committed := readTree(t, "cases")
	var diff []string
	for p, body := range made {
		if got, ok := committed[p]; !ok {
			diff = append(diff, "not committed: "+p)
		} else if !bytes.Equal(got, body) {
			diff = append(diff, "differs: "+p)
		}
	}
	for p := range committed {
		if _, ok := made[p]; !ok {
			diff = append(diff, "committed and not made: "+p)
		}
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		t.Errorf("the committed vectors are not what this makes (run with -update and read candidates/):\n%s", strings.Join(diff, "\n"))
	}
}
