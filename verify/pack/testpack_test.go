package pack_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/collection"
	"go.acciew.io/collector/verify/pack"
)

// The packs in these tests are made here, in the form docs/evidence-format.md
// describes, from nothing but invented data: one connection, three collections
// of which the second is the one a review was locked from, and a workflow chain
// that holds the lock and the collections, among other events.

const (
	connID     = "conn-1"
	plugin     = "keycloak"
	campaignID = "c-1"
	lockDigest = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
)

var epoch = time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tpack is a pack under construction. The fields are what a test may change
// before build; files and the documents are what it may change after.
type tpack struct {
	t testing.TB

	runs []collection.Run
	// lockSeq is the entry of the connection's collection log the review is locked from.
	lockSeq uint64

	// Before build: each is applied to what is about to be written, so that the
	// pack still agrees with itself everywhere but where the test changes it.
	// recordedAfter moves when an entry of the collection log was recorded, which
	// changes its chain value and not its digest.
	recordedAfter  map[int]time.Duration
	workflowBodies func(bodies []string) []string
	manifestEdit   func(m map[string]any)
	campaignEdit   func(c map[string]any)

	files    map[string][]byte
	manifest map[string]any
	entries  []collection.Entry // the connection's log
	wentries []chain.Entry      // the workflow log
}

func newPack(t testing.TB) *tpack {
	p := &tpack{t: t, lockSeq: 2}
	for i := range 3 {
		p.runs = append(p.runs, collection.Run{
			Source: plugin, StartedAt: epoch.Add(time.Duration(i) * time.Hour), Whole: true, Verdict: 1,
			Scopes:   []collection.Scope{{ID: "realm-a", Status: 1, ActivityAvailable: true}},
			Counts:   collection.Counts{Identities: int64(i + 1), Grants: int64(i + 1)},
			Observed: []collection.Grant{{Identity: collection.Key{Scope: "realm-a", Type: 1, ID: fmt.Sprint("user-", i)}, Entitlement: collection.Key{Scope: "realm-a", Type: 3, ID: "admin"}, Fidelity: 2}},
		})
	}
	return p
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

func (p *tpack) historyLog() (log, head string) {
	var out strings.Builder
	previous := ""
	p.entries = nil
	for i, r := range p.runs {
		e := collection.Entry{Entry: chain.Entry{
			Sequence: uint64(i + 1), RecordedAt: epoch.Add(time.Duration(i)*time.Hour + time.Minute + p.recordedAfter[i]),
			Digest: collection.Digest(r), Previous: previous,
		}, Run: r}
		e.Chain = chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous)
		line, err := json.Marshal(e)
		if err != nil {
			p.t.Fatal(err)
		}
		out.Write(line)
		out.WriteByte('\n')
		previous = e.Chain
		p.entries = append(p.entries, e)
	}
	return out.String(), anchorText(len(p.runs), previous)
}

func anchorText(seq int, chainValue string) string {
	return fmt.Sprintf(`{"format":1,"sequence":%d,"chain":%q}`, seq, chainValue)
}

func (p *tpack) workflowLog(bodies []string) (log, head string) {
	var out strings.Builder
	previous := ""
	p.wentries = nil
	for i, body := range bodies {
		seq := uint64(i + 1)
		at := epoch.Add(2*time.Hour + time.Duration(i)*time.Second)
		digest := sha([]byte(body))
		value := chain.Value(seq, at, digest, previous)
		fmt.Fprintf(&out, `{"sequence":%d,"recorded_at":%q,"digest":%q,"previous":%q,"chain":%q,"body":%s}`+"\n",
			seq, at.Format(time.RFC3339Nano), digest, previous, value, body)
		p.wentries = append(p.wentries, chain.Entry{Sequence: seq, RecordedAt: at, Digest: digest, Previous: previous, Chain: value})
		previous = value
	}
	return out.String(), anchorText(len(bodies), previous)
}

func (p *tpack) locked() collection.Entry { return p.entries[p.lockSeq-1] }

func (p *tpack) source() map[string]any {
	l := p.locked()
	return map[string]any{"connection": connID, "seq": l.Sequence, "digest": l.Digest, "chain_value": l.Chain, "collected_at": "2026-10-06T09:00:00Z"}
}

func (p *tpack) bodies() []string {
	first, locked := p.entries[0], p.locked()
	completed := func(e collection.Entry) string {
		return event("collection.completed", "system", map[string]any{"run": "run-" + fmt.Sprint(e.Sequence), "connection": connID,
			"seq": e.Sequence, "digest": e.Digest, "chain_value": e.Chain, "whole": true})
	}
	return []string{
		event("example.created", "system", map[string]any{"name": "Acme <&> Co"}),
		// another review's lock, which an account's chain also holds
		event("campaign.locked", "admin:1", map[string]any{"campaign": "c-0", "digest": strings.Repeat("0", 64), "items": 1,
			"sources": []any{map[string]any{"connection": "conn-9", "seq": 7, "digest": strings.Repeat("1", 64), "chain_value": strings.Repeat("2", 64), "collected_at": "2026-09-01T00:00:00Z"}}}),
		completed(first),
		completed(locked),
		event("campaign.locked", "admin:1", map[string]any{"campaign": campaignID, "digest": lockDigest, "items": 3, "without_address": 2,
			"sources": []any{p.source()}}),
		event("example.decided", "reviewer:r@example.com", map[string]any{"verb": "approve", "note": "ok"}),
	}
}

func (p *tpack) build() *tpack {
	history, historyHead := p.historyLog()
	bodies := p.bodies()
	if p.workflowBodies != nil {
		bodies = p.workflowBodies(bodies)
	}
	wlog, whead := p.workflowLog(bodies)
	last := p.wentries[len(p.wentries)-1]
	head := p.entries[len(p.entries)-1]

	snapshot := "snapshots/" + connID + "/snapshot-" + plugin + "-" + fmt.Sprint(p.lockSeq) + ".json"
	p.files = map[string][]byte{
		"README.txt":    []byte("Evidence for the review\n"),
		"register.xlsx": []byte("PK\x03\x04 pretend this is a workbook"),
		"document.json": []byte(`{"format":1}` + "\n"),
		"report.docx":   []byte("PK\x03\x04 pretend this is a document"),
		snapshot:        []byte(`{"format":1,"source":"keycloak"}`),
		"history/" + connID + "/" + plugin + ".jsonl": []byte(history),
		"history/" + connID + "/" + plugin + ".head":  []byte(historyHead),
		"workflow/workflow.jsonl":                     []byte(wlog),
		"workflow/workflow.head":                      []byte(whead),
	}

	campaign := map[string]any{
		"id": campaignID, "name": "Q4 access review", "state": "open", "reviewer": "reviewer@example.com", "deadline": "2026-10-20T09:00:00Z",
		"locked_at": "2026-10-06T09:00:00Z", "lock_digest": lockDigest, "items": 3, "items_without_address": 2, "status": "OPEN, INCOMPLETE",
		"sources": []any{map[string]any{"connection": connID, "name": "prod keycloak", "plugin": plugin,
			"seq": p.locked().Sequence, "digest": p.locked().Digest, "chain_value": p.locked().Chain}},
	}
	if p.campaignEdit != nil {
		p.campaignEdit(campaign)
	}
	p.files["campaign.json"] = jsonFile(p.t, campaign)

	p.manifest = map[string]any{
		"version":      1,
		"generated_at": "2026-10-20T15:30:00Z",
		"campaign": map[string]any{"id": campaignID, "name": "Q4 access review", "lock_digest": lockDigest,
			"locked_at": "2026-10-06T09:00:00Z", "items": 3},
		"completeness": map[string]any{"all_decided": false, "decided": 2, "undecided": 1, "approved": 1, "rejected": 1, "changed": 0},
		"finalization": map[string]any{"finalized": false},
		"document":     map[string]any{"format": 1, "pdf": map[string]any{"made": false, "reason": "not asked for"}},
		"collections": []any{map[string]any{"connection": connID, "plugin": plugin, "seq": p.locked().Sequence, "digest": p.locked().Digest,
			"chain_value": p.locked().Chain, "snapshot": snapshot, "head_seq": head.Sequence, "head_chain_value": head.Chain}},
		"heads": map[string]any{"workflow": map[string]any{"seq": last.Sequence, "chain_value": last.Chain}},
	}
	if p.manifestEdit != nil {
		p.manifestEdit(p.manifest)
	}
	p.relist()
	return p
}

func jsonFile(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// relist makes the manifest list the files as they now are, and writes
// manifest.json and manifest.sha256.
func (p *tpack) relist() {
	var paths []string
	for path := range p.files {
		if path != "manifest.json" && path != "manifest.sha256" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	var list []any
	var sums strings.Builder
	for _, path := range paths {
		list = append(list, map[string]any{"path": path, "sha256": sha(p.files[path]), "bytes": len(p.files[path])})
		fmt.Fprintf(&sums, "%s  %s\n", sha(p.files[path]), path)
	}
	p.manifest["files"] = list
	p.writeManifest(sums.String())
}

// writeManifest writes manifest.json from the map and a manifest.sha256 that is
// the given list of the listed files followed by the manifest's own line.
func (p *tpack) writeManifest(listed string) {
	p.files["manifest.json"] = jsonFile(p.t, p.manifest)
	p.files["manifest.sha256"] = []byte(listed + sha(p.files["manifest.json"]) + "  manifest.json\n")
}

func (p *tpack) manifestSHA() string { return sha(p.files["manifest.json"]) }

// dirOf writes files into a folder.
func dirOf(t testing.TB, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// zipOf writes files into an archive, in order of name.
func zipOf(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// verifyBoth checks the same files as a folder and as an archive and requires the
// two to say the same, which they must: the container is not part of the claim.
func verifyBoth(t testing.TB, files map[string][]byte, opts pack.Options) (*pack.Report, error) {
	t.Helper()
	dirRep, dirErr := pack.VerifyDir(dirOf(t, files), opts)
	data := zipOf(t, files)
	zipRep, zipErr := pack.VerifyZip(bytes.NewReader(data), int64(len(data)), opts)
	if (dirErr == nil) != (zipErr == nil) || (dirErr != nil && pack.ReasonOf(dirErr) != pack.ReasonOf(zipErr)) {
		t.Fatalf("a folder says %v, an archive says %v", dirErr, zipErr)
	}
	if dirErr != nil {
		return nil, dirErr
	}
	if a, b := findingKeys(dirRep), findingKeys(zipRep); strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("a folder says\n%s\nan archive says\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
	return dirRep, nil
}

// findingKeys are the findings as "reason path", in order of reason and path.
func findingKeys(r *pack.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Reason+" "+f.Path)
	}
	sort.Strings(out)
	return out
}

// expect requires the findings to be exactly these, each "reason path".
func expect(t *testing.T, r *pack.Report, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := findingKeys(r)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		for _, f := range r.Findings {
			t.Logf("  %s", f)
		}
	}
}

const (
	hist     = "history/" + connID + "/" + plugin + ".jsonl"
	histHead = "history/" + connID + "/" + plugin + ".head"
	wf       = "workflow/workflow.jsonl"
	wfHead   = "workflow/workflow.head"
)

// resign writes manifest.json from the manifest as it now is, and a
// manifest.sha256 that agrees with the manifest's own list of files, whatever the
// files themselves are.
func (p *tpack) resign() {
	var sums strings.Builder
	for _, f := range list(p.manifest["files"]) {
		m := obj(f)
		fmt.Fprintf(&sums, "%s  %s\n", m["sha256"], m["path"])
	}
	p.writeManifest(sums.String())
}

// edit changes a file by text and relists.
func (p *tpack) edit(path string, f func(string) string) *tpack {
	p.t.Helper()
	before := string(p.files[path])
	after := f(before)
	if after == before {
		p.t.Fatalf("the test's own change did nothing to %s", path)
	}
	p.files[path] = []byte(after)
	return p
}

func dropLine(s string, n int) string {
	ls := strings.SplitAfter(s, "\n")
	return strings.Join(append(ls[:n:n], ls[n+1:]...), "")
}

func filesOf(m map[string]any) []any                  { return list(m["files"]) }
func collections(m map[string]any) []any              { return list(m["collections"]) }
func firstCollection(m map[string]any) map[string]any { return obj(collections(m)[0]) }
func workflowHead(m map[string]any) map[string]any {
	return obj(obj(m["heads"])["workflow"])
}

// obj and list are the JSON values the tests build, asserted to be what they
// are.
func obj(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		panic(fmt.Sprintf("%T is not an object", v))
	}
	return m
}

func list(v any) []any {
	l, ok := v.([]any)
	if !ok {
		panic(fmt.Sprintf("%T is not a list", v))
	}
	return l
}
