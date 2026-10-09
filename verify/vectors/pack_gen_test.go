package vectors_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/collection"
	"go.acciew.io/collector/verify/vectors"
	"go.acciew.io/collector/verify/workflow"
)

// The pack vectors are one small pack, invented, and the packs that differ from it
// in one named way. The pack's collection log is the separate implementation's
// collection/good; its workflow log is written here.

const (
	connID     = "conn-1"
	plugin     = "alpha"
	campaignID = "c-1"
	lockDigest = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"

	hist     = "history/" + connID + "/" + plugin + ".jsonl"
	histHead = "history/" + connID + "/" + plugin + ".head"
	wf       = "workflow/workflow.jsonl"
	wfHead   = "workflow/workflow.head"
	snapshot = "snapshots/" + connID + "/snapshot-" + plugin + "-2.json"
)

type pkg struct {
	t        testing.TB
	files    map[string][]byte
	manifest map[string]any
}

func readEntries(t testing.TB, log []byte) []collection.Entry {
	t.Helper()
	var out []collection.Entry
	if err := collection.Read(strings.NewReader(string(log)), collection.Limits{}, func(_ int, e collection.Entry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func sum(b []byte) string { return workflow.Digest(b) }

func jsonFile(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func newPkg(t testing.TB, colLog, colHead string) *pkg {
	t.Helper()
	entries := readEntries(t, []byte(colLog))
	locked, third := entries[1], entries[2]
	completed := func(e collection.Entry) string {
		return event("collection.completed", "system", map[string]any{"run": fmt.Sprint("run-", e.Sequence), "connection": connID,
			"seq": e.Sequence, "digest": e.Digest, "chain_value": e.Chain, "whole": true})
	}
	wfLog, wfHeadText, wfLast := workflowChain(
		event("example.created", "system", map[string]any{"name": "Acme <&> Co"}),
		event("campaign.locked", "admin:1", map[string]any{"campaign": "c-0", "digest": strings.Repeat("0", 64), "items": 1, "sources": []any{
			map[string]any{"connection": "conn-9", "seq": 7, "digest": strings.Repeat("1", 64), "chain_value": strings.Repeat("2", 64), "collected_at": "2026-09-01T00:00:00Z"}}}),
		completed(entries[0]),
		completed(locked),
		event("campaign.locked", "admin:1", map[string]any{"campaign": campaignID, "digest": lockDigest, "items": 3, "without_address": 2, "sources": []any{
			map[string]any{"connection": connID, "seq": locked.Sequence, "digest": locked.Digest, "chain_value": locked.Chain, "collected_at": "2026-10-06T09:00:00Z"}}}),
		completed(third),
		event("example.decided", "reviewer:r@example.com", map[string]any{"verb": "approve", "note": "ok"}),
	)

	p := &pkg{t: t, files: map[string][]byte{
		"README.txt":    []byte("Evidence for the review\n"),
		"register.xlsx": []byte("PK\x03\x04 pretend this is a workbook"),
		"document.json": []byte(`{"format":1}` + "\n"),
		"report.docx":   []byte("PK\x03\x04 pretend this is a document"),
		snapshot:        []byte(`{"format":1,"source":"alpha"}`),
		hist:            []byte(colLog),
		histHead:        []byte(colHead),
		wf:              []byte(wfLog),
		wfHead:          []byte(wfHeadText),
		"campaign.json": jsonFile(t, map[string]any{
			"id": campaignID, "name": "Q4 access review", "state": "open", "reviewer": "reviewer@example.com", "deadline": "2026-10-20T09:00:00Z",
			"locked_at": "2026-10-06T09:00:00Z", "lock_digest": lockDigest, "items": 3, "items_without_address": 2, "status": "OPEN, INCOMPLETE",
			"sources": []any{map[string]any{"connection": connID, "name": "prod alpha", "plugin": plugin, "seq": locked.Sequence, "digest": locked.Digest, "chain_value": locked.Chain}}}),
	}}
	p.manifest = map[string]any{
		"version": 1, "generated_at": "2026-10-20T15:30:00Z",
		"campaign":     map[string]any{"id": campaignID, "name": "Q4 access review", "lock_digest": lockDigest, "locked_at": "2026-10-06T09:00:00Z", "items": 3},
		"completeness": map[string]any{"all_decided": false, "decided": 2, "undecided": 1},
		"finalization": map[string]any{"finalized": false},
		"document":     map[string]any{"format": 1, "pdf": map[string]any{"made": false, "reason": "not asked for"}},
		"collections": []any{map[string]any{"connection": connID, "plugin": plugin, "seq": locked.Sequence, "digest": locked.Digest,
			"chain_value": locked.Chain, "snapshot": snapshot, "head_seq": third.Sequence, "head_chain_value": third.Chain}},
		"heads": map[string]any{"workflow": map[string]any{"seq": 7, "chain_value": wfLast}},
	}
	p.relist()
	return p
}

// workflowChain writes bodies as a workflow log and returns the chain value of the last.
func workflowChain(bodies ...string) (log, head, last string) {
	log, head = workflowLog(bodies...)
	var e struct {
		Chain string `json:"chain"`
	}
	ls := lines(log)
	if err := json.Unmarshal([]byte(ls[len(ls)-1]), &e); err != nil {
		panic(err)
	}
	return log, head, e.Chain
}

func (p *pkg) clone() *pkg {
	raw, err := json.Marshal(p.manifest)
	if err != nil {
		p.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		p.t.Fatal(err)
	}
	return &pkg{t: p.t, files: copyFiles(p.files), manifest: m}
}

// relist makes the manifest list the files as they now are, and writes
// manifest.json and manifest.sha256.
func (p *pkg) relist() {
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
		list = append(list, map[string]any{"path": path, "sha256": sum(p.files[path]), "bytes": len(p.files[path])})
		fmt.Fprintf(&sums, "%s  %s\n", sum(p.files[path]), path)
	}
	p.manifest["files"] = list
	p.write(sums.String())
}

// resign writes the manifest as it is, with a manifest.sha256 that agrees with its
// own list of files, whatever the files are.
func (p *pkg) resign() {
	var sums strings.Builder
	for _, f := range list(p.manifest["files"]) {
		m := obj(f)
		fmt.Fprintf(&sums, "%s  %s\n", m["sha256"], m["path"])
	}
	p.write(sums.String())
}

func (p *pkg) write(listed string) {
	p.files["manifest.json"] = jsonFile(p.t, p.manifest)
	p.files["manifest.sha256"] = []byte(listed + sum(p.files["manifest.json"]) + "  manifest.json\n")
}

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

func (p *pkg) collection() map[string]any { return obj(list(p.manifest["collections"])[0]) }

func (p *pkg) text(path string) string { return string(p.files[path]) }

func packCases(t testing.TB, colLog, colHead string) []vcase {
	t.Helper()
	base := newPkg(t, colLog, colHead)
	var out []vcase
	out = append(out, vcase{name: "pack/good", kind: vectors.Pack, files: base.files, verified: true,
		note: "A small invented pack: one connection, three collections of which the second is the one the review was locked from, and a workflow chain that holds the lock and the collections, with another review's lock among its events."})

	mutate := func(name, note string, f func(p *pkg), findings ...string) {
		p := base.clone()
		f(p)
		sort.Strings(findings)
		out = append(out, vcase{name: "pack/" + name, kind: vectors.Pack, files: p.files, base: "pack/good", findings: findings,
			verified: len(findings) == 0, note: note})
	}
	failing := func(name, note, code string, f func(p *pkg)) {
		p := base.clone()
		f(p)
		out = append(out, vcase{name: "pack/" + name, kind: vectors.Pack, files: p.files, base: "pack/good", errCode: code, note: note})
	}

	// the files, against the manifest
	mutate("byte-changed", "One byte of a listed file changed.", func(p *pkg) { p.files["register.xlsx"][3] ^= 1 }, "sha256 register.xlsx")
	mutate("file-cut-short", "A listed file cut short.", func(p *pkg) { p.files["README.txt"] = p.files["README.txt"][:5] }, "size README.txt")
	mutate("file-missing", "A listed file removed.", func(p *pkg) { delete(p.files, "document.json") }, "missing document.json")
	mutate("file-added", "A file added that the manifest does not list, which sha256sum -c cannot see.", func(p *pkg) { p.files["notes.txt"] = []byte("added") }, "unlisted notes.txt")
	mutate("files-swapped", "The contents of two listed files swapped.", func(p *pkg) {
		p.files["README.txt"], p.files["document.json"] = p.files["document.json"], p.files["README.txt"]
	}, "size README.txt", "size document.json")
	mutate("file-with-a-name-no-pack-has", "A file whose name has a space in it, which no pack has, added to the pack.", func(p *pkg) { p.files["x y.txt"] = []byte("added") }, "name x y.txt")
	mutate("snapshot-changed", "A stored collection changed.", func(p *pkg) { p.files[snapshot][2] ^= 1 }, "sha256 "+snapshot)
	mutate("manifest-edited", "The manifest edited, and manifest.sha256 left as it was.", func(p *pkg) {
		p.files["manifest.json"] = []byte(strings.Replace(p.text("manifest.json"), "2026-10-20T15:30:00Z", "2026-10-21T15:30:00Z", 1))
	}, "list manifest.sha256")
	mutate("list-removed", "manifest.sha256 removed.", func(p *pkg) { delete(p.files, "manifest.sha256") }, "missing manifest.sha256")
	mutate("list-with-a-line-added", "A line added to manifest.sha256.", func(p *pkg) {
		p.files["manifest.sha256"] = append(p.files["manifest.sha256"], strings.Repeat("0", 64)+"  extra.txt\n"...)
	}, "list manifest.sha256")
	mutate("rewritten-with-its-manifest", "A file changed and the manifest and its list made to agree. Nothing inside a pack ties the manifest to anything: the digest of manifest.json is what to compare with the service's record.", func(p *pkg) {
		p.files["register.xlsx"] = []byte("PK a workbook with other figures in it")
		p.relist()
	})

	// the manifest, in a shape this verifier does or does not read
	mutate("manifest-unknown-member", "A member of the manifest that the format does not have. It may be one a later revision added, so the verifier says it is older than the pack and not that anything disagrees.", func(p *pkg) { p.manifest["supersedes"] = "p-1"; p.resign() }, "unknown-member manifest.json")
	mutate("manifest-unknown-member-of-a-file", "A member of a file entry that the format does not have.", func(p *pkg) {
		obj(list(p.manifest["files"])[0])["mode"] = "0644"
		p.resign()
	}, "unknown-member manifest.json")
	mutate("manifest-lists-a-path-that-climbs", "A listed path that climbs out of the pack.", func(p *pkg) {
		obj(list(p.manifest["files"])[0])["path"] = "../escape"
		p.resign()
	}, "manifest manifest.json", "unlisted README.txt")
	failing("manifest-format-2", "A manifest of a version this verifier does not know. The pack is not called altered; it is not checked.", "format", func(p *pkg) {
		p.manifest["version"] = 2
		p.relist()
	})
	failing("manifest-without-version", "A manifest that does not say which version it is.", "format", func(p *pkg) {
		delete(p.manifest, "version")
		p.relist()
	})
	failing("manifest-not-json", "manifest.json that is not JSON.", "unreadable", func(p *pkg) { p.files["manifest.json"] = []byte("<html>not a manifest</html>") })

	// the collection log
	editHistory := func(p *pkg, f func(log string) string) {
		p.files[hist] = []byte(f(p.text(hist)))
		p.relist()
	}
	mutate("history-record-edited", "A record in the collection log edited and the manifest made to agree. The entry's digest no longer matches.", func(p *pkg) {
		editHistory(p, func(s string) string { return replaceOnce(t, s, `"identities":3`, `"identities":9`) })
	}, "digest "+hist)
	mutate("history-entry-cut", "The second entry removed from the collection log.", func(p *pkg) {
		editHistory(p, func(s string) string { l := lines(s); return l[0] + l[2] })
	}, "sequence "+hist)
	mutate("history-tail-cut", "The last entry removed from the collection log and its anchor left as it was.", func(p *pkg) {
		editHistory(p, func(s string) string { l := lines(s); return l[0] + l[1] })
	}, "tail-cut "+hist)
	mutate("history-tail-cut-with-anchor", "The last entry removed and the anchor moved with it. The log agrees with itself; the manifest says where it ended.", func(p *pkg) {
		p.files[histHead] = []byte(anchor(2, "f809155c2b9d4971c05ab0cf4cbde5f06112e014340b21882c476f5308676373"))
		editHistory(p, func(s string) string { l := lines(s); return l[0] + l[1] })
	}, "head "+hist)
	mutate("history-anchor-behind", "The anchor of the collection log made to name the second entry.", func(p *pkg) {
		p.files[histHead] = []byte(anchor(2, "f809155c2b9d4971c05ab0cf4cbde5f06112e014340b21882c476f5308676373"))
		p.relist()
	}, "anchor-stale "+hist)
	mutate("history-anchor-removed", "The anchor of the collection log removed.", func(p *pkg) { delete(p.files, histHead); p.relist() }, "anchor-missing "+hist)
	mutate("history-anchor-format-2", "The anchor of the collection log in a format this verifier does not know.", func(p *pkg) {
		p.files[histHead] = []byte(`{"format":2,"sequence":3,"chain":"253b941f286f85c0a76ef200de1441ccd50bc767adba17be29ddd9fe2eeeec6f"}`)
		p.relist()
	}, "format "+hist)
	mutate("history-unknown-field", "A member of a line of the collection log that the format does not have. The verifier says it is older than the file.", func(p *pkg) {
		editHistory(p, func(s string) string { return replaceOnce(t, s, `{"sequence":2,`, `{"note":"x","sequence":2,`) })
	}, "unknown-member "+hist)
	mutate("history-entry-replaced-after-the-lock", "The third collection replaced by another, the log, its anchor and the manifest made to agree. The workflow log still holds the completion of the one it replaced.", func(p *pkg) {
		entries := readEntries(t, p.files[hist])
		e := entries[2]
		e.Run.Counts.Identities = 99
		e.Digest = collection.Digest(e.Run)
		e.Chain = chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous)
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		l := lines(p.text(hist))
		p.files[hist] = []byte(l[0] + l[1] + string(line) + "\n")
		p.files[histHead] = []byte(anchor(3, e.Chain))
		p.collection()["head_chain_value"] = e.Chain
		p.relist()
	}, "completed "+wf)

	// the workflow log
	mutate("workflow-entry-cut", "An event removed from the middle of the workflow log.", func(p *pkg) {
		p.files[wf] = []byte(func() string { l := lines(p.text(wf)); return strings.Join(append(l[:2:2], l[3:]...), "") }())
		p.relist()
	}, "sequence "+wf)
	mutate("workflow-tail-cut", "The last event removed from the workflow log and its anchor left as it was.", func(p *pkg) {
		p.files[wf] = []byte(func() string { l := lines(p.text(wf)); return strings.Join(l[:6], "") }())
		p.relist()
	}, "tail-cut "+wf)
	mutate("workflow-anchor-format-2", "The anchor of the workflow log in a format this verifier does not know.", func(p *pkg) {
		p.files[wfHead] = []byte(`{"format":2,"sequence":7,"chain":"` + fmt.Sprint(obj(obj(p.manifest["heads"])["workflow"])["chain_value"]) + `"}`)
		p.relist()
	}, "format "+wf)
	mutate("workflow-event-rewritten", "An event of the workflow log rewritten. Its digest no longer matches.", func(p *pkg) {
		p.files[wf] = []byte(replaceOnce(t, p.text(wf), `"verb":"approve"`, `"verb":"approvf"`))
		p.relist()
	}, "digest "+wf)

	// what the documents say of one another
	mutate("campaign-names-another-review", "campaign.json names another campaign than the manifest.", func(p *pkg) {
		p.files["campaign.json"] = []byte(strings.Replace(p.text("campaign.json"), `"id": "c-1"`, `"id": "c-2"`, 1))
		p.relist()
	}, "campaign campaign.json")
	mutate("campaign-names-another-collection", "campaign.json names another entry of the collection log than the manifest.", func(p *pkg) {
		p.files["campaign.json"] = []byte(strings.Replace(p.text("campaign.json"), `"seq": 2`, `"seq": 3`, 1))
		p.relist()
	}, "campaign campaign.json")
	mutate("manifest-names-another-entry", "The manifest names an entry the collection log does not hold in that form.", func(p *pkg) {
		p.collection()["digest"] = strings.Repeat("0", 64)
		p.relist()
	}, "campaign campaign.json", "collection "+hist, "completed "+wf, "locked "+wf)
	mutate("manifest-says-the-log-ends-elsewhere", "The manifest says the collection log has more entries than it has.", func(p *pkg) {
		p.collection()["head_seq"] = 9
		p.relist()
	}, "head "+hist)
	mutate("manifest-says-the-workflow-ends-elsewhere", "The manifest says the workflow log ends at an entry it does not.", func(p *pkg) {
		obj(obj(p.manifest["heads"])["workflow"])["seq"] = 9
		p.relist()
	}, "head "+wf)
	reflow := func(p *pkg, f func(bodies []string) []string) {
		bodies := bodiesOf(t, p.files[wf])
		bodies = f(bodies)
		log, head, last := workflowChain(bodies...)
		p.files[wf], p.files[wfHead] = []byte(log), []byte(head)
		obj(obj(p.manifest["heads"])["workflow"])["seq"] = len(bodies)
		obj(obj(p.manifest["heads"])["workflow"])["chain_value"] = last
		p.relist()
	}
	mutate("lock-missing", "The workflow log holds no lock of the campaign.", func(p *pkg) {
		reflow(p, func(b []string) []string { return append(b[:4:4], b[5:]...) })
	}, "locked "+wf)
	mutate("lock-digest-differs", "The lock in the workflow log has another digest than the manifest's lock digest.", func(p *pkg) {
		reflow(p, func(b []string) []string {
			b[4] = strings.Replace(b[4], lockDigest, strings.Repeat("0", 64), 1)
			return b
		})
	}, "locked "+wf)
	mutate("collection-never-completed", "The collection the lock names has no completion in the workflow log.", func(p *pkg) {
		reflow(p, func(b []string) []string { return append(b[:3:3], b[4:]...) })
	}, "completed "+wf)
	mutate("collection-completed-after-the-lock", "The collection the lock names completed, in the workflow log, after the lock.", func(p *pkg) {
		reflow(p, func(b []string) []string { b[3], b[4] = b[4], b[3]; return b })
	}, "completed "+wf)
	return out
}

// bodiesOf are the bodies of a workflow log, as written.
func bodiesOf(t testing.TB, log []byte) []string {
	t.Helper()
	var out []string
	if err := workflow.Read(strings.NewReader(string(log)), workflow.Limits{}, func(_ int, e workflow.Entry) error {
		out = append(out, string(e.Body))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
