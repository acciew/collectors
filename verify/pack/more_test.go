package pack_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"go.acciew.io/collector/verify/pack"
)

func TestACampaignFileThatCannotBeReadIsNamedWhenItIsTheFileTheManifestLists(t *testing.T) {
	cases := map[string]func(c map[string]any) []byte{
		"not JSON":                func(map[string]any) []byte { return []byte("{ not json") },
		"an array":                func(map[string]any) []byte { return []byte("[1]") },
		"a repeated member":       func(map[string]any) []byte { return []byte(`{"id":"c-1","id":"c-1","lock_digest":"x","sources":[]}`) },
		"no id":                   func(c map[string]any) []byte { delete(c, "id"); return jsonFile(t, c) },
		"no lock digest":          func(c map[string]any) []byte { delete(c, "lock_digest"); return jsonFile(t, c) },
		"no sources":              func(c map[string]any) []byte { delete(c, "sources"); return jsonFile(t, c) },
		"sources that are a map":  func(c map[string]any) []byte { c["sources"] = map[string]any{}; return jsonFile(t, c) },
		"a source that is a list": func(c map[string]any) []byte { c["sources"] = []any{[]any{}}; return jsonFile(t, c) },
		"a source with no name": func(c map[string]any) []byte {
			delete(obj(list(c["sources"])[0]), "name")
			return jsonFile(t, c)
		},
		"a source with a name that is a number": func(c map[string]any) []byte {
			obj(list(c["sources"])[0])["name"] = 3
			return jsonFile(t, c)
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPack(t).build()
			campaign := map[string]any{"id": campaignID, "name": "n", "lock_digest": lockDigest, "sources": []any{map[string]any{
				"connection": connID, "name": "prod", "plugin": plugin, "seq": p.locked().Sequence, "digest": p.locked().Digest, "chain_value": p.locked().Chain}}}
			p.files["campaign.json"] = write(campaign)
			p.relist()
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			expect(t, rep, "campaign campaign.json")
		})
	}
}

func TestACampaignFileTheManifestDoesNotListIsNamedAsSuch(t *testing.T) {
	p := newPack(t).build()
	var kept []any
	for _, f := range filesOf(p.manifest) {
		if obj(f)["path"] != "campaign.json" {
			kept = append(kept, f)
		}
	}
	p.manifest["files"] = kept
	p.resign()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "manifest manifest.json", "unlisted campaign.json")
}

func TestASnapshotThatIsNotListedOrIsNotAPlainNameIsNamed(t *testing.T) {
	p := newPack(t).build()
	firstCollection(p.manifest)["snapshot"] = "snapshots/other.json"
	p.resign()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "manifest manifest.json")

	p = newPack(t).build()
	firstCollection(p.manifest)["snapshot"] = "../x"
	p.resign()
	rep, err = verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "manifest manifest.json")
}

func TestTheWorkflowAnchorRemovedIsNamed(t *testing.T) {
	p := newPack(t).build()
	delete(p.files, wfHead)
	p.relist()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "anchor-missing "+wf)
}

func TestTwoCollectionsOfOneLogAreBothChecked(t *testing.T) {
	p := newPack(t)
	p.manifestEdit = func(m map[string]any) {
		first := p.entries[0]
		second := map[string]any{}
		for k, v := range firstCollection(m) {
			second[k] = v
		}
		second["seq"], second["digest"], second["chain_value"] = first.Sequence, first.Digest, first.Chain
		m["collections"] = append(collections(m), second)
	}
	p.build()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The log is read once and both entries are found in it. The review was locked from one.
	expect(t, rep, "campaign campaign.json", "locked "+wf)
	if len(rep.Collections) != 1 {
		t.Errorf("collections = %+v", rep.Collections)
	}
}

func TestAReportHoldsTheFirstFindingsAndSaysHowManyMoreThereWere(t *testing.T) {
	p := newPack(t).build()
	for i := range 300 {
		p.files[fmt.Sprintf("extra/f%04d.txt", i)] = []byte("x")
	}
	rep, err := pack.VerifyDir(dirOf(t, p.files), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 200 || rep.More != 100 || rep.Verified() {
		t.Errorf("%d findings and %d more", len(rep.Findings), rep.More)
	}
}

func TestLimitsOnAFolder(t *testing.T) {
	p := newPack(t).build()
	dir := dirOf(t, p.files)
	for name, lim := range map[string]pack.Limits{
		"too many files": {MaxEntries: 5},
		"a file too big": {MaxFileBytes: 100},
		"too big in all": {MaxTotalBytes: 300},
	} {
		_, err := pack.VerifyDir(dir, pack.Options{Limits: lim})
		if err == nil || pack.ReasonOf(err) != "limit" {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestALineLimitReachesTheLogs(t *testing.T) {
	p := newPack(t).build()
	rep, err := verifyBoth(t, p.files, pack.Options{Limits: pack.Limits{MaxLineBytes: 100}})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "limit "+hist, "limit "+wf)
}

func TestErrors(t *testing.T) {
	if pack.ReasonOf(nil) != "" || pack.ReasonOf(errors.New("x")) != "" {
		t.Error("ReasonOf names a reason for what is not one of ours")
	}
	_, err := pack.VerifyDir(t.TempDir(), pack.Options{})
	if err == nil || errors.Unwrap(err) != nil && !strings.Contains(err.Error(), "manifest.json") {
		t.Errorf("error = %v", err)
	}
	var e *pack.Error
	if !errors.As(err, &e) || e.Reason != "unreadable" {
		t.Errorf("error = %#v", err)
	}
	_, err = pack.VerifyDir("/nonexistent/"+strings.Repeat("a", 10), pack.Options{})
	if err == nil || errors.Unwrap(err) == nil {
		t.Errorf("a folder that is not there does not carry its cause: %v", err)
	}
}

func TestAnchorsAreReadOnlyAsFarAsAnAnchorCanBeAndTheRestOnlyForItsDigest(t *testing.T) {
	p := newPack(t).build()
	p.files[histHead] = append([]byte(anchorText(3, p.entries[2].Chain)), bytes.Repeat([]byte(" "), 24<<20)...)
	p.relist()
	data := zipOf(t, p.files)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	rep, err := pack.VerifyZip(bytes.NewReader(data), int64(len(data)), pack.Options{Limits: pack.Limits{MaxRatio: 1_000_000}})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	// The anchor is too long to be one, and that is said; its digest is right, so
	// that is all that is said.
	expect(t, rep, "unreadable "+hist)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 12<<20 {
		t.Errorf("checking a pack with a 24 MiB anchor allocated %d bytes: the anchor is being kept", alloc)
	}
}

// A completion the workflow log holds for an entry of a packed collection has to
// say what the collection log says of that entry, whether or not the review was
// locked from it; so replacing an entry after the lock means rewriting the workflow
// chain as well.
func TestAnEntryReplacedAfterTheLockIsCaughtByTheCompletionTheWorkflowLogHolds(t *testing.T) {
	original := newPack(t).build().entries[2]
	p := newPack(t)
	p.runs[2].Counts.Identities = 99
	p.workflowBodies = func(b []string) []string {
		return append(b, event("collection.completed", "system", map[string]any{"run": "run-3", "connection": connID,
			"seq": 3, "digest": original.Digest, "chain_value": original.Chain, "whole": true}))
	}
	p.build()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "completed "+wf)
}

func TestCompletionsOfOtherEntriesAndOtherConnectionsAreNotHeldToTheLog(t *testing.T) {
	p := newPack(t)
	p.workflowBodies = func(b []string) []string {
		return append(b,
			// another connection, which the pack does not carry
			event("collection.completed", "system", map[string]any{"run": "r", "connection": "conn-9", "seq": 2, "digest": strings.Repeat("1", 64), "chain_value": strings.Repeat("2", 64)}),
			// an entry the pack's log had not reached when it was exported
			event("collection.completed", "system", map[string]any{"run": "r", "connection": connID, "seq": 7, "digest": strings.Repeat("3", 64), "chain_value": strings.Repeat("4", 64)}))
	}
	p.build()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep)
}

// A folder an auditor has opened holds what the operating system puts there. It
// is noted and does not fail the pack; an archive is checked as it was handed
// over, and the same files in one are findings.
func TestWhatTheOperatingSystemLeavesInAFolderIsNotedAndInAnArchiveIsAFinding(t *testing.T) {
	p := newPack(t).build()
	junk := []string{".DS_Store", "Thumbs.db", "desktop.ini", "__MACOSX/._README.txt", "history/._keycloak.jsonl"}
	files := map[string][]byte{}
	for k, v := range p.files {
		files[k] = v
	}
	for _, name := range junk {
		files[name] = []byte("junk")
	}

	rep, err := pack.VerifyDir(dirOf(t, files), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep)
	if !rep.Verified() {
		t.Error("a folder with what the operating system leaves in it does not verify")
	}
	var noted []string
	for _, n := range rep.Notes {
		noted = append(noted, n.Path)
	}
	sort.Strings(noted)
	if strings.Join(noted, ",") != ".DS_Store,Thumbs.db,__MACOSX,desktop.ini,history/._keycloak.jsonl" {
		t.Errorf("notes = %v", noted)
	}

	data := zipOf(t, files)
	zrep, err := pack.VerifyZip(bytes.NewReader(data), int64(len(data)), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, zrep, "name .DS_Store", "unlisted Thumbs.db", "unlisted desktop.ini", "name __MACOSX/._README.txt", "name history/._keycloak.jsonl")
	if len(zrep.Notes) != 0 {
		t.Errorf("an archive has notes: %v", zrep.Notes)
	}
	// A finding that could read as an accusation says what it looks like.
	const looksLike = "this looks like a file the operating system added when the archive was made again; check the archive as it was handed over"
	for _, f := range zrep.Findings {
		if !strings.Contains(f.Message, looksLike) {
			t.Errorf("%s: message = %q", f.Path, f.Message)
		}
	}
	// And what is not that does not say so.
	files["notes.txt"] = []byte("added")
	data = zipOf(t, files)
	zrep, err = pack.VerifyZip(bytes.NewReader(data), int64(len(data)), pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zrep.Findings {
		if f.Path == "notes.txt" && strings.Contains(f.Message, "operating system") {
			t.Errorf("notes.txt: message = %q", f.Message)
		}
	}
}

// The digest is the same and only the time the entry was recorded differs, so the
// chain value does: the completion the workflow log holds is held to that half too.
func TestAnEntryReplacedByOneWithTheSameDigestAndAnotherChainValueIsCaught(t *testing.T) {
	original := newPack(t).build().entries[2]
	p := newPack(t)
	p.recordedAfter = map[int]time.Duration{2: time.Second}
	p.workflowBodies = func(b []string) []string {
		return append(b, event("collection.completed", "system", map[string]any{"run": "run-3", "connection": connID,
			"seq": 3, "digest": original.Digest, "chain_value": original.Chain, "whole": true}))
	}
	p.build()
	if p.entries[2].Digest != original.Digest || p.entries[2].Chain == original.Chain {
		t.Fatalf("the test's own change: digest %s chain %s", p.entries[2].Digest[:8], p.entries[2].Chain[:8])
	}
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "completed "+wf)
}

// A member this verifier does not know may be one a later revision of the format
// added: the verifier is older than the pack, and nothing is said to disagree.
func TestAMemberThisVerifierDoesNotKnowIsSaidToBeThatInTheManifestAndTheCampaignFile(t *testing.T) {
	cases := map[string]struct {
		change func(p *tpack)
		want   string
	}{
		"in the manifest": {func(p *tpack) { p.manifest["supersedes"] = "p-1"; p.resign() }, "unknown-member manifest.json"},
		"in a file entry": {func(p *tpack) { obj(filesOf(p.manifest)[0])["mode"] = "0644"; p.resign() }, "unknown-member manifest.json"},
		"in a collection": {func(p *tpack) { firstCollection(p.manifest)["note"] = "x"; p.resign() }, "unknown-member manifest.json"},
		"in the campaign": {func(p *tpack) { obj(p.manifest["campaign"])["owner"] = "x"; p.resign() }, "unknown-member manifest.json"},
		"in the heads":    {func(p *tpack) { obj(p.manifest["heads"])["collections"] = 1; p.resign() }, "unknown-member manifest.json"},
		"in a source of the file": {func(p *tpack) {
			c := map[string]any{"id": campaignID, "lock_digest": lockDigest, "sources": []any{map[string]any{"connection": connID, "name": "n", "plugin": plugin,
				"seq": p.locked().Sequence, "digest": p.locked().Digest, "chain_value": p.locked().Chain, "owner": "x"}}}
			p.files["campaign.json"] = jsonFile(t, c)
			p.relist()
		}, "unknown-member campaign.json"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPack(t).build()
			tc.change(p)
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			expect(t, rep, tc.want)
			for _, f := range rep.Findings {
				if !strings.Contains(f.Message, "that this verifier does not know") || !strings.Contains(f.Message, "newer") {
					t.Errorf("message = %q", f.Message)
				}
			}
		})
	}
}

func TestABoundNearTheLargestNumberDoesNotOverflow(t *testing.T) {
	p := newPack(t).build()
	rep, err := verifyBoth(t, p.files, pack.Options{Limits: pack.Limits{MaxFileBytes: math.MaxInt64, MaxTotalBytes: math.MaxInt64, MaxLineBytes: math.MaxInt}})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep)
	if got := (pack.Limits{MaxFileBytes: math.MaxInt64}).Resolved(); got.MaxFileBytes == math.MaxInt64 || got.MaxFileBytes < 1<<60 {
		t.Errorf("resolved = %+v", got)
	}
	if got := (pack.Limits{}).Resolved(); got.MaxEntries != 10_000 || got.MaxRatio != 500 || got.MaxFileBytes != 2<<30 || got.MaxTotalBytes != 8<<30 || got.MaxLineBytes != 64<<20 {
		t.Errorf("defaults = %+v", got)
	}
	if pack.MaxDocumentBytes != 64<<20 {
		t.Errorf("MaxDocumentBytes = %d", pack.MaxDocumentBytes)
	}
}
