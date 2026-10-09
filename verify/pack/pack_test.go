package pack_test

import (
	"strings"
	"testing"

	"go.acciew.io/collector/verify/pack"
)

func TestAPackThatIsWhatItSaysItIsVerifies(t *testing.T) {
	p := newPack(t).build()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep)
	if !rep.Verified() || rep.Files != 10 || rep.ManifestSHA256 != p.manifestSHA() {
		t.Errorf("report = %+v", rep)
	}
	if len(rep.Collections) != 1 || rep.Collections[0].Path != hist || rep.Collections[0].Entries != 3 || rep.Collections[0].Head != p.entries[2].Chain {
		t.Errorf("collections = %+v", rep.Collections)
	}
	if rep.Workflow.Path != wf || rep.Workflow.Entries != 6 || rep.Workflow.Head != p.wentries[5].Chain {
		t.Errorf("workflow = %+v", rep.Workflow)
	}
}

// What a check of a pack can show is that the files agree with each other. Whoever
// can rewrite a file and the manifest that lists it leaves nothing to find, which
// is why the digest of the manifest is reported: it is what the service records
// when it hands a pack out.
func TestAPackRewrittenWithItsManifestAgreesWithItselfAndReportsAnotherManifestDigest(t *testing.T) {
	p := newPack(t).build()
	original := p.manifestSHA()
	p.files["register.xlsx"] = []byte("PK a workbook with other figures in it")
	p.relist()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep)
	if rep.ManifestSHA256 == original {
		t.Error("a rewritten pack reports the digest of the manifest it was made with")
	}
}

func TestAChangeToAFileIsNamed(t *testing.T) {
	cases := []struct {
		name   string
		change func(p *tpack)
		want   []string
	}{
		{"a byte of a listed file changed", func(p *tpack) { p.files["register.xlsx"][3] ^= 1 }, []string{"sha256 register.xlsx"}},
		{"a listed file cut short", func(p *tpack) { p.files["README.txt"] = p.files["README.txt"][:5] }, []string{"size README.txt"}},
		{"a listed file made longer", func(p *tpack) { p.files["README.txt"] = append(p.files["README.txt"], "more"...) }, []string{"size README.txt"}},
		{"a listed file missing", func(p *tpack) { delete(p.files, "document.json") }, []string{"missing document.json"}},
		{"a file added", func(p *tpack) { p.files["notes.txt"] = []byte("added") }, []string{"unlisted notes.txt"}},
		{"a file added in a folder", func(p *tpack) { p.files["extra/more.txt"] = []byte("added") }, []string{"unlisted extra/more.txt"}},
		{"two files swapped", func(p *tpack) {
			p.files["README.txt"], p.files["document.json"] = p.files["document.json"], p.files["README.txt"]
		}, []string{"size README.txt", "size document.json"}},
		{"a snapshot changed", func(p *tpack) {
			p.files["snapshots/conn-1/snapshot-keycloak-2.json"][2] ^= 1
		}, []string{"sha256 snapshots/conn-1/snapshot-keycloak-2.json"}},
		{"the campaign file changed", func(p *tpack) { p.files["campaign.json"][3] ^= 1 }, []string{"sha256 campaign.json"}},
		{"the list of digests removed", func(p *tpack) { delete(p.files, "manifest.sha256") }, []string{"missing manifest.sha256"}},
		{"a line added to the list of digests", func(p *tpack) {
			p.files["manifest.sha256"] = append(p.files["manifest.sha256"], strings.Repeat("0", 64)+"  extra.txt\n"...)
		}, []string{"list manifest.sha256"}},
		{"a digest in the list of digests changed", func(p *tpack) { p.files["manifest.sha256"][0] ^= 1 }, []string{"list manifest.sha256"}},
		{"the list of digests in another order", func(p *tpack) {
			ls := strings.SplitAfter(string(p.files["manifest.sha256"]), "\n")
			ls[0], ls[1] = ls[1], ls[0]
			p.files["manifest.sha256"] = []byte(strings.Join(ls, ""))
		}, []string{"list manifest.sha256"}},
		{"the list of digests with windows line endings", func(p *tpack) {
			p.files["manifest.sha256"] = []byte(strings.ReplaceAll(string(p.files["manifest.sha256"]), "\n", "\r\n"))
		}, []string{"list manifest.sha256"}},
		{"the manifest edited and not the list", func(p *tpack) {
			p.files["manifest.json"] = []byte(strings.Replace(string(p.files["manifest.json"]), "2026-10-20T15:30:00Z", "2026-10-21T15:30:00Z", 1))
		}, []string{"list manifest.sha256"}},
		{"a digest in the manifest changed and the list made to agree", func(p *tpack) {
			obj(filesOf(p.manifest)[0])["sha256"] = strings.Repeat("e", 64)
			p.resign()
		}, []string{"sha256 README.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPack(t).build()
			tc.change(p)
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			expect(t, rep, tc.want...)
		})
	}
}

func TestAChangeToAChainIsNamedOnceTheManifestAgreesWithTheFiles(t *testing.T) {
	cases := []struct {
		name   string
		change func(p *tpack)
		want   []string
	}{
		{"a record in a collection log edited", func(p *tpack) {
			p.edit(hist, func(s string) string { return strings.Replace(s, `"identities":1`, `"identities":9`, 1) })
		}, []string{"sha256 " + hist, "digest " + hist}},
		{"a record edited and the manifest made to agree", func(p *tpack) {
			p.edit(hist, func(s string) string { return strings.Replace(s, `"identities":1`, `"identities":9`, 1) }).relist()
		}, []string{"digest " + hist}},
		{"an entry cut out of the middle of a collection log", func(p *tpack) {
			p.files[hist] = []byte(dropLine(string(p.files[hist]), 1))
			p.relist()
		}, []string{"sequence " + hist}},
		{"the end of a collection log cut off", func(p *tpack) {
			p.files[hist] = []byte(dropLine(string(p.files[hist]), 2))
			p.relist()
		}, []string{"tail-cut " + hist}},
		{"the end cut off and the anchor moved with it", func(p *tpack) {
			p.files[hist] = []byte(dropLine(string(p.files[hist]), 2))
			p.files[histHead] = []byte(anchorText(2, p.entries[1].Chain))
			p.relist()
		}, []string{"head " + hist}},
		{"the anchor of a collection log edited", func(p *tpack) {
			p.files[histHead] = []byte(anchorText(2, p.entries[1].Chain))
			p.relist()
		}, []string{"anchor-stale " + hist}},
		{"the anchor of a collection log removed", func(p *tpack) {
			delete(p.files, histHead)
			p.relist()
		}, []string{"anchor-missing " + hist}},
		{"the anchor of a collection log in format 2", func(p *tpack) {
			p.files[histHead] = []byte(`{"format":2,"sequence":3,"chain":"` + p.entries[2].Chain + `"}`)
			p.relist()
		}, []string{"format " + hist}},
		{"a field no one asked for in a line of a collection log", func(p *tpack) {
			p.edit(hist, func(s string) string { return strings.Replace(s, `{"sequence":1,`, `{"note":"x","sequence":1,`, 1) }).relist()
		}, []string{"unknown-member " + hist}},
		{"an entry cut out of the middle of the workflow log", func(p *tpack) {
			p.files[wf] = []byte(dropLine(string(p.files[wf]), 2))
			p.relist()
		}, []string{"sequence " + wf}},
		{"the end of the workflow log cut off", func(p *tpack) {
			p.files[wf] = []byte(dropLine(string(p.files[wf]), 5))
			p.relist()
		}, []string{"tail-cut " + wf}},
		{"the end cut off and the anchor moved with it", func(p *tpack) {
			p.files[wf] = []byte(dropLine(string(p.files[wf]), 5))
			p.files[wfHead] = []byte(anchorText(5, p.wentries[4].Chain))
			p.relist()
		}, []string{"head " + wf}},
		{"an event in the workflow log rewritten", func(p *tpack) {
			p.edit(wf, func(s string) string { return strings.Replace(s, `"verb":"approve"`, `"verb":"reject"`, 1) }).relist()
		}, []string{"digest " + wf}},
		{"a field no one asked for in a line of the workflow log", func(p *tpack) {
			p.edit(wf, func(s string) string { return strings.Replace(s, `"chain":`, `"note":"x","chain":`, 1) }).relist()
		}, []string{"unknown-member " + wf}},
		{"the anchor of the workflow log in format 2", func(p *tpack) {
			p.files[wfHead] = []byte(`{"format":2,"sequence":6,"chain":"` + p.wentries[5].Chain + `"}`)
			p.relist()
		}, []string{"format " + wf}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPack(t).build()
			tc.change(p)
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			expect(t, rep, tc.want...)
		})
	}
}

func TestADisagreementBetweenTheDocumentsIsNamed(t *testing.T) {
	zeros := strings.Repeat("0", 64)
	cases := []struct {
		name string
		set  func(p *tpack)
		want []string
	}{
		{"the campaign file names another campaign", func(p *tpack) { p.campaignEdit = func(c map[string]any) { c["id"] = "c-2" } }, []string{"campaign campaign.json"}},
		{"the campaign file has another lock digest", func(p *tpack) { p.campaignEdit = func(c map[string]any) { c["lock_digest"] = zeros } }, []string{"campaign campaign.json"}},
		{"the campaign file names another collection", func(p *tpack) {
			p.campaignEdit = func(c map[string]any) { obj(list(c["sources"])[0])["digest"] = zeros }
		}, []string{"campaign campaign.json"}},
		{"the campaign file names no collection", func(p *tpack) { p.campaignEdit = func(c map[string]any) { c["sources"] = []any{} } }, []string{"campaign campaign.json"}},
		{"the campaign file names a collection twice", func(p *tpack) {
			p.campaignEdit = func(c map[string]any) {
				s := list(c["sources"])
				c["sources"] = append(s, s[0])
			}
		}, []string{"campaign campaign.json"}},
		{"the campaign file has other facts the verifier does not read", func(p *tpack) {
			p.campaignEdit = func(c map[string]any) { c["finalize_note"], c["stages"] = "kept", 2 }
		}, nil},
		{"the manifest names another campaign", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { obj(m["campaign"])["id"] = "c-2" }
		}, []string{"campaign campaign.json", "locked " + wf}},
		{"the manifest has another lock digest", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { obj(m["campaign"])["lock_digest"] = zeros }
		}, []string{"campaign campaign.json", "locked " + wf}},
		{"the manifest names a collection that is not in the log", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { firstCollection(m)["digest"] = zeros }
		}, []string{"collection " + hist, "campaign campaign.json", "locked " + wf, "completed " + wf}},
		{"the manifest names an entry the log does not have", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { firstCollection(m)["seq"] = 9 }
		}, []string{"collection " + hist, "campaign campaign.json", "locked " + wf, "completed " + wf}},
		{"the manifest names another chain value for the entry", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { firstCollection(m)["chain_value"] = zeros }
		}, []string{"collection " + hist, "campaign campaign.json", "locked " + wf, "completed " + wf}},
		{"the manifest says the collection log ends elsewhere", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { firstCollection(m)["head_seq"] = 9 }
		}, []string{"head " + hist}},
		{"the manifest says the collection log ends in another link", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { firstCollection(m)["head_chain_value"] = zeros }
		}, []string{"head " + hist}},
		{"the manifest says the workflow log ends elsewhere", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { workflowHead(m)["seq"] = 9 }
		}, []string{"head " + wf}},
		{"the manifest says the workflow log ends in another link", func(p *tpack) {
			p.manifestEdit = func(m map[string]any) { workflowHead(m)["chain_value"] = zeros }
		}, []string{"head " + wf}},
		{"the workflow log holds no lock of the campaign", func(p *tpack) {
			p.workflowBodies = func(b []string) []string { return append(b[:4:4], b[5:]...) }
		}, []string{"locked " + wf}},
		{"the workflow log holds the lock twice", func(p *tpack) {
			p.workflowBodies = func(b []string) []string { return append(b[:5:5], b[4:]...) }
		}, []string{"locked " + wf}},
		{"the lock event has another digest", func(p *tpack) {
			p.workflowBodies = func(b []string) []string {
				b[4] = strings.Replace(b[4], lockDigest, zeros, 1)
				return b
			}
		}, []string{"locked " + wf}},
		{"the lock event names another collection", func(p *tpack) {
			p.workflowBodies = func(b []string) []string {
				b[4] = strings.Replace(b[4], `"seq":2`, `"seq":3`, 1)
				return b
			}
		}, []string{"locked " + wf}},
		{"the lock event names no collection", func(p *tpack) {
			p.workflowBodies = func(b []string) []string {
				b[4] = event("campaign.locked", "admin:1", map[string]any{"campaign": campaignID, "digest": lockDigest, "sources": []any{}})
				return b
			}
		}, []string{"locked " + wf}},
		{"the collection the lock names never completed", func(p *tpack) {
			p.workflowBodies = func(b []string) []string { return append(b[:3:3], b[4:]...) }
		}, []string{"completed " + wf}},
		{"the collection completed after the lock", func(p *tpack) {
			p.workflowBodies = func(b []string) []string { b[3], b[4] = b[4], b[3]; return b }
		}, []string{"completed " + wf}},
		{"a lock event whose data cannot be read", func(p *tpack) {
			p.workflowBodies = func(b []string) []string {
				b[1] = event("campaign.locked", "admin:1", map[string]any{"digest": zeros})
				return b
			}
		}, []string{"event " + wf}},
		{"a completed event whose data cannot be read", func(p *tpack) {
			p.workflowBodies = func(b []string) []string {
				b[2] = event("collection.completed", "system", map[string]any{"connection": connID, "seq": "two"})
				return b
			}
		}, []string{"event " + wf}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPack(t)
			tc.set(p)
			p.build()
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			expect(t, rep, tc.want...)
		})
	}
}

func TestAManifestInAShapeThisVerifierDoesNotKnowIsNamed(t *testing.T) {
	cases := []struct {
		name string
		set  func(m map[string]any)
	}{
		{"a member it does not know", func(m map[string]any) { m["supersedes"] = "p-1" }},
		{"a member of a file it does not know", func(m map[string]any) { obj(filesOf(m)[0])["mode"] = "0644" }},
		{"a file with no digest", func(m map[string]any) { delete(obj(filesOf(m)[0]), "sha256") }},
		{"a file digest that is not hex", func(m map[string]any) { obj(filesOf(m)[0])["sha256"] = strings.Repeat("G", 64) }},
		{"a file digest in capitals", func(m map[string]any) { obj(filesOf(m)[0])["sha256"] = strings.Repeat("E", 64) }},
		{"a file with a negative size", func(m map[string]any) { obj(filesOf(m)[0])["bytes"] = -1 }},
		{"a file with a fractional size", func(m map[string]any) { obj(filesOf(m)[0])["bytes"] = 1.5 }},
		{"a file listed twice", func(m map[string]any) { m["files"] = append(filesOf(m), filesOf(m)[0]) }},
		{"the manifest listing itself", func(m map[string]any) {
			m["files"] = append(filesOf(m), map[string]any{"path": "manifest.json", "sha256": strings.Repeat("0", 64), "bytes": 1})
		}},
		{"a path that climbs out", func(m map[string]any) { obj(filesOf(m)[0])["path"] = "../escape" }},
		{"an absolute path", func(m map[string]any) { obj(filesOf(m)[0])["path"] = "/etc/passwd" }},
		{"a path with a backslash", func(m map[string]any) { obj(filesOf(m)[0])["path"] = `a\b` }},
		{"a path with an empty part", func(m map[string]any) { obj(filesOf(m)[0])["path"] = "a//b" }},
		{"a path with a dot part", func(m map[string]any) { obj(filesOf(m)[0])["path"] = "./a" }},
		{"a path with a name Windows reserves", func(m map[string]any) { obj(filesOf(m)[0])["path"] = "con.txt" }},
		{"a path with a control character", func(m map[string]any) { obj(filesOf(m)[0])["path"] = "a\x1b[2Jb" }},
		{"no files", func(m map[string]any) { m["files"] = []any{} }},
		{"no collections", func(m map[string]any) { m["collections"] = []any{} }},
		{"a member of a collection it does not know", func(m map[string]any) { firstCollection(m)["note"] = "x" }},
		{"a collection with no digest", func(m map[string]any) { delete(firstCollection(m), "digest") }},
		{"a collection whose connection climbs out", func(m map[string]any) { firstCollection(m)["connection"] = ".." }},
		{"a collection whose plugin has a slash", func(m map[string]any) { firstCollection(m)["plugin"] = "a/b" }},
		{"a member of the campaign it does not know", func(m map[string]any) { obj(m["campaign"])["owner"] = "x" }},
		{"no campaign id", func(m map[string]any) { delete(obj(m["campaign"]), "id") }},
		{"a member of the heads it does not know", func(m map[string]any) { obj(m["heads"])["collections"] = 1 }},
		{"a member of the workflow head it does not know", func(m map[string]any) { workflowHead(m)["extra"] = 1 }},
		{"no heads", func(m map[string]any) { delete(m, "heads") }},
		{"a collection head that is a string", func(m map[string]any) { firstCollection(m)["head_seq"] = "3" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPack(t).build()
			tc.set(p.manifest)
			p.resign()
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var manifestFindings int
			for _, f := range rep.Findings {
				if (f.Reason == "manifest" || f.Reason == "unknown-member") && f.Path == "manifest.json" {
					manifestFindings++
				}
			}
			if manifestFindings == 0 {
				t.Errorf("findings = %v, want one about the manifest", findingKeys(rep))
			}
		})
	}
}

func TestAManifestThatIsNotOneThisVerifierReadsIsNotAChangeToTheFiles(t *testing.T) {
	cases := []struct {
		name   string
		change func(p *tpack)
		reason string
	}{
		{"format 2", func(p *tpack) { p.manifest["version"] = 2; p.relist() }, "format"},
		{"no version", func(p *tpack) { delete(p.manifest, "version"); p.relist() }, "format"},
		{"a version that is a string", func(p *tpack) { p.manifest["version"] = "1"; p.relist() }, "format"},
		{"a version of 1.0", func(p *tpack) {
			p.files["manifest.json"] = []byte(strings.Replace(string(p.files["manifest.json"]), `"version": 1`, `"version": 1.0`, 1))
		}, "format"},
		{"not JSON", func(p *tpack) { p.files["manifest.json"] = []byte("<html>not a manifest</html>") }, "unreadable"},
		{"an array", func(p *tpack) { p.files["manifest.json"] = []byte("[1]") }, "unreadable"},
		{"a repeated member", func(p *tpack) {
			p.files["manifest.json"] = []byte(strings.Replace(string(p.files["manifest.json"]), "\"version\": 1\n", "\"version\": 1,\n  \"version\": 1\n", 1))
		}, "unreadable"},
		{"missing", func(p *tpack) { delete(p.files, "manifest.json") }, "unreadable"},
		{"empty", func(p *tpack) { p.files["manifest.json"] = nil }, "unreadable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPack(t).build()
			tc.change(p)
			rep, err := verifyBoth(t, p.files, pack.Options{})
			if err == nil {
				t.Fatalf("verified or reported findings: %+v", rep)
			}
			if got := pack.ReasonOf(err); got != tc.reason {
				t.Errorf("reason = %q, want %q (%v)", got, tc.reason, err)
			}
			if tc.reason == "format" && !strings.Contains(err.Error(), "not a format this verifier knows") {
				t.Errorf("%q does not say the format is not known", err)
			}
			for _, word := range []string{"altered", "changed"} {
				if tc.reason == "format" && strings.Contains(err.Error(), word) {
					t.Errorf("%q: a format this verifier does not know is not evidence of a change", err)
				}
			}
		})
	}
}

func TestAFileTheCrossReferencesNeedIsNamedWhenTheManifestDoesNotListIt(t *testing.T) {
	p := newPack(t).build()
	var kept []any
	for _, f := range filesOf(p.manifest) {
		if obj(f)["path"] != hist {
			kept = append(kept, f)
		}
	}
	p.manifest["files"] = kept
	p.resign()
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "manifest manifest.json", "unlisted "+hist)
}

func TestAListedLogThatIsNotThereIsMissingAndNothingMoreIsSaidAboutIt(t *testing.T) {
	p := newPack(t).build()
	delete(p.files, hist)
	rep, err := verifyBoth(t, p.files, pack.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, rep, "missing "+hist)
}
