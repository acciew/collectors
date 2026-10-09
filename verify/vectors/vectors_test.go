package vectors_test

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/chain"
	"go.acciew.io/collector/verify/collection"
	"go.acciew.io/collector/verify/pack"
	"go.acciew.io/collector/verify/vectors"
	"go.acciew.io/collector/verify/workflow"
)

// write puts the files of a case in a folder.
func write(t testing.TB, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func zipped(t testing.TB, files map[string][]byte) []byte {
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

func TestThereAreVectors(t *testing.T) {
	counts := map[vectors.Kind]int{}
	for _, c := range vectors.All() {
		counts[c.Kind]++
	}
	if counts[vectors.Collection] < 15 || counts[vectors.Workflow] < 10 || counts[vectors.Pack] < 30 {
		t.Errorf("counts = %v", counts)
	}
}

// Every vector is run through the verifier and must come out as it says. A verifier
// written in another language, and the service that writes these formats, do the same
// with the same files.
func TestEveryVectorComesOutAsItSays(t *testing.T) {
	for _, c := range vectors.All() {
		t.Run(c.Name, func(t *testing.T) {
			switch c.Kind {
			case vectors.Collection:
				dir := write(t, c.Files)
				_, err := collection.Verify(dir, vectors.LogName)
				checkLog(t, c, err, collection.ReasonOf(err))
				if c.Digests != nil {
					var got []string
					f, err := os.Open(filepath.Join(dir, "x.jsonl"))
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					_ = collection.Read(f, collection.Limits{}, func(_ int, e collection.Entry) error {
						got = append(got, collection.Digest(e.Run))
						return nil
					})
					if strings.Join(got, ",") != strings.Join(c.Digests, ",") {
						t.Errorf("digests = %v, want %v", got, c.Digests)
					}
				}
			case vectors.Workflow:
				dir := write(t, c.Files)
				_, err := workflow.Verify(dir, vectors.LogName)
				checkLog(t, c, err, workflow.ReasonOf(err))
				if c.Digests != nil {
					var got []string
					f, err := os.Open(filepath.Join(dir, "x.jsonl"))
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					_ = workflow.Read(f, workflow.Limits{}, func(_ int, e workflow.Entry) error {
						got = append(got, workflow.Digest(e.Body))
						return nil
					})
					if strings.Join(got, ",") != strings.Join(c.Digests, ",") {
						t.Errorf("digests = %v, want %v", got, c.Digests)
					}
				}
			case vectors.Pack:
				data := zipped(t, c.Files)
				for name, run := range map[string]func() (*pack.Report, error){
					"folder": func() (*pack.Report, error) { return pack.VerifyDir(write(t, c.Files), pack.Options{}) },
					"archive": func() (*pack.Report, error) {
						return pack.VerifyZip(bytes.NewReader(data), int64(len(data)), pack.Options{})
					},
				} {
					rep, err := run()
					checkPack(t, name, c, rep, err)
				}
			default:
				t.Fatalf("kind %q", c.Kind)
			}
		})
	}
}

func checkLog(t *testing.T, c vectors.Case, err error, reason string) {
	t.Helper()
	switch {
	case c.Verified && err != nil:
		t.Errorf("did not verify: %v", err)
	case !c.Verified && err == nil:
		t.Errorf("verified; want %q", c.Reason)
	case !c.Verified && reason != c.Reason:
		t.Errorf("reason = %q, want %q (%v)", reason, c.Reason, err)
	}
}

func checkPack(t *testing.T, how string, c vectors.Case, rep *pack.Report, err error) {
	t.Helper()
	if c.Error != "" {
		if err == nil || pack.ReasonOf(err) != c.Error {
			t.Errorf("%s: error = %v, want %q", how, err, c.Error)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: could not be checked: %v", how, err)
		return
	}
	var got []string
	for _, f := range rep.Findings {
		got = append(got, f.Reason+" "+f.Path)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(c.Findings, "\n") {
		t.Errorf("%s: findings\n%s\nwant\n%s", how, strings.Join(got, "\n"), strings.Join(c.Findings, "\n"))
	}
	if rep.Verified() != c.Verified {
		t.Errorf("%s: verified = %v, want %v", how, rep.Verified(), c.Verified)
	}
}

// A vector that said nothing would pass every verifier.
func TestEveryVectorSaysWhatItIsFor(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range vectors.All() {
		if c.Note == "" {
			t.Errorf("%s has no note", c.Name)
		}
		if seen[c.Name] {
			t.Errorf("%s twice", c.Name)
		}
		seen[c.Name] = true
		if !c.Verified && c.Reason == "" && len(c.Findings) == 0 && c.Error == "" {
			t.Errorf("%s does not verify and does not say why", c.Name)
		}
		if len(c.Files) == 0 {
			t.Errorf("%s has no files", c.Name)
		}
	}
}

// The digests this package expects were worked out outside Go. The script that did it
// is in the repository, and prints them.
func TestTheDigestsWorkedOutOutsideGoAreThePythonScriptsOwn(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	script := filepath.Join("..", "collection", "testdata", "gen", "fixture.py")
	out, err := exec.Command(python, "-B", script, "--vectors").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, digest := range []string{tieGrantsDigest, tieScopesDigest, escapesDigest} {
		if !strings.Contains(string(out), digest) {
			t.Errorf("the script does not print %s", digest)
		}
	}
}

// The chain value of an entry is worked out from its sequence, time, digest and
// previous, and not read from the entry's chain member; a verifier that read it
// would pass a log with a wrong one.
func TestTheChainValuesAVerifierComputesAreTheOnesExpected(t *testing.T) {
	for _, c := range vectors.All() {
		if c.Chains == nil {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			var got []string
			read := func(e chain.Entry) {
				got = append(got, chain.Value(e.Sequence, e.RecordedAt, e.Digest, e.Previous))
			}
			switch c.Kind {
			case vectors.Collection:
				_ = collection.Read(bytes.NewReader(c.Files["x.jsonl"]), collection.Limits{}, func(_ int, e collection.Entry) error { read(e.Entry); return nil })
			case vectors.Workflow:
				_ = workflow.Read(bytes.NewReader(c.Files["x.jsonl"]), workflow.Limits{}, func(_ int, e workflow.Entry) error { read(e.Entry); return nil })
			default:
				t.Fatalf("chains on a %s", c.Kind)
			}
			if strings.Join(got, ",") != strings.Join(c.Chains, ",") {
				t.Errorf("chain values = %v, want %v", got, c.Chains)
			}
		})
	}
}

// Every reason code in the specification is in at least one vector, or is one a
// file cannot be: so that a verifier that never names one of them is found out.
func TestEveryReasonCodeOfTheSpecificationIsInAVector(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "evidence-format.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(doc), "\n## Reason codes\n")
	if !ok {
		t.Fatal("the specification has no reason codes")
	}
	table, _, _ = strings.Cut(table, "\n## ")
	codes := map[string]bool{}
	for _, line := range strings.Split(table, "\n") {
		if rest, ok := strings.CutPrefix(line, "| `"); ok {
			code, _, _ := strings.Cut(rest, "`")
			codes[code] = true
		}
	}
	if len(codes) < 25 {
		t.Fatalf("read %d reason codes from the specification: %v", len(codes), codes)
	}

	// What an archive, a folder, a name or a bound is, and not the content of a file.
	notInAFile := map[string]string{
		"notplain": "a link or device in a container", "duplicate": "a name twice in an archive",
		"limit": "a bound exceeded", "note": "what an operating system left in a folder",
	}
	seen := map[string]bool{}
	for _, c := range vectors.All() {
		if c.Reason != "" {
			seen[c.Reason] = true
		}
		if c.Error != "" {
			seen[c.Error] = true
		}
		for _, f := range c.Findings {
			code, _, _ := strings.Cut(f, " ")
			seen[code] = true
		}
	}
	for code := range codes {
		if _, exempt := notInAFile[code]; exempt {
			continue
		}
		if !seen[code] {
			t.Errorf("no vector has the reason %q", code)
		}
	}
	for code := range seen {
		if !codes[code] {
			t.Errorf("a vector has the reason %q and the specification does not list it", code)
		}
	}
}
