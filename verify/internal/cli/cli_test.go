package cli_test

import (
	"archive/zip"
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.acciew.io/collector/verify/internal/cli"
	"go.acciew.io/collector/verify/vectors"
)

var update = flag.Bool("update", false, "write the output this makes to testdata/golden.candidates/, for review; golden files are never written over")

func run(t testing.TB, args ...string) (status int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	status = cli.Run(args, &out, &errs, "9.9.9")
	return status, out.String(), errs.String()
}

func vector(t testing.TB, name string) vectors.Case {
	t.Helper()
	for _, c := range vectors.All() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no vector %s", name)
	return vectors.Case{}
}

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

func zipFile(t testing.TB, files map[string][]byte) string {
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
	path := filepath.Join(t.TempDir(), "pack.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// golden compares output with a committed file, with the folder the test made
// written as DIR. A golden file is never written by the test that reads it: with
// -update the output goes to testdata/golden.candidates/ and the test fails, for
// someone to read the difference and move what is intended.
func golden(t *testing.T, name, got, dir string) {
	t.Helper()
	got = strings.ReplaceAll(got, dir, "DIR")
	if *update {
		path := filepath.Join("testdata", "golden.candidates", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Errorf("candidate written to %s; nothing under testdata/golden was changed", path)
		return
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("no golden file %s (run with -update and read testdata/golden.candidates/): %v", name, err)
	}
	if got != string(want) {
		t.Errorf("%s: output is\n%s\nwant\n%s", name, got, want)
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version"} {
		status, out, errs := run(t, arg)
		if status != 0 || out != "acciew-verify 9.9.9\n" || errs != "" {
			t.Errorf("%s: %d %q %q", arg, status, out, errs)
		}
	}
}

func TestTheCommandLine(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		status int
		in     string // stdout or stderr must contain
		onErr  bool
	}{
		{"no command", nil, 2, "usage: acciew-verify", true},
		{"an unknown command", []string{"frobnicate"}, 2, `unknown command "frobnicate"`, true},
		{"help", []string{"help"}, 0, "usage: acciew-verify", false},
		{"-h", []string{"-h"}, 0, "usage: acciew-verify", false},
		{"pack without a place", []string{"pack"}, 2, "needs one folder or archive", true},
		{"pack with two", []string{"pack", "a", "b"}, 2, "needs one folder or archive", true},
		{"history without a folder", []string{"history"}, 2, "needs one folder", true},
		{"workflow without a folder", []string{"workflow"}, 2, "needs one folder", true},
		{"an option it does not have", []string{"pack", "--frob", "x"}, 2, "frob", true},
		{"a bound that is not a number", []string{"pack", "--max-bytes", "lots", "x"}, 2, "max-bytes", true},
		{"a bound that is negative", []string{"pack", "--max-bytes=-5", "x"}, 2, "max-bytes", true},
		{"a pack that is not there", []string{"pack", "/nonexistent/pack"}, 2, "cannot be", true},
		{"a log folder that is not there", []string{"history", "/nonexistent/logs"}, 2, "cannot", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, out, errs := run(t, tc.args...)
			got := out
			if tc.onErr {
				got = errs
			}
			if status != tc.status || !strings.Contains(got, tc.in) {
				t.Errorf("status %d, want %d; output %q / %q, want it to contain %q", status, tc.status, out, errs, tc.in)
			}
		})
	}
}

func TestAPackThatVerifiesAsAFolderAndAsAnArchive(t *testing.T) {
	c := vector(t, "pack/good")
	dir := write(t, c.Files)
	status, out, errs := run(t, "pack", dir)
	if status != 0 || errs != "" {
		t.Fatalf("folder: %d %q", status, errs)
	}
	golden(t, "pack-good.txt", out, dir)

	zipPath := zipFile(t, c.Files)
	status, zout, errs := run(t, "pack", zipPath)
	if status != 0 || errs != "" {
		t.Fatalf("archive: %d %q", status, errs)
	}
	golden(t, "pack-good.txt", zout, zipPath)
}

func TestAPackThatDoesNotVerify(t *testing.T) {
	for _, name := range []string{"pack/file-added", "pack/byte-changed", "pack/history-tail-cut", "pack/manifest-names-another-entry"} {
		t.Run(name, func(t *testing.T) {
			c := vector(t, name)
			dir := write(t, c.Files)
			status, out, errs := run(t, "pack", dir)
			if status != 1 || errs != "" {
				t.Fatalf("%d %q", status, errs)
			}
			golden(t, strings.ReplaceAll(name, "/", "-")+".txt", out, dir)
		})
	}
}

func TestAPackThatCannotBeChecked(t *testing.T) {
	c := vector(t, "pack/manifest-format-2")
	status, out, errs := run(t, "pack", write(t, c.Files))
	if status != 2 || out != "" || !strings.Contains(errs, "not a format this verifier knows") {
		t.Errorf("%d %q %q", status, out, errs)
	}
	for _, word := range []string{"altered", "tam" + "per"} {
		if strings.Contains(errs, word) {
			t.Errorf("%q: a format this verifier does not know is not evidence of a change", errs)
		}
	}
}

func TestHistory(t *testing.T) {
	good := write(t, vector(t, "collection/good").Files)
	status, out, errs := run(t, "history", good)
	if status != 0 || errs != "" {
		t.Fatalf("%d %q", status, errs)
	}
	golden(t, "history-good.txt", out, good)

	cut := write(t, vector(t, "collection/tail-cut").Files)
	status, out, errs = run(t, "history", cut)
	if status != 1 || errs != "" {
		t.Fatalf("%d %q", status, errs)
	}
	golden(t, "history-tail-cut.txt", out, cut)

	// One source named, and options after the folder as well as before it.
	for _, args := range [][]string{{"history", good, "--source", "x"}, {"history", "--source", "x", good}, {"history", "--source=x", good}} {
		if status, out, _ := run(t, args...); status != 0 || !strings.Contains(out, "3 collections, consistent") {
			t.Errorf("%v: %d %q", args, status, out)
		}
	}
	if status, out, errs := run(t, "history", good, "--source", "nothing"); status != 2 || !strings.Contains(out+errs, "nothing.jsonl is not there") {
		t.Errorf("a source that is not there: %d %q %q", status, out, errs)
	}
}

func TestWorkflow(t *testing.T) {
	good := write(t, vector(t, "workflow/good").Files)
	status, out, errs := run(t, "workflow", good)
	if status != 0 || errs != "" {
		t.Fatalf("%d %q", status, errs)
	}
	golden(t, "workflow-good.txt", out, good)

	bad := write(t, vector(t, "workflow/event-rewritten").Files)
	status, out, errs = run(t, "workflow", bad, "--name", "x")
	if status != 1 || errs != "" {
		t.Fatalf("%d %q", status, errs)
	}
	golden(t, "workflow-event-rewritten.txt", out, bad)
}

func TestExitCodesOfLogs(t *testing.T) {
	cases := map[string]int{
		"collection/good": 0, "collection/tail-cut": 1, "collection/byte-changed": 1, "collection/anchor-removed": 1,
		"collection/previous-edited": 1, "collection/chain-value-edited": 1, "collection/anchor-without-entries": 1,
		"collection/unknown-field": 2, "collection/anchor-format-2": 2, "collection/anchor-without-format": 2,
		"collection/tie-grants-ab": 0, "collection/escapes": 0,
	}
	for name, want := range cases {
		dir := write(t, vector(t, name).Files)
		if status, out, errs := run(t, "history", dir); status != want {
			t.Errorf("%s: %d, want %d\n%s%s", name, status, want, out, errs)
		}
	}
	for name, want := range map[string]int{"workflow/good": 0, "workflow/tail-cut": 1, "workflow/body-not-an-event": 1, "workflow/chain-value-edited": 1,
		"workflow/unknown-field": 2, "workflow/anchor-format-2": 2} {
		dir := write(t, vector(t, name).Files)
		if status, out, errs := run(t, "workflow", dir); status != want {
			t.Errorf("%s: %d, want %d\n%s%s", name, status, want, out, errs)
		}
	}
}

// Every vector comes out of the command as it does out of the library.
func TestEveryPackVectorIsGivenTheStatusItShouldBe(t *testing.T) {
	for _, c := range vectors.All() {
		if c.Kind != vectors.Pack {
			continue
		}
		var want int
		switch {
		case c.Verified:
			want = 0
		case c.Error != "":
			want = 2
		default:
			// A pack whose only findings are that a log is in a format this verifier does
			// not know, or cannot be read, was not found to disagree with itself.
			want = 2
			for _, f := range c.Findings {
				code, _, _ := strings.Cut(f, " ")
				if code != "format" && code != "unreadable" && code != "unknown-member" && code != "limit" {
					want = 1
				}
			}
		}
		if status, out, errs := run(t, "pack", write(t, c.Files)); status != want {
			t.Errorf("%s: %d, want %d\n%s%s", c.Name, status, want, out, errs)
		}
	}
}

// The command says what a pass shows and what it does not, on a pass and on the
// rest, in the words the README gives.
func TestTheClaimIsTheSameInTheCommandAndTheReadme(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	squash := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	text := squash(string(readme))
	for _, paragraph := range []string{cli.PackShows, cli.PackDoesNotShow, cli.LogShows, cli.Disagreement} {
		if !strings.Contains(text, squash(paragraph)) {
			t.Errorf("the README does not hold, in these words:\n%s", paragraph)
		}
	}
	// The decision record says it in the same words.
	adr, err := os.ReadFile("../../../docs/adr/0015-evidence-verifier.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, paragraph := range []string{cli.PackShows, cli.PackDoesNotShow} {
		if !strings.Contains(squash(string(adr)), squash(paragraph)) {
			t.Errorf("the decision record does not hold, in these words:\n%s", paragraph)
		}
	}
	good := write(t, vector(t, "pack/good").Files)
	_, out, _ := run(t, "pack", good)
	for _, paragraph := range []string{cli.PackShows, cli.PackDoesNotShow} {
		if !strings.Contains(squash(out), squash(paragraph)) {
			t.Errorf("the command does not print:\n%s", paragraph)
		}
	}
	// And never the words the claims rule out.
	for _, word := range []string{"prov" + "es", "tamper" + "-proof", "independently " + "verifiable", "tam" + "per"} {
		for _, s := range []string{string(readme), out, cli.PackShows, cli.PackDoesNotShow, cli.LogShows, cli.Disagreement} {
			if strings.Contains(strings.ToLower(s), word) {
				t.Errorf("%q appears in %.80q", word, s)
			}
		}
	}
}

// ---- input from outside

const raw = "a\x1b[2Jb\xe2\x80\xaec"

func noRaw(t *testing.T, label, s string) {
	t.Helper()
	if strings.ContainsAny(s, "\x1b") || strings.Contains(s, "\xe2\x80\xae") {
		t.Errorf("%s: a raw name reached the output: %q", label, s)
	}
}

func TestNoNameFromOutsideReachesTheOutputRaw(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file names with control characters are not made here")
	}
	// A folder argument that is not there.
	_, out, errs := run(t, "pack", "/nonexistent/"+raw)
	noRaw(t, "pack path", out+errs)
	_, out, errs = run(t, "history", "/nonexistent/"+raw)
	noRaw(t, "history path", out+errs)

	// A pack in a folder named so, which verifies and prints where it was.
	odd := filepath.Join(t.TempDir(), raw)
	for name, body := range vector(t, "pack/good").Files {
		path := filepath.Join(odd, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	status, out, errs := run(t, "pack", odd)
	noRaw(t, "the folder a pack is in", out+errs)
	if status != 0 {
		t.Errorf("a pack in a folder with a strange name: %d\n%s%s", status, out, errs)
	}

	// A log folder with files named so.
	good := vector(t, "collection/good")
	files := map[string][]byte{raw + ".jsonl": good.Files["x.jsonl"], raw + ".head": good.Files["x.head"], "x.jsonl": good.Files["x.jsonl"], "x.head": good.Files["x.head"]}
	dir := write(t, files)
	status, out, errs = run(t, "history", dir)
	noRaw(t, "history names", out+errs)
	if status != 1 && status != 0 && status != 2 {
		t.Errorf("status %d", status)
	}
	if !strings.Contains(out, "x ") {
		t.Errorf("the log with a plain name was not checked: %q", out)
	}

	// A pack with hostile names, as an archive.
	p := vector(t, "pack/good")
	hostile := map[string][]byte{}
	for k, v := range p.Files {
		hostile[k] = v
	}
	hostile[raw] = []byte("x")
	hostile["../escape"] = []byte("x")
	status, out, errs = run(t, "pack", zipFile(t, hostile))
	noRaw(t, "pack names", out+errs)
	if status != 1 {
		t.Errorf("status %d\n%s%s", status, out, errs)
	}
	if !strings.Contains(out, "escape") {
		t.Errorf("the name that climbs was not named:\n%s", out)
	}
}

func TestALinkInAFolderOfLogsIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links are not made here")
	}
	good := vector(t, "collection/good")
	dir := write(t, map[string][]byte{"x.head": good.Files["x.head"]})
	target := filepath.Join(t.TempDir(), "elsewhere.jsonl")
	if err := os.WriteFile(target, good.Files["x.jsonl"], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "x.jsonl")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	status, out, errs := run(t, "history", dir)
	if status != 2 || !strings.Contains(out+errs, "not a plain file") {
		t.Errorf("%d %q %q", status, out, errs)
	}
}

func TestTheBoundsCanBeRaisedAndLowered(t *testing.T) {
	good := vector(t, "pack/good")
	dir := write(t, good.Files)
	if status, _, errs := run(t, "pack", dir, "--max-bytes", "300"); status != 2 || !strings.Contains(errs, "--max-bytes") {
		t.Errorf("a pack past the bound: %d %q", status, errs)
	}
	if status, out, errs := run(t, "pack", "--max-bytes", "1000000", dir); status != 0 || !strings.Contains(out, "1000000 bytes a file") {
		t.Errorf("a pack within the bound: %d %q %q", status, out, errs)
	}
	// A bound is capped below the largest number, and a bound past the cap is said to be.
	if status, out, errs := run(t, "pack", "--max-bytes", "1125899906842624", dir); status != 0 || !strings.Contains(out, "1 PiB a file") {
		t.Errorf("the largest bound: %d %q %q", status, out, errs)
	}
	if status, _, errs := run(t, "pack", "--max-bytes", "9223372036854775807", dir); status != 2 || !strings.Contains(errs, "at most 1125899906842624") {
		t.Errorf("a bound past the cap: %d %q", status, errs)
	}
	// A pack refused for a bound says which bounds were in force.
	if _, _, errs := run(t, "pack", dir, "--max-bytes", "300"); !strings.Contains(errs, "bounds in force") || !strings.Contains(errs, "300 bytes a file") {
		t.Errorf("a refusal for a bound does not say the bounds: %q", errs)
	}
	// A line past the bound is a bound exceeded and not a disagreement: exit 2, and it says
	// how to raise it.
	status, out, _ := run(t, "pack", "--max-line-bytes", "50", dir)
	if status != 2 || !strings.Contains(out, "longer than 50 bytes") || !strings.Contains(out, "--max-line-bytes") || strings.Contains(out, "does not verify") {
		t.Errorf("a line past the bound: %d %q", status, out)
	}
	col := write(t, vector(t, "collection/good").Files)
	if status, out, _ := run(t, "history", col, "--max-line-bytes", "50"); status != 2 || !strings.Contains(out, "longer than 50 bytes") ||
		!strings.Contains(out, "--max-line-bytes") || strings.Contains(out, "disagree") {
		t.Errorf("history: %d %q", status, out)
	}
	wf := write(t, vector(t, "workflow/good").Files)
	if status, out, _ := run(t, "workflow", wf, "--max-line-bytes", "50"); status != 2 || !strings.Contains(out, "longer than 50 bytes") || strings.Contains(out, "disagree") {
		t.Errorf("workflow: %d %q", status, out)
	}
}

// The bounds in force are said on a pass.
func TestTheBoundsInForceAreSaidOnAPass(t *testing.T) {
	dir := write(t, vector(t, "pack/good").Files)
	_, out, _ := run(t, "pack", dir)
	for _, want := range []string{"bounds in force", "10000 files and folders", "2 GiB a file", "8 GiB in all", "500 times its size", "64 MiB a line of a log", "manifest.sha256 and campaign.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	_, out, _ = run(t, "history", write(t, vector(t, "collection/good").Files))
	if !strings.Contains(out, "bound in force: 64 MiB a line") {
		t.Errorf("history does not say its bound:\n%s", out)
	}
}

func TestAFolderOfLogsWithNoLogsInIt(t *testing.T) {
	for _, cmd := range []string{"history", "workflow"} {
		status, _, errs := run(t, cmd, t.TempDir())
		if status != 2 || !strings.Contains(errs, "no ") {
			t.Errorf("%s: %d %q", cmd, status, errs)
		}
	}
}

func TestAnAnchorWithNoLogIsNamed(t *testing.T) {
	good := vector(t, "collection/good")
	dir := write(t, map[string][]byte{"x.head": good.Files["x.head"]})
	status, out, errs := run(t, "history", dir)
	if status != 2 || !strings.Contains(out+errs, "x") {
		t.Errorf("%d %q %q", status, out, errs)
	}
}

// A member this verifier does not know is the verifier being older than the file, and
// is said in plain words, with exit status 2.
func TestAMemberThisVerifierDoesNotKnowIsNotADisagreement(t *testing.T) {
	status, out, errs := run(t, "history", write(t, vector(t, "collection/unknown-field").Files))
	if status != 2 || errs != "" {
		t.Fatalf("%d %q", status, errs)
	}
	if !strings.Contains(out, `line 2 holds a member "note" that this verifier does not know: the file may be newer than this verifier`) {
		t.Errorf("output:\n%s", out)
	}
	for _, word := range []string{"json:", "unknown field", "disagree"} {
		if strings.Contains(out, word) {
			t.Errorf("%q in\n%s", word, out)
		}
	}
	status, out, _ = run(t, "pack", write(t, vector(t, "pack/manifest-unknown-member").Files))
	if status != 2 || !strings.Contains(out, "that this verifier does not know") || strings.Contains(out, "does not verify") {
		t.Errorf("pack: %d\n%s", status, out)
	}
}

// The flag package says nothing of its own, and what it would say goes through text.Show.
func TestTheFlagPackageIsHeldToTheSameRules(t *testing.T) {
	_, out, errs := run(t, "pack", "--\x1b[2Jfrob", "x")
	noRaw(t, "an option that is not there", out+errs)
	if status, _, _ := run(t, "pack", "--\x1b[2Jfrob", "x"); status != 2 {
		t.Errorf("status %d", status)
	}
	for _, args := range [][]string{{"pack", "-h"}, {"history", "--help"}, {"workflow", "-help"}} {
		status, out, errs := run(t, args...)
		if status != 0 || !strings.Contains(out, "usage: acciew-verify") || errs != "" || strings.Contains(out, "Usage of") {
			t.Errorf("%v: %d %q %q", args, status, out, errs)
		}
	}
}

func TestAnUnknownCommandIsQuotedOnce(t *testing.T) {
	_, _, errs := run(t, "\x1b[2Jfrob")
	if strings.Contains(errs, `""`) || !strings.Contains(errs, strconv.Quote("\x1b[2Jfrob")) {
		t.Errorf("stderr = %q", errs)
	}
	_, _, errs = run(t, "frobnicate")
	if !strings.Contains(errs, `unknown command "frobnicate"`) {
		t.Errorf("stderr = %q", errs)
	}
}

// A failing log is listed once by name.
func TestAFailingLogIsNamedOnce(t *testing.T) {
	_, out, _ := run(t, "history", write(t, vector(t, "collection/tail-cut").Files))
	first, _, _ := strings.Cut(out, "\n")
	if strings.Count(first, "x") != 1 || !strings.HasPrefix(first, "! x ") || !strings.Contains(first, "chain: the log ends at entry 2") {
		t.Errorf("first line = %q", first)
	}
}

// The hint to raise the line bound is given whenever a line past it is listed, whether
// or not something else in the pack disagrees too.
func TestTheLineBoundHintIsGivenWhateverElseIsWrong(t *testing.T) {
	c := vector(t, "pack/history-tail-cut")
	dir := write(t, c.Files)
	status, out, _ := run(t, "pack", "--max-line-bytes", "50", dir)
	if !strings.Contains(out, "longer than 50 bytes") || !strings.Contains(out, "raise the bound with --max-line-bytes") {
		t.Errorf("%d\n%s", status, out)
	}
	// With a disagreement as well, the status is 1 and the hint is still there.
	files := map[string][]byte{}
	for k, v := range c.Files {
		files[k] = v
	}
	files["notes.txt"] = []byte("added")
	status, out, _ = run(t, "pack", "--max-line-bytes", "50", write(t, files))
	if status != 1 || !strings.Contains(out, "raise the bound with --max-line-bytes") {
		t.Errorf("%d\n%s", status, out)
	}
}

// What the operating system adds when an archive is made again reads as what it is.
func TestOperatingSystemJunkInAnArchiveIsSaidToLookLikeThat(t *testing.T) {
	files := map[string][]byte{}
	for k, v := range vector(t, "pack/good").Files {
		files[k] = v
	}
	files[".DS_Store"] = []byte("x")
	files["__MACOSX/._README.txt"] = []byte("x")
	status, out, _ := run(t, "pack", zipFile(t, files))
	if status != 1 || strings.Count(out, "this looks like a file the operating system added when the archive was made again; check the archive as it was handed over") != 2 {
		t.Errorf("%d\n%s", status, out)
	}
}

func TestTheUsageSaysWhatMakesExitStatus2(t *testing.T) {
	_, out, _ := run(t, "help")
	if !strings.Contains(strings.Join(strings.Fields(out), " "), "a member of a file that it does not know") {
		t.Errorf("usage:\n%s", out)
	}
}
