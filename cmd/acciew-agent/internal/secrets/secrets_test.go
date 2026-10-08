package secrets_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
}

func policy(t *testing.T, vars map[string]string) *secrets.Policy {
	t.Helper()
	// The mechanics are tested with the opt-out on; what the default refuses is tested in deny_test.go.
	return &secrets.Policy{LookupEnv: env(vars), Dir: t.TempDir(), AllowAny: true}
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	return m
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestAConfigurationWithNoReferencesPassesThroughAsItWas(t *testing.T) {
	p := policy(t, nil)
	in := []byte(`{"url": "https://kc.example.test",  "page_size": 100, "big": 12345678901234567890}`)
	b, err := p.Bind(in)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if string(b.Config) != string(in) {
		t.Errorf("config changed: %s", b.Config)
	}
	if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
		t.Errorf("a directory was made for nothing: %v", entries)
	}
}

func TestAnEnvironmentReferenceBecomesAFileOnlyTheOwnerCanReadHoldingTheValue(t *testing.T) {
	p := policy(t, map[string]string{"KC_SECRET": "s3cr3t-value-123"})
	b, err := p.Bind([]byte(`{"url":"https://kc","client_secret":"env:KC_SECRET","n":[1,{"deep":"env:KC_SECRET"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := decode(t, b.Config)
	ref, _ := cfg["client_secret"].(string)
	path, ok := strings.CutPrefix(ref, "file:")
	if !ok || !filepath.IsAbs(path) {
		t.Fatalf("client_secret = %q, want file:/absolute/path", ref)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "s3cr3t-value-123" {
		t.Errorf("file holds %q (%v)", got, err)
	}
	if m := mode(t, path); m != 0o600 {
		t.Errorf("secret file is %o, want 600", m)
	}
	if m := mode(t, filepath.Dir(path)); m != 0o700 {
		t.Errorf("secret directory is %o, want 700", m)
	}
	if strings.Contains(string(b.Config), "s3cr3t-value-123") || strings.Contains(string(b.Config), "KC_SECRET") {
		t.Errorf("the bound config still has the reference or the value: %s", b.Config)
	}
	if cfg["url"] != "https://kc" {
		t.Errorf("another field changed: %v", cfg["url"])
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the secret directory survived Close: %v", err)
	}
}

// A collector trims a trailing newline off a file it reads; the agent must hand over exactly
// what was there so that it sees what it would have seen reading the original.
func TestAFileReferenceIsCopiedByteForByte(t *testing.T) {
	src := filepath.Join(t.TempDir(), "kc-secret")
	if err := os.WriteFile(src, []byte("from-a-file\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	p := policy(t, nil)
	b, err := p.Bind([]byte(`{"token":"file:` + src + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	ref, _ := decode(t, b.Config)["token"].(string)
	copyPath := strings.TrimPrefix(ref, "file:")
	if copyPath == src {
		t.Error("the collector was pointed at the original file")
	}
	got, _ := os.ReadFile(copyPath)
	if string(got) != "from-a-file\n" || mode(t, copyPath) != 0o600 {
		t.Errorf("copy holds %q at %o", got, mode(t, copyPath))
	}
}

func TestOnlyAStringThatIsExactlyAReferenceIsOne(t *testing.T) {
	p := policy(t, map[string]string{"X": "v"})
	in := `{"a":"environment:X","b":"ENV:X","c":" env:X","d":"see env:X","e":"files:/etc/passwd","f":"https://x/file:y","env:X":"key","g":null,"h":true}`
	b, err := p.Bind([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if string(b.Config) == "" || decode(t, b.Config)["a"] != "environment:X" || decode(t, b.Config)["env:X"] != "key" || decode(t, b.Config)["c"] != " env:X" {
		t.Errorf("something that was not a reference was changed: %s", b.Config)
	}
	if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
		t.Errorf("a directory was made though there was no reference: %v", entries)
	}
}

func TestAnUnsetOrEmptyVariableIsNamedAndNeverGuessedAt(t *testing.T) {
	for name, vars := range map[string]map[string]string{"unset": nil, "empty": {"KC_SECRET": ""}} {
		p := policy(t, vars)
		_, err := p.Bind([]byte(`{"client_secret":"env:KC_SECRET"}`))
		if err == nil || !strings.Contains(err.Error(), "KC_SECRET") || !strings.Contains(err.Error(), "empty or unset") {
			t.Errorf("%s: err = %v", name, err)
		}
		if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
			t.Errorf("%s: left %v behind", name, entries)
		}
	}
}

func TestAFailureHalfwayLeavesNoSecretOnDisk(t *testing.T) {
	p := policy(t, map[string]string{"GOOD": "value-that-was-written"})
	_, err := p.Bind([]byte(`{"a":"env:GOOD","b":"env:MISSING"}`))
	if err == nil {
		t.Fatal("bound a missing variable")
	}
	if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
		t.Errorf("a secret was left on disk: %v", entries)
	}
}

func TestAFileThatCannotBeReadIsNamedWithoutItsContents(t *testing.T) {
	p := policy(t, nil)
	dir := t.TempDir()
	for name, ref := range map[string]string{
		"missing":   "file:" + filepath.Join(dir, "nope"),
		"directory": "file:" + dir,
		"relative":  "file:secrets/kc",
	} {
		_, err := p.Bind([]byte(`{"s":"` + ref + `"}`))
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(big, make([]byte, 2<<20), 0o600)
	if _, err := p.Bind([]byte(`{"s":"file:` + big + `"}`)); err == nil || !strings.Contains(err.Error(), "too big") {
		t.Errorf("a 2 MiB secret: %v", err)
	}
}

func TestAMalformedReferenceIsRefused(t *testing.T) {
	p := policy(t, map[string]string{"OK": "v"})
	for _, ref := range []string{"env:", "file:", "env:has space", "env:A-B", "env:1ST", "env:a=b"} {
		if _, err := p.Bind([]byte(`{"s":"` + ref + `"}`)); err == nil {
			t.Errorf("%q was accepted", ref)
		}
	}
}

// The agent's own key must not be something a job can send to the source it names.
func TestAReferenceIntoTheAgentsOwnDirectoryIsRefused(t *testing.T) {
	state := t.TempDir()
	key := filepath.Join(state, "agent.key")
	_ = os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----"), 0o600)
	link := filepath.Join(t.TempDir(), "innocent")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	p := policy(t, nil)
	p.Forbidden = func(path string) bool { return strings.HasPrefix(resolved(t, path), resolved(t, state)) }
	for _, ref := range []string{"file:" + key, "file:" + link} {
		if _, err := p.Bind([]byte(`{"s":"` + ref + `"}`)); err == nil || !strings.Contains(err.Error(), "agent's own") {
			t.Errorf("%q: err = %v", ref, err)
		}
	}
}

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return r
}

func TestAnOperatorCanLimitWhatAJobMayNameToWhatIsListed(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "run", "secrets")
	_ = os.MkdirAll(allowed, 0o700)
	ok := filepath.Join(allowed, "kc")
	_ = os.WriteFile(ok, []byte("v1"), 0o600)
	other := filepath.Join(dir, "run", "elsewhere")
	_ = os.WriteFile(other, []byte("v2"), 0o600)

	p := policy(t, map[string]string{"KC_SECRET": "v", "AWS_SECRET_ACCESS_KEY": "no"})
	p.AllowAny = false
	p.AllowEnv = []string{"KC_SECRET"}
	p.AllowPaths = []string{allowed}

	for _, c := range []struct {
		ref string
		ok  bool
	}{
		{"env:KC_SECRET", true},
		{"env:AWS_SECRET_ACCESS_KEY", false},
		{"file:" + ok, true},
		{"file:" + other, false},
		{"file:" + allowed + "/../elsewhere", false},
	} {
		b, err := p.Bind([]byte(`{"s":"` + c.ref + `"}`))
		if (err == nil) != c.ok {
			t.Errorf("%q: accepted = %v (%v), want %v", c.ref, err == nil, err, c.ok)
		}
		if b != nil {
			_ = b.Close()
		}
	}
}

func TestWhatWasResolvedCanBeScrubbedFromAnyTextThatLeaves(t *testing.T) {
	p := policy(t, map[string]string{"A": "alpha-secret-value", "B": "beta-secret\n", "SHORT": "ab"})
	b, err := p.Bind([]byte(`{"a":"env:A","b":"env:B","c":"env:SHORT"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	aRef, _ := decode(t, b.Config)["a"].(string)
	dir := filepath.Dir(strings.TrimPrefix(aRef, "file:"))
	in := "failed with alpha-secret-value and beta-secret and \"beta-secret\\n\" in " + dir + "/s0, ab"
	got := b.Redact.Scrub(in)
	for _, leak := range []string{"alpha-secret-value", "beta-secret", dir} {
		if strings.Contains(got, leak) {
			t.Errorf("%q survived: %s", leak, got)
		}
	}
	if !strings.Contains(got, "[redacted]") || !strings.HasSuffix(got, ", ab") {
		t.Errorf("scrubbed = %q (a two-character value is not a secret worth wrecking text for)", got)
	}
}

func TestAConfigurationThatIsNotJSONIsRefusedAndAnEmptyOneIsLeftAlone(t *testing.T) {
	p := policy(t, nil)
	for _, bad := range []string{`{"a":`, `[1,2`, `{} {}`, `nope`} {
		if _, err := p.Bind([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{``, `  `, `null`, `{}`} {
		b, err := p.Bind([]byte(ok))
		if err != nil || string(b.Config) != ok {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

// SIGKILL runs no defers, so what a killed agent left behind is found and removed at the next start.
func TestRunDirectoriesACrashLeftAreRemovedAndNothingElseIs(t *testing.T) {
	p := policy(t, map[string]string{"A": "value-left-behind"})
	b, err := p.Bind([]byte(`{"a":"env:A"}`)) // never closed: the agent was killed
	if err != nil {
		t.Fatal(err)
	}
	_ = b
	keep := filepath.Join(p.Dir, "somebody-elses")
	_ = os.Mkdir(keep, 0o700)
	if err := secrets.CleanStale(p.Dir, ""); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(p.Dir)
	if len(entries) != 1 || entries[0].Name() != "somebody-elses" {
		t.Errorf("left: %v", entries)
	}
	if err := secrets.CleanStale(filepath.Join(t.TempDir(), "missing"), ""); err != nil {
		t.Errorf("a directory that is not there: %v", err)
	}
}
