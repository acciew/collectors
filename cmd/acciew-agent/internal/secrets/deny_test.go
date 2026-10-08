package secrets_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

// strict is the policy an agent has when nobody has said what a job may name.
func strict(t testing.TB, vars map[string]string) *secrets.Policy {
	t.Helper()
	return &secrets.Policy{LookupEnv: env(vars), Dir: t.TempDir()}
}

func bindOne(p *secrets.Policy, ref string) (*secrets.Bound, error) {
	return p.Bind([]byte(`{"s":"` + ref + `"}`))
}

func nothingLeft(t *testing.T, p *secrets.Policy) {
	t.Helper()
	if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
		t.Errorf("a refused reference left %v on disk", entries)
	}
}

// The service writes a job's configuration. Until the operator says what a job may name, it may
// name nothing: not an environment variable, not a file.
func TestByDefaultNoReferenceIsResolvedAndTheRefusalNamesTheReferenceAndTheFlagThatAllowsIt(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "kc")
	if err := os.WriteFile(secretFile, []byte("a-value-that-must-not-appear"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := strict(t, map[string]string{"KC_SECRET": "a-value-that-must-not-appear"})
	for ref, flag := range map[string]string{"env:KC_SECRET": "--secret-env KC_SECRET", "file:" + secretFile: "--secret-path"} {
		_, err := bindOne(p, ref)
		if err == nil {
			t.Fatalf("%s was resolved though nothing was allowed", ref)
		}
		if !strings.Contains(err.Error(), ref) || !strings.Contains(err.Error(), flag) {
			t.Errorf("%s: the refusal should name the reference and the flag %q: %v", ref, flag, err)
		}
		if strings.Contains(err.Error(), "a-value-that-must-not-appear") {
			t.Errorf("%s: the refusal holds the value: %v", ref, err)
		}
	}
	nothingLeft(t, p)
}

func TestAllowingVariablesDoesNotAllowFilesAndAllowingFilesDoesNotAllowVariables(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "kc")
	_ = os.WriteFile(file, []byte("v"), 0o600)

	p := strict(t, map[string]string{"KC_SECRET": "a-secret-value"})
	p.AllowEnv = []string{"KC_SECRET"}
	if _, err := bindOne(p, "file:"+file); err == nil {
		t.Error("a file was resolved with only variables allowed")
	}
	if b, err := bindOne(p, "env:KC_SECRET"); err != nil {
		t.Errorf("the variable that was allowed: %v", err)
	} else {
		_ = b.Close()
	}

	q := strict(t, map[string]string{"KC_SECRET": "a-secret-value"})
	q.AllowPaths = []string{dir}
	if _, err := bindOne(q, "env:KC_SECRET"); err == nil {
		t.Error("a variable was resolved with only paths allowed")
	}
	if b, err := bindOne(q, "file:"+file); err != nil {
		t.Errorf("the file that was allowed: %v", err)
	} else {
		_ = b.Close()
	}
}

// With only --secret-env set, file:/proc/self/environ would hand a collector the agent's whole
// environment, every variable in it. These places are never anything a job may name.
func TestProcSysAndDevAreNeverResolvedWhateverIsAllowed(t *testing.T) {
	for _, p := range []*secrets.Policy{
		{LookupEnv: env(nil), Dir: t.TempDir()},
		{LookupEnv: env(nil), Dir: t.TempDir(), AllowAny: true},
		{LookupEnv: env(nil), Dir: t.TempDir(), AllowPaths: []string{"/"}},
		{LookupEnv: env(nil), Dir: t.TempDir(), AllowEnv: []string{"X"}},
	} {
		for _, path := range []string{
			"/proc/self/environ", "/proc/1/environ", "/proc", "/proc/../proc/self/environ", "//proc//self/environ",
			"/sys/kernel/notes", "/dev/zero", "/dev/shm/acciew-run-x/s0", "/dev",
		} {
			_, err := bindOne(p, "file:"+path)
			if err == nil || !strings.Contains(err.Error(), "never") {
				t.Errorf("%+v %s: err = %v, want a refusal that says it is never allowed", p.AllowPaths, path, err)
			}
		}
	}
}

func TestTheAgentsOwnDirectoryAndRunDirectoryAreRefusedEvenWhenAllowed(t *testing.T) {
	state := t.TempDir()
	key := filepath.Join(state, "agent.key")
	_ = os.WriteFile(key, []byte("k"), 0o600)
	p := strict(t, nil)
	p.AllowAny = true
	p.Forbidden = func(path string) bool { return strings.HasPrefix(path, state) }
	if _, err := bindOne(p, "file:"+key); err == nil || !strings.Contains(err.Error(), "never") {
		t.Errorf("the agent's key: %v", err)
	}
	// And a file in the directory the run's own secret files are made in.
	other := filepath.Join(p.Dir, "acciew-run-old", "s0")
	_ = os.MkdirAll(filepath.Dir(other), 0o700)
	_ = os.WriteFile(other, []byte("v"), 0o600)
	if _, err := bindOne(p, "file:"+other); err == nil || !strings.Contains(err.Error(), "never") {
		t.Errorf("another run's secret: %v", err)
	}
}

// A link inside the allowed directory that points out of it is not inside it.
func TestALinkThatLeavesTheAllowedTreeIsRefusedAndOneThatStaysIsNot(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{allowed, outside, filepath.Join(allowed, "sub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(allowed, "sub", "kc"), []byte("inside-value"), 0o600)
	_ = os.WriteFile(filepath.Join(outside, "ssh-key"), []byte("outside-value"), 0o600)
	links := map[string]string{
		"leaves":     filepath.Join(outside, "ssh-key"),
		"leaves-dir": outside,
		"stays":      filepath.Join(allowed, "sub", "kc"),
		"dotdot":     filepath.Join("..", "outside", "ssh-key"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(allowed, name)); err != nil {
			t.Fatal(err)
		}
	}

	p := strict(t, nil)
	p.AllowPaths = []string{allowed}
	for ref, ok := range map[string]bool{
		"file:" + filepath.Join(allowed, "sub", "kc"):                true,
		"file:" + filepath.Join(allowed, "stays"):                    true,
		"file:" + filepath.Join(allowed, "leaves"):                   false,
		"file:" + filepath.Join(allowed, "leaves-dir", "ssh-key"):    false,
		"file:" + filepath.Join(allowed, "dotdot"):                   false,
		"file:" + filepath.Join(allowed, "..", "outside", "ssh-key"): false,
		"file:" + filepath.Join(outside, "ssh-key"):                  false,
	} {
		b, err := bindOne(p, ref)
		if (err == nil) != ok {
			t.Errorf("%s: accepted = %v (%v), want %v", ref, err == nil, err, ok)
		}
		if err != nil && strings.Contains(err.Error(), "outside-value") {
			t.Errorf("%s: the refusal holds the value", ref)
		}
		if b != nil {
			_ = b.Close()
		}
	}
}

// A path can be allowed as one file as well as a directory.
func TestAnAllowedPathMayBeOneFile(t *testing.T) {
	dir := t.TempDir()
	one, two := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	_ = os.WriteFile(one, []byte("v1"), 0o600)
	_ = os.WriteFile(two, []byte("v2"), 0o600)
	p := strict(t, nil)
	p.AllowPaths = []string{one}
	if b, err := bindOne(p, "file:"+one); err != nil {
		t.Errorf("the file that was named: %v", err)
	} else {
		_ = b.Close()
	}
	if _, err := bindOne(p, "file:"+two); err == nil {
		t.Error("a sibling of the file that was named was resolved")
	}
	// A directory that merely starts with the same letters is not inside it.
	if _, err := bindOne(p, "file:"+one+"-x"); err == nil {
		t.Error("a path that only shares a prefix was resolved")
	}
}

func TestAnAllowedPathThatIsNotAbsoluteIsRefusedBeforeAnythingIsResolved(t *testing.T) {
	p := strict(t, map[string]string{"A": "value-here"})
	p.AllowPaths = []string{"secrets"}
	if _, err := bindOne(p, "env:A"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("err = %v", err)
	}
}

// Where a link ends is checked as well as where it starts: a link inside a listed directory that
// leads to /dev, or into the agent's own directory, is refused.
func TestALinkIntoDevOrIntoTheAgentsOwnFilesIsRefused(t *testing.T) {
	links := t.TempDir()
	state := t.TempDir()
	key := filepath.Join(state, "agent.key")
	_ = os.WriteFile(key, []byte("k"), 0o600)
	toDev := filepath.Join(links, "dev-null")
	toKey := filepath.Join(links, "the-key")
	toRuns := filepath.Join(links, "runs")
	for link, target := range map[string]string{toDev: "/dev/null", toKey: key} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	p := strict(t, nil)
	p.AllowAny = true // the list is not what stops these
	p.Forbidden = func(path string) bool { return pathInside(state, path) }
	_ = os.Symlink(p.Dir, toRuns)
	_ = os.WriteFile(filepath.Join(p.Dir, "s0"), []byte("v"), 0o600)
	for _, link := range []string{toDev, toKey, filepath.Join(toRuns, "s0")} {
		_, err := bindOne(p, "file:"+link)
		if err == nil || !strings.Contains(err.Error(), "never") {
			t.Errorf("%s: err = %v, want it refused as never allowed", link, err)
		}
	}
	// Where the link leads is what is said, for a link the text of the path does not give away.
	if _, err := bindOne(p, "file:"+toDev); err == nil || !strings.Contains(err.Error(), "leads to") {
		t.Errorf("a link to /dev/null: %v", err)
	}
}

func pathInside(root, path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	rel, err := filepath.Rel(root, resolved)
	return err == nil && !strings.HasPrefix(rel, "..")
}
