package secrets_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/secrets"
)

func TestADirectoryThatIsNotThereIsMadePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "secrets")
	if err := secrets.PrepareDir(dir); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, dir); m != 0o700 {
		t.Errorf("mode %o, want 700", m)
	}
	if err := secrets.PrepareDir(dir); err != nil {
		t.Errorf("a directory that is already private: %v", err)
	}
}

// Someone who can write to a directory the agent will put secrets in can read them.
func TestADirectoryOthersCanEnterOrThatIsALinkOrAFileIsRefused(t *testing.T) {
	root := t.TempDir()
	open := filepath.Join(root, "open")
	_ = os.Mkdir(open, 0o755)
	_ = os.Chmod(open, 0o755)
	group := filepath.Join(root, "group")
	_ = os.Mkdir(group, 0o750)
	_ = os.Chmod(group, 0o750)
	good := filepath.Join(root, "good")
	_ = os.Mkdir(good, 0o700)
	link := filepath.Join(root, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	_ = os.WriteFile(file, nil, 0o600)

	for name, c := range map[string]struct{ path, want string }{
		"open":  {open, "chmod 700"},
		"group": {group, "chmod 700"},
		"link":  {link, "link"},
		"file":  {file, "not a directory"},
	} {
		err := secrets.PrepareDir(c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), c.path) {
			t.Errorf("%s: err = %v, want it to name the path and say %q", name, err, c.want)
		}
	}
	if m := mode(t, open); m != 0o755 {
		t.Errorf("the directory was changed to %o: it is not ours to change", m)
	}
}

func TestADirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.CheckOwner(info, 4242424242); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Errorf("a directory owned by someone else: %v", err)
	}
	if err := secrets.CheckOwner(info, uint32(os.Getuid())); err != nil {
		t.Errorf("our own directory: %v", err)
	}
}

// What a crash left is removed. What another agent left is not: it may be running, and a name
// that merely looks like ours may be a link to somewhere else.
func TestOnlyThisAgentsOwnLeftoverRunDirectoriesAreRemoved(t *testing.T) {
	base := t.TempDir()
	mine := filepath.Join(base, "acciew-run-aaaa1111-x1")
	theirs := filepath.Join(base, "acciew-run-bbbb2222-x1")
	elsewhere := filepath.Join(base, "victim")
	for _, d := range []string{mine, theirs, elsewhere} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(d, "s0"), []byte("v"), 0o600)
	}
	lookalike := filepath.Join(base, "acciew-run-aaaa1111-link")
	if err := os.Symlink(elsewhere, lookalike); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(base, "acciew-run-aaaa1111-file")
	_ = os.WriteFile(notDir, []byte("x"), 0o600)

	if err := secrets.CleanStale(base, "aaaa1111"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mine); !os.IsNotExist(err) {
		t.Error("this agent's leftover was kept")
	}
	for _, kept := range []string{theirs, elsewhere, filepath.Join(elsewhere, "s0")} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was removed: %v", kept, err)
		}
	}
	if _, err := os.Lstat(notDir); err != nil {
		t.Error("a file was removed")
	}
}

func TestARunDirectoryHasARandomNameThatCarriesTheAgentsTag(t *testing.T) {
	p := strict(t, map[string]string{"S": "a-secret-value-here"})
	p.AllowAny, p.Tag = true, "cafe0123"
	names := map[string]bool{}
	for range 5 {
		b, err := bindOne(p, "env:S")
		if err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(p.Dir)
		for _, e := range entries {
			names[e.Name()] = true
			if !strings.HasPrefix(e.Name(), "acciew-run-cafe0123-") {
				t.Errorf("run directory %q", e.Name())
			}
		}
		_ = b.Close()
	}
	if len(names) != 5 {
		t.Errorf("%d different names in 5 runs: they should not repeat", len(names))
	}
}

// A filesystem that ignores case (APFS, as the Mac the agent is released for has it) reaches one
// file by many spellings. What is forbidden is forbidden by what it is, not by how it is written.
func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

func TestTheRunDirectoryIsRefusedWhateverCaseItIsSpelledIn(t *testing.T) {
	base := t.TempDir()
	if !caseInsensitive(t, base) {
		t.Skip("this filesystem tells cases apart")
	}
	p := strict(t, nil)
	p.AllowAny = true
	p.Dir = filepath.Join(base, "Secrets")
	_ = os.MkdirAll(filepath.Join(p.Dir, "acciew-run-old"), 0o700)
	leftover := filepath.Join(p.Dir, "acciew-run-old", "s0")
	_ = os.WriteFile(leftover, []byte("a-leftover"), 0o600)
	respelled := filepath.Join(base, "sEcReTs", "ACCIEW-run-OLD", "S0")
	if _, err := bindOne(p, "file:"+respelled); err == nil || !strings.Contains(err.Error(), "never") {
		t.Errorf("%s: err = %v", respelled, err)
	}
}

func TestTheSameFileIsRefusedUnderAnyNameItHasOnAnyFilesystem(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "inside", "key")
	_ = os.MkdirAll(filepath.Dir(secret), 0o700)
	_ = os.WriteFile(secret, []byte("a-key-that-is-not-a-job's"), 0o600)
	hard := filepath.Join(root, "elsewhere-hardlink")
	if err := os.Link(secret, hard); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	p := strict(t, nil)
	p.AllowAny = true
	p.Forbidden = func(path string) bool {
		a, err1 := os.Stat(path)
		b, err2 := os.Stat(secret)
		return err1 == nil && err2 == nil && os.SameFile(a, b)
	}
	if _, err := bindOne(p, "file:"+hard); err == nil || !strings.Contains(err.Error(), "never") {
		t.Errorf("err = %v", err)
	}
}
