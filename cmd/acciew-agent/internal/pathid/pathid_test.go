package pathid_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.acciew.io/collector/cmd/acciew-agent/internal/pathid"
)

func TestAPathIsInsideADirectoryByWhatItIsAndNotByHowItIsSpelled(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "State Dir")
	_ = os.MkdirAll(filepath.Join(dir, "spool"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "agent.key"), []byte("k"), 0o600)
	link := filepath.Join(root, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		dir:                                        true,
		filepath.Join(dir, "agent.key"):            true,
		filepath.Join(dir, "spool", "not-yet"):     true,
		filepath.Join(dir, "a", "b", "c"):          true,
		filepath.Join(dir, "x", "..", "agent.key"): true,
		link:                             true,
		filepath.Join(link, "agent.key"): true,
		filepath.Join(root, "other"):     false,
		dir + "-sibling":                 false,
		root:                             false,
		"/":                              false,
	} {
		if got := pathid.Inside(dir, path); got != want {
			t.Errorf("Inside(%q) = %v, want %v", path, got, want)
		}
	}
	// On a filesystem that ignores case, the other spellings are inside too.
	if _, err := os.Stat(strings.ToLower(dir)); err == nil {
		if !pathid.Inside(dir, strings.ToUpper(filepath.Join(dir, "AGENT.KEY"))) {
			t.Error("another case of a path inside was not inside")
		}
	}
	if pathid.Inside(filepath.Join(root, "missing"), dir) {
		t.Error("a directory that is not there contains something")
	}
}

func TestTwoNamesOfOneFileAreTheSameFile(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	_ = os.WriteFile(a, []byte("x"), 0o600)
	_ = os.WriteFile(b, []byte("x"), 0o600)
	hard := filepath.Join(root, "hard")
	if err := os.Link(a, hard); err != nil {
		t.Skip(err)
	}
	if !pathid.Same(a, hard) || pathid.Same(a, b) || pathid.Same(a, filepath.Join(root, "missing")) || pathid.Same(filepath.Join(root, "missing"), a) {
		t.Error("Same is wrong")
	}
}

// Leftovers are named for the agent that made them, and found again by it after a restart however
// its state directory is spelled, including in another case where the filesystem ignores it.
func TestADirectoryHasOneTagWhateverItIsCalled(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Agent State")
	other := filepath.Join(root, "other state")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.MkdirAll(other, 0o700)
	link := filepath.Join(root, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	tag := pathid.Tag(dir)
	if len(tag) != 8 {
		t.Fatalf("tag = %q: want eight hex digits", tag)
	}
	t.Chdir(root)
	for name, spelled := range map[string]string{
		"relative": "Agent State", "dotted": "./Agent State/../Agent State", "a link": link, "with a slash": dir + "/",
	} {
		if got := pathid.Tag(spelled); got != tag {
			t.Errorf("%s: tag %q, want %q", name, got, tag)
		}
	}
	if pathid.Tag(other) == tag {
		t.Error("two directories have one tag: one agent would clean the other's leftovers")
	}
	if _, err := os.Stat(strings.ToLower(dir)); err == nil {
		if got := pathid.Tag(strings.ToLower(dir)); got != tag {
			t.Errorf("another case: tag %q, want %q", got, tag)
		}
		if got := pathid.Tag(strings.ToUpper(dir)); got != tag {
			t.Errorf("upper case: tag %q, want %q", got, tag)
		}
	} else {
		t.Log("this filesystem tells cases apart: the case checks are skipped")
	}
	// A directory that is not there has a tag from its name, and it is not the tag of one that is.
	if got := pathid.Tag(filepath.Join(root, "missing")); len(got) != 8 || got == tag {
		t.Errorf("missing: %q", got)
	}
}
