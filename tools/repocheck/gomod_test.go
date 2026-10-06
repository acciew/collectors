package repocheck_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// What a module's go.mod requires is what everyone who installs it inherits,
// in `go mod graph`, in their scanners, and in the review of their lockfile.
// A container library used only by a test would put roughly seventeen modules
// of someone else's code in front of a security team auditing a collector.
// Tests that need one live in a module of their own, plugins/<name>/integration,
// which nobody installs.
var testOnly = []string{
	"github.com/testcontainers/",
	"github.com/docker/",
	"github.com/moby/",
}

func TestShippedModulesRequireNoTestOnlyLibraries(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	dir := strings.TrimSpace(string(root))

	out, err := exec.Command("git", "-C", dir, "ls-files", "-z", "--", "go.mod", "*/go.mod").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if ok, _ := path.Match("plugins/*/integration/go.mod", name); name == "" || strings.HasPrefix(name, "tools/") || ok {
			continue
		}
		file := filepath.Join(dir, name)
		if _, err := os.Stat(file); err != nil {
			continue // deleted in the working tree
		}
		// Go's own parser, so every legal way of writing a require is read.
		out, err := exec.Command("go", "mod", "edit", "-json", file).Output()
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exit.Stderr)))
			}
			t.Errorf("go mod edit -json %s: %v", name, err)
			continue
		}
		var mod struct{ Require []struct{ Path string } }
		if err := json.Unmarshal(out, &mod); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, r := range mod.Require {
			for _, prefix := range testOnly {
				if strings.HasPrefix(r.Path, prefix) {
					t.Errorf("%s requires %s; move the test that needs it into an integration module",
						name, r.Path)
				}
			}
		}
	}
}
