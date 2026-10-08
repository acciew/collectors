// Package testbin builds the collectors the agent's tests run, once per test process.
package testbin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	mu    sync.Mutex
	dir   string
	built = map[string]bool{}
)

// Dir is the directory the collectors are built into: a collectors directory, as the agent
// is given one. Cleanup removes it.
func Dir() string {
	mu.Lock()
	defer mu.Unlock()
	return dirLocked()
}

func dirLocked() string {
	if dir == "" {
		d, err := os.MkdirTemp("", "acciew-agent-test-collectors-")
		if err != nil {
			panic(err)
		}
		dir = d
	}
	return dir
}

// Build compiles a main package into the directory as acciew-collector-<name>, unless it is
// already there, and returns the directory.
func Build(t testing.TB, importPath, name string) string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	d := dirLocked()
	if built[name] {
		return d
	}
	out, err := exec.CommandContext(context.Background(), "go", "build", "-o", filepath.Join(d, "acciew-collector-"+name), importPath).CombinedOutput() //nolint:gosec // a fixed command, and import paths that the tests wrote
	if err != nil {
		t.Fatalf("building %s: %v\n%s", importPath, err, out)
	}
	built[name] = true
	return d
}

// Collectors builds the reference collector as "minimal" and the test collector as "testcollector".
func Collectors(t testing.TB) string {
	t.Helper()
	Build(t, "go.acciew.io/collector/sdk/examples/minimal", "minimal")
	return Build(t, "go.acciew.io/collector/cmd/acciew-agent/internal/testcollector", "testcollector")
}

// Cleanup removes what was built. A package's TestMain calls it after the tests.
func Cleanup() {
	mu.Lock()
	defer mu.Unlock()
	if dir != "" {
		_ = os.RemoveAll(dir)
		dir = ""
		built = map[string]bool{}
	}
}
