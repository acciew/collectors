package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const sib = "go.acciew.io/collector/"

func TestMismatches(t *testing.T) {
	tests := []struct {
		name    string
		mods    map[string][]require
		version string
		want    []string
	}{
		{"every sibling at the version", map[string][]require{
			"plugins/a/go.mod": {{sib + "api", "v0.1.1"}, {sib + "sdk/go", "v0.1.1"}},
			"sdk/go/go.mod":    {{sib + "api", "v0.1.1"}},
		}, "0.1.1", nil},
		{"one module still on the old version", map[string][]require{
			"plugins/a/go.mod": {{sib + "api", "v0.1.1"}, {sib + "sdk/go", "v0.1.0"}},
		}, "0.1.1", []string{"plugins/a/go.mod requires " + sib + "sdk/go v0.1.0, want v0.1.1"}},
		{"a module with no siblings", map[string][]require{"api/go.mod": nil}, "0.1.1", nil},
		{"other modules are not siblings", map[string][]require{
			"plugins/a/go.mod": {{"google.golang.org/grpc", "v1.84.0"}, {"example.com/collector/api", "v9.9.9"}},
		}, "0.1.1", nil},
		{"a pre-release", map[string][]require{
			"plugins/a/go.mod": {{sib + "api", "v0.2.0-rc.1"}},
		}, "0.2.0-rc.1", nil},
		{"a release does not match its pre-release", map[string][]require{
			"plugins/a/go.mod": {{sib + "api", "v0.2.0-rc.1"}},
		}, "0.2.0", []string{"plugins/a/go.mod requires " + sib + "api v0.2.0-rc.1, want v0.2.0"}},
		{"reported in a stable order", map[string][]require{
			"z/go.mod": {{sib + "api", "v0.1.0"}},
			"a/go.mod": {{sib + "api", "v0.1.0"}},
		}, "0.1.1", []string{
			"a/go.mod requires " + sib + "api v0.1.0, want v0.1.1",
			"z/go.mod requires " + sib + "api v0.1.0, want v0.1.1",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mismatches(tc.mods, tc.version); !slices.Equal(got, tc.want) {
				t.Errorf("mismatches = %q, want %q", got, tc.want)
			}
		})
	}
}

// go.mod has several ways to write a require, and the tooling and the build
// output are not this tool's to skip: it reads them with Go's own parser.
func TestReadModulesReadsEveryGoMod(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module go.acciew.io/collector\n\ngo 1.26.0\n")
	write("plugins/a/go.mod", "module go.acciew.io/collector/plugins/a\n\ngo 1.26.0\n\nrequire (\n\t"+sib+"api v0.1.1\n\tgithub.com/x/y v1.0.0 // indirect\n)\nrequire "+sib+"sdk/go v0.1.0\n")
	write("plugins/a/integration/go.mod", "module go.acciew.io/collector/plugins/a/integration\n\ngo 1.26.0\n\nrequire "+sib+"plugins/a v0.1.1\n")
	write("tools/go.mod", "module go.acciew.io/collector/tools\n\ngo 1.26.0\n\nrequire "+sib+"api v0.0.1\n")
	write("bin/stale/go.mod", "module stale\n\ngo 1.26.0\n\nrequire "+sib+"api v0.0.1\n")
	write(".git/go.mod", "module git\n\ngo 1.26.0\n")
	write(".claude/copy/go.mod", "module copy\n\ngo 1.26.0\n\nrequire "+sib+"api v0.0.1\n")

	mods, err := readModules(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range mods {
		names = append(names, n)
	}
	slices.Sort(names)
	if want := []string{"go.mod", "plugins/a/go.mod", "plugins/a/integration/go.mod"}; !slices.Equal(names, want) {
		t.Fatalf("read %v, want %v (tools, bin and hidden folders are not shipped code)", names, want)
	}
	if got := mismatches(mods, "0.1.1"); !slices.Equal(got, []string{"plugins/a/go.mod requires " + sib + "sdk/go v0.1.0, want v0.1.1"}) {
		t.Errorf("mismatches over the tree = %q", got)
	}
}

func TestAMalformedGoModIsAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n\nrequire (\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readModules(root); err == nil {
		t.Error("an unreadable go.mod was skipped")
	}
}

func TestVersionMustBeSemver(t *testing.T) {
	for v, ok := range map[string]bool{
		"0.1.1": true, "1.9.9": true, "0.2.0-rc.1": true, "1.0.0-alpha-1": true,
		// A v2 module has /v2 in its path, and these do not.
		"2.0.0": false, "10.20.30": false, "2.0.0-rc.1": false,
		"-x": false, "v0.1.2": false, "01.2.3": false, "0.1.2-": false, "0.1": false,
		"0.1.0+build": false, "0.1.0-rc.01": false, "": false, "0.1.1 && touch x": false, "0.1.1\n0.1.2": false,
	} {
		if got := validVersion(v); got != ok {
			t.Errorf("validVersion(%q) = %v, want %v", v, got, ok)
		}
	}
}

func TestBumpMovesSiblingRequiresAndBuiltInVersions(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const old = "module go.acciew.io/collector/plugins/a\n\ngo 1.26.0\n\n" +
		"// the sdk/conformance suite " + sib + "sdk/conformance v0.1.0 is not a require\n" +
		"require (\n\t" + sib + "api v0.1.0\n\t" + sib + "sdk/go v0.1.0\n\tgithub.com/x/y v1.0.0\n)\n"
	write("plugins/a/go.mod", old)
	write("plugins/a/main.go", "package main\n\n// version is stamped at build time.\nvar version = \"0.1.0-dev\"\n")
	write("go.mod", "module go.acciew.io/collector\n\ngo 1.26.0\n")
	write("tools/go.mod", "module go.acciew.io/collector/tools\n\ngo 1.26.0\n\nrequire "+sib+"api v0.1.0\n")
	write(".claude/copy/go.mod", "module copy\n\ngo 1.26.0\n\nrequire "+sib+"api v0.1.0\n")

	if err := bump(root, "0.1.1"); err != nil {
		t.Fatal(err)
	}
	mods, err := readModules(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := mismatches(mods, "0.1.1"); len(got) != 0 {
		t.Errorf("still mismatched after the bump: %q", got)
	}
	if got := read("plugins/a/go.mod"); !strings.Contains(got, "sdk/conformance v0.1.0 is not a require") ||
		strings.Contains(got, "require "+sib+"sdk/conformance") || !strings.Contains(got, "github.com/x/y v1.0.0") {
		t.Errorf("the bump touched more than the sibling requires:\n%s", got)
	}
	if got := read("plugins/a/main.go"); !strings.Contains(got, `var version = "0.1.1-dev"`) {
		t.Errorf("the built-in version did not move:\n%s", got)
	}
	if !strings.Contains(read("tools/go.mod"), "api v0.1.0") || !strings.Contains(read(".claude/copy/go.mod"), "api v0.1.0") {
		t.Error("the bump edited tooling or a hidden folder")
	}
}

// The verifier is a module with no sibling to require, and its command is not beside
// its go.mod: the bump has to find the built-in version where it is.
func TestBumpMovesTheBuiltInVersionOfACommandInsideAModule(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module go.acciew.io/collector\n\ngo 1.26.0\n")
	write("verify/go.mod", "module go.acciew.io/collector/verify\n\ngo 1.26.0\n")
	write("verify/doc.go", "package verify\n")
	write("verify/cmd/acciew-verify/main.go", "package main\n\nvar version = \"0.1.1-dev\"\n")
	write("verify/internal/cli/cli.go", "package cli\n\nvar version = \"not a built-in version\"\n")
	// A command may keep its version in another file than main.go.
	write("verify/cmd/other/main.go", "package main\n\nfunc main() {}\n")
	write("verify/cmd/other/version.go", "package main\n\n// stamped at build time\nvar version = \"0.1.1-dev\"\n")
	write("verify/cmd/other/version_test.go", "package main\n\nvar version = \"0.1.1-dev\"\n")
	// A module inside the module is a module of its own, and is bumped as one.
	write("verify/inner/go.mod", "module go.acciew.io/collector/verify/inner\n\ngo 1.26.0\n")
	write("verify/inner/main.go", "package main\n\nvar version = \"0.1.1-dev\"\n")
	write("cmd/acciew-agent/go.mod", "module go.acciew.io/collector/cmd/acciew-agent\n\ngo 1.26.0\n\nrequire "+sib+"api v0.1.1\n")
	write("cmd/acciew-agent/main.go", "package main\n\nvar version = \"0.1.1-dev\"\n")

	// With no sibling to require, the verifier passes the check at any version.
	mods, err := readModules(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := mismatches(mods, "0.2.0"); !slices.Equal(got, []string{"cmd/acciew-agent/go.mod requires " + sib + "api v0.1.1, want v0.2.0"}) {
		t.Errorf("mismatches = %q", got)
	}

	if err := bump(root, "0.2.0"); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read("verify/cmd/acciew-verify/main.go"); !strings.Contains(got, `var version = "0.2.0-dev"`) {
		t.Errorf("the verifier's built-in version did not move:\n%s", got)
	}
	if got := read("cmd/acciew-agent/main.go"); !strings.Contains(got, `var version = "0.2.0-dev"`) {
		t.Errorf("the agent's built-in version did not move:\n%s", got)
	}
	if got := read("verify/cmd/other/version.go"); !strings.Contains(got, `var version = "0.2.0-dev"`) {
		t.Errorf("a version kept in another file of a command did not move:\n%s", got)
	}
	if got := read("verify/cmd/other/version_test.go"); !strings.Contains(got, `"0.1.1-dev"`) {
		t.Errorf("the bump rewrote a test file:\n%s", got)
	}
	if got := read("verify/inner/main.go"); !strings.Contains(got, `var version = "0.2.0-dev"`) {
		t.Errorf("a module inside a module was not bumped as a module of its own:\n%s", got)
	}
	if got := read("verify/internal/cli/cli.go"); !strings.Contains(got, "not a built-in version") {
		t.Errorf("the bump rewrote a file that is not a command's:\n%s", got)
	}
	if got := read("verify/go.mod"); strings.Contains(got, "require") {
		t.Errorf("the verifier gained a require:\n%s", got)
	}
	mods, err = readModules(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := mismatches(mods, "0.2.0"); len(got) != 0 {
		t.Errorf("still mismatched: %q", got)
	}
}

// A binary added later whose built-in version the bump does not find would report the
// last release's number for ever. Every file in this repository that holds one is
// found.
func TestEveryBuiltInVersionInThisRepositoryIsFoundByTheBump(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Skip("not run inside the repository")
	}
	mods, err := readModules(root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for name := range mods {
		for _, f := range builtInVersionFiles(filepath.Join(root, filepath.Dir(name))) {
			found[filepath.Clean(f)] = true
		}
	}
	var holders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "tools" || d.Name() == "bin" || d.Name() == "dist" || d.Name() == "testdata" || (path != root && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if builtInVersion.Match(src) && packageMain.Match(src) {
			holders = append(holders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The collectors, the agent and the verifier, at least.
	if len(holders) < 6 {
		t.Fatalf("found only %v", holders)
	}
	for _, h := range holders {
		if !found[filepath.Clean(h)] {
			t.Errorf("%s holds a built-in version that the bump does not find", h)
		}
	}
}
