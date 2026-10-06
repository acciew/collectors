// Command releasecheck fails unless every module in the repository requires
// its siblings at the version being released.
//
// Usage:
//
//	releasecheck -version 0.1.1 [-root dir]
//	releasecheck -bump -version 0.1.1 [-root dir]
//
// With -bump it moves every sibling require to the version instead, and the
// plugins' built-in version (what an unstamped build reports) to "<version>-dev".
//
// Consumers ignore the replace directives that make the modules resolve to
// each other's directories here. What they get is what the go.mod files say, so
// a plugin that still requires the previous SDK is built, by everyone but us,
// against the previous SDK, whatever this repository's tests ran against.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const siblings = "go.acciew.io/collector/"

type require struct{ path, version string }

// mismatches names every sibling require that is not at the version, sorted.
func mismatches(mods map[string][]require, version string) []string {
	var out []string
	for name, reqs := range mods {
		for _, r := range reqs {
			if strings.HasPrefix(r.path, siblings) && r.version != "v"+version {
				out = append(out, fmt.Sprintf("%s requires %s %s, want v%s", name, r.path, r.version, version))
			}
		}
	}
	slices.Sort(out)
	return out
}

// readModules reads every go.mod under root that is shipped code or tests of it:
// not the tooling module, and not build output.
func readModules(root string) (map[string][]require, error) {
	mods := map[string][]require{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			// Tooling, build output, and anything hidden: .git, .cover, and
			// whatever an editor or an agent leaves a copy of the tree in.
			if rel == "tools" || d.Name() == "bin" || d.Name() == "dist" ||
				(path != root && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		out, err := exec.CommandContext(context.Background(), "go", "mod", "edit", "-json", path).Output() //nolint:gosec // a path found under the root
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exit.Stderr)))
			}
			return fmt.Errorf("reading %s: %w", rel, err)
		}
		var mod struct {
			Require []struct{ Path, Version string }
		}
		if err := json.Unmarshal(out, &mod); err != nil {
			return fmt.Errorf("reading %s: %w", rel, err)
		}
		for _, r := range mod.Require {
			mods[filepath.ToSlash(rel)] = append(mods[filepath.ToSlash(rel)], require{r.Path, r.Version})
		}
		if _, ok := mods[filepath.ToSlash(rel)]; !ok {
			mods[filepath.ToSlash(rel)] = nil
		}
		return nil
	})
	return mods, err
}

// semver, as Go requires of a module tag, without build metadata. The major is
// 0 or 1: a module at v2 or later has /v2 in its path, and these do not.
var semver = func() *regexp.Regexp {
	id := `(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)`
	n := `(?:0|[1-9][0-9]*)`
	return regexp.MustCompile(`^[01]\.` + n + `\.` + n + `(?:-` + id + `(?:\.` + id + `)*)?$`)
}()

func validVersion(v string) bool { return semver.MatchString(v) }

var builtInVersion = regexp.MustCompile(`(?m)^var version = "[^"]*"`)

// bump moves every sibling require under root to v<version>, and the built-in
// version of each plugin to "<version>-dev". It reads the requires with Go's
// parser, so a comment that names a sibling is not one.
func bump(root, version string) error {
	mods, err := readModules(root)
	if err != nil {
		return err
	}
	for name, reqs := range mods {
		dir := filepath.Join(root, filepath.Dir(name))
		var args []string
		for _, r := range reqs {
			if strings.HasPrefix(r.path, siblings) {
				args = append(args, "-require="+r.path+"@v"+version)
			}
		}
		if len(args) > 0 {
			cmd := exec.CommandContext(context.Background(), "go", append([]string{"mod", "edit"}, args...)...) //nolint:gosec // paths and a validated version
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("go mod edit in %s: %w: %s", filepath.Dir(name), err, strings.TrimSpace(string(out)))
			}
		}
		main := filepath.Join(dir, "main.go")
		src, err := os.ReadFile(main) //nolint:gosec // beside a go.mod found under the root
		if err != nil {
			continue
		}
		if next := builtInVersion.ReplaceAll(src, []byte(`var version = "`+version+`-dev"`)); !slices.Equal(next, src) {
			if err := os.WriteFile(main, next, 0o644); err != nil { //nolint:gosec // a source file
				return err
			}
		}
	}
	return nil
}

func main() {
	version := flag.String("version", "", "the version being released, without the v")
	root := flag.String("root", ".", "the repository root")
	doBump := flag.Bool("bump", false, "move the requires to the version instead of checking them")
	flag.Parse()
	if !validVersion(*version) {
		fmt.Fprintf(os.Stderr, "releasecheck: -version must look like 0.1.1, without the v; got %q\n", *version)
		os.Exit(2)
	}
	if *doBump {
		if err := bump(*root, *version); err != nil {
			fmt.Fprintln(os.Stderr, "releasecheck:", err)
			os.Exit(2)
		}
		fmt.Printf("releasecheck: every sibling require is now v%s; run `task tidy`\n", *version)
		return
	}
	mods, err := readModules(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasecheck:", err)
		os.Exit(2)
	}
	bad := mismatches(mods, *version)
	for _, line := range bad {
		fmt.Println(line)
	}
	if len(bad) > 0 {
		fmt.Printf("releasecheck: bump them to v%s in a change of its own, merge it, then release\n", *version)
		os.Exit(1)
	}
	fmt.Printf("releasecheck: every module requires its siblings at v%s\n", *version)
}
