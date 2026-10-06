// Command importlint enforces the repo's import boundaries.
//
// The policy lives in importlint.json at the repo root so that it can be read
// without reading Go. Every rule states why it exists; a rule nobody can
// justify should be deleted, not weakened.
//
// Two things the tool does that a path-prefix matcher does not:
//
//   - It resolves imports back to repository directories by reading every
//     go.mod in the tree, so renaming a plugin's module path does not stop it
//     being a plugin.
//   - It fails on any directory containing Go files that no rule governs, so a
//     new top-level directory cannot quietly sit outside the policy.
//
// What it does not do: follow imports transitively. Laundering an import
// through an intermediate package is prevented by governing every directory in
// the repository, not by dependency analysis. That holds as long as every
// zone has rules — which is exactly what the coverage check enforces.
//
// Usage:
//
//	importlint [-policy path] [-root path]
//
// Exits non-zero and prints one line per violation.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ruleEveryDirectoryGoverned is reported for a directory of Go files that no
// rule's From covers. It is a synthetic rule name: the check is structural
// rather than declared, because a policy cannot list rules for directories
// nobody has created yet.
const ruleEveryDirectoryGoverned = "every-directory-must-be-governed"

// Policy is the parsed contents of importlint.json.
type Policy struct {
	Module string `json:"module"`
	Rules  []Rule `json:"rules"`
}

// Rule denies imports to the files it governs.
//
// From and Except are repository-relative directory prefixes. DenyDirs are
// also repository directories, matched after an import has been resolved
// through the module map, so they survive a module rename. Deny is for imports
// outside this repository, matched on the import path itself.
type Rule struct {
	Name     string   `json:"name"`
	Why      string   `json:"why"`
	From     []string `json:"from"`
	Except   []string `json:"except,omitempty"`
	DenyDirs []string `json:"denyDirs,omitempty"`
	Deny     []string `json:"deny,omitempty"`
}

// Violation is one offending import, or one ungoverned directory.
type Violation struct {
	File   string // for an ungoverned directory, the directory
	Line   int    // 0 for an ungoverned directory
	Rule   string
	Import string // empty for an ungoverned directory
}

func main() {
	policyPath := flag.String("policy", "importlint.json", "path to the policy file")
	root := flag.String("root", ".", "repo root to scan")
	flag.Parse()

	policy, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "importlint: %v\n", err)
		os.Exit(2)
	}

	violations, err := Check(os.DirFS(*root), policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "importlint: %v\n", err)
		os.Exit(2)
	}

	if len(violations) == 0 {
		fmt.Printf("importlint: ok (%d rules)\n", len(policy.Rules))
		return
	}

	why := map[string]string{
		ruleEveryDirectoryGoverned: "Rules are an allowlist of directories. A directory no rule " +
			"governs is a directory outside the policy, so add it to a rule's `from` " +
			"before putting Go files in it.",
	}
	for _, r := range policy.Rules {
		why[r.Name] = r.Why
	}
	seen := map[string]bool{}
	for _, v := range violations {
		if v.Import == "" {
			fmt.Fprintf(os.Stderr, "%s: %s: no rule governs this directory\n", v.File, v.Rule)
		} else {
			fmt.Fprintf(os.Stderr, "%s:%d: %s: may not import %q\n", v.File, v.Line, v.Rule, v.Import)
		}
		if !seen[v.Rule] {
			seen[v.Rule] = true
			fmt.Fprintf(os.Stderr, "\t%s\n", why[v.Rule])
		}
	}
	fmt.Fprintf(os.Stderr, "importlint: %d violation(s)\n", len(violations))
	os.Exit(1)
}

func loadPolicy(path string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is a command-line flag of a build tool, not user input
	if err != nil {
		return p, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("parsing %s: %w", path, err)
	}
	if p.Module == "" {
		return p, fmt.Errorf("parsing %s: no module", path)
	}
	for i, r := range p.Rules {
		switch {
		case r.Name == "":
			return p, fmt.Errorf("parsing %s: rule %d has no name", path, i)
		case r.Why == "":
			return p, fmt.Errorf("parsing %s: rule %q has no why", path, r.Name)
		case len(r.From) == 0:
			return p, fmt.Errorf("parsing %s: rule %q has no from", path, r.Name)
		case len(r.Deny) == 0 && len(r.DenyDirs) == 0:
			return p, fmt.Errorf("parsing %s: rule %q denies nothing", path, r.Name)
		}
	}
	return p, nil
}

// Check walks fsys and reports every import a rule denies, plus every
// directory of Go files that no rule governs. Results are sorted so output is
// stable.
func Check(fsys fs.FS, policy Policy) ([]Violation, error) {
	modules, err := readModules(fsys)
	if err != nil {
		return nil, err
	}
	if dir, ok := modules[policy.Module]; !ok || dir != "" {
		return nil, fmt.Errorf("policy module %q is not the module declared in the root go.mod", policy.Module)
	}

	var violations []Violation
	governed := map[string]bool{}

	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}

		dir := path.Dir(p)
		rules := rulesFor(policy.Rules, p)
		if len(rules) == 0 {
			if !governed[dir] {
				governed[dir] = true
				violations = append(violations, Violation{File: dir, Rule: ruleEveryDirectoryGoverned})
			}
			return nil
		}

		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, p, src, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", p, err)
		}
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("parsing %s: bad import literal %s", p, spec.Path.Value)
			}
			importedDir := repoDirFor(modules, imported)
			for _, r := range rules {
				if r.denies(imported, importedDir) {
					violations = append(violations, Violation{
						File:   p,
						Line:   fset.Position(spec.Pos()).Line,
						Rule:   r.Name,
						Import: imported,
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(violations, func(i, j int) bool {
		a, b := violations[i], violations[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return violations, nil
}

// denies reports whether the rule forbids this import. importedDir is the
// repository directory the import resolves to, or "" if it is external.
func (r Rule) denies(importPath, importedDir string) bool {
	for _, deny := range r.Deny {
		if matches(importPath, deny) {
			return true
		}
	}
	if importedDir == "" {
		return false
	}
	for _, deny := range r.DenyDirs {
		if matches(importedDir, deny) {
			return true
		}
	}
	return false
}

var moduleLine = regexp.MustCompile(`(?m)^module\s+(\S+)\s*$`)

// readModules maps every module path declared in the tree to its directory,
// relative to the repo root. The root module maps to "".
func readModules(fsys fs.FS) (map[string]string, error) {
	modules := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		m := moduleLine.FindSubmatch(b)
		if m == nil {
			return fmt.Errorf("%s: no module line", p)
		}
		dir := path.Dir(p)
		if dir == "." {
			dir = ""
		}
		modules[string(m[1])] = dir
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("no go.mod found; is -root pointing at the repository?")
	}
	return modules, nil
}

// repoDirFor resolves an import path to a repository directory, or "" if the
// import comes from outside this repository. The longest matching module wins,
// so a nested module claims its own subtree.
func repoDirFor(modules map[string]string, importPath string) string {
	bestPath, bestDir, found := "", "", false
	for modPath, modDir := range modules {
		if !matches(importPath, modPath) {
			continue
		}
		if !found || len(modPath) > len(bestPath) {
			bestPath, bestDir, found = modPath, modDir, true
		}
	}
	if !found {
		return ""
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(importPath, bestPath), "/")
	return path.Join(bestDir, rest)
}

func skipDir(name string) bool {
	switch name {
	case ".git", "vendor", "node_modules", "testdata", ".task", ".cover", "bin":
		return true
	}
	return false
}

// rulesFor returns the rules whose From prefixes cover path and whose Except
// prefixes do not.
func rulesFor(rules []Rule, filePath string) []Rule {
	var out []Rule
	for _, r := range rules {
		if !anyMatch(filePath, r.From) || anyMatch(filePath, r.Except) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func anyMatch(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if matches(s, p) {
			return true
		}
	}
	return false
}

// matches reports whether s is covered by prefix. A prefix ending in "/" covers
// that path and everything beneath it; otherwise the match is exact or on a
// path boundary.
func matches(s, prefix string) bool {
	if prefix == "" {
		return false
	}
	if strings.HasSuffix(prefix, "/") {
		return s == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(s, prefix)
	}
	return s == prefix || strings.HasPrefix(s, prefix+"/")
}
