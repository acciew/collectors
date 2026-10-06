// Command covergate enforces per-package line-coverage minimums.
//
// The gates live in .coverage-gates at the repo root, one per line:
//
//	<module-relative-package-path> <minimum-percent>
//
// Paths are relative to the module so that the module path appears in exactly
// one place outside go.mod files (the Taskfile), and renaming the module does
// not mean editing gate definitions.
//
// Gates apply to domain packages only. Coverage on HTTP glue is a number that
// makes people write tests for the wrong thing.
//
// A gate whose packages contain no statements yet passes with a printed
// notice; a gate whose directory does not exist fails, so a rename cannot
// quietly disable a gate.
//
// Usage:
//
//	covergate -profile .cover/coverage.out [-gates .coverage-gates] [-module M] [-root .]
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Gate is one line of .coverage-gates. Path is relative to the module, so
// "internal/inventory" rather than the full import path.
type Gate struct {
	Path string
	Min  float64
}

// Block is one statement block from a coverage profile.
type Block struct {
	File  string // import path + "/" + base name, as Go writes it
	Span  string // "start.col,end.col"
	Stmts int
	Count int
}

// Result is the outcome of evaluating one gate.
type Result struct {
	Gate    Gate
	Stmts   int
	Covered int
	Percent float64
	Empty   bool
	Pass    bool
}

// errBelowMinimum is returned by run when gates fail, as opposed to when the
// tool itself could not do its job.
var errBelowMinimum = errors.New("below minimum")

func main() {
	profile := flag.String("profile", ".cover/coverage.out", "merged coverage profile")
	gatesPath := flag.String("gates", ".coverage-gates", "gate definitions")
	module := flag.String("module", "", "module path the gated packages live in (required)")
	root := flag.String("root", ".", "repo root, used to confirm gated directories exist")
	flag.Parse()

	if *module == "" {
		fmt.Fprintln(os.Stderr, "covergate: -module is required")
		os.Exit(2)
	}

	err := run(*profile, *gatesPath, *module, *root)
	switch {
	case err == nil:
		return
	case errors.Is(err, errBelowMinimum):
		fmt.Fprintf(os.Stderr, "covergate: %v\n", err)
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "covergate: %v\n", err)
		os.Exit(2)
	}
}

func run(profile, gatesPath, module, root string) error {
	gates, err := loadGates(gatesPath)
	if err != nil {
		return err
	}
	if err := checkGateDirs(os.DirFS(root), gates); err != nil {
		return err
	}

	blocks, err := readProfile(profile)
	if err != nil {
		return err
	}

	failed := 0
	for _, r := range Evaluate(gates, blocks, module) {
		switch {
		case r.Empty:
			fmt.Printf("  --  %-40s no statements yet\n", r.Gate.Path)
		case r.Pass:
			fmt.Printf("  ok  %-40s %.1f%% (min %.0f%%)\n", r.Gate.Path, r.Percent, r.Gate.Min)
		default:
			failed++
			fmt.Printf("FAIL  %-40s %.1f%% (min %.0f%%, %d of %d statements)\n",
				r.Gate.Path, r.Percent, r.Gate.Min, r.Covered, r.Stmts)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d gate(s) %w", failed, errBelowMinimum)
	}
	fmt.Printf("covergate: ok (%d gates)\n", len(gates))
	return nil
}

func readProfile(path string) ([]Block, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is a command-line flag of a build tool, not user input
	if err != nil {
		return nil, fmt.Errorf("opening coverage profile: %w (run `task test` first)", err)
	}
	defer func() { _ = f.Close() }()
	return parseProfile(f)
}

func loadGates(path string) ([]Gate, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is a command-line flag of a build tool, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var gates []Gate
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want `<module-relative-path> <min-percent>`, got %q", path, line, text)
		}
		if strings.HasPrefix(fields[0], "/") || strings.Contains(fields[0], ".") {
			return nil, fmt.Errorf("%s:%d: %q looks like a full import path; gates are relative to the module, e.g. internal/inventory", path, line, fields[0])
		}
		minimum, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad minimum %q", path, line, fields[1])
		}
		if minimum < 0 || minimum > 100 {
			return nil, fmt.Errorf("%s:%d: minimum %v is not a percentage", path, line, minimum)
		}
		gates = append(gates, Gate{Path: fields[0], Min: minimum})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(gates) == 0 {
		return nil, fmt.Errorf("%s defines no gates", path)
	}
	return gates, nil
}

// parseProfile reads a Go coverage profile, deduplicating blocks so that
// profiles merged from several test runs are counted once.
func parseProfile(r io.Reader) ([]Block, error) {
	seen := map[string]Block{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "mode:") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("coverage profile line %d: want 3 fields, got %q", line, text)
		}
		colon := strings.LastIndex(fields[0], ":")
		if colon < 0 {
			return nil, fmt.Errorf("coverage profile line %d: no file:span in %q", line, fields[0])
		}
		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("coverage profile line %d: bad statement count %q", line, fields[1])
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("coverage profile line %d: bad hit count %q", line, fields[2])
		}
		b := Block{File: fields[0][:colon], Span: fields[0][colon+1:], Stmts: stmts, Count: count}
		key := b.File + ":" + b.Span
		if prev, ok := seen[key]; !ok || b.Count > prev.Count {
			seen[key] = b
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]Block, 0, len(seen))
	for _, b := range seen {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Span < out[j].Span
	})
	return out, nil
}

// Evaluate scores every gate against the profile blocks. Coverage profiles key
// blocks by import path, so the module path is joined onto each gate here.
func Evaluate(gates []Gate, blocks []Block, module string) []Result {
	results := make([]Result, 0, len(gates))
	for _, g := range gates {
		prefix := module + "/" + g.Path
		var stmts, covered int
		for _, b := range blocks {
			if !underPrefix(b.File, prefix) || isGenerated(b.File) {
				continue
			}
			stmts += b.Stmts
			if b.Count > 0 {
				covered += b.Stmts
			}
		}
		r := Result{Gate: g, Stmts: stmts, Covered: covered}
		if stmts == 0 {
			r.Empty, r.Pass = true, true
		} else {
			r.Percent = 100 * float64(covered) / float64(stmts)
			r.Pass = r.Percent+1e-9 >= g.Min
		}
		results = append(results, r)
	}
	return results
}

// generatedSuffixes are the file-name conventions Go code generators use.
// Coverage on generated code measures the generator, not us: a package whose
// hand-written logic is fully covered would fail its gate because protoc
// emitted several thousand untested statements beside it.
var generatedSuffixes = []string{
	".pb.go",  // protoc-gen-go, protoc-gen-go-grpc
	".gen.go", // oapi-codegen and friends
}

// isGenerated reports whether a coverage profile file key names generated code.
func isGenerated(fileKey string) bool {
	base := fileKey
	if i := strings.LastIndex(fileKey, "/"); i >= 0 {
		base = fileKey[i+1:]
	}
	if strings.HasPrefix(base, "zz_generated.") {
		return true
	}
	for _, suffix := range generatedSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// underPrefix reports whether a profile file key belongs to a gated package
// tree. The key is an import path plus a file name, so the prefix must land on
// a path boundary: internal/inventory must not match internal/inventoryx.
func underPrefix(fileKey, prefix string) bool {
	dir := fileKey
	if i := strings.LastIndex(fileKey, "/"); i >= 0 {
		dir = fileKey[:i]
	}
	return dir == prefix || strings.HasPrefix(dir, prefix+"/")
}

// checkGateDirs fails if a gate points at a directory that does not exist, so
// that renaming a package cannot quietly switch its gate off.
func checkGateDirs(fsys fs.FS, gates []Gate) error {
	for _, g := range gates {
		info, err := fs.Stat(fsys, g.Path)
		if err != nil {
			return fmt.Errorf("gate %q: directory does not exist", g.Path)
		}
		if !info.IsDir() {
			return fmt.Errorf("gate %q: not a directory", g.Path)
		}
	}
	return nil
}
