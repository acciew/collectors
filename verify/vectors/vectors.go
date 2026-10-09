// Package vectors holds the test vectors of the evidence format: logs and packs,
// good and altered in one named way each, with what a verifier must say of each.
//
// They are committed files, under cases/, reviewed in the diff like code. A case is
// a folder with a case.json and the files it is made of; a case that is a change
// to another names it as its base and holds only the files that differ. All
// returns every case with its files complete, so that a verifier written in any
// language, or the service that writes the formats, can run all of them and
// compare what it says with what is expected here.
//
// The vectors are not generated when they are used. The test that makes them
// compares what it makes with what is committed and fails if they differ; run with
// -update it writes what it made to candidates/, for someone to read the
// difference and move what is intended into cases/.
package vectors

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed all:cases
var embedded embed.FS

// Kind says what a case is a case of, and so how its files are checked.
type Kind string

const (
	// Collection is a collection log "x.jsonl" and its anchor "x.head".
	Collection Kind = "collection"
	// Workflow is a workflow log "x.jsonl" and its anchor "x.head".
	Workflow Kind = "workflow"
	// Pack is an evidence pack: its files, by path.
	Pack Kind = "pack"
)

// LogName is the name of the log in a Collection or Workflow case.
const LogName = "x"

// Case is one vector.
type Case struct {
	// Name is the case's path under cases/, such as "collection/tail-cut".
	Name string
	Kind Kind
	// Files are the files of the case by path, relative to the folder they are checked in.
	Files map[string][]byte

	// Verified says whether a verifier must find nothing wrong.
	Verified bool
	// Reason is, for a log that does not verify, the reason code a verifier must name.
	Reason string
	// Findings are, for a pack that does not verify, what a verifier must find, each as
	// "reason path", in order.
	Findings []string
	// Error is, for a pack that cannot be checked, the reason code of the error.
	Error string
	// Digests are, for a log, the digests of its entries, which a verifier must compute
	// from the content, whether or not the log verifies as a whole.
	Digests []string
	// Chains are, for a log, the chain values of its entries, which a verifier must
	// compute from each entry's sequence, time, digest and previous, and not read from
	// its chain member, whether or not the log verifies as a whole.
	Chains []string
	// Note says in a sentence what the case is for.
	Note string
}

// spec is a case as it is committed: case.json.
type spec struct {
	Kind     Kind     `json:"kind"`
	Base     string   `json:"base,omitempty"`
	Delete   []string `json:"delete,omitempty"`
	Verified bool     `json:"verified"`
	Reason   string   `json:"reason,omitempty"`
	Findings []string `json:"findings,omitempty"`
	Error    string   `json:"error,omitempty"`
	Digests  []string `json:"digests,omitempty"`
	Chains   []string `json:"chains,omitempty"`
	Note     string   `json:"note"`
}

// All returns every case, in order of name. It panics if the committed cases are
// not well formed, which a test of this package would have said first.
func All() []Case {
	cases, err := load(embedded, "cases")
	if err != nil {
		panic("vectors: " + err.Error())
	}
	return cases
}

func load(fsys fs.FS, root string) ([]Case, error) {
	specs := map[string]spec{}
	own := map[string]map[string][]byte{}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path.Base(p) != "case.json" {
			return nil
		}
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		var s spec
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		dir := path.Dir(p)
		name := strings.TrimPrefix(dir, root+"/")
		files := map[string][]byte{}
		filesRoot := path.Join(dir, "files")
		err = fs.WalkDir(fsys, filesRoot, func(fp string, fd fs.DirEntry, err error) error {
			if err != nil {
				return nil // a case may have no files of its own
			}
			if fd.IsDir() {
				return nil
			}
			body, err := fs.ReadFile(fsys, fp)
			if err != nil {
				return err
			}
			files[strings.TrimPrefix(fp, filesRoot+"/")] = body
			return nil
		})
		if err != nil {
			return err
		}
		specs[name], own[name] = s, files
		return nil
	})
	if err != nil {
		return nil, err
	}

	var resolve func(name string, depth int) (map[string][]byte, error)
	resolve = func(name string, depth int) (map[string][]byte, error) {
		s, ok := specs[name]
		if !ok {
			return nil, fmt.Errorf("%s: no such case", name)
		}
		if depth > 8 {
			return nil, fmt.Errorf("%s: bases nested too deeply", name)
		}
		files := map[string][]byte{}
		if s.Base != "" {
			base, err := resolve(s.Base, depth+1)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			for k, v := range base {
				files[k] = v
			}
		}
		for _, d := range s.Delete {
			delete(files, d)
		}
		for k, v := range own[name] {
			files[k] = v
		}
		return files, nil
	}

	names := make([]string, 0, len(specs))
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Case, 0, len(names))
	for _, name := range names {
		s := specs[name]
		files, err := resolve(name, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, Case{Name: name, Kind: s.Kind, Files: files, Verified: s.Verified, Reason: s.Reason,
			Findings: s.Findings, Error: s.Error, Digests: s.Digests, Chains: s.Chains, Note: s.Note})
	}
	return out, nil
}
