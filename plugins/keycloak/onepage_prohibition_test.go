package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Client.OnePage bounds a paged read to a single page. That is right for a
// pre-flight check, which asks whether a read is allowed, and catastrophic
// anywhere else: a collection that ran on such a client would return one page
// of a realm and report the scope collected, which is a population that reads
// as whole and is not.
//
// The type system cannot stop it — a bounded client is a *Client like any
// other — so the constraint is mechanical instead. A comment saying "only the
// check" is advice. This is the decision.
func TestOnlyThePreFlightCheckBoundsAReadToOnePage(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	// The plugin's entry point, and only it. A basename would let any
	// internal/*/main.go through.
	allowed := filepath.Join(root, "main.go")

	fset := token.NewFileSet()
	var found []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir(), !strings.HasSuffix(path, ".go"), strings.HasSuffix(path, "_test.go"):
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "OnePage" {
				return true
			}
			if path != allowed {
				found = append(found, fset.Position(sel.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range found {
		t.Errorf("OnePage used outside %s, at %s: a collection that runs on a bounded client "+
			"returns one page of a realm and calls the scope collected",
			filepath.Base(allowed), at)
	}
}
