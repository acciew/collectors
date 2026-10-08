package secrets_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func spellings(dir, name string, n int) []string {
	var out []string
	for i := range n {
		switch i % 4 {
		case 0:
			out = append(out, dir+strings.Repeat("/.", i/4+1)+"/"+name)
		case 1:
			out = append(out, dir+strings.Repeat("/", i/4+2)+name)
		case 2:
			out = append(out, dir+"/sub"+strings.Repeat("/../sub", i/4)+"/../"+name)
		default:
			out = append(out, dir+"/"+strings.Repeat("x/../", i/4+1)+name)
		}
	}
	return out
}

func configOf(refs []string) []byte {
	var parts []string
	for i, r := range refs {
		parts = append(parts, fmt.Sprintf(`"f%d":%q`, i, "file:"+r))
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

// One 256 KiB file spelled five thousand ways used to be written five thousand times.
func TestManyReferencesToOneFileAreRefusedPastALimitAndCostOneFileBelowIt(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0o700)
	_ = os.MkdirAll(filepath.Join(dir, "x"), 0o700)
	if err := os.WriteFile(filepath.Join(dir, "kc"), make([]byte, 256<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	p := policy(t, nil)

	few := spellings(dir, "kc", 20)
	b, err := p.Bind(configOf(few))
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(b.Dir())
	if len(entries) != 1 {
		t.Errorf("%d secret files for 20 spellings of one file: want one, read and written once", len(entries))
	}
	_ = b.Close()

	_, err = p.Bind(configOf(spellings(dir, "kc", 200)))
	if err == nil || !strings.Contains(err.Error(), "references") || !strings.Contains(err.Error(), "32") {
		t.Errorf("200 spellings: err = %v, want a refusal that says how many references a job may have", err)
	}
	if entries, _ := os.ReadDir(p.Dir); len(entries) != 0 {
		t.Errorf("the refused job left %v behind", entries)
	}
}

func TestTheNumberOfDistinctVariablesIsLimitedToo(t *testing.T) {
	vars := map[string]string{}
	var parts []string
	for i := range 40 {
		vars[fmt.Sprintf("V%d", i)] = "value-number-" + fmt.Sprint(i)
		parts = append(parts, fmt.Sprintf(`"k%d":"env:V%d"`, i, i))
	}
	p := policy(t, vars)
	if _, err := p.Bind([]byte("{" + strings.Join(parts, ",") + "}")); err == nil || !strings.Contains(err.Error(), "references") {
		t.Errorf("err = %v", err)
	}
	// And thirty-two is fine.
	if b, err := p.Bind([]byte("{" + strings.Join(parts[:32], ",") + "}")); err != nil {
		t.Errorf("32 references: %v", err)
	} else {
		_ = b.Close()
	}
}

func TestWhatAJobAsksToBeWrittenIsLimitedInTotal(t *testing.T) {
	dir := t.TempDir()
	var refs []string
	for i := range 5 {
		path := filepath.Join(dir, fmt.Sprintf("big%d", i))
		if err := os.WriteFile(path, make([]byte, 900<<10), 0o600); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, path)
	}
	p := policy(t, nil)
	if _, err := p.Bind(configOf(refs)); err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Errorf("4.5 MiB of secrets: err = %v", err)
	}
	if b, err := p.Bind(configOf(refs[:4])); err != nil {
		t.Errorf("3.5 MiB of secrets: %v", err)
	} else {
		_ = b.Close()
	}
}
