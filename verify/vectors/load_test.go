package vectors

import (
	"strings"
	"testing"
	"testing/fstest"
)

func memory(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func TestACaseThatIsAChangeToAnotherHoldsOnlyWhatDiffers(t *testing.T) {
	cases, err := load(memory(map[string]string{
		"cases/a/case.json":         `{"kind":"pack","verified":true,"note":"a"}`,
		"cases/a/files/one":         "1",
		"cases/a/files/two":         "2",
		"cases/a/files/dir/three":   "3",
		"cases/b/case.json":         `{"kind":"pack","base":"a","delete":["one"],"verified":false,"findings":["x y"],"note":"b"}`,
		"cases/b/files/two":         "two",
		"cases/b/files/dir/four":    "4",
		"cases/c/case.json":         `{"kind":"pack","base":"b","verified":true,"note":"c"}`,
		"cases/nested/d/case.json":  `{"kind":"collection","verified":true,"note":"d"}`,
		"cases/nested/d/files/x.jl": "d",
	}), "cases")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Case{}
	var names []string
	for _, c := range cases {
		byName[c.Name] = c
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "a,b,c,nested/d" {
		t.Fatalf("names = %v", names)
	}
	b := byName["b"]
	if len(b.Files) != 3 || string(b.Files["two"]) != "two" || string(b.Files["dir/three"]) != "3" || string(b.Files["dir/four"]) != "4" || b.Files["one"] != nil {
		t.Errorf("b = %v", b.Files)
	}
	if c := byName["c"]; len(c.Files) != 3 || !c.Verified {
		t.Errorf("c = %v", c.Files)
	}
	if byName["nested/d"].Kind != Collection {
		t.Errorf("d = %+v", byName["nested/d"])
	}
}

func TestACaseThatCannotBeReadIsAnErrorAndNeverAGuess(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"not JSON":       {"cases/a/case.json": `{`},
		"a missing base": {"cases/a/case.json": `{"kind":"pack","base":"nowhere"}`},
		"a base cycle":   {"cases/a/case.json": `{"kind":"pack","base":"b"}`, "cases/b/case.json": `{"kind":"pack","base":"a"}`},
	} {
		if _, err := load(memory(files), "cases"); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestAllPanicsOnlyOnCommittedDataThatIsNotWellFormed(t *testing.T) {
	if len(All()) == 0 {
		t.Error("no vectors")
	}
}
