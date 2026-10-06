package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

const mod = "example.com/repo"

func TestParseProfileDeduplicatesMergedBlocks(t *testing.T) {
	// The same block appears twice, as it does when profiles from two test
	// runs are concatenated. It must count once, and the hit wins.
	profile := strings.Join([]string{
		"mode: set",
		"example.com/repo/internal/inventory/graph.go:10.2,12.16 2 0",
		"example.com/repo/internal/inventory/graph.go:10.2,12.16 2 1",
		"example.com/repo/internal/inventory/graph.go:14.2,15.4 1 0",
	}, "\n")

	blocks, err := parseProfile(strings.NewReader(profile))
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2: %+v", len(blocks), blocks)
	}
	got := Evaluate([]Gate{{Path: "internal/inventory", Min: 60}}, blocks, mod)[0]
	if got.Stmts != 3 || got.Covered != 2 {
		t.Fatalf("got %d of %d statements, want 2 of 3", got.Covered, got.Stmts)
	}
	if !got.Pass {
		t.Errorf("66.7%% should pass a 60%% gate")
	}
}

func TestParseProfileRejectsMalformedLines(t *testing.T) {
	for _, bad := range []string{
		"example.com/repo/internal/x/a.go:1.1,2.2 2",
		"nocolonhere 2 1",
		"example.com/repo/internal/x/a.go:1.1,2.2 two 1",
		"example.com/repo/internal/x/a.go:1.1,2.2 2 once",
	} {
		if _, err := parseProfile(strings.NewReader("mode: set\n" + bad + "\n")); err == nil {
			t.Errorf("want an error for %q, got nil", bad)
		}
	}
}

func TestEvaluate(t *testing.T) {
	blocks := []Block{
		{File: mod + "/internal/inventory/graph.go", Span: "1.1,2.2", Stmts: 8, Count: 7},
		{File: mod + "/internal/inventory/sub/x.go", Span: "1.1,2.2", Stmts: 2, Count: 0},
		{File: mod + "/internal/inventoryx/other.go", Span: "1.1,2.2", Stmts: 10, Count: 0},
		{File: mod + "/internal/history/log.go", Span: "1.1,2.2", Stmts: 5, Count: 3},
		{File: mod + "/internal/history/log.go", Span: "3.1,4.2", Stmts: 5, Count: 0},
	}

	tests := []struct {
		name        string
		gate        Gate
		wantPercent float64
		wantPass    bool
		wantEmpty   bool
	}{
		{"subpackages count toward the gate", Gate{"internal/inventory", 80}, 80, true, false},
		{"a package below its minimum fails", Gate{"internal/history", 80}, 50, false, false},
		{"exactly at the minimum passes", Gate{"internal/inventory", 80}, 80, true, false},
		{"a gate matching no statements is empty, not zero", Gate{"internal/export", 80}, 0, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate([]Gate{tt.gate}, blocks, mod)[0]
			if got.Empty != tt.wantEmpty {
				t.Fatalf("Empty = %v, want %v", got.Empty, tt.wantEmpty)
			}
			if !tt.wantEmpty && got.Percent != tt.wantPercent {
				t.Errorf("Percent = %v, want %v", got.Percent, tt.wantPercent)
			}
			if got.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v", got.Pass, tt.wantPass)
			}
		})
	}
}

func TestUnderPrefix(t *testing.T) {
	tests := []struct {
		fileKey, prefix string
		want            bool
	}{
		{"a/b/x.go", "a/b", true},
		{"a/b/c/x.go", "a/b", true},
		{"a/bc/x.go", "a/b", false},
		{"a/x.go", "a/b", false},
	}
	for _, tt := range tests {
		if got := underPrefix(tt.fileKey, tt.prefix); got != tt.want {
			t.Errorf("underPrefix(%q, %q) = %v, want %v", tt.fileKey, tt.prefix, got, tt.want)
		}
	}
}

func TestCheckGateDirsCatchesARenamedPackage(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/inventory/doc.go": &fstest.MapFile{Data: []byte("package inventory\n")},
	}
	if err := checkGateDirs(fsys, []Gate{{"internal/inventory", 80}}); err != nil {
		t.Fatalf("existing directory should pass: %v", err)
	}
	if err := checkGateDirs(fsys, []Gate{{"internal/renamed", 80}}); err == nil {
		t.Error("want an error when a gated directory does not exist, got nil")
	}
}

func TestLoadGatesRejectsMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := dir + "/gates"
		if err := writeGates(p, body); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, bad := range map[string]string{
		"no minimum":          "internal/inventory\n",
		"minimum not numeric": "internal/inventory eighty\n",
		"not a percentage":    "internal/inventory 140\n",
		"no gates at all":     "# only comments\n",
		// A gate carrying the module path would silently match nothing once
		// prefixes became module-relative, so reject it loudly instead.
		"module-qualified path": "example.com/repo/internal/inventory 80\n",
		"absolute path":         "/internal/inventory 80\n",
	} {
		if _, err := loadGates(write(bad)); err == nil {
			t.Errorf("%s: want an error for %q, got nil", name, bad)
		}
	}

	gates, err := loadGates(write("# comment\n\ninternal/inventory 80\n"))
	if err != nil {
		t.Fatalf("loadGates: %v", err)
	}
	if len(gates) != 1 || gates[0].Min != 80 || gates[0].Path != "internal/inventory" {
		t.Fatalf("got %+v, want one gate on internal/inventory at 80", gates)
	}
}

// Generated code must not count toward a gate. A package whose hand-written
// logic is fully covered would otherwise fail because protoc emitted ten
// thousand untested statements beside it.
func TestGeneratedFilesAreExcluded(t *testing.T) {
	blocks := []Block{
		{File: mod + "/api/collector/v1/validate.go", Span: "1.1,2.2", Stmts: 10, Count: 1},
		{File: mod + "/api/collector/v1/collector.pb.go", Span: "1.1,2.2", Stmts: 5000, Count: 0},
		{File: mod + "/api/collector/v1/collector_grpc.pb.go", Span: "1.1,2.2", Stmts: 400, Count: 0},
		{File: mod + "/api/collector/v1/zz_generated.deepcopy.go", Span: "1.1,2.2", Stmts: 100, Count: 0},
		{File: mod + "/api/collector/v1/thing.gen.go", Span: "1.1,2.2", Stmts: 50, Count: 0},
	}
	got := Evaluate([]Gate{{"api/collector/v1", 90}}, blocks, mod)[0]
	if got.Stmts != 10 || got.Covered != 10 {
		t.Fatalf("got %d of %d statements, want 10 of 10; generated files leaked in", got.Covered, got.Stmts)
	}
	if !got.Pass {
		t.Error("a fully covered hand-written file should pass")
	}
}

func TestIsGenerated(t *testing.T) {
	tests := []struct {
		file string
		want bool
	}{
		{"a/b/collector.pb.go", true},
		{"a/b/collector_grpc.pb.go", true},
		{"a/b/zz_generated.deepcopy.go", true},
		{"a/b/api.gen.go", true},
		{"a/b/validate.go", false},
		{"a/b/pbgo.go", false},
		{"a/b/generated_thing.go", false},
	}
	for _, tt := range tests {
		if got := isGenerated(tt.file); got != tt.want {
			t.Errorf("isGenerated(%q) = %v, want %v", tt.file, got, tt.want)
		}
	}
}
