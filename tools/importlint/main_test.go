package main

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

const rootModule = "example.com/repo"

func testPolicy() Policy {
	return Policy{
		Module: rootModule,
		Rules: []Rule{
			{
				Name:     "core-must-not-import-plugins",
				Why:      "because",
				From:     []string{"internal/", "cmd/", "test/"},
				DenyDirs: []string{"plugins/"},
			},
			{
				Name: "core-must-not-import-source-clients",
				Why:  "because",
				From: []string{"internal/", "cmd/", "test/"},
				Deny: []string{"github.com/aws/aws-sdk-go"},
			},
			{
				Name:     "core-must-not-import-the-sdk",
				Why:      "because",
				From:     []string{"internal/", "cmd/"},
				DenyDirs: []string{"sdk/"},
			},
			{
				Name:   "transport-stays-in-pluginhost",
				Why:    "because",
				From:   []string{"internal/", "cmd/"},
				Except: []string{"internal/pluginhost/"},
				Deny:   []string{"google.golang.org/grpc"},
			},
			{
				Name:     "plugins-must-not-import-core",
				Why:      "because",
				From:     []string{"plugins/"},
				DenyDirs: []string{"internal/"},
			},
			{
				Name:     "sdk-must-not-import-core-or-plugins",
				Why:      "because",
				From:     []string{"sdk/"},
				DenyDirs: []string{"internal/", "plugins/"},
			},
			{Name: "api-standalone", Why: "because", From: []string{"api/"}, DenyDirs: []string{"internal/"}},
			{Name: "tools-standalone", Why: "because", From: []string{"tools/"}, DenyDirs: []string{"internal/"}},
		},
	}
}

func file(imports ...string) string {
	src := "package p\n\nimport (\n"
	for _, i := range imports {
		src += "\t\"" + i + "\"\n"
	}
	return src + ")\n"
}

func gomod(path string) string { return "module " + path + "\n\ngo 1.26.0\n" }

// baseTree is a workspace whose module paths match its directories.
func baseTree() fstest.MapFS {
	return fstest.MapFS{
		"go.mod":                  &fstest.MapFile{Data: []byte(gomod(rootModule))},
		"api/go.mod":              &fstest.MapFile{Data: []byte(gomod(rootModule + "/api"))},
		"sdk/go/go.mod":           &fstest.MapFile{Data: []byte(gomod(rootModule + "/sdk/go"))},
		"plugins/keycloak/go.mod": &fstest.MapFile{Data: []byte(gomod(rootModule + "/plugins/keycloak"))},
		"tools/go.mod":            &fstest.MapFile{Data: []byte(gomod(rootModule + "/tools"))},
	}
}

func withFiles(files map[string]string) fstest.MapFS {
	fsys := baseTree()
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func check(t *testing.T, files map[string]string) []Violation {
	t.Helper()
	got, err := Check(withFiles(files), testPolicy())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return got
}

func wantRules(t *testing.T, got []Violation, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d violations %+v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i].Rule != want[i] {
			t.Errorf("violation %d: rule %q, want %q (%+v)", i, got[i].Rule, want[i], got[i])
		}
	}
}

func TestCleanTreePasses(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/inventory/x.go": file("fmt", rootModule+"/api"),
		"plugins/keycloak/x.go":   file(rootModule+"/sdk/go", rootModule+"/api"),
		"sdk/go/x.go":             file(rootModule + "/api"),
		"api/x.go":                file("google.golang.org/protobuf/proto"),
		"tools/x/x.go":            file("go/parser"),
	}))
}

func TestCoreImportingAPluginIsCaught(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/inventory/x.go": file(rootModule + "/plugins/keycloak"),
	}), "core-must-not-import-plugins")
}

// Bypass (b) from the review: plugins are separate modules, so a plugin's
// module path is free. A path-prefix rule cannot see through a rename; a rule
// that resolves imports back to repository directories can.
func TestRenamedPluginModuleIsStillAPlugin(t *testing.T) {
	fsys := withFiles(map[string]string{
		"cmd/cli/main.go": file("github.com/someone/keycloak-collector/client"),
	})
	fsys["plugins/keycloak/go.mod"] = &fstest.MapFile{
		Data: []byte(gomod("github.com/someone/keycloak-collector")),
	}
	got, err := Check(fsys, testPolicy())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	wantRules(t, got, "core-must-not-import-plugins")
}

// Bypass (a) from the review: core -> sdk -> a source client. Closing the
// core->sdk edge and the sdk->source-client edge kills the laundering path.
func TestCoreMayNotLaunderThroughTheSDK(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/inventory/x.go": file(rootModule + "/sdk/go/kcutil"),
	}), "core-must-not-import-the-sdk")
}

// Bypass (d) from the review: the transport must not escape pluginhost.
func TestTransportIsConfinedToPluginhost(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/pluginhost/host.go": file("google.golang.org/grpc"),
		"internal/inventory/x.go":     file("google.golang.org/grpc"),
	}), "transport-stays-in-pluginhost")
}

// Bypass (c) from the review: rules are a from-allowlist, so a new top-level
// directory was governed by nothing at all.
func TestADirectoryGovernedByNoRuleIsAViolation(t *testing.T) {
	got := check(t, map[string]string{
		"pkg/helpers/x.go": file(rootModule + "/plugins/keycloak"),
	})
	wantRules(t, got, ruleEveryDirectoryGoverned)
	if got[0].File != "pkg/helpers" {
		t.Errorf("File = %q, want the directory %q", got[0].File, "pkg/helpers")
	}
}

func TestTestDirectoryIsGovernedByTheHeadlineRule(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"test/contract/x_test.go": file(rootModule + "/plugins/keycloak"),
	}), "core-must-not-import-plugins")
}

func TestPluginsMayNotImportCore(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"plugins/keycloak/x.go": file(rootModule + "/internal/inventory"),
	}), "plugins-must-not-import-core")
}

func TestSourceClientInCoreIsCaught(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/inventory/x.go": file("github.com/aws/aws-sdk-go/service/iam"),
	}), "core-must-not-import-source-clients")
}

func TestPrefixMustLandOnAPathBoundary(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/inventory/x.go": file("github.com/aws/aws-sdk-go-v2/service/iam"),
	}))
}

func TestSkippedTrees(t *testing.T) {
	wantRules(t, check(t, map[string]string{
		"internal/inventory/vendor/x/x.go": file(rootModule + "/plugins/keycloak"),
		"internal/inventory/testdata/x.go": file(rootModule + "/plugins/keycloak"),
		"internal/inventory/notes.md":      "import " + rootModule + "/plugins/keycloak",
	}))
}

func TestEveryDeniedImportInAFileIsReported(t *testing.T) {
	got := check(t, map[string]string{
		"internal/inventory/x.go": file(
			rootModule+"/plugins/keycloak",
			"github.com/aws/aws-sdk-go/service/iam",
		),
	})
	if len(got) != 2 {
		t.Fatalf("got %d violations %+v, want 2", len(got), got)
	}
}

func TestCheckRejectsUnparseableGo(t *testing.T) {
	if _, err := Check(withFiles(map[string]string{
		"internal/inventory/x.go": "not go at all",
	}), testPolicy()); err == nil {
		t.Fatal("want an error for a file that does not parse, got nil")
	}
}

func TestCheckRejectsAPolicyThatDisagreesWithTheRootGoMod(t *testing.T) {
	p := testPolicy()
	p.Module = "example.com/somethingelse"
	if _, err := Check(baseTree(), p); err == nil {
		t.Fatal("want an error when the policy module does not match go.mod, got nil")
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		s, prefix string
		want      bool
	}{
		{"a/b/c", "a/", true},
		{"a", "a/", true},
		{"ab/c", "a/", false},
		{"a/b", "a/b", true},
		{"a/b/c", "a/b", true},
		{"a/bc", "a/b", false},
		{"anything", "", false},
	}
	for _, tt := range tests {
		if got := matches(tt.s, tt.prefix); got != tt.want {
			t.Errorf("matches(%q, %q) = %v, want %v", tt.s, tt.prefix, got, tt.want)
		}
	}
}

func TestModuleDirResolvesTheLongestMatchingModule(t *testing.T) {
	mods := map[string]string{
		rootModule:             "",
		rootModule + "/sdk/go": "sdk/go",
	}
	tests := []struct{ importPath, want string }{
		{rootModule + "/internal/inventory", "internal/inventory"},
		{rootModule + "/sdk/go", "sdk/go"},
		{rootModule + "/sdk/go/kcutil", "sdk/go/kcutil"},
		{"github.com/elsewhere/thing", ""},
	}
	for _, tt := range tests {
		if got := repoDirFor(mods, tt.importPath); got != tt.want {
			t.Errorf("repoDirFor(%q) = %q, want %q", tt.importPath, got, tt.want)
		}
	}
}

func TestLoadPolicyRejectsIncompleteRules(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := dir + "/policy.json"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"no why":        `{"module":"m","rules":[{"name":"r","from":["internal/"],"deny":["x"]}]}`,
		"no name":       `{"module":"m","rules":[{"why":"w","from":["internal/"],"deny":["x"]}]}`,
		"no from":       `{"module":"m","rules":[{"name":"r","why":"w","deny":["x"]}]}`,
		"nothing deny":  `{"module":"m","rules":[{"name":"r","why":"w","from":["internal/"]}]}`,
		"no module":     `{"rules":[{"name":"r","why":"w","from":["internal/"],"deny":["x"]}]}`,
		"unknown field": `{"module":"m","rules":[{"name":"r","why":"w","from":["a/"],"deny":["x"],"nope":1}]}`,
	} {
		if _, err := loadPolicy(write(body)); err == nil {
			t.Errorf("%s: want an error, got nil", name)
		}
	}

	good := `{"module":"m","rules":[{"name":"r","why":"w","from":["internal/"],"denyDirs":["plugins/"]}]}`
	p, err := loadPolicy(write(good))
	if err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}
	if len(p.Rules) != 1 || !strings.Contains(p.Rules[0].DenyDirs[0], "plugins") {
		t.Fatalf("got %+v", p)
	}
}
