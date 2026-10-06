package collect_test

import (
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

func errorsOf(issues []collector.Issue) map[string]string {
	out := map[string]string{}
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			out[i.Field] = i.Code
		}
	}
	return out
}

const validConfig = `{
  "base_url": "https://sso.example.com",
  "auth_realm": "master",
  "client_id": "acciew",
  "client_secret": "env:KC_SECRET"
}`

func TestAGoodConfigurationProducesNoErrors(t *testing.T) {
	cfg, issues := collect.Validate([]byte(validConfig))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if cfg.BaseURL != "https://sso.example.com" || cfg.ClientID != "acciew" {
		t.Errorf("parsed = %+v", cfg)
	}
}

// Every problem is addressed by JSON Pointer, so a CLI can point at the field
// rather than at the file.
func TestEachProblemNamesItsField(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		wantField string
		wantCode  string
	}{
		{"no document", ``, "", "keycloak.config.empty"},
		{"not JSON", `{nope`, "", "keycloak.config.malformed"},
		{
			// A typo in a field name would otherwise be ignored and the
			// collector would quietly read the wrong thing.
			name: "an unknown field", config: `{"base_url":"https://a","auth_realm":"m","client_id":"c","client_secret":"env:S","relams":["x"]}`,
			wantField: "", wantCode: "keycloak.config.malformed",
		},
		{"no base url", `{"auth_realm":"m","client_id":"c","client_secret":"env:S"}`,
			"/base_url", "keycloak.base_url.missing"},
		{"a relative base url", `{"base_url":"sso.example.com","auth_realm":"m","client_id":"c","client_secret":"env:S"}`,
			"/base_url", "keycloak.base_url.invalid"},
		{"no auth realm", `{"base_url":"https://a","client_id":"c","client_secret":"env:S"}`,
			"/auth_realm", "keycloak.auth_realm.missing"},
		{"no client id", `{"base_url":"https://a","auth_realm":"m","client_secret":"env:S"}`,
			"/client_id", "keycloak.client_id.missing"},
		{"no secret", `{"base_url":"https://a","auth_realm":"m","client_id":"c"}`,
			"/client_secret", "keycloak.client_secret.missing"},
		{
			// The core logs and hashes this document without knowing what any
			// field means, which is only safe if none of them is a credential.
			name: "a literal secret", config: `{"base_url":"https://a","auth_realm":"m","client_id":"c","client_secret":"hunter2"}`,
			wantField: "/client_secret", wantCode: "keycloak.client_secret.literal",
		},
		{"a blank realm name", `{"base_url":"https://a","auth_realm":"m","client_id":"c","client_secret":"env:S","realms":["ok","  "]}`,
			"/realms/1", "keycloak.realm.empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := collect.Validate([]byte(tt.config))
			got := errorsOf(issues)
			if code, ok := got[tt.wantField]; !ok || code != tt.wantCode {
				t.Errorf("errors = %v, want %s at %q", got, tt.wantCode, tt.wantField)
			}
		})
	}
}

// Plain HTTP puts the client secret on the wire, but a local Keycloak and a
// mesh with TLS termination are both legitimate — so it is a warning, and a
// warning does not block.
func TestPlainHTTPWarnsWithoutBlocking(t *testing.T) {
	_, issues := collect.Validate([]byte(
		`{"base_url":"http://sso.example.com","auth_realm":"m","client_id":"c","client_secret":"env:S"}`))

	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("plain HTTP should not block: %v", got)
	}
	var warned bool
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_WARNING &&
			strings.Contains(i.Message, "plain HTTP") {
			warned = true
		}
	}
	if !warned {
		t.Error("it should still say that credentials go over plain HTTP")
	}
}

func TestLocalhostOverPlainHTTPIsNotWorthWarningAbout(t *testing.T) {
	for _, host := range []string{"http://localhost:8080", "http://127.0.0.1:8080"} {
		_, issues := collect.Validate([]byte(
			`{"base_url":"` + host + `","auth_realm":"m","client_id":"c","client_secret":"env:S"}`))
		for _, i := range issues {
			if i.Code == "keycloak.base_url.insecure" {
				t.Errorf("%s: warned about a local Keycloak", host)
			}
		}
	}
}
