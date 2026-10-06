package collect

import (
	"encoding/json"
	"net/url"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// Config is this collector's configuration document.
//
// The core never parses it — it stores, hashes and logs it without knowing
// what any field means — which is only safe because the secret is a reference
// rather than a value.
type Config struct {
	// BaseURL of the Keycloak, e.g. https://sso.example.com
	BaseURL string `json:"base_url"`
	// AuthRealm is the realm the service account authenticates against. Often
	// master, and not necessarily a realm being collected.
	AuthRealm string `json:"auth_realm"`
	// ClientID of a confidential client with a service account.
	ClientID string `json:"client_id"`
	// ClientSecret is a reference, never a literal: "env:KC_SECRET" or
	// "file:/run/secrets/kc".
	ClientSecret string `json:"client_secret"`
	// Realms to collect. Empty means every realm the credentials reach.
	Realms []string `json:"realms"`
	// PageSize for paged endpoints. Zero means the client's default.
	PageSize int `json:"page_size"`
}

// Validate checks a configuration document without contacting Keycloak.
//
// Every issue is addressed by JSON Pointer so a CLI can point at the field
// rather than at the file. The empty pointer addresses the document itself,
// which is where a parse failure belongs: there is no field to blame yet.
func Validate(raw []byte) (Config, []collector.Issue) {
	var cfg Config
	if len(raw) == 0 {
		return cfg, []collector.Issue{issue("", "keycloak.config.empty",
			"a configuration document is required")}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		// Unknown fields are worth rejecting rather than ignoring: a typo in
		// a field name would otherwise silently collect the wrong thing.
		return cfg, []collector.Issue{issue("", "keycloak.config.malformed",
			"the configuration is not valid: "+err.Error())}
	}

	var issues []collector.Issue
	if cfg.BaseURL == "" {
		issues = append(issues, issue("/base_url", "keycloak.base_url.missing",
			"the Keycloak base URL is required, e.g. https://sso.example.com"))
	} else {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			issues = append(issues, issue("/base_url", "keycloak.base_url.invalid",
				"the base URL must be absolute, e.g. https://sso.example.com"))
		} else if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			// Client credentials over plain HTTP put a secret on the wire.
			// A warning rather than an error, because a local Keycloak and a
			// service mesh with TLS termination are both legitimate.
			issues = append(issues, warning("/base_url", "keycloak.base_url.insecure",
				"this sends client credentials over plain HTTP"))
		}
	}
	if cfg.AuthRealm == "" {
		issues = append(issues, issue("/auth_realm", "keycloak.auth_realm.missing",
			"the realm to authenticate against is required, usually master"))
	}
	if cfg.ClientID == "" {
		issues = append(issues, issue("/client_id", "keycloak.client_id.missing",
			"a confidential client with a service account is required"))
	}
	if cfg.ClientSecret == "" {
		issues = append(issues, issue("/client_secret", "keycloak.client_secret.missing",
			"a client secret reference is required"))
	} else if _, err := collector.ParseSecret(cfg.ClientSecret); err != nil {
		issues = append(issues, issue("/client_secret", "keycloak.client_secret.literal",
			"the secret must be a reference such as env:KC_SECRET or "+
				"file:/run/secrets/kc, not the value itself"))
	}
	for i, r := range cfg.Realms {
		if strings.TrimSpace(r) == "" {
			issues = append(issues, issue(pointer("/realms/", i), "keycloak.realm.empty",
				"a realm name cannot be blank"))
		}
	}
	return cfg, issues
}

func issue(field, code, message string) collector.Issue {
	return collector.Issue{
		Field: field, Severity: collectorv1.Severity_SEVERITY_ERROR,
		Code: code, Message: message,
	}
}

func warning(field, code, message string) collector.Issue {
	return collector.Issue{
		Field: field, Severity: collectorv1.Severity_SEVERITY_WARNING,
		Code: code, Message: message,
	}
}

func pointer(prefix string, i int) string {
	digits := ""
	if i == 0 {
		digits = "0"
	}
	for n := i; n > 0; n /= 10 {
		digits = string(rune('0'+n%10)) + digits
	}
	return prefix + digits
}
