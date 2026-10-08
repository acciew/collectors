// Package collect turns a Microsoft Entra tenant into the contract's records.
package collect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Config is this collector's configuration document.
//
// The core never parses it: it stores, hashes and logs it without knowing what
// any field means, which is only safe because both credentials are references
// and never values.
type Config struct {
	// TenantID is a tenant GUID or a verified domain name.
	TenantID string `json:"tenant_id"`
	// ClientID is the application registration's application (client) ID.
	ClientID string `json:"client_id"`
	// ClientSecret and Certificate are references ("env:NAME", "file:/path");
	// exactly one is given. A certificate reference points at a PEM holding the
	// private key and the certificate.
	ClientSecret string `json:"client_secret"`
	Certificate  string `json:"certificate"`
	// CloudName is global, usgov, usgov-dod or china. Empty means global.
	CloudName string `json:"cloud"`
	// Collect switches optional parts on and off.
	Collect Flags `json:"collect"`
	// PageSize for paged reads. Zero means the collector's own default.
	PageSize int `json:"page_size"`
}

// Flags are the optional parts of a collection. A flag left out keeps its
// default, so naming one never changes the others.
type Flags struct {
	ServicePrincipals   *bool `json:"service_principals"`
	AppRoles            *bool `json:"app_roles"`
	PIM                 *bool `json:"pim"`
	AdministrativeUnits *bool `json:"administrative_units"`
	OAuth2Grants        *bool `json:"oauth2_grants"`
}

// Wanted is Flags with the defaults applied.
type Wanted struct {
	ServicePrincipals, AppRoles, PIM, AdministrativeUnits, OAuth2Grants bool
}

// Wants applies the defaults: service principals, app roles and PIM on;
// administrative units and OAuth2 grants off. OAuth2 grants are off because
// reading them needs Directory.Read.All, far broader than anything else here.
func (c Config) Wants() Wanted {
	on := func(f *bool, def bool) bool {
		if f == nil {
			return def
		}
		return *f
	}
	return Wanted{
		ServicePrincipals:   on(c.Collect.ServicePrincipals, true),
		AppRoles:            on(c.Collect.AppRoles, true),
		PIM:                 on(c.Collect.PIM, true),
		AdministrativeUnits: on(c.Collect.AdministrativeUnits, false),
		OAuth2Grants:        on(c.Collect.OAuth2Grants, false),
	}
}

// Cloud is the configured cloud, global when none is named.
func (c Config) Cloud() graph.Cloud {
	if c.CloudName == "" {
		return graph.Global
	}
	return graph.Cloud(c.CloudName)
}

// The page sizes a configuration may ask for. 999 is the most Graph returns for a
// user or group page. 100 is the least, so that the cap on pages a part may read
// (100,000, to stop a loop) is ten million objects and no tenant
// reaches it; at a page size of 1 a large tenant would.
const (
	minPageSize = 100
	maxPageSize = 999
)

var (
	guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// A verified domain: labels of letters, digits and hyphens, with a dot.
	domainPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
)

// Validate checks a configuration document without contacting Microsoft.
//
// Every issue is addressed by JSON Pointer so a CLI can point at the field
// rather than at the file. The empty pointer addresses the document itself.
func Validate(raw []byte) (Config, []collector.Issue) {
	var cfg Config
	if len(raw) == 0 {
		return cfg, []collector.Issue{issue("", "entra.config.empty", "a configuration document is required")}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// A typo in a field name would otherwise silently collect the wrong thing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, []collector.Issue{issue("", "entra.config.malformed",
			"the configuration is not valid: "+err.Error())}
	}

	var issues []collector.Issue
	switch {
	case cfg.TenantID == "":
		issues = append(issues, issue("/tenant_id", "entra.tenant_id.missing",
			"the tenant is required: its ID, or a verified domain such as example.onmicrosoft.com"))
	case !guidPattern.MatchString(cfg.TenantID) && !domainPattern.MatchString(cfg.TenantID):
		issues = append(issues, issue("/tenant_id", "entra.tenant_id.invalid",
			"the tenant must be a GUID or a verified domain name; common, organizations and "+
				"consumers are for interactive sign-in and an application token is not issued for them"))
	}
	switch {
	case cfg.ClientID == "":
		issues = append(issues, issue("/client_id", "entra.client_id.missing",
			"the application (client) ID of the app registration is required"))
	case !guidPattern.MatchString(cfg.ClientID):
		issues = append(issues, issue("/client_id", "entra.client_id.invalid",
			"the application (client) ID is a GUID"))
	}

	switch {
	case cfg.ClientSecret == "" && cfg.Certificate == "":
		issues = append(issues, issue("/client_secret", "entra.credential.missing",
			"a client secret or a certificate is required, as a reference"))
	case cfg.ClientSecret != "" && cfg.Certificate != "":
		issues = append(issues, issue("/certificate", "entra.credential.both",
			"give a client secret or a certificate, not both"))
	}
	if cfg.ClientSecret != "" {
		if _, err := collector.ParseSecret(cfg.ClientSecret); err != nil {
			issues = append(issues, issue("/client_secret", "entra.client_secret.literal",
				"the secret must be a reference such as env:ENTRA_SECRET or "+
					"file:/run/secrets/entra, not the value itself"))
		}
	}
	if cfg.Certificate != "" {
		if _, err := collector.ParseSecret(cfg.Certificate); err != nil {
			issues = append(issues, issue("/certificate", "entra.certificate.literal",
				"the certificate must be a reference such as file:/run/secrets/entra.pem, "+
					"not the key itself"))
		}
	}

	if cfg.CloudName != "" {
		if _, ok := graph.EndpointsFor(cfg.Cloud()); !ok {
			issues = append(issues, issue("/cloud", "entra.cloud.unknown",
				fmt.Sprintf("%q is not a cloud: use global, usgov, usgov-dod or china", cfg.CloudName)))
		}
	}
	if cfg.PageSize != 0 && (cfg.PageSize < minPageSize || cfg.PageSize > maxPageSize) {
		issues = append(issues, issue("/page_size", "entra.page_size.invalid",
			fmt.Sprintf("the page size is between %d and %d; leave it out for the default", minPageSize, maxPageSize)))
	}
	return cfg, issues
}

func issue(field, code, message string) collector.Issue {
	return collector.Issue{
		Field: field, Severity: collectorv1.Severity_SEVERITY_ERROR,
		Code: code, Message: message,
	}
}
