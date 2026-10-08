package collect_test

import (
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/graph"
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

const (
	tenantGUID = "11111111-2222-4333-8444-555555555555"
	clientGUID = "66666666-7777-4888-9999-000000000000"
	validBase  = `"tenant_id":"` + tenantGUID + `","client_id":"` + clientGUID + `"`
)

func TestAGoodConfigurationProducesNoErrorsAndTheDefaultsThePlanStates(t *testing.T) {
	cfg, issues := collect.Validate([]byte(`{` + validBase + `,"client_secret":"env:ENTRA_SECRET"}`))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if cfg.Cloud() != graph.Global {
		t.Errorf("cloud = %q, want global when none is given", cfg.Cloud())
	}
	w := cfg.Wants()
	if !w.ServicePrincipals || !w.AppRoles || !w.PIM || w.AdministrativeUnits || w.OAuth2Grants {
		t.Errorf("collect defaults = %+v; service principals, app roles and PIM are on, "+
			"administrative units and OAuth2 grants are off", w)
	}
	if cfg.PageSize != 0 {
		t.Errorf("page_size = %d, want 0 (the collector's own default)", cfg.PageSize)
	}
}

func TestACertificateIsAnAlternativeToASecret(t *testing.T) {
	_, issues := collect.Validate([]byte(`{` + validBase + `,"certificate":"file:/run/secrets/entra.pem","cloud":"usgov-dod"}`))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestACollectFlagCanSwitchADefaultOffOrAnOptionalOn(t *testing.T) {
	cfg, issues := collect.Validate([]byte(`{` + validBase + `,"client_secret":"env:S","collect":{"pim":false,"administrative_units":true}}`))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	w := cfg.Wants()
	if w.PIM || !w.AdministrativeUnits || !w.ServicePrincipals {
		t.Errorf("collect = %+v; naming one flag must leave the others at their default", w)
	}
}

// Every problem is addressed by JSON Pointer, so a CLI can point at the field
// rather than at the file.
func TestEachProblemNamesItsField(t *testing.T) {
	for _, tt := range []struct {
		name, config, wantField, wantCode string
	}{
		{"no document", ``, "", "entra.config.empty"},
		{"not JSON", `{nope`, "", "entra.config.malformed"},
		// A typo in a field name would otherwise collect the wrong thing.
		{"an unknown field", `{` + validBase + `,"client_secret":"env:S","cloud_name":"global"}`, "", "entra.config.malformed"},
		{"an unknown collect flag", `{` + validBase + `,"client_secret":"env:S","collect":{"licences":true}}`, "", "entra.config.malformed"},
		{"no tenant", `{"client_id":"` + clientGUID + `","client_secret":"env:S"}`, "/tenant_id", "entra.tenant_id.missing"},
		// The multi-tenant aliases are for interactive sign-in; an application
		// token request against one is refused, and a path with a slash in it
		// is a different URL.
		{"a tenant alias", `{"tenant_id":"common","client_id":"` + clientGUID + `","client_secret":"env:S"}`, "/tenant_id", "entra.tenant_id.invalid"},
		{"a tenant with a path in it", `{"tenant_id":"a/../b.com","client_id":"` + clientGUID + `","client_secret":"env:S"}`, "/tenant_id", "entra.tenant_id.invalid"},
		{"no client", `{"tenant_id":"` + tenantGUID + `","client_secret":"env:S"}`, "/client_id", "entra.client_id.missing"},
		{"a client that is not a GUID", `{"tenant_id":"` + tenantGUID + `","client_id":"acciew","client_secret":"env:S"}`, "/client_id", "entra.client_id.invalid"},
		{"no credential", `{` + validBase + `}`, "/client_secret", "entra.credential.missing"},
		{"both credentials", `{` + validBase + `,"client_secret":"env:S","certificate":"file:/c.pem"}`, "/certificate", "entra.credential.both"},
		// The core logs and hashes this document without knowing what any
		// field means, which is only safe if none of them is a credential.
		{"a literal secret", `{` + validBase + `,"client_secret":"hunter2"}`, "/client_secret", "entra.client_secret.literal"},
		{"a literal certificate", `{` + validBase + `,"certificate":"-----BEGIN PRIVATE KEY-----"}`, "/certificate", "entra.certificate.literal"},
		{"an unknown cloud", `{` + validBase + `,"client_secret":"env:S","cloud":"mars"}`, "/cloud", "entra.cloud.unknown"},
		{"a page too small to read a large tenant in", `{` + validBase + `,"client_secret":"env:S","page_size":99}`, "/page_size", "entra.page_size.invalid"},
		{"a negative page size", `{` + validBase + `,"client_secret":"env:S","page_size":-1}`, "/page_size", "entra.page_size.invalid"},
		// Graph answers a larger page with an error, not a smaller one.
		{"a page larger than Graph allows", `{` + validBase + `,"client_secret":"env:S","page_size":1000}`, "/page_size", "entra.page_size.invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := collect.Validate([]byte(tt.config))
			got := errorsOf(issues)
			if code, ok := got[tt.wantField]; !ok || code != tt.wantCode {
				t.Errorf("errors = %v, want %s at %q", got, tt.wantCode, tt.wantField)
			}
		})
	}
}

func TestADomainNameIsAcceptedAsATenant(t *testing.T) {
	_, issues := collect.Validate([]byte(`{"tenant_id":"example.onmicrosoft.com","client_id":"` + clientGUID + `","client_secret":"env:S"}`))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestNoIssueRepeatsAConfiguredSecretReference(t *testing.T) {
	_, issues := collect.Validate([]byte(`{` + validBase + `,"client_secret":"hunter2-literal"}`))
	for _, i := range issues {
		if strings.Contains(i.Message, "hunter2-literal") {
			t.Errorf("an issue repeats what was configured as a secret: %q", i.Message)
		}
	}
}

func TestThePageSizesAConfigurationMayAskForAreHundredToNineHundredNinetyNine(t *testing.T) {
	for _, n := range []string{"0", "100", "500", "999"} {
		if _, issues := collect.Validate([]byte(`{` + validBase + `,"client_secret":"env:S","page_size":` + n + `}`)); len(errorsOf(issues)) != 0 {
			t.Errorf("page_size %s was refused: %v", n, errorsOf(issues))
		}
	}
}
