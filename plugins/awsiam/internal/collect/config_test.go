package collect_test

import (
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/awsiam/internal/collect"
)

func errorsFrom(t *testing.T, doc string) map[string]string {
	t.Helper()
	_, issues := collect.Validate([]byte(doc))
	out := map[string]string{}
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			out[i.Field] = i.Code
		}
	}
	return out
}

// An empty document is legitimate here, unlike the other collectors: it means
// "read whatever account the ambient credentials are in", which is the
// ordinary case for something running inside AWS.
func TestAnEmptyConfigurationIsTheOrdinaryCase(t *testing.T) {
	if got := errorsFrom(t, ""); len(got) != 0 {
		t.Errorf("an empty document was refused: %v", got)
	}
	if got := errorsFrom(t, "{}"); len(got) != 0 {
		t.Errorf("an empty object was refused: %v", got)
	}
}

func TestTheCrossAccountShapeIsAccepted(t *testing.T) {
	cfg, issues := collect.Validate([]byte(
		`{"role_arn":"arn:aws:iam::123456789012:role/AcciewReader","external_id":"s3cret"}`))
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			t.Errorf("unexpected error: %s %s", i.Field, i.Message)
		}
	}
	if cfg.RoleARN == "" || cfg.ExternalID != "s3cret" {
		t.Errorf("config = %+v", cfg)
	}
}

func TestARoleThatIsNotAnARNIsRefused(t *testing.T) {
	if got := errorsFrom(t, `{"role_arn":"AcciewReader"}`); got["/role_arn"] == "" {
		t.Errorf("issues = %v", got)
	}
}

// A typo in a field name would otherwise silently collect against the wrong
// credentials.
func TestAnUnknownFieldIsRefusedRatherThanIgnored(t *testing.T) {
	if got := errorsFrom(t, `{"profil":"prod"}`); got[""] == "" {
		t.Errorf("issues = %v", got)
	}
}

// An external id with nothing to assume does nothing, and silently ignoring
// it would leave somebody believing they had configured a protection they
// have not.
func TestAnExternalIdWithNoRoleWarns(t *testing.T) {
	_, issues := collect.Validate([]byte(`{"external_id":"s3cret"}`))
	var warned bool
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			t.Errorf("it was refused rather than flagged: %s", i.Message)
		}
		if strings.Contains(i.Message, "ignored") {
			warned = true
		}
	}
	if !warned {
		t.Error("an external id that does nothing passed without a word")
	}
}
