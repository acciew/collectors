package collect

import (
	"encoding/json"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// Config is this collector's configuration document.
//
// It carries no credential at all, not even a reference: AWS credentials are
// temporary by design and are resolved by the SDK's own chain — environment,
// shared config, an instance or pod role — which is what an operator already
// knows how to configure and what rotates without us. What the document says
// is which account to read and, for the cross-account case, which role to
// assume to get there.
type Config struct {
	// Region for the API calls. IAM is global; the SDK still needs one.
	Region string `json:"region"`
	// Profile from the shared config file. Empty means the default chain.
	Profile string `json:"profile"`
	// RoleARN to assume before reading. This is the cross-account shape: the
	// collector runs in one account and reads another.
	RoleARN string `json:"role_arn"`
	// ExternalID accompanies the assumption when the trusted account
	// requires one, which is what stops a confused deputy.
	ExternalID string `json:"external_id"`
}

// Validate checks a configuration document without contacting AWS.
func Validate(raw []byte) (Config, []collector.Issue) {
	var cfg Config
	if len(raw) == 0 {
		// An empty document is legitimate here, unlike the other collectors:
		// it means "read whatever account the ambient credentials are in",
		// which is the ordinary case for something running inside AWS.
		return cfg, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, []collector.Issue{{
			Field: "", Code: "aws.config.malformed",
			Message:  "the configuration is not valid: " + err.Error(),
			Severity: collectorv1.Severity_SEVERITY_ERROR,
		}}
	}

	var issues []collector.Issue
	if cfg.RoleARN != "" && !strings.HasPrefix(cfg.RoleARN, "arn:") {
		issues = append(issues, collector.Issue{
			Field: "/role_arn", Code: "aws.role_arn.invalid",
			Message:  "the role must be an ARN, e.g. arn:aws:iam::123456789012:role/AcciewReader",
			Severity: collectorv1.Severity_SEVERITY_ERROR,
		})
	}
	if cfg.ExternalID != "" && cfg.RoleARN == "" {
		issues = append(issues, collector.Issue{
			Field: "/external_id", Code: "aws.external_id.unused",
			Message: "an external id only means something with a role to assume; " +
				"this one will be ignored",
			Severity: collectorv1.Severity_SEVERITY_WARNING,
		})
	}
	return cfg, issues
}
