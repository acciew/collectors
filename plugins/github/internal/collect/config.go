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
// what any field means — which is only safe because the credential is a
// reference rather than a value.
type Config struct {
	// BaseURL of the API. Empty means github.com. An Enterprise Server
	// installation is https://ghe.example.com/api/v3.
	BaseURL string `json:"base_url"`
	// Token is a reference, never a literal: "env:GITHUB_TOKEN" or
	// "file:/run/secrets/gh".
	Token string `json:"token"`
	// Orgs to collect. Empty means every organization the token can see.
	Orgs []string `json:"orgs"`
	// PageSize for paged endpoints. Zero means 100, GitHub's maximum.
	PageSize int `json:"page_size"`
	// Verify is how much of the collection is checked against GitHub's own
	// resolved answer: "sample" (the default), "all", or "off".
	//
	// The check costs one extra request per repository, which on a large
	// organization is the difference between one rate-limit window and two.
	// It is a check on this collector rather than the collection itself, so
	// sampling it is a real choice rather than a compromise — but turning it
	// off entirely means a derivation bug shows up as wrong evidence rather
	// than as a warning.
	Verify string `json:"verify"`
	// VerifySample is how many repositories to check when Verify is
	// "sample". Zero means 25.
	VerifySample int `json:"verify_sample"`
}

// Verification modes.
const (
	VerifyOff     = "off"
	VerifySome    = "sample"
	VerifyAll     = "all"
	defaultSample = 25
)

// Checks says how many repositories this configuration will verify out of n.
func (c Config) Checks(repos int) int {
	switch c.Verify {
	case VerifyOff:
		return 0
	case VerifyAll:
		return repos
	default:
		return min(repos, c.sampleSize())
	}
}

func (c Config) sampleSize() int {
	if c.VerifySample > 0 {
		return c.VerifySample
	}
	return defaultSample
}

// Validate checks a configuration document without contacting GitHub.
//
// Every issue is addressed by JSON Pointer so a CLI can point at the field
// rather than at the file.
func Validate(raw []byte) (Config, []collector.Issue) {
	var cfg Config
	if len(raw) == 0 {
		return cfg, []collector.Issue{issue("", "github.config.empty",
			"a configuration document is required")}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// A typo in a field name would otherwise silently collect the wrong
	// thing, which is worse than refusing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, []collector.Issue{issue("", "github.config.malformed",
			"the configuration is not valid: "+err.Error())}
	}

	var issues []collector.Issue
	if cfg.BaseURL != "" {
		u, err := url.Parse(cfg.BaseURL)
		switch {
		case err != nil || u.Scheme == "" || u.Host == "":
			issues = append(issues, issue("/base_url", "github.base_url.invalid",
				"the base URL must be absolute, e.g. https://ghe.example.com/api/v3"))
		case u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1":
			issues = append(issues, warning("/base_url", "github.base_url.insecure",
				"this sends the token over plain HTTP"))
		}
	}
	if cfg.Token == "" {
		issues = append(issues, issue("/token", "github.token.missing",
			"a token reference is required, e.g. env:GITHUB_TOKEN"))
	} else if !strings.HasPrefix(cfg.Token, "env:") && !strings.HasPrefix(cfg.Token, "file:") {
		// A literal in the configuration ends up in whatever stores it, and
		// the whole point of a reference is that nothing but this process
		// ever holds the credential.
		issues = append(issues, issue("/token", "github.token.literal",
			"the token must be a reference, not the credential itself: "+
				"use env:VARNAME or file:/path"))
	}
	for i, org := range cfg.Orgs {
		if strings.TrimSpace(org) == "" {
			issues = append(issues, issue(jsonPointer("/orgs", i), "github.orgs.empty",
				"an organization name cannot be blank"))
		}
	}
	switch cfg.Verify {
	case "", VerifyOff, VerifySome, VerifyAll:
	default:
		issues = append(issues, issue("/verify", "github.verify.invalid",
			`verify must be "off", "sample" or "all"`))
	}
	if cfg.VerifySample < 0 {
		issues = append(issues, issue("/verify_sample", "github.verify_sample.invalid",
			"the sample size cannot be negative"))
	}
	if cfg.PageSize < 0 || cfg.PageSize > 100 {
		issues = append(issues, issue("/page_size", "github.page_size.invalid",
			"the page size must be between 1 and 100, GitHub's maximum"))
	}
	return cfg, issues
}

func jsonPointer(base string, i int) string {
	return base + "/" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

func issue(field, code, message string) collector.Issue {
	return collector.Issue{
		Field: field, Code: code, Message: message,
		Severity: collectorv1.Severity_SEVERITY_ERROR,
	}
}

func warning(field, code, message string) collector.Issue {
	return collector.Issue{
		Field: field, Code: code, Message: message,
		Severity: collectorv1.Severity_SEVERITY_WARNING,
	}
}
