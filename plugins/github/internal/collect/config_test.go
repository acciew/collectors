package collect_test

import (
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/collect"
)

func problems(t *testing.T, doc string) map[string]string {
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

func TestAValidConfigurationIsAccepted(t *testing.T) {
	cfg, issues := collect.Validate([]byte(`{"token":"env:GH","orgs":["acme-org"]}`))
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			t.Errorf("unexpected error: %s %s", i.Field, i.Message)
		}
	}
	if cfg.Orgs[0] != "acme-org" {
		t.Errorf("orgs = %v", cfg.Orgs)
	}
}

// The whole point of a reference is that nothing but this process ever holds
// the credential. A literal in the document ends up in whatever stores it.
func TestATokenThatIsTheCredentialItselfIsRefused(t *testing.T) {
	got := problems(t, `{"token":"ghp_realLookingSecret","orgs":["acme-org"]}`)
	if got["/token"] != "github.token.literal" {
		t.Errorf("issues = %v, want the literal refused", got)
	}
}

func TestAMissingTokenIsRefused(t *testing.T) {
	if got := problems(t, `{"orgs":["acme-org"]}`); got["/token"] == "" {
		t.Errorf("issues = %v", got)
	}
}

// A typo in a field name would otherwise silently collect the wrong thing.
func TestAnUnknownFieldIsRefusedRatherThanIgnored(t *testing.T) {
	got := problems(t, `{"token":"env:GH","organisations":["acme-org"]}`)
	if got[""] != "github.config.malformed" {
		t.Errorf("issues = %v, want the document refused", got)
	}
}

func TestAnEmptyDocumentIsRefused(t *testing.T) {
	if got := problems(t, ``); got[""] == "" {
		t.Errorf("issues = %v", got)
	}
}

func TestABadVerificationSettingIsNamed(t *testing.T) {
	got := problems(t, `{"token":"env:GH","verify":"maybe"}`)
	if got["/verify"] != "github.verify.invalid" {
		t.Errorf("issues = %v", got)
	}
}

func TestAPageSizeGitHubWouldRefuseIsCaughtHere(t *testing.T) {
	got := problems(t, `{"token":"env:GH","page_size":500}`)
	if got["/page_size"] == "" {
		t.Errorf("issues = %v", got)
	}
}

func TestABlankOrganizationNameIsAddressedByPosition(t *testing.T) {
	got := problems(t, `{"token":"env:GH","orgs":["acme-org","  "]}`)
	if got["/orgs/1"] == "" {
		t.Errorf("issues = %v, want the second entry named", got)
	}
}

// Plain HTTP is a warning rather than an error: a local Enterprise Server
// behind a TLS-terminating proxy is legitimate, and the operator is the one
// who knows.
func TestPlainHTTPWarnsAndDoesNotBlock(t *testing.T) {
	_, issues := collect.Validate([]byte(`{"base_url":"http://ghe.internal/api/v3","token":"env:GH"}`))
	var warned bool
	for _, i := range issues {
		if i.Severity == collectorv1.Severity_SEVERITY_ERROR {
			t.Errorf("plain HTTP blocked the collection: %s", i.Message)
		}
		if strings.Contains(i.Message, "plain HTTP") {
			warned = true
		}
	}
	if !warned {
		t.Error("plain HTTP passed without a word")
	}
}

func TestHowMuchIsVerified(t *testing.T) {
	for _, c := range []struct {
		cfg   collect.Config
		repos int
		want  int
	}{
		{collect.Config{}, 100, 25},
		{collect.Config{Verify: "off"}, 100, 0},
		{collect.Config{Verify: "all"}, 100, 100},
		{collect.Config{Verify: "sample", VerifySample: 5}, 100, 5},
		// Never more than there are.
		{collect.Config{}, 3, 3},
	} {
		if got := c.cfg.Checks(c.repos); got != c.want {
			t.Errorf("%+v over %d repositories checks %d, want %d", c.cfg, c.repos, got, c.want)
		}
	}
}
