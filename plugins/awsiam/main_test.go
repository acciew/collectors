package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.acciew.io/collector/plugins/awsiam/internal/iam"
	"go.acciew.io/collector/sdk/go/collector"
)

// A configuration this collector cannot use is not the source's doing. The
// source was never reached, and the host reads the cause — filed as a source
// error it sends an operator to look at something that did nothing wrong.
func TestABadConfigurationIsNotASourceError(t *testing.T) {
	noCredentials(t)
	for _, c := range []struct{ name, config string }{
		{"a document that is not JSON", `{not json`},
		// A profile is a field in our own document, and the SDK reads it from
		// files on this machine without calling AWS at all.
		{"a profile that does not exist", `{"profile": "no-such-profile-zz"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertConfigFailure(t, (&awsiam{}).Collect(context.Background(),
				collector.CollectRequest{Config: []byte(c.config)}, nil))
		})
	}
}

func assertConfigFailure(t *testing.T, err error) {
	t.Helper()
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("want an incomplete collection, got %v", err)
	}
	if inc.Cause != collector.InvalidConfig {
		t.Errorf("Cause = %v, want InvalidConfig", inc.Cause)
	}
	var faulty interface{ Fault() collector.Fault }
	if !errors.As(inc.Err, &faulty) || faulty.Fault() != collector.FaultConfig {
		t.Errorf("the failure does not classify itself as a config problem: %v", inc.Err)
	}
}

// Assembling an AWS client reads files and environment on this machine and
// calls AWS for none of it, so every way it can fail is the deployment's.
// Naming the kinds we thought of and leaving the rest as source errors is how
// a bad line in ~/.aws/config gets reported as AWS misbehaving.
func TestEveryLocalConfigurationFailureIsOne(t *testing.T) {
	// The runner's own AWS configuration would otherwise decide some of
	// these: a machine with a profile called p passes a case meant to fail.
	noCredentials(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Each case says what the SDK should complain about, so it can only pass
	// for its own reason. Without that, every one of these was satisfied by
	// "profile p does not exist" and the file contents were never read.
	for _, c := range []struct {
		name   string
		config string
		env    map[string]string
		says   string
	}{
		{"a profile that does not exist", `{"profile":"no-such-profile-zz"}`, nil,
			"no-such-profile-zz"},
		// Not here: a config file that will not parse. The SDK does not
		// surface an INI error, it reports the profile as absent, so such a
		// case would pass for the same reason as the one above and prove
		// nothing new.
		{"a profile naming two credential sources", `{"profile":"p"}`, map[string]string{
			"AWS_CONFIG_FILE": write("two", "[profile p]\n"+
				"credential_source = Ec2InstanceMetadata\nsource_profile = other\n"+
				"role_arn = arn:aws:iam::1:role/r\n"),
		}, "only one credential type"},
		{"a profile with half a credential", `{"profile":"p"}`, map[string]string{
			"AWS_CONFIG_FILE": write("half", "[profile p]\naws_access_key_id = AKIA\n"),
		}, "partial credentials"},
		{"a retry count that is not a number", `{}`, map[string]string{
			"AWS_MAX_ATTEMPTS": "abc",
		}, "AWS_MAX_ATTEMPTS=abc"},
		{"a CA bundle that is not there", `{}`, map[string]string{
			"AWS_CA_BUNDLE": filepath.Join(dir, "no-such-bundle"),
		}, "no-such-bundle"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			err := (&awsiam{}).Collect(context.Background(),
				collector.CollectRequest{Config: []byte(c.config)}, nil)
			inc, ok := collector.AsIncomplete(err)
			if !ok {
				t.Fatalf("want an incomplete collection, got %v", err)
			}
			if inc.Cause != collector.InvalidConfig {
				t.Errorf("Cause = %v, want InvalidConfig; AWS was never called: %v",
					inc.Cause, inc.Err)
			}
			if !strings.Contains(inc.Err.Error(), c.says) {
				t.Errorf("the failure does not mention %q, so this case is passing for some "+
					"other reason: %v", c.says, inc.Err)
			}
		})
	}
}

// The one thing loading the AWS configuration reaches out for: under
// defaults_mode=auto the SDK asks the instance metadata service which region
// this is, at load time.
//
// Its failure is swallowed unless the context ended first, so there are two
// ways this goes and neither is a bad document. Cancelled: the load fails and
// must not be blamed on the configuration. Not cancelled: the load succeeds
// despite the probe failing, and there is nothing here to misreport.
//
// The second half stops at Dial rather than running a collection. Collect
// would go on to call AWS, and on a machine with working credentials it would
// read somebody's real IAM account — a test has no business doing that, and
// on CI it passes only because there are no credentials to find.
func TestADisabledMetadataServiceIsNeverABadDocument(t *testing.T) {
	noCredentials(t)

	t.Run("the collection was cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := (&awsiam{}).Collect(ctx,
			collector.CollectRequest{Config: []byte(`{}`)}, nil)
		inc, ok := collector.AsIncomplete(err)
		if !ok {
			t.Fatalf("want an incomplete collection, got %v", err)
		}
		if inc.Cause == collector.InvalidConfig {
			t.Errorf("an unreachable metadata service was reported as a bad document, "+
				"sending an operator to edit a file that was never the problem: %v", inc.Err)
		}
		// And it failed where the guard is, not later: without this, a load
		// that succeeded and a collection that died on the cancelled context
		// would pass for the wrong reason.
		if !strings.Contains(inc.Err.Error(), "loading the AWS configuration") {
			t.Errorf("the failure did not come from loading the configuration: %v", inc.Err)
		}
	})

	t.Run("nobody cancelled anything", func(t *testing.T) {
		if _, err := iam.Dial(context.Background(), iam.Config{}); err != nil {
			t.Errorf("the probe failed and the load did not survive it: %v", err)
		}
	})
}

// noCredentials makes the environment say nothing, so that neither the
// runner's own AWS configuration nor its credentials can decide what a test
// sees — and so that nothing here can reach a real account.
func noCredentials(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_PROFILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CA_BUNDLE", "AWS_MAX_ATTEMPTS",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "no-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "no-credentials"))
	t.Setenv("AWS_DEFAULTS_MODE", "auto")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_REGION", "us-east-1")
}
