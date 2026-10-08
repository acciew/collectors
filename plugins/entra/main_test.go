package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/conformance"
	"go.acciew.io/collector/sdk/go/collector"
)

const (
	testClient = "00000000-0000-4000-8000-0000000000c1"
	testSecret = "synthetic-secret-value"
	// fakeEnv names the fake Graph's URL for a copy of this test binary that
	// has been started as the collector.
	fakeEnv = "ACCIEW_ENTRA_TEST_GRAPH"
)

// TestMain lets the test binary stand in for the collector. The conformance
// suite starts a collector as a separate process, as the host does, and the
// production binary has no way to be pointed at a fake: its hosts are
// Microsoft's, chosen by the cloud, and a setting that redirected them would
// be a setting that redirected a credential.
func TestMain(m *testing.M) {
	if url := os.Getenv(fakeEnv); url != "" {
		collector.Serve(&entra{endpoints: fixed(url)})
		return
	}
	os.Exit(m.Run())
}

func fixed(url string) func(graph.Cloud) (graph.Endpoints, bool) {
	return func(graph.Cloud) (graph.Endpoints, bool) {
		return graph.Endpoints{Login: url, Graph: url}, true
	}
}

func config(t *testing.T, tenant string, extra map[string]any) []byte {
	t.Helper()
	doc := map[string]any{
		"tenant_id": tenant, "client_id": testClient, "client_secret": "env:ENTRA_TEST_SECRET",
	}
	for k, v := range extra {
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fake(t *testing.T, tenant *fakegraph.Tenant) *fakegraph.Server {
	t.Helper()
	srv := fakegraph.New(t, tenant)
	srv.AcceptSecret(testClient, testSecret)
	t.Setenv("ENTRA_TEST_SECRET", testSecret)
	return srv
}

// The collector must pass the suite a third party's would. It runs as its own
// process against a fake Graph, so Describe, the configuration checks, the
// pre-flight check and a whole collection are all exercised over the same
// transport the host uses. A budget is reached only at the end and a cursor is
// set aside, so the suite's resume check has nothing to prove and says so.
func TestTheCollectorConforms(t *testing.T) {
	srv := fake(t, fakegraph.Example())
	t.Setenv(fakeEnv, srv.URL)

	conformance.Run(t, conformance.Options{
		Binary: os.Args[0],
		Config: config(t, srv.Tenant.ID, nil),
	})
}

// A collection that could not sign in is reporting a fact about the tenant or
// the credential. Returned raw it arrives as a plugin error, which sends
// whoever reads it to this code and not to the credential.
func TestACollectionThatCannotSignInBlamesTheCredential(t *testing.T) {
	srv := fake(t, fakegraph.Example())
	t.Setenv("ENTRA_TEST_SECRET", "a-rotated-secret")

	err := (&entra{endpoints: fixed(srv.URL)}).Collect(context.Background(),
		collector.CollectRequest{Config: config(t, srv.Tenant.ID, nil)}, nil)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("want an incomplete collection the host can classify, got %v", err)
	}
	if inc.Cause != collector.SourceFailed {
		t.Errorf("Cause = %v, want source failed", inc.Cause)
	}
	if !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Errorf("the message does not say what Entra said: %v", err)
	}
	if strings.Contains(err.Error(), "a-rotated-secret") {
		t.Errorf("the message repeats the secret: %v", err)
	}
}

// A configuration this collector cannot use is not the source's doing. The
// source was never reached, and an operator sent to look at Entra is looking
// at the wrong thing.
func TestABadConfigurationIsNotASourceError(t *testing.T) {
	t.Setenv("ENTRA_TEST_EMPTY", "")
	const ids = `"tenant_id":"example.onmicrosoft.com","client_id":"` + testClient + `"`
	for _, c := range []struct{ name, config string }{
		{"a document that is not JSON", `{not json`},
		{"a document missing what it needs", `{"tenant_id":""}`},
		{"a secret reference pointing at nothing", `{` + ids + `,"client_secret":"env:ENTRA_TEST_EMPTY"}`},
		{"a secret that is not a reference", `{` + ids + `,"client_secret":"s3cr3t"}`},
		{"a certificate file that is not there", `{` + ids + `,"certificate":"file:/nonexistent/entra.pem"}`},
		{"a certificate that is not a certificate", `{` + ids + `,"certificate":"env:ENTRA_TEST_NOT_PEM"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ENTRA_TEST_NOT_PEM", "this is not a pem bundle")
			err := (&entra{}).Collect(context.Background(), collector.CollectRequest{Config: []byte(c.config)}, nil)
			inc, ok := collector.AsIncomplete(err)
			if !ok {
				t.Fatalf("want an incomplete collection, got %v", err)
			}
			var faulty interface{ Fault() collector.Fault }
			if !errors.As(inc.Err, &faulty) || faulty.Fault() != collector.FaultConfig {
				t.Errorf("the failure does not classify itself as configuration: %v", inc.Err)
			}
			// The cause as well as the code: the host reads the cause.
			if inc.Cause != collector.InvalidConfig {
				t.Errorf("Cause = %v, want InvalidConfig", inc.Cause)
			}
		})
	}
}

func TestTheCollectorDescribesItselfAsReadOnlyAndHonestAboutFidelity(t *testing.T) {
	d, err := (&entra{}).Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Fidelities {
		if f == collectorv1.Fidelity_FIDELITY_COARSE {
			t.Error("Describe declares COARSE; a directory role is the source's own named permission, not an unevaluated container")
		}
	}
	if d.Name != "entra" {
		t.Errorf("Name = %q", d.Name)
	}
}

// The limitations are the contract's way of saying what the data does not
// mean, so a reviewer finds them in the snapshot and not only in a README.
func TestEveryLimitationTheCollectorHasIsDeclared(t *testing.T) {
	d, err := (&entra{}).Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, l := range d.Limitations {
		have[l.Code] = true
	}
	for _, code := range []string{
		"entra.activity-needs-p1",
		"entra.blank-sign-in-is-unanswerable",
		"entra.sign-in-lag-24h",
		"entra.sp-sign-in-not-collected",
		"entra.tenant-scoped",
		"entra.external-tenants-not-supported",
		"entra.group-service-principal-members-not-listed",
		"entra.hidden-membership-needs-permission",
		"entra.app-roles-nested-groups-not-expanded",
		"entra.replication-delay",
		"entra.oauth2-grants-off-by-default",
		"entra.eligible-is-a-separate-entitlement",
		"entra.conditional-access-not-evaluated",
		"entra.azure-rbac-not-collected",
		"entra.workload-roles-not-collected",
	} {
		if !have[code] {
			t.Errorf("Describe does not declare %s", code)
		}
	}
}

func TestTheCheckReportsTheTenantAsOneScopeAndWhatItCanAnswerAboutActivity(t *testing.T) {
	srv := fake(t, fakegraph.Example())
	probes, err := (&entra{endpoints: fixed(srv.URL)}).TestConnection(context.Background(), config(t, srv.Tenant.ID, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 {
		t.Fatalf("%d scopes, want the tenant", len(probes))
	}
	p := probes[0]
	if p.Scope.GetId() != srv.Tenant.ID || p.Name != "Example Corp" || !p.Reachable || !p.ActivityAvailable ||
		p.ActivityUndetermined || p.ActivityNote != "" {
		t.Errorf("probe = %+v", p)
	}
}

func TestTheCheckSaysWhatToGrantAndWhatToLicence(t *testing.T) {
	tenant := fakegraph.Example()
	tenant.ActivityRefusal = &fakegraph.Refusal{
		Status: 403, Code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", Message: "No premium licence.",
	}
	srv := fake(t, tenant)
	srv.Refuse("/v1.0/groups", 403, "Authorization_RequestDenied", "Insufficient privileges.")

	probes, err := (&entra{endpoints: fixed(srv.URL)}).TestConnection(context.Background(), config(t, tenant.ID, nil))
	if err != nil {
		t.Fatal(err)
	}
	p := probes[0]
	if p.Reachable || p.Err == nil || !strings.Contains(p.Err.Error(), "Group.Read.All") {
		t.Errorf("probe = %+v, want unreachable and Group.Read.All named", p)
	}
	if p.ActivityAvailable || p.ActivityUndetermined || !strings.Contains(p.ActivityNote, "Entra ID P1") {
		t.Errorf("activity = %v / %v / %q, want unavailable with a note that names the licence",
			p.ActivityAvailable, p.ActivityUndetermined, p.ActivityNote)
	}
}

func TestACheckThatCannotSignInIsAnErrorAndNotAScope(t *testing.T) {
	srv := fake(t, fakegraph.Example())
	t.Setenv("ENTRA_TEST_SECRET", "a-rotated-secret")

	probes, err := (&entra{endpoints: fixed(srv.URL)}).TestConnection(context.Background(), config(t, srv.Tenant.ID, nil))
	if err == nil || len(probes) != 0 || !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Errorf("probes = %v, err = %v; want the credential's failure", probes, err)
	}
}

// A sign-in that fails on a collection that was handed a cursor offers none back:
// Entra does not resume, so there is no place to return to, and the earlier
// cursor is no more use after the failure than before it.
func TestASignInThatFailsOffersNoCursor(t *testing.T) {
	cursor := []byte(`{"v":1}`)

	for _, c := range []struct {
		name  string
		setup func(t *testing.T) (entraFor *entra, config []byte)
	}{
		{"a token service that cannot be reached", func(t *testing.T) (*entra, []byte) {
			srv := fake(t, fakegraph.Example())
			cfg := config(t, srv.Tenant.ID, nil)
			srv.Close()
			return &entra{endpoints: fixed(srv.URL)}, cfg
		}},
		{"a secret that has been rotated", func(t *testing.T) (*entra, []byte) {
			srv := fake(t, fakegraph.Example())
			t.Setenv("ENTRA_TEST_SECRET", "a-rotated-secret")
			return &entra{endpoints: fixed(srv.URL)}, config(t, srv.Tenant.ID, nil)
		}},
		{"a configuration that cannot be used", func(t *testing.T) (*entra, []byte) {
			return &entra{}, []byte(`{"tenant_id":""}`)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, cfg := c.setup(t)
			err := e.Collect(context.Background(), collector.CollectRequest{Config: cfg, ResumeFrom: cursor}, nil)

			inc, ok := collector.AsIncomplete(err)
			if !ok {
				t.Fatalf("err = %v, want an incomplete collection", err)
			}
			if len(inc.ResumeFrom) != 0 {
				t.Errorf("ResumeFrom = %q, want none: there is nothing to resume", inc.ResumeFrom)
			}
		})
	}
}
