package collect_test

import (
	"context"
	"os"
	"testing"

	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// A whole collection of a real tenant, held to the contract. Skipped without
// credentials; see the graph package's live test for how to run it.
//
//	ACCIEW_ENTRA_LIVE=1 ACCIEW_ENTRA_TENANT=... ACCIEW_ENTRA_CLIENT=... \
//	  ACCIEW_ENTRA_SECRET=... go test ./internal/collect -run Live -v
//
// ACCIEW_ENTRA_FLAGS, a JSON object such as {"oauth2_grants":true}, sets the
// collect flags.
func TestLiveACollectionOfARealTenantSatisfiesTheContract(t *testing.T) {
	if os.Getenv("ACCIEW_ENTRA_LIVE") == "" {
		t.Skip("set ACCIEW_ENTRA_LIVE=1, with ACCIEW_ENTRA_TENANT, ACCIEW_ENTRA_CLIENT and " +
			"ACCIEW_ENTRA_SECRET, to check against a real tenant")
	}
	hosts, ok := graph.EndpointsFor(graph.Cloud(orGlobal(os.Getenv("ACCIEW_ENTRA_CLOUD"))))
	if !ok {
		t.Fatal("ACCIEW_ENTRA_CLOUD is not a cloud")
	}
	ctx := context.Background()
	client, err := graph.Dial(ctx, graph.Config{
		TenantID: os.Getenv("ACCIEW_ENTRA_TENANT"), ClientID: os.Getenv("ACCIEW_ENTRA_CLIENT"),
		ClientSecret: os.Getenv("ACCIEW_ENTRA_SECRET"), Endpoints: hosts,
	})
	if err != nil {
		t.Fatalf("signing in: %v", err)
	}
	cfg, issues := collect.Validate([]byte(`{"tenant_id":"` + client.TenantID() + `","client_id":"` +
		os.Getenv("ACCIEW_ENTRA_CLIENT") + `","client_secret":"env:ACCIEW_ENTRA_SECRET","collect":` +
		orDefault(os.Getenv("ACCIEW_ENTRA_FLAGS"), "{}") + `}`))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("configuration: %v", got)
	}

	out := &capture{t: t}
	err = collect.Run{Graph: client, Config: cfg}.Collect(ctx, collector.CollectRequest{}, out)
	if inc, ok := collector.AsIncomplete(err); ok {
		t.Logf("the collection ended incomplete (%v): %v", inc.Cause, inc.Err)
	} else if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	t.Logf("%d events, %d checkpoints, %d diagnostics", len(out.events), len(out.checkpoints), len(out.diags))
	for _, d := range out.diags {
		t.Logf("diagnostic %s: %s", d.GetCode(), d.GetMessage())
	}
	out.assertContract()
}

func orGlobal(s string) string { return orDefault(s, string(graph.Global)) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
