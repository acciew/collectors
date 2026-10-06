package main

import (
	"context"
	"errors"
	"testing"

	"go.acciew.io/collector/sdk/go/collector"
)

// A configuration this collector cannot use is not the source's doing. The
// source was never reached, and the host reads the cause — filed as a source
// error it sends an operator to look at something that did nothing wrong.
func TestABadConfigurationIsNotASourceError(t *testing.T) {
	err := (&github{}).Collect(context.Background(),
		collector.CollectRequest{Config: []byte(`{"orgs": []}`)}, nil)

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

// dial contacts nothing, so every way it can fail is the document. Each of
// these is fixed in the deployment, and reporting one as a source failure
// sends an operator to look at a GitHub that was never called.
func TestEveryWayDiallingCanFailIsAboutTheDocument(t *testing.T) {
	t.Setenv("GH_TEST_EMPTY", "")
	for _, c := range []struct{ name, config string }{
		{"a document that is not JSON", `{not json`},
		{"a token reference pointing at nothing", `{"orgs":["acme"],"token":"env:GH_TEST_EMPTY"}`},
		{"a token reference that is not a reference", `{"orgs":["acme"],"token":"ghp_literal"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := (&github{}).Collect(context.Background(),
				collector.CollectRequest{Config: []byte(c.config)}, nil)

			inc, ok := collector.AsIncomplete(err)
			if !ok {
				t.Fatalf("want an incomplete collection, got %v", err)
			}
			if inc.Cause != collector.InvalidConfig {
				t.Errorf("Cause = %v, want InvalidConfig: %v", inc.Cause, inc.Err)
			}
		})
	}
}
