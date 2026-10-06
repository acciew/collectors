// Package conformance is the test suite every collector must pass.
//
// It is the mechanical form of one rule: a plugin's declared capabilities
// must match its observed behaviour. A collector that says it produces
// activity data and then produces none, or that declares only direct grants
// and then emits a derived one, is not merely inconsistent — it makes a
// reviewer trust a claim the data does not support, which is the one failure
// this product cannot absorb.
//
// A plugin author writes one test:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, conformance.Options{
//	        Binary: "./my-collector",
//	        Config: []byte(`{"realm": "..."}`),
//	    })
//	}
//
// It is a separate module from the SDK so that a plugin's shipped binary does
// not carry the suite's dependencies.
package conformance

import (
	"context"
	"fmt"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// Plugin is the surface the suite exercises. It is an interface rather than a
// concrete client so that the checks can be driven by a fake, which is how
// the suite's own tests prove that it catches what it claims to catch.
type Plugin interface {
	Describe(context.Context) (*collectorv1.DescribeResponse, error)
	ValidateConfig(context.Context, []byte) ([]*collectorv1.ConfigIssue, error)
	TestConnection(context.Context, []byte) ([]*collectorv1.ScopeProbe, error)
	Collect(context.Context, *collectorv1.CollectRequest) ([]*collectorv1.CollectResponse, error)
	Revoke(context.Context, *collectorv1.RevokeRequest) (*collectorv1.RevokeResponse, error)
}

// Result is one finding.
type Result struct {
	// Name is stable and hierarchical: "collect/declared-types". A plugin
	// author greps for it, and it becomes a subtest name.
	Name string
	// Detail says what happened, in a sentence an author can act on.
	Detail string
	// Failed means the plugin broke the contract.
	Failed bool
	// Warned means something is worth knowing but is not a breach: a
	// capability declared and never exercised, for instance, which may just
	// mean the test configuration did not reach it.
	Warned bool
}

func pass(name string) Result { return Result{Name: name} }

func fail(name, format string, args ...any) Result {
	return Result{Name: name, Detail: fmt.Sprintf(format, args...), Failed: true}
}

func warn(name, format string, args ...any) Result {
	return Result{Name: name, Detail: fmt.Sprintf(format, args...), Warned: true}
}

// Report is everything one run found.
type Report struct {
	Results []Result
}

// Failed reports whether any check failed. Warnings do not fail a run.
func (r *Report) Failed() bool {
	for _, res := range r.Results {
		if res.Failed {
			return true
		}
	}
	return false
}

func (r *Report) add(results ...Result) { r.Results = append(r.Results, results...) }
