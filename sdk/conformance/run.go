package conformance

import (
	"context"
	"testing"
	"time"
)

// Options configures a run.
type Options struct {
	// Binary is the path to the collector to test. Required by Run and
	// ignored by Inspect, which takes an already-connected plugin.
	Binary string
	// Config is a configuration document the collector should accept. The
	// suite passes it to ValidateConfig, TestConnection and Collect, so it
	// should be one that reaches a source with something in it — a run
	// against an empty source proves very little.
	Config []byte
	// Timeout bounds the whole run. Zero means two minutes.
	Timeout time.Duration
}

// Run launches a collector binary and asserts that it conforms.
//
// This is the whole of a plugin's conformance test:
//
//	func TestConformance(t *testing.T) {
//	    conformance.Run(t, conformance.Options{Binary: "./my-collector", Config: cfg})
//	}
//
// Every check becomes a subtest, so a failure names the rule that broke
// rather than reporting that "conformance failed".
func Run(t *testing.T, opts Options) {
	t.Helper()
	if opts.Binary == "" {
		t.Fatal("conformance.Run needs Options.Binary, the path to the collector under test")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	p, err := Dial(ctx, opts.Binary)
	if err != nil {
		t.Fatalf("could not start %s: %v", opts.Binary, err)
	}
	defer p.Close()

	Assert(t, Inspect(ctx, p, opts))
}

// Assert turns a report into subtests. Exported so that a caller who obtained
// a report some other way — from Inspect against their own client — can still
// get one subtest per rule.
func Assert(t *testing.T, r *Report) {
	t.Helper()
	for _, res := range r.Results {
		t.Run(res.Name, func(t *testing.T) {
			switch {
			case res.Failed:
				t.Error(res.Detail)
			case res.Warned:
				// Not a failure: a capability the configuration never reached
				// is common and harmless, and failing on it would push
				// authors to under-declare, which is the outcome the suite
				// exists to prevent.
				t.Log("warning: " + res.Detail)
			}
		})
	}
}
