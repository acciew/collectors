package main_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/conformance"
)

// buildMinimal compiles this reference collector once per run and returns the
// path to the binary. The test runs from the module's own directory.
var buildMinimal = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "acciew-plugin-*")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "minimal")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", errors.New("building the reference collector: " + string(out))
	}
	return bin, nil
})

// The reference collector has to pass the suite a third party will run.
//
// If it does not, either the example is teaching the wrong thing or the suite
// is asking for something no reasonable collector would do — and both of
// those are bugs we would rather find here than in someone else's repository.
func TestTheReferenceCollectorConforms(t *testing.T) {
	bin, err := buildMinimal()
	if err != nil {
		t.Fatal(err)
	}
	opts := conformance.Options{Binary: bin, Config: []byte(`{}`)}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := conformance.Dial(ctx, bin)
	if err != nil {
		t.Fatalf("could not start %s: %v", bin, err)
	}
	defer p.Close()

	// One run, asserted twice: conformance.Run would dial and inspect again,
	// and the suite collects the whole source several times per pass.
	report := conformance.Inspect(ctx, p, opts)
	conformance.Assert(t, report)

	// And with nothing warned. A warning means a check could not be
	// exercised — the source fits inside the budget, a declared capability
	// was never reached — which for the reference collector means the example
	// stopped demonstrating the thing it exists to demonstrate. On a real
	// collector a warning is information; here it is a regression.
	for _, r := range report.Results {
		if r.Warned {
			t.Errorf("%s warned: %s", r.Name, r.Detail)
		}
	}
}

// The contract lets a collector that cannot read a cursor start over, and
// requires it to say so under a reserved code. Starting over silently leaves
// an operator watching a resume take as long as a full run with no reason
// given, which is the collector withholding something it knows.
func TestARejectedCursorIsAnnouncedAndCollectsEverything(t *testing.T) {
	bin, err := buildMinimal()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := conformance.Dial(ctx, bin)
	if err != nil {
		t.Fatalf("could not start %s: %v", bin, err)
	}
	defer p.Close()

	whole, err := p.Collect(ctx, &collectorv1.CollectRequest{Config: []byte(`{}`)})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, cursor := range []struct{ name, token string }{
		{"one this build did not write", "not a cursor this build wrote"},
		// Zero is a position, but not one this build ever checkpoints, so
		// honouring it would collect everything and call it a continuation.
		{"the start, which it never writes", "0"},
		// Past the end is the dangerous one: taken at face value it collects
		// nothing and reports a whole population of nobody.
		{"one past the end", "999"},
		{"a negative position", "-1"},
	} {
		t.Run(cursor.name, func(t *testing.T) {
			events, err := p.Collect(ctx, &collectorv1.CollectRequest{
				Config:     []byte(`{}`),
				ResumeFrom: &collectorv1.Cursor{Token: []byte(cursor.token)},
			})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}

			var said bool
			var done *collectorv1.Completion
			records := 0
			for _, e := range events {
				switch {
				case e.GetDiagnostic().GetCode() == "cursor.rejected":
					said = true
				case e.GetCompletion() != nil:
					done = e.GetCompletion()
				case e.GetNode() != nil, e.GetEdge() != nil, e.GetActivity() != nil:
					records++
				}
			}
			if !said {
				t.Error("the cursor was unreadable and the collection started over without saying so")
			}
			// Both halves of the rule: it may restart, and if it does the
			// population it produces is the whole one.
			if want := countRecords(whole); records != want {
				t.Errorf("collected %d records after restarting, want the whole %d", records, want)
			}
			if done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
				t.Errorf("a restart collects everything, so the stream should be COMPLETE, got %v",
					done.GetVerdict())
			}
		})
	}
}

func countRecords(events []*collectorv1.CollectResponse) int {
	n := 0
	for _, e := range events {
		if e.GetNode() != nil || e.GetEdge() != nil || e.GetActivity() != nil {
			n++
		}
	}
	return n
}

// What a resumed stream calls itself, and what it says about the part it
// carried. A continuation is not a whole population; a cursor naming the
// start collects everything and is one; and neither may be described by a
// sentence that is not true of it.
func TestWhatAResumedStreamCallsItself(t *testing.T) {
	bin, err := buildMinimal()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := conformance.Dial(ctx, bin)
	if err != nil {
		t.Fatalf("could not start %s: %v", bin, err)
	}
	defer p.Close()

	whole := countRecords(mustCollect(ctx, t, p, nil))

	for _, c := range []struct {
		name    string
		cursor  string
		records int
		says    string
	}{
		{"from the middle", "5", whole - 5, "resumed after record 5 of 10, so this stream " +
			"carries the remaining 5"},
		// The end. Nothing is left, which is an answer and not a failure.
		{"from the end", "10", 0, "carries the remaining 0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			events := mustCollect(ctx, t, p, []byte(c.cursor))
			done := completionIn(events)
			if got := countRecords(events); got != c.records {
				t.Errorf("carried %d records, want %d", got, c.records)
			}
			if done.GetVerdict() != collectorv1.Verdict_VERDICT_INCOMPLETE {
				t.Fatalf("verdict = %v, want INCOMPLETE", done.GetVerdict())
			}
			if done.GetCause() !=
				collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM {
				t.Errorf("cause = %v, want PARTIAL_STREAM", done.GetCause())
			}
			// A bare "incomplete" reads like a failure, and a sentence that
			// is not true of the stream is worse than none: the last defect
			// here was a message claiming a whole population.
			if got := done.GetError().GetMessage(); !strings.Contains(got, c.says) {
				t.Errorf("the stream says %q, which does not contain %q", got, c.says)
			}
			// And the scope it half-read is not reported as collected, while
			// still saying what it knows about activity. "This source
			// records nothing" and "this stream did not finish" are
			// different facts and the same field must not carry both.
			for _, sc := range done.GetScopes() {
				if sc.GetStatus() == collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
					t.Errorf("scope %s reported collected by a stream that carried %d of %d "+
						"records", sc.GetScope().GetId(), c.records, whole)
				}
				if sc.GetActivity() !=
					collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE {
					t.Errorf("scope %s says activity is %v; the stream carries an activity "+
						"record, so the scope answers and only this stream is partial",
						sc.GetScope().GetId(), sc.GetActivity())
				}
			}
		})
	}
}

func mustCollect(ctx context.Context, t *testing.T, p *conformance.Client,
	cursor []byte,
) []*collectorv1.CollectResponse {
	t.Helper()
	req := &collectorv1.CollectRequest{Config: []byte(`{}`)}
	if cursor != nil {
		req.ResumeFrom = &collectorv1.Cursor{Token: cursor}
	}
	events, err := p.Collect(ctx, req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return events
}

func completionIn(events []*collectorv1.CollectResponse) *collectorv1.Completion {
	for _, e := range events {
		if c := e.GetCompletion(); c != nil {
			return c
		}
	}
	return nil
}

// A collection nobody resumed is a whole one. Calling it partial because the
// resume branch was written carelessly makes every ordinary run look like a
// continuation, which is the promise inverted: a complete population reading
// as an incomplete one is not safe, it is noise that teaches people to ignore
// the verdict.
func TestAFreshCollectionIsNotAContinuation(t *testing.T) {
	bin, err := buildMinimal()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := conformance.Dial(ctx, bin)
	if err != nil {
		t.Fatalf("could not start %s: %v", bin, err)
	}
	defer p.Close()

	done := completionIn(mustCollect(ctx, t, p, nil))
	if done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
		t.Errorf("a collection with no cursor ended %v (%v)", done.GetVerdict(), done.GetCause())
	}
}

// The stream that stops for budget is half of a resumed pair, and it reports
// the same scope the continuation does. Saying the scope records no activity
// here, while the other half says it does, is the two halves contradicting
// each other about one fact — and the "no activity" reading is the one a
// reviewer acts on.
func TestABudgetedStreamSaysWhatTheScopeAnswers(t *testing.T) {
	bin, err := buildMinimal()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := conformance.Dial(ctx, bin)
	if err != nil {
		t.Fatalf("could not start %s: %v", bin, err)
	}
	defer p.Close()

	events, err := p.Collect(ctx, &collectorv1.CollectRequest{
		Config: []byte(`{}`),
		Budget: &collectorv1.Budget{MaxRecords: 1},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	done := completionIn(events)
	if done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED {
		t.Fatalf("cause = %v, want BUDGET_EXHAUSTED", done.GetCause())
	}
	if len(done.GetScopes()) == 0 {
		t.Fatal("the stream stopped without reporting the scope it was part-way through")
	}
	for _, sc := range done.GetScopes() {
		if sc.GetStatus() != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL {
			t.Errorf("scope %s reported %v by a stream the budget cut short",
				sc.GetScope().GetId(), sc.GetStatus())
		}
		if sc.GetActivity() !=
			collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE {
			t.Errorf("scope %s says activity is %v; the budget stopped the stream, not the "+
				"source, and the other half of this pair says the scope answers",
				sc.GetScope().GetId(), sc.GetActivity())
		}
	}
}
