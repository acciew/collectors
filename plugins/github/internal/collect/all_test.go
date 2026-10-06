package collect_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/plugins/github/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// A collection that did not cover everything it was asked for must say so.
// These are the same failures the Keycloak collector had, checked here
// because the code is not shared and neither are the bugs.

// failing fails for one named organization and behaves normally otherwise.
type failing struct {
	*fakeSource
	failFor string
	err     error
}

func (f failing) Org(ctx context.Context, org string) (api.Org, error) {
	if org == f.failFor {
		return api.Org{}, f.err
	}
	return f.fakeSource.Org(ctx, org)
}

func (c *capture) scopeStatus() map[string]collectorv1.ScopeStatus {
	out := map[string]collectorv1.ScopeStatus{}
	for _, r := range c.scopes {
		out[r.Scope.GetId()] = r.Status
	}
	return out
}

// checkStreamIsSendable applies the rule the SDK applies before it will send
// a completion: records with no checkpoint are a stream that cannot be
// resumed, and the SDK refuses it — the host then loses the verdict and the
// data together.
func (c *capture) checkStreamIsSendable() {
	c.t.Helper()
	records := 0
	for _, e := range c.events {
		if e.GetNode() != nil || e.GetEdge() != nil || e.GetActivity() != nil {
			records++
		}
	}
	if records > 0 && len(c.checkpoints) == 0 {
		c.t.Errorf("the collector emitted %d records and never checkpointed; the SDK will "+
			"refuse to send the completion and the host loses everything", records)
	}
}

func runAll(t *testing.T, src collect.Source, orgs []string,
	req collector.CollectRequest, out *capture) error {
	t.Helper()
	err := collect.All(context.Background(), src, orgs, req, out)
	out.checkStreamIsSendable()
	return err
}

func cursorFor(orgs ...string) []byte {
	raw, err := json.Marshal(struct {
		Collected []string `json:"collected"`
	}{Collected: orgs})
	if err != nil {
		panic(err)
	}
	return raw
}

func TestCollectingWhatWasAskedForIsComplete(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, org(), []string{"acme-org"}, collector.CollectRequest{}, out); err != nil {
		t.Fatalf("All: %v", err)
	}
	if got := out.scopeStatus()["acme-org"]; got != collector.Collected {
		t.Errorf("status = %v, want collected", got)
	}
}

// One organization failing does not abandon the others, and the collection
// ends incomplete so the rest is not read as everything.
func TestAnOrganizationThatFailsMakesTheWholeCollectionIncomplete(t *testing.T) {
	src := failing{fakeSource: org(), failFor: "broken", err: errors.New("github said no")}
	out := &capture{t: t}

	err := runAll(t, src, []string{"acme-org", "broken"}, collector.CollectRequest{}, out)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want an incomplete verdict", err)
	}
	if inc.Cause != collector.ScopeUnreachable {
		t.Errorf("cause = %v", inc.Cause)
	}
	status := out.scopeStatus()
	if status["acme-org"] != collector.Collected {
		t.Errorf("the good organization = %v", status["acme-org"])
	}
	if status["broken"] != collector.Partial {
		t.Errorf("the failed organization = %v", status["broken"])
	}
}

// Running out of quota is not the same as running into a mistake, and only
// one of them is fixed by waiting.
func TestRunningOutOfQuotaIsReportedAsARateLimit(t *testing.T) {
	src := failing{
		fakeSource: org(), failFor: "acme-org",
		err: &api.Error{Kind: api.RateLimited, What: "listing repositories"},
	}
	out := &capture{t: t}

	err := runAll(t, src, []string{"acme-org"}, collector.CollectRequest{}, out)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Cause != collector.RateLimited {
		t.Errorf("cause = %v, want rate limited: an operator should be told to wait, "+
			"not to go and change something", inc.Cause)
	}
}

// An organization named in the configuration that the token cannot see used
// to produce no outcome at all and a complete verdict.
func TestAnOrganizationAskedForAndNotVisibleIsReported(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, org(), []string{"acme-org"},
		collector.CollectRequest{Scopes: []string{"acme-org", "ghost"}}, out)

	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if got := out.scopeStatus()["ghost"]; got != collector.Unreachable {
		t.Errorf("the invisible organization = %v", got)
	}
}

func TestAnOrganizationExcludedByRequestDoesNotMakeThePopulationPartial(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, org(), []string{"acme-org", "other"},
		collector.CollectRequest{Scopes: []string{"acme-org"}}, out); err != nil {
		t.Fatalf("All: %v", err)
	}
	if got := out.scopeStatus()["other"]; got != collector.Skipped {
		t.Errorf("status = %v, want skipped", got)
	}
}

// The cursor is a set, not a position. A high-water mark cannot say "the
// second failed and the third succeeded", so the failed one would sit behind
// the mark for ever while the next run reported itself complete.
func TestAResumeDoesNotSkipPastAnOrganizationThatFailed(t *testing.T) {
	src := failing{fakeSource: org(), failFor: "beta", err: errors.New("github said no")}
	first := &capture{t: t}

	err := runAll(t, src, []string{"alpha", "beta", "gamma"}, collector.CollectRequest{}, first)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}

	second := &capture{t: t}
	err = runAll(t, org(), []string{"alpha", "beta", "gamma"},
		collector.CollectRequest{ResumeFrom: inc.ResumeFrom}, second)
	if resumed, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("the resumed run: %v", err)
	} else if resumed.Cause != collector.PartialStream {
		t.Errorf("cause = %v, want partial stream", resumed.Cause)
	}
	if got := second.scopeStatus()["beta"]; got != collector.Collected {
		t.Errorf("beta = %v after a resume; the organization that failed was never revisited", got)
	}
}

// A resumed stream carries only the remainder, whatever it managed to
// collect. The host does not stitch streams, so a continuation holding one
// organization is a snapshot of one organization.
func TestAResumedStreamIsNeverAWholePopulation(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, org(), []string{"alpha", "acme-org"},
		collector.CollectRequest{ResumeFrom: cursorFor("alpha")}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Cause != collector.PartialStream {
		t.Errorf("cause = %v", inc.Cause)
	}
	if _, looked := out.scopeStatus()["alpha"]; looked {
		t.Error("an organization the cursor covered was given an outcome by a stream " +
			"that did not look at it")
	}
}

func TestAnUnreadableCursorIsRefusedRatherThanIgnored(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, org(), []string{"acme-org"},
		collector.CollectRequest{ResumeFrom: []byte("{not json")}, out)
	if err == nil {
		t.Fatal("want an error for a cursor that cannot be read")
	}
	if len(out.scopeStatus()) != 0 {
		t.Error("something was collected against an unreadable cursor")
	}
}

// A cursor naming an organization that is gone is not a reason to re-collect
// everything: there is simply nothing to skip.
func TestACursorNamingAnOrganizationThatIsGoneIsStillUsable(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, org(), []string{"acme-org"},
		collector.CollectRequest{ResumeFrom: cursorFor("deleted-org")}, out)
	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete: a resumed stream is part of a population", err)
	}
	if got := out.scopeStatus()["acme-org"]; got != collector.Collected {
		t.Errorf("acme-org = %v, want collected", got)
	}
}

// A budget is a promise to stop, and stopping without saying so leaves a
// partial population looking whole.
func TestExhaustingTheBudgetEndsIncompleteWithSomethingToResumeFrom(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, org(), []string{"acme-org", "second"},
		collector.CollectRequest{MaxRecords: 1}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Cause != collector.BudgetExhausted {
		t.Errorf("cause = %v", inc.Cause)
	}
	if len(inc.ResumeFrom) == 0 {
		t.Error("a budget stop has to say where to resume from")
	}
}

// A budget that trips after an organization failed must not report the budget
// and drop the failure: the one thing an operator has to fix would never
// reach them.
func TestABudgetStopDoesNotSwallowAnOrganizationThatFailed(t *testing.T) {
	src := failing{fakeSource: org(), failFor: "alpha", err: errors.New("github said no")}
	out := &capture{t: t}

	err := runAll(t, src, []string{"alpha", "beta"},
		collector.CollectRequest{MaxRecords: 1}, out)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Err == nil {
		t.Error("the failure did not survive the budget stop")
	}
}

// Records are emitted before a failure can happen. A stream carrying records
// with no checkpoint is one the SDK refuses to complete, losing the verdict
// and the data together — and for a single-organization token that is every
// partial failure.
func TestACollectionWhereEveryOrganizationFailsStillCheckpoints(t *testing.T) {
	src := failing{fakeSource: org(), failFor: "only", err: errors.New("github said no")}
	out := &capture{t: t}

	err := runAll(t, src, []string{"only"}, collector.CollectRequest{}, out)
	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if len(out.checkpoints) == 0 {
		t.Error("no checkpoint was emitted")
	}
}

// A cursor this build cannot read is not the source's doing, and reporting it
// as a source error sends an operator to look at something that did nothing
// wrong. The contract has a code for exactly this.
func TestAnUnreadableCursorIsNotASourceError(t *testing.T) {
	src := &fakeSource{}
	orgs := []string{"acme"}
	out := &capture{t: t}

	err := collect.All(context.Background(), src, orgs, collector.CollectRequest{
		ResumeFrom: []byte("this is not a cursor"),
	}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("want an incomplete collection, got %v", err)
	}
	var faulty interface{ Fault() collector.Fault }
	if !errors.As(inc.Err, &faulty) {
		t.Fatalf("the refusal does not classify itself, so it reaches the wire as a source "+
			"error: %v", inc.Err)
	}
	if got := faulty.Fault(); got != collector.FaultInvalidCursor {
		t.Errorf("Fault = %v, want FaultInvalidCursor", got)
	}
	// And the cause, which is what the host reads. PartialStream would say a
	// continuation arrived; nothing was collected at all.
	if inc.Cause != collector.InvalidCursor {
		t.Errorf("Cause = %v, want InvalidCursor", inc.Cause)
	}
}
