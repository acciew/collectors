package collect_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/smithy-go"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/awsiam/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

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
		c.t.Error("records were emitted with no checkpoint; the SDK will refuse to send " +
			"the completion and the host loses everything")
	}
}

func runAll(t *testing.T, src collect.Source, req collector.CollectRequest, out *capture) error {
	t.Helper()
	err := collect.All(context.Background(), src, now, req, out)
	out.checkStreamIsSendable()
	return err
}

func cursorFor(accounts ...string) []byte {
	raw, err := json.Marshal(struct {
		Collected []string `json:"collected"`
	}{Collected: accounts})
	if err != nil {
		panic(err)
	}
	return raw
}

func TestCollectingTheAccountIsComplete(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, account(), collector.CollectRequest{}, out); err != nil {
		t.Fatalf("All: %v", err)
	}
	if got := out.scopeStatus()["111122223333"]; got != collector.Collected {
		t.Errorf("status = %v, want collected", got)
	}
}

// Nothing was read, so there is nothing to present as a population.
func TestAnAccountThatCannotBeReadIsNotACompleteCollectionOfNothing(t *testing.T) {
	src := account()
	src.err = errors.New("aws said no")
	out := &capture{t: t}

	err := runAll(t, src, collector.CollectRequest{}, out)
	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want an incomplete verdict", err)
	}
}

// IAM throttles. Being told to wait is a different instruction to an operator
// than being told something is wrong.
func TestBeingThrottledIsReportedAsARateLimit(t *testing.T) {
	src := account()
	// As the SDK reports it: a typed API error with AWS's own code, not a
	// string a collector has to guess from.
	src.err = &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}
	out := &capture{t: t}

	err := runAll(t, src, collector.CollectRequest{}, out)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Cause != collector.RateLimited {
		t.Errorf("cause = %v, want rate limited: an operator should be told to wait", inc.Cause)
	}
}

// A resumed stream carries only the remainder, whatever it managed to
// collect. The host does not stitch streams together.
func TestAResumedStreamThatHasNothingLeftSaysSo(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, account(),
		collector.CollectRequest{ResumeFrom: cursorFor("111122223333")}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete rather than a complete collection of nothing", err)
	}
	if inc.Cause != collector.PartialStream {
		t.Errorf("cause = %v", inc.Cause)
	}
	if len(out.scopeStatus()) != 0 {
		t.Error("a scope outcome was claimed by a stream that looked at nothing")
	}
}

func TestAnUnreadableCursorIsRefusedRatherThanIgnored(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, account(),
		collector.CollectRequest{ResumeFrom: []byte("{not json")}, out); err == nil {
		t.Fatal("want an error for a cursor that cannot be read")
	}
}

// Asking for an account these credentials do not reach is not a collection of
// nothing: it is a request that could not be honoured.
func TestAskingForAnAccountTheseCredentialsDoNotReachIsReported(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, account(), collector.CollectRequest{Scopes: []string{"999999999999"}}, out)

	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if got := out.scopeStatus()["111122223333"]; got != collector.Skipped {
		t.Errorf("status = %v, want skipped", got)
	}
}

// This account can answer about activity: roles carry their own last-used and
// the credential report covers the users.
func TestTheScopeSaysItCanAnswerAboutActivity(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, account(), collector.CollectRequest{}, out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.scopes {
		if !r.ActivityAvailable {
			t.Errorf("scope %s says it has no activity data", r.Scope.GetId())
		}
	}
}

// An account nobody read has no activity answer. The zero value would say it
// records nothing, which is not true of any AWS account.
func TestAnAccountNotReadHasNoActivityAnswer(t *testing.T) {
	out := &capture{t: t}
	_ = runAll(t, account(), collector.CollectRequest{Scopes: []string{"999999999999"}}, out)
	if len(out.scopes) != 2 {
		t.Fatalf("scope results = %+v, want the unreachable one and the skipped one", out.scopes)
	}
	for _, r := range out.scopes {
		if r.ActivityAvailable || !r.ActivityUndetermined {
			t.Errorf("%s (%v): available=%v undetermined=%v, want undetermined",
				r.Scope.GetId(), r.Status, r.ActivityAvailable, r.ActivityUndetermined)
		}
	}
}

// An account the caller named and these credentials cannot reach has to be
// accounted for. Never mentioned, the host is free to present a collection of
// one account as a collection of the two that were asked for.
func TestAnAccountAskedForAndUnreachableIsReported(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, account(),
		collector.CollectRequest{Scopes: []string{"111122223333", "999999999999"}}, out)

	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete: one of the two accounts was not collected", err)
	}
	status := out.scopeStatus()
	if status["999999999999"] != collector.Unreachable {
		t.Errorf("the unreachable account = %v, want unreachable", status["999999999999"])
	}
	if status["111122223333"] != collector.Collected {
		t.Errorf("the reachable account = %v, want collected", status["111122223333"])
	}
}

// The account's authorization details are the most expensive call in the
// collection — many pages and several minutes on a real account. Reading
// them twice doubles that and lets the two reads disagree.
func TestTheAuthorizationDetailsAreReadOnce(t *testing.T) {
	src := account()
	out := &capture{t: t}
	if err := runAll(t, src, collector.CollectRequest{}, out); err != nil {
		t.Fatal(err)
	}
	if src.snapshots != 1 {
		t.Errorf("the authorization details were read %d times, want once", src.snapshots)
	}
}

// The credential report can fail on a permission that has nothing to do with
// roles, and roles carry their own last-used. Losing every role's activity
// over it throws away the signal that matters most in AWS.
func TestARoleKeepsItsActivityWhenTheCredentialReportFails(t *testing.T) {
	src := account()
	src.reportErr = errors.New("AccessDenied: GenerateCredentialReport")
	out := &capture{t: t}

	if err := runAll(t, src, collector.CollectRequest{}, out); err != nil {
		t.Fatalf("a credential report failure ended the collection: %v", err)
	}
	if a := out.activityFor("AROAEXAMPLE1", "role_last_used"); a == nil {
		t.Error("every role lost its activity over a report that roles do not need")
	}
	// And the users are answered for as unanswerable rather than silently.
	a := out.activityFor("AIDAEXAMPLE1", "console_password")
	if a == nil || a.GetUnavailable() == nil {
		t.Errorf("the users were left unanswered: %v", a)
	}
	var warned bool
	for _, d := range out.diags {
		if strings.Contains(d, "aws.credential_report.unreadable") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("nothing said the report could not be read: %v", out.diags)
	}
}

// The other half: something that merely mentions throttling is not
// throttling. A role called ThrottleReader in an access-denied message would
// otherwise send an operator away to wait for an hour.
func TestAnAccessDeniedThatMentionsThrottlingIsNotARateLimit(t *testing.T) {
	src := account()
	src.err = &smithy.GenericAPIError{
		Code:    "AccessDenied",
		Message: "not authorized to perform iam:GetRole on resource ThrottleReader",
	}
	out := &capture{t: t}

	err := runAll(t, src, collector.CollectRequest{}, out)
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	if inc.Cause == collector.RateLimited {
		t.Error("a permission failure was reported as a rate limit; the operator would " +
			"wait for something that never clears")
	}
}

// A cursor this build cannot read is not the source's doing, and reporting it
// as a source error sends an operator to look at something that did nothing
// wrong. The contract has a code for exactly this.
func TestAnUnreadableCursorIsNotASourceError(t *testing.T) {
	src := &fakeSource{}
	out := &capture{t: t}

	err := collect.All(context.Background(), src, now, collector.CollectRequest{
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
