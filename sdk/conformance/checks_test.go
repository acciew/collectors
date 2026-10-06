package conformance_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/conformance"
	"go.acciew.io/collector/sdk/go/collector"
)

// liar is a collector that can be told to misbehave in one specific way. The
// suite's only real proof is that each lie is caught, so each test tells it a
// different one.
type liar struct {
	describe *collectorv1.DescribeResponse
	events   []*collectorv1.CollectResponse
	// budgeted is what a one-record collection returns; nil means "behave".
	budgeted []*collectorv1.CollectResponse
	resumed  []*collectorv1.CollectResponse
	issues   func([]byte) []*collectorv1.ConfigIssue
	probes   []*collectorv1.ScopeProbe
	revoke   *collectorv1.RevokeResponse
}

func (l *liar) Describe(context.Context) (*collectorv1.DescribeResponse, error) {
	return l.describe, nil
}

func (l *liar) ValidateConfig(_ context.Context, c []byte) ([]*collectorv1.ConfigIssue, error) {
	if l.issues != nil {
		return l.issues(c), nil
	}
	if !isJSON(c) {
		return []*collectorv1.ConfigIssue{{
			Severity: collectorv1.Severity_SEVERITY_ERROR,
			Code:     "liar.bad_json", Message: "not JSON",
		}}, nil
	}
	return nil, nil
}

func isJSON(b []byte) bool { return len(b) > 0 && b[0] == '{' && b[len(b)-1] == '}' }

func (l *liar) TestConnection(context.Context, []byte) ([]*collectorv1.ScopeProbe, error) {
	if l.probes != nil {
		return l.probes, nil
	}
	return []*collectorv1.ScopeProbe{{
		Scope: collector.Scope("s", "s"), Name: "the scope", Reachable: true,
		Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
	}}, nil
}

func (l *liar) Revoke(context.Context, *collectorv1.RevokeRequest) (*collectorv1.RevokeResponse, error) {
	if l.revoke != nil {
		return l.revoke, nil
	}
	return &collectorv1.RevokeResponse{
		Outcome: collectorv1.RevokeOutcome_REVOKE_OUTCOME_NOT_SUPPORTED,
	}, nil
}

func (l *liar) Collect(_ context.Context, req *collectorv1.CollectRequest) ([]*collectorv1.CollectResponse, error) {
	switch {
	case req.GetBudget().GetMaxRecords() > 0 && l.budgeted != nil:
		return l.budgeted, nil
	case len(req.GetResumeFrom().GetToken()) > 0 && l.resumed != nil:
		return l.resumed, nil
	}
	return l.events, nil
}

// --- a well-formed baseline -------------------------------------------------

func describeOK() *collectorv1.DescribeResponse {
	return &collectorv1.DescribeResponse{
		Kind: collectorv1.Kind, ProtocolVersion: collectorv1.ProtocolVersion,
		Name: "honest", Version: "1.0.0", Description: "behaves",
		Capabilities: &collectorv1.Capabilities{
			Activity:   true,
			Fidelities: []collectorv1.Fidelity{collector.Direct},
			NodeTypes: []collectorv1.NodeType{
				collectorv1.NodeType_NODE_TYPE_SCOPE,
				collectorv1.NodeType_NODE_TYPE_IDENTITY,
				collectorv1.NodeType_NODE_TYPE_ENTITLEMENT,
			},
			EdgeTypes: []collectorv1.EdgeType{collectorv1.EdgeType_EDGE_TYPE_HOLDS},
		},
		ActivitySignals: []*collectorv1.ActivitySignal{{
			Name: "login", Description: "a login",
		}},
	}
}

func node(n *collectorv1.Node) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: n}}
}
func edge(e *collectorv1.Edge) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Edge{Edge: e}}
}
func activity(a *collectorv1.Activity) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Activity{Activity: a}}
}
func checkpoint(tok string) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{
		Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: []byte(tok)}}}}
}
func completion(c *collectorv1.Completion) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: c}}
}

var (
	scopeKey   = collector.Scope("s", "s")
	aliceKey   = collector.IdentityKey("s", "alice")
	adminKey   = collector.EntitlementKey("s", "admin")
	now        = time.Unix(1e9, 0).UTC()
	fullWindow = collector.Window(now.Add(-30*24*time.Hour), now)
)

func streamOK() []*collectorv1.CollectResponse {
	return []*collectorv1.CollectResponse{
		node(collector.ScopeNode(scopeKey, "the scope", "scope")),
		node(collector.Identity(aliceKey, "alice", "user", collector.Human, collector.Active)),
		node(collector.Entitlement(adminKey, "admin", "role")),
		edge(collector.Holds(aliceKey, adminKey, collector.Direct)),
		activity(collector.Seen(aliceKey, "login", now, fullWindow, 0, now.Add(-time.Hour), collector.Exact)),
		checkpoint("done"),
		completion(&collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
			Counts: &collectorv1.Counts{
				Scopes: 1, Identities: 1, Entitlements: 1, Edges: 1, Activities: 1,
			},
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey, Status: collector.Collected,
				Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
			}},
		}),
	}
}

func inspect(l *liar) *conformance.Report {
	return conformance.Inspect(context.Background(), l, conformance.Options{Config: []byte(`{}`)})
}

func failuresFor(t *testing.T, r *conformance.Report) []string {
	t.Helper()
	var out []string
	for _, res := range r.Results {
		if res.Failed {
			out = append(out, res.Name+": "+res.Detail)
		}
	}
	return out
}

func wantFailure(t *testing.T, r *conformance.Report, check, phrase string) {
	t.Helper()
	for _, res := range r.Results {
		if res.Failed && res.Name == check && strings.Contains(res.Detail, phrase) {
			return
		}
	}
	t.Errorf("want a %q failure mentioning %q; got %v", check, phrase, failuresFor(t, r))
}

// --- the baseline must pass, or nothing below means anything ---------------

func TestAnHonestCollectorPasses(t *testing.T) {
	r := inspect(&liar{describe: describeOK(), events: streamOK()})
	if r.Failed() {
		t.Fatalf("an honest collector should pass: %v", failuresFor(t, r))
	}
}

// --- each lie, and the check that catches it -------------------------------

func TestEmittingATypeThatWasNotDeclared(t *testing.T) {
	d := describeOK()
	d.Capabilities.NodeTypes = []collectorv1.NodeType{
		collectorv1.NodeType_NODE_TYPE_SCOPE, collectorv1.NodeType_NODE_TYPE_IDENTITY,
	} // entitlement removed, but the stream still emits one
	wantFailure(t, inspect(&liar{describe: d, events: streamOK()}),
		"collect/declared-types", "which Describe did not declare")
}

func TestEmittingAFidelityThatWasNotDeclared(t *testing.T) {
	events := streamOK()
	events[3] = edge(collector.Holds(aliceKey, adminKey, collector.Coarse))
	wantFailure(t, inspect(&liar{describe: describeOK(), events: events}),
		"collect/declared-fidelities", "COARSE")
}

func TestEmittingASignalThatWasNotDeclared(t *testing.T) {
	events := streamOK()
	events[4] = activity(collector.Seen(aliceKey, "undeclared_signal", now, fullWindow, 0,
		now.Add(-time.Hour), collector.Exact))
	wantFailure(t, inspect(&liar{describe: describeOK(), events: events}),
		"collect/declared-signals", "undeclared_signal")
}

// The rule that matters most: silence about an identity reads as "never
// used", and a dormant-account review acts on that.
func TestClaimingActivityAndLeavingAnIdentityUnaccountedFor(t *testing.T) {
	events := streamOK()
	bob := collector.IdentityKey("s", "bob")
	events = append(events[:5],
		append([]*collectorv1.CollectResponse{
			node(collector.Identity(bob, "bob", "user", collector.Human, collector.Active)),
		}, events[5:]...)...)
	events[len(events)-1].GetCompletion().Counts.Identities = 2

	wantFailure(t, inspect(&liar{describe: describeOK(), events: events}),
		"collect/activity-accounting", "silence reads as")
}

// ...unless the scope itself says it cannot answer, which is what stops a
// realm with event storage off, or one whose events read was refused,
// needing one record per user.
func TestAScopeThatCannotAnswerExcusesEveryIdentityInIt(t *testing.T) {
	for _, answer := range []collectorv1.ActivityAvailability{
		collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNAVAILABLE,
		collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNDETERMINED,
	} {
		t.Run(answer.String(), func(t *testing.T) {
			events := streamOK()
			events = append(events[:4], events[5:]...) // drop the activity record
			done := events[len(events)-1].GetCompletion()
			done.Counts.Activities = 0
			done.Scopes[0].Activity = answer

			r := inspect(&liar{describe: describeOK(), events: events})
			if r.Failed() {
				t.Errorf("a scope that cannot answer should account for its identities: %v", failuresFor(t, r))
			}
		})
	}
}

func TestEmittingActivityWithoutDeclaringIt(t *testing.T) {
	d := describeOK()
	d.Capabilities.Activity = false
	d.ActivitySignals = nil
	wantFailure(t, inspect(&liar{describe: d, events: streamOK()}),
		"collect/activity-accounting", "without declaring the activity capability")
}

func TestDeclaringRevocation(t *testing.T) {
	d := describeOK()
	d.Capabilities.Revoke = true
	wantFailure(t, inspect(&liar{describe: d, events: streamOK()}),
		"describe/revoke-not-declared", "no collector may declare revocation yet")
}

func TestAnsweringRevokeWithAnythingElse(t *testing.T) {
	l := &liar{describe: describeOK(), events: streamOK(),
		revoke: &collectorv1.RevokeResponse{Outcome: collectorv1.RevokeOutcome_REVOKE_OUTCOME_REVOKED}}
	wantFailure(t, inspect(l), "revoke/not-supported", "must answer NOT_SUPPORTED")
}

func TestAcceptingAConfigThatIsNotJSON(t *testing.T) {
	l := &liar{describe: describeOK(), events: streamOK(),
		issues: func([]byte) []*collectorv1.ConfigIssue { return nil }}
	wantFailure(t, inspect(l), "validate-config/rejects-malformed", "not JSON")
}

func TestReportingNoScopesAtAll(t *testing.T) {
	l := &liar{describe: describeOK(), events: streamOK(),
		probes: []*collectorv1.ScopeProbe{}}
	wantFailure(t, inspect(l), "test-connection/reports-scopes", "nothing to select")
}

func TestAnUnreachableScopeThatDoesNotSayWhy(t *testing.T) {
	l := &liar{describe: describeOK(), events: streamOK(),
		probes: []*collectorv1.ScopeProbe{{Scope: scopeKey, Name: "the scope"}}}
	wantFailure(t, inspect(l), "test-connection/reports-scopes", "does not say why")
}

func TestAStreamThatBreaksTheContract(t *testing.T) {
	events := streamOK()
	events = events[:len(events)-1] // no completion marker
	wantFailure(t, inspect(&liar{describe: describeOK(), events: events}),
		"collect/contract", "completion")
}

// --- resume, the property the whole design rests on ------------------------

func TestStoppingForBudgetWithoutOfferingACursor(t *testing.T) {
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: []*collectorv1.CollectResponse{
			node(collector.ScopeNode(scopeKey, "the scope", "scope")),
			checkpoint("x"),
			completion(&collectorv1.Completion{
				Verdict: collectorv1.Verdict_VERDICT_INCOMPLETE,
				Cause:   collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED,
				Counts:  &collectorv1.Counts{Scopes: 1},
			}),
		},
	}
	wantFailure(t, inspect(l), "collect/resume", "no way back in")
}

// A cursor that silently skips records is worse than no cursor at all,
// because the caller believes they have the whole population.
func TestResumingAndLosingRecords(t *testing.T) {
	budgeted := []*collectorv1.CollectResponse{
		node(collector.ScopeNode(scopeKey, "the scope", "scope")),
		checkpoint("page-2"),
		completion(&collectorv1.Completion{
			Verdict:      collectorv1.Verdict_VERDICT_INCOMPLETE,
			Cause:        collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED,
			ResumeCursor: &collectorv1.Cursor{Token: []byte("page-2")},
			Counts:       &collectorv1.Counts{Scopes: 1},
		}),
	}
	// The resumed half forgets alice entirely.
	resumed := []*collectorv1.CollectResponse{
		node(collector.Entitlement(adminKey, "admin", "role")),
		checkpoint("done"),
		completion(&collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
			Counts:  &collectorv1.Counts{Entitlements: 1},
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey, Status: collector.Collected,
				Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
			}},
		}),
	}
	l := &liar{describe: describeOK(), events: streamOK(), budgeted: budgeted, resumed: resumed}
	wantFailure(t, inspect(l), "collect/resume", "lost")
}

func TestASourceSmallerThanTheBudgetWarnsRatherThanFails(t *testing.T) {
	l := &liar{describe: describeOK(), events: streamOK(), budgeted: streamOK()}
	r := inspect(l)
	if r.Failed() {
		t.Errorf("a source that fits in the budget is not a failure: %v", failuresFor(t, r))
	}
	var warned bool
	for _, res := range r.Results {
		if res.Name == "collect/resume" && res.Warned {
			warned = true
		}
	}
	if !warned {
		t.Error("it should warn that resumption was never exercised")
	}
}

// A capability the configuration never reached is common and harmless.
// Failing on it would push authors to under-declare, which is the outcome the
// suite exists to prevent.
func TestADeclaredButUnusedCapabilityWarnsRatherThanFails(t *testing.T) {
	d := describeOK()
	d.Capabilities.EdgeTypes = append(d.Capabilities.EdgeTypes,
		collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF)

	r := inspect(&liar{describe: d, events: streamOK()})
	if r.Failed() {
		t.Fatalf("declaring more than the fixture exercises is not a breach: %v", failuresFor(t, r))
	}
	var warned bool
	for _, res := range r.Results {
		if res.Warned && strings.Contains(res.Detail, "MEMBER_OF") {
			warned = true
		}
	}
	if !warned {
		t.Error("it should say which declared capability went unexercised")
	}
}

func TestADescriptionThatDoesNotValidateStopsTheRun(t *testing.T) {
	d := describeOK()
	d.Capabilities.Fidelities = []collectorv1.Fidelity{collector.Coarse} // no limitation declared
	r := inspect(&liar{describe: d, events: streamOK()})
	wantFailure(t, r, "describe/valid", "limitation")
	// Nothing downstream is measurable once the description is unusable.
	for _, res := range r.Results {
		if strings.HasPrefix(res.Name, "collect/") {
			t.Errorf("no collect check should run without a usable description, got %q", res.Name)
		}
	}
}

func TestAPluginThatCannotDescribeItself(t *testing.T) {
	r := conformance.Inspect(context.Background(), &brokenDescribe{}, conformance.Options{})
	wantFailure(t, r, "describe/answers", "returned an error")
}

type brokenDescribe struct{ liar }

func (*brokenDescribe) Describe(context.Context) (*collectorv1.DescribeResponse, error) {
	return nil, errors.New("cannot reach my own configuration")
}

// A stream that started from a cursor carries the rest of a population and
// not the whole of one. Ending it COMPLETE lets a caller read a continuation
// as an inventory, which is the failure the whole verdict exists to prevent.
func TestAResumedStreamThatCallsItselfWhole(t *testing.T) {
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(),
		resumed:  restOfIt(collectorv1.Verdict_VERDICT_COMPLETE, 0, nil),
	}
	wantFailure(t, inspect(l), "collect/resume", "must end INCOMPLETE with PARTIAL_STREAM")
}

// Incomplete for the wrong reason is nearly as misleading: a caller retrying
// a rate limit will retry forever.
func TestAResumedStreamThatBlamesSomethingElse(t *testing.T) {
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(),
		resumed: restOfIt(collectorv1.Verdict_VERDICT_INCOMPLETE,
			collectorv1.IncompleteCause_INCOMPLETE_CAUSE_SOURCE_ERROR, nil),
	}
	wantFailure(t, inspect(l), "collect/resume", "rather than PARTIAL_STREAM")
}

// The exception. A collector that could not read the cursor, said so, and
// collected everything from the beginning really did produce a whole
// population, and must say COMPLETE.
func TestARestartedStreamIsWholeAndSaysSo(t *testing.T) {
	rejected := diagnostic("cursor.rejected", "could not read the cursor; started over")
	restart := func(v collectorv1.Verdict, c collectorv1.IncompleteCause,
	) []*collectorv1.CollectResponse {
		events := streamOK()
		events = events[:len(events)-1] // a restart carries everything
		events = append([]*collectorv1.CollectResponse{rejected}, events...)
		return append(events, completion(&collectorv1.Completion{
			Verdict: v, Cause: c, Counts: countsOf(events),
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey, Status: collector.Collected,
				Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
			}},
		}))
	}
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(),
		resumed:  restart(collectorv1.Verdict_VERDICT_COMPLETE, 0),
	}
	if r := inspect(l); r.Failed() {
		t.Errorf("a restart that collected everything is whole: %v", failuresFor(t, r))
	}

	l.resumed = restart(collectorv1.Verdict_VERDICT_INCOMPLETE,
		collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM)
	wantFailure(t, inspect(l), "collect/resume", "started over, which produces a whole population")
}

// budgetedHalf is a first pass that stopped for budget with a cursor.
func budgetedHalf() []*collectorv1.CollectResponse {
	return []*collectorv1.CollectResponse{
		node(collector.ScopeNode(scopeKey, "the scope", "scope")),
		checkpoint("page-2"),
		completion(&collectorv1.Completion{
			Verdict:      collectorv1.Verdict_VERDICT_INCOMPLETE,
			Cause:        collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED,
			ResumeCursor: &collectorv1.Cursor{Token: []byte("page-2")},
			Counts:       &collectorv1.Counts{Scopes: 1},
		}),
	}
}

// restOfIt is a continuation carrying what budgetedHalf did not: everything
// but the scope node, so the union is whole and only the verdict is under
// test.
func restOfIt(verdict collectorv1.Verdict, cause collectorv1.IncompleteCause,
	first *collectorv1.CollectResponse,
) []*collectorv1.CollectResponse {
	events := streamOK()
	events = events[1 : len(events)-1] // no scope node, no completion of its own
	if first != nil {
		events = append([]*collectorv1.CollectResponse{first}, events...)
	}
	return append(events, completion(&collectorv1.Completion{
		Verdict: verdict, Cause: cause,
		Counts: countsOf(events),
		Scopes: []*collectorv1.ScopeOutcome{{
			Scope: scopeKey, Status: collector.Collected,
			Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
		}},
	}))
}

func diagnostic(code, message string) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Diagnostic{
		Diagnostic: &collectorv1.Diagnostic{
			Severity: collectorv1.Severity_SEVERITY_WARNING, Code: code, Message: message,
		}}}
}

// countsOf tallies what a stream actually carried, so a completion cannot
// disagree with it and fail a different check than the one under test.
func countsOf(events []*collectorv1.CollectResponse) *collectorv1.Counts {
	c := &collectorv1.Counts{}
	for _, e := range events {
		switch {
		case e.GetNode() != nil:
			switch e.GetNode().GetKey().GetType() {
			case collectorv1.NodeType_NODE_TYPE_SCOPE:
				c.Scopes++
			case collectorv1.NodeType_NODE_TYPE_IDENTITY:
				c.Identities++
			case collectorv1.NodeType_NODE_TYPE_GROUPING:
				c.Groupings++
			case collectorv1.NodeType_NODE_TYPE_ENTITLEMENT:
				c.Entitlements++
			case collectorv1.NodeType_NODE_TYPE_RESOURCE:
				c.Resources++
			case collectorv1.NodeType_NODE_TYPE_UNSPECIFIED:
			}
		case e.GetEdge() != nil:
			c.Edges++
		case e.GetActivity() != nil:
			c.Activities++
		}
	}
	return c
}

// The configuration the suite was handed is one the collector is supposed to
// accept. Rejecting it means the suite is about to test nothing, and saying
// so beats a run of green checks that never reached the source.
func TestRejectingTheConfigurationTheSuiteWasGiven(t *testing.T) {
	l := &liar{
		describe: describeOK(), events: streamOK(),
		issues: func(c []byte) []*collectorv1.ConfigIssue {
			return []*collectorv1.ConfigIssue{{
				Severity: collectorv1.Severity_SEVERITY_ERROR,
				Code:     "example.no", Message: "not today",
			}}
		},
	}
	wantFailure(t, inspect(l), "validate-config/accepts-valid", "rejected the configuration")
}

// A scope with no human name leaves an operator choosing between opaque ids.
func TestAScopeWithNoName(t *testing.T) {
	l := &liar{
		describe: describeOK(), events: streamOK(),
		probes: []*collectorv1.ScopeProbe{{Scope: scopeKey, Reachable: true}},
	}
	wantFailure(t, inspect(l), "test-connection/reports-scopes", "no human name")
}

// A conservative resume re-emits every node its edges refer to, which can
// mean re-emitting the whole population. That is correct, and it looks
// identical to a restart from out here — so it must not be failed.
func TestAResumeThatReEmitsEverythingIsNotFailed(t *testing.T) {
	events := streamOK()
	events = events[:len(events)-1]
	events = append(events, completion(&collectorv1.Completion{
		Verdict: collectorv1.Verdict_VERDICT_INCOMPLETE,
		Cause:   collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM,
		Counts:  countsOf(events),
		Scopes: []*collectorv1.ScopeOutcome{{
			Scope: scopeKey, Status: collector.Collected,
			Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
		}},
	}))
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(), resumed: events,
	}
	if r := inspect(l); r.Failed() {
		t.Errorf("a resume that re-emitted its referenced nodes was failed: %v", failuresFor(t, r))
	}
}

// A restart the source rate-limited is incomplete for a reason of its own and
// says so; requiring COMPLETE of it would fail a correct collector. Budget is
// not on that list: a resume request carries none, so a stream blaming one is
// claiming something that did not happen.
func TestARestartTheSourceRateLimitedIsNotFailed(t *testing.T) {
	events := streamOK()
	events = events[:len(events)-1]
	events = append([]*collectorv1.CollectResponse{
		diagnostic("cursor.rejected", "could not read the cursor; started over"),
	}, events...)
	events = append(events, completion(&collectorv1.Completion{
		Verdict:      collectorv1.Verdict_VERDICT_INCOMPLETE,
		Cause:        collectorv1.IncompleteCause_INCOMPLETE_CAUSE_RATE_LIMITED,
		ResumeCursor: &collectorv1.Cursor{Token: []byte("page-3")},
		Counts:       countsOf(events),
		Scopes: []*collectorv1.ScopeOutcome{{
			Scope: scopeKey, Status: collector.Collected,
			Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
		}},
	}))
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(), resumed: events,
	}
	if r := inspect(l); r.Failed() {
		t.Errorf("a restart the source rate-limited was failed: %v", failuresFor(t, r))
	}
}

// The hole the restart branch opened: saying "I rejected the cursor" is a
// claim to have started over, and a stream that then carries only the
// remainder is a partial population calling itself whole. The diagnostic
// cannot be a free pass.
func TestARestartThatOnlyCarriedTheRemainder(t *testing.T) {
	rejected := diagnostic("cursor.rejected", "could not read the cursor; started over")
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(),
		resumed:  restOfIt(collectorv1.Verdict_VERDICT_COMPLETE, 0, rejected),
	}
	wantFailure(t, inspect(l), "collect/resume", "missing records a straight-through collection")
}

// And a stream cannot dodge that by blaming a budget the request never set.
func TestAResumedStreamBlamingABudgetItWasNotGiven(t *testing.T) {
	l := &liar{
		describe: describeOK(), events: streamOK(),
		budgeted: budgetedHalf(),
		resumed: restOfIt(collectorv1.Verdict_VERDICT_INCOMPLETE,
			collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED, nil),
	}
	wantFailure(t, inspect(l), "collect/resume", "rather than PARTIAL_STREAM")
}
