package conformance

import (
	"bytes"
	"context"
	"fmt"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// Inspect runs every check against a plugin and returns what it found.
//
// It takes no *testing.T, so the checks can be exercised directly and so the
// suite can be used outside a test — by a CLI that validates a plugin before
// registering it, for instance.
func Inspect(ctx context.Context, p Plugin, opts Options) *Report {
	r := &Report{}

	described, results := checkDescribe(ctx, p)
	r.add(results...)
	if described == nil {
		// Everything below is measured against what the plugin said it can
		// do. Without that there is nothing to measure against.
		return r
	}

	r.add(checkRevoke(ctx, p)...)
	r.add(checkValidateConfig(ctx, p, opts)...)
	r.add(checkTestConnection(ctx, p, opts)...)

	events, results := checkCollect(ctx, p, opts)
	r.add(results...)
	if events == nil {
		return r
	}

	r.add(checkDeclaredMatchesEmitted(described, events)...)
	r.add(checkActivityAccounting(described, events)...)
	r.add(checkResume(ctx, p, opts, events)...)
	return r
}

func checkDescribe(ctx context.Context, p Plugin) (*collectorv1.DescribeResponse, []Result) {
	d, err := p.Describe(ctx)
	if err != nil {
		return nil, []Result{fail("describe/answers", "Describe returned an error: %v", err)}
	}
	out := []Result{pass("describe/answers")}

	if vs := collectorv1.ValidateDescribeResponse(d); len(vs) > 0 {
		out = append(out, fail("describe/valid", "%s", vs[0]))
		return nil, out
	}
	out = append(out, pass("describe/valid"))

	// This is the one check the suite enforces as policy rather than
	// as contract: write-back is a different risk class and a different sale.
	if d.GetCapabilities().GetRevoke() {
		out = append(out, fail("describe/revoke-not-declared",
			"capabilities.revoke is true; no collector may declare revocation yet"))
	} else {
		out = append(out, pass("describe/revoke-not-declared"))
	}
	return d, out
}

func checkRevoke(ctx context.Context, p Plugin) []Result {
	resp, err := p.Revoke(ctx, &collectorv1.RevokeRequest{})
	if err != nil {
		// An error is acceptable: the plugin refused. What is not acceptable
		// is claiming to have revoked something.
		return []Result{pass("revoke/not-supported")}
	}
	if resp.GetOutcome() != collectorv1.RevokeOutcome_REVOKE_OUTCOME_NOT_SUPPORTED {
		return []Result{fail("revoke/not-supported",
			"Revoke answered %v; a collector must answer NOT_SUPPORTED while revocation is not implemented", resp.GetOutcome())}
	}
	return []Result{pass("revoke/not-supported")}
}

func checkValidateConfig(ctx context.Context, p Plugin, opts Options) []Result {
	// Malformed JSON is the one input every plugin must reject, whatever its
	// schema, and the empty field path is how the contract addresses "the
	// document as a whole".
	issues, err := p.ValidateConfig(ctx, []byte("{not json"))
	if err != nil {
		return []Result{fail("validate-config/rejects-malformed",
			"ValidateConfig returned a transport error on malformed input rather than an issue: %v", err)}
	}
	if !hasError(issues) {
		return []Result{fail("validate-config/rejects-malformed",
			"ValidateConfig accepted a document that is not JSON")}
	}
	out := []Result{pass("validate-config/rejects-malformed")}

	if len(opts.Config) > 0 {
		issues, err = p.ValidateConfig(ctx, opts.Config)
		switch {
		case err != nil:
			out = append(out, fail("validate-config/accepts-valid",
				"ValidateConfig errored on the configuration this suite was given: %v", err))
		case hasError(issues):
			out = append(out, fail("validate-config/accepts-valid",
				"ValidateConfig rejected the configuration this suite was given: %s",
				issues[0].GetMessage()))
		default:
			out = append(out, pass("validate-config/accepts-valid"))
		}
	}
	return out
}

func hasError(issues []*collectorv1.ConfigIssue) bool {
	for _, i := range issues {
		if i.GetSeverity() == collectorv1.Severity_SEVERITY_ERROR {
			return true
		}
	}
	return false
}

func checkTestConnection(ctx context.Context, p Plugin, opts Options) []Result {
	probes, err := p.TestConnection(ctx, opts.Config)
	if err != nil {
		return []Result{fail("test-connection/reports-scopes",
			"TestConnection returned an error: %v", err)}
	}
	if len(probes) == 0 {
		// A source with no scopes is not impossible, but it is far more often
		// a collector that forgot to enumerate them, and the operator ends up
		// with nothing to choose from.
		return []Result{fail("test-connection/reports-scopes",
			"TestConnection reported no scopes at all; an operator has nothing to select")}
	}
	for i, probe := range probes {
		if probe.GetName() == "" {
			return []Result{fail("test-connection/reports-scopes",
				"scope %d has no human name", i)}
		}
		if !probe.GetReachable() && probe.GetError() == nil {
			return []Result{fail("test-connection/reports-scopes",
				"scope %q is unreachable and does not say why", probe.GetName())}
		}
	}
	return []Result{pass("test-connection/reports-scopes")}
}

func checkCollect(ctx context.Context, p Plugin, opts Options) ([]*collectorv1.CollectResponse, []Result) {
	events, err := p.Collect(ctx, &collectorv1.CollectRequest{Config: opts.Config})
	if err != nil {
		return nil, []Result{fail("collect/completes", "Collect failed: %v", err)}
	}
	out := []Result{pass("collect/completes")}

	// Every record-level rule, then every stream-level rule. This is the same
	// implementation the host runs, so a plugin that passes here passes there.
	checker := collectorv1.NewStreamChecker()
	var violations []collectorv1.Violation
	for _, e := range events {
		violations = append(violations, collectorv1.ValidateEvent(e)...)
		violations = append(violations, checker.Event(e)...)
	}
	violations = append(violations, checker.EndStream()...)
	violations = append(violations, checker.Close()...)

	if len(violations) > 0 {
		for _, v := range violations[:min(len(violations), 5)] {
			out = append(out, fail("collect/contract", "%s", v))
		}
		return events, out
	}
	out = append(out, pass("collect/contract"))

	if done := completionOf(events); done.GetVerdict() != collectorv1.Verdict_VERDICT_COMPLETE {
		out = append(out, fail("collect/complete-population",
			"the collection ended %v (%v); a conformance run should collect everything it can reach",
			done.GetVerdict(), done.GetCause()))
	} else {
		out = append(out, pass("collect/complete-population"))
	}
	return events, out
}

// checkDeclaredMatchesEmitted is the rule the suite exists for. A plugin that
// emits a type it did not declare has told the host to degrade in a way that
// does not match what it does.
func checkDeclaredMatchesEmitted(d *collectorv1.DescribeResponse, events []*collectorv1.CollectResponse) []Result {
	caps := d.GetCapabilities()
	nodeTypes := map[collectorv1.NodeType]bool{}
	edgeTypes := map[collectorv1.EdgeType]bool{}
	fidelities := map[collectorv1.Fidelity]bool{}
	signals := map[string]bool{}

	for _, t := range caps.GetNodeTypes() {
		nodeTypes[t] = false
	}
	for _, t := range caps.GetEdgeTypes() {
		edgeTypes[t] = false
	}
	for _, f := range caps.GetFidelities() {
		fidelities[f] = false
	}
	for _, s := range d.GetActivitySignals() {
		signals[s.GetName()] = false
	}

	var out []Result
	for _, e := range events {
		switch ev := e.GetEvent().(type) {
		case *collectorv1.CollectResponse_Node:
			t := ev.Node.GetKey().GetType()
			if _, declared := nodeTypes[t]; !declared {
				out = append(out, fail("collect/declared-types",
					"emitted a %v node, which Describe did not declare", t))
			}
			nodeTypes[t] = true
		case *collectorv1.CollectResponse_Edge:
			if _, declared := edgeTypes[ev.Edge.GetType()]; !declared {
				out = append(out, fail("collect/declared-types",
					"emitted a %v edge, which Describe did not declare", ev.Edge.GetType()))
			}
			edgeTypes[ev.Edge.GetType()] = true
			if _, declared := fidelities[ev.Edge.GetFidelity()]; !declared {
				out = append(out, fail("collect/declared-fidelities",
					"emitted a %v grant, which Describe did not declare", ev.Edge.GetFidelity()))
			}
			fidelities[ev.Edge.GetFidelity()] = true
		case *collectorv1.CollectResponse_Activity:
			name := ev.Activity.GetSignal()
			if _, declared := signals[name]; !declared {
				out = append(out, fail("collect/declared-signals",
					"emitted activity signal %q, which Describe did not declare", name))
			}
			signals[name] = true
		}
	}

	// The other direction is a warning, not a failure: a capability the test
	// configuration never reached is common and harmless, and treating it as
	// a breach would push authors to under-declare.
	for t, seen := range nodeTypes {
		if !seen {
			out = append(out, warn("collect/declared-types",
				"declared %v but emitted none; the test configuration may not reach it", t))
		}
	}
	for t, seen := range edgeTypes {
		if !seen {
			out = append(out, warn("collect/declared-types", "declared %v but emitted none", t))
		}
	}
	if len(out) == 0 {
		out = append(out, pass("collect/declared-types"))
	}
	return out
}

// checkActivityAccounting enforces R4's total accounting: if a plugin claims
// activity data, every identity is either accounted for or explicitly
// unaccountable. Silence is the one answer that is not allowed, because a
// reviewer reads it as "never used".
func checkActivityAccounting(d *collectorv1.DescribeResponse, events []*collectorv1.CollectResponse) []Result {
	claimed := d.GetCapabilities().GetActivity()

	identities := map[string]bool{}
	covered := map[string]bool{}
	unanswerable := map[string]bool{}
	activities := 0

	for _, e := range events {
		switch ev := e.GetEvent().(type) {
		case *collectorv1.CollectResponse_Node:
			if ev.Node.GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY {
				identities[keyOf(ev.Node.GetKey())] = true
			}
		case *collectorv1.CollectResponse_Activity:
			activities++
			covered[keyOf(ev.Activity.GetSubject())] = true
		case *collectorv1.CollectResponse_Completion:
			for _, s := range ev.Completion.GetScopes() {
				switch s.GetActivity() {
				case collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNAVAILABLE,
					collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_UNDETERMINED:
					unanswerable[s.GetScope().GetScope()] = true
				}
			}
		}
	}

	if !claimed {
		if activities > 0 {
			return []Result{fail("collect/activity-accounting",
				"emitted %d activity records without declaring the activity capability", activities)}
		}
		return []Result{pass("collect/activity-accounting")}
	}

	var unaccounted []string
	for id := range identities {
		if covered[id] {
			continue
		}
		// A scope that answers nothing for anyone, or could not find out
		// whether it would, excuses every identity in it. That is what stops
		// a plugin emitting one Unavailable record per user in a realm with
		// event storage off.
		if unanswerable[scopeOf(id)] {
			continue
		}
		unaccounted = append(unaccounted, id)
	}
	if len(unaccounted) > 0 {
		return []Result{fail("collect/activity-accounting",
			"declared activity but %d identities have neither an activity record nor a scope that says activity is unavailable or undetermined (for example %s); silence reads as \"never used\"",
			len(unaccounted), unaccounted[0])}
	}
	return []Result{pass("collect/activity-accounting")}
}

// checkResume proves the property the whole resume design rests on: stopping
// early and starting again produces the same population as running straight
// through. A cursor that silently skips records is worse than no cursor.
func checkResume(ctx context.Context, p Plugin, opts Options, full []*collectorv1.CollectResponse) []Result {
	first, err := p.Collect(ctx, &collectorv1.CollectRequest{
		Config: opts.Config,
		Budget: &collectorv1.Budget{MaxRecords: 1},
	})
	if err != nil {
		return []Result{fail("collect/resume", "a budgeted collection failed: %v", err)}
	}

	done := completionOf(first)
	if done.GetVerdict() == collectorv1.Verdict_VERDICT_COMPLETE {
		// The source is smaller than the budget. Nothing is wrong; there is
		// simply nothing to prove.
		return []Result{warn("collect/resume",
			"the source fits inside a one-record budget, so resumption was not exercised")}
	}
	if done.GetCause() != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED {
		return []Result{fail("collect/resume",
			"a budgeted collection ended %v rather than BUDGET_EXHAUSTED", done.GetCause())}
	}
	cursor := done.GetResumeCursor().GetToken()
	if len(cursor) == 0 {
		return []Result{fail("collect/resume",
			"stopped for budget without offering a cursor; resume is mandatory, so there is no way back in")}
	}

	rest, err := p.Collect(ctx, &collectorv1.CollectRequest{
		Config:     opts.Config,
		ResumeFrom: &collectorv1.Cursor{Token: cursor},
	})
	if err != nil {
		return []Result{fail("collect/resume", "resuming failed: %v", err)}
	}

	union := keySet(first)
	for k := range keySet(rest) {
		union[k] = true
	}
	whole := keySet(full)
	var missing []string
	for k := range whole {
		if !union[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return []Result{fail("collect/resume",
			"resuming lost %d records that a straight-through collection produced (for example %s)",
			len(missing), missing[0])}
	}

	// What the continuation calls itself. A stream that started from a cursor
	// carries the rest of a population and not the whole of one, so ending it
	// COMPLETE lets a caller read a continuation as an inventory. The
	// exception is a collector that could not read the cursor, said so, and
	// collected everything from the beginning: that stream really is whole.
	restarted := hasDiagnostic(rest, "cursor.rejected")
	verdict := completionOf(rest).GetVerdict()
	cause := completionOf(rest).GetCause()
	// A restart the source rate-limited is incomplete for a reason of its own
	// and says so. Budget is not on that list: this request carried none, so
	// a stream claiming the caller's budget stopped it is claiming something
	// that did not happen — and it would be a way to dodge the rule below.
	stoppedEarly := cause == collectorv1.IncompleteCause_INCOMPLETE_CAUSE_RATE_LIMITED
	// What this cannot check: a collector that ignores the cursor, re-collects
	// everything and says nothing. A resumed stream may legitimately re-emit
	// nodes its edges refer to — it need not, since referential integrity is
	// checked across the resumed pair rather than per stream, but it is
	// allowed to — so carrying everything is not evidence of a restart. The
	// contract's requirement to announce one is left to the author.
	//
	// What it can check is the claim, which is the part that misleads: a
	// stream saying it restarted, and therefore whole, has to hold
	// everything a straight-through run produced.
	//
	// Both this and the missing-records check above compare against a run
	// taken moments earlier, so a source that changed in between can make
	// either look like a loss. That is the suite's shape rather than this
	// rule's: a conformance run wants a source that is holding still.
	switch {
	case restarted && verdict == collectorv1.Verdict_VERDICT_COMPLETE &&
		!containsAll(keySet(rest), whole):
		return []Result{fail("collect/resume",
			"the stream says it rejected the cursor and started over, which would make it a "+
				"whole population, but it is missing records a straight-through collection "+
				"produced")}
	case restarted && !stoppedEarly && verdict != collectorv1.Verdict_VERDICT_COMPLETE:
		return []Result{fail("collect/resume",
			"the cursor was rejected and the collection started over, which produces a whole "+
				"population, but the stream ended %v", verdict)}
	case restarted && stoppedEarly:
		// It restarted and stopped for its own reason. Nothing to assert.
	case !restarted && verdict != collectorv1.Verdict_VERDICT_INCOMPLETE:
		return []Result{fail("collect/resume",
			"a resumed stream ended %v; it carries the rest of a population and not the whole "+
				"of one, so it must end INCOMPLETE with PARTIAL_STREAM", verdict)}
	case !restarted && !stoppedEarly &&
		cause != collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM:
		return []Result{fail("collect/resume",
			"a resumed stream ended INCOMPLETE for %v rather than PARTIAL_STREAM", cause)}
	}
	return []Result{pass("collect/resume")}
}

// containsAll says whether got holds every key in want.
func containsAll(got, want map[string]bool) bool {
	for k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

func hasDiagnostic(events []*collectorv1.CollectResponse, code string) bool {
	for _, e := range events {
		if e.GetDiagnostic().GetCode() == code {
			return true
		}
	}
	return false
}

func keySet(events []*collectorv1.CollectResponse) map[string]bool {
	out := map[string]bool{}
	for _, e := range events {
		switch ev := e.GetEvent().(type) {
		case *collectorv1.CollectResponse_Node:
			out["node:"+keyOf(ev.Node.GetKey())] = true
		case *collectorv1.CollectResponse_Edge:
			out[fmt.Sprintf("edge:%v:%s->%s", ev.Edge.GetType(),
				keyOf(ev.Edge.GetFrom()), keyOf(ev.Edge.GetTo()))] = true
		case *collectorv1.CollectResponse_Activity:
			out["activity:"+keyOf(ev.Activity.GetSubject())+":"+ev.Activity.GetSignal()] = true
		}
	}
	return out
}

func completionOf(events []*collectorv1.CollectResponse) *collectorv1.Completion {
	for i := len(events) - 1; i >= 0; i-- {
		if done := events[i].GetCompletion(); done != nil {
			return done
		}
	}
	return nil
}

func keyOf(k *collectorv1.Key) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\x00%d\x00%s", k.GetScope(), int32(k.GetType()), k.GetId())
	return b.String()
}

func scopeOf(key string) string {
	if i := bytes.IndexByte([]byte(key), 0); i >= 0 {
		return key[:i]
	}
	return key
}
