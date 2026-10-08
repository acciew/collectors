package collect_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

const (
	harnessClient = "00000000-0000-4000-8000-0000000000c1"
	harnessSecret = "synthetic-secret-value"
)

// capture is the stream a collection writes into. It validates every record
// as the SDK does before it goes on the wire, so a test fails on a record the
// contract would refuse and not only on one it did not expect.
type capture struct {
	t           *testing.T
	events      []*collectorv1.CollectResponse
	diags       []*collectorv1.Diagnostic
	scopes      []collector.ScopeResult
	checkpoints [][]byte
	progress    []*collector.RateLimit
	phases      []string
	// err is what Collect returned, when the capture came from world.run.
	err error
}

func (c *capture) add(e *collectorv1.CollectResponse) { c.events = append(c.events, e) }

// bytes is how many bytes the records and checkpoints came to, as the service
// would count them.
func (c *capture) bytes() int {
	n := 0
	for _, e := range c.events {
		n += proto.Size(e)
	}
	return n
}

// total is every event the stream sent: the records and checkpoints in events,
// and the diagnostics and progress that are kept apart.
func (c *capture) total() int { return len(c.events) + len(c.diags) + len(c.phases) }

func (c *capture) Node(n *collectorv1.Node) error {
	if vs := collectorv1.ValidateNode(n); len(vs) > 0 {
		c.t.Errorf("invalid node %q: %s", n.GetName(), vs[0])
	}
	c.add(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: n}})
	return nil
}

func (c *capture) Edge(e *collectorv1.Edge) error {
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 {
		c.t.Errorf("invalid edge: %s", vs[0])
	}
	c.add(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Edge{Edge: e}})
	return nil
}

func (c *capture) Activity(a *collectorv1.Activity) error {
	if vs := collectorv1.ValidateActivity(a); len(vs) > 0 {
		c.t.Errorf("invalid activity: %s", vs[0])
	}
	c.add(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Activity{Activity: a}})
	return nil
}

func (c *capture) Checkpoint(cursor []byte) error {
	c.checkpoints = append(c.checkpoints, cursor)
	c.add(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{
		Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: cursor}}}})
	return nil
}

func (c *capture) Progress(phase string, rl *collector.RateLimit) error {
	c.phases = append(c.phases, phase)
	if rl != nil {
		c.progress = append(c.progress, rl)
	}
	return nil
}

func (c *capture) ScopeDone(r collector.ScopeResult) error {
	c.scopes = append(c.scopes, r)
	return nil
}

func (c *capture) Diagnostic(sev collectorv1.Severity, code, message string) error {
	d := &collectorv1.Diagnostic{Severity: sev, Code: code, Message: message}
	if vs := collectorv1.ValidateDiagnostic(d); len(vs) > 0 {
		c.t.Errorf("invalid diagnostic: %s", vs[0])
	}
	c.diags = append(c.diags, d)
	return nil
}

func (c *capture) diag(code string) *collectorv1.Diagnostic {
	for _, d := range c.diags {
		if d.GetCode() == code {
			return d
		}
	}
	return nil
}

func (c *capture) node(scope, typ, id string) *collectorv1.Node {
	for _, e := range c.events {
		if n := e.GetNode(); n != nil && n.GetKey().GetId() == id && n.GetKey().GetType().String() == typ {
			return n
		}
	}
	return nil
}

// edges returns every edge of a type between two ids.
func (c *capture) edges(typ collectorv1.EdgeType, from, to string) []*collectorv1.Edge {
	var out []*collectorv1.Edge
	for _, e := range c.events {
		if ed := e.GetEdge(); ed != nil && ed.GetType() == typ &&
			ed.GetFrom().GetId() == from && ed.GetTo().GetId() == to {
			out = append(out, ed)
		}
	}
	return out
}

func (c *capture) activities(subject string) map[string]*collectorv1.Activity {
	out := map[string]*collectorv1.Activity{}
	for _, e := range c.events {
		if a := e.GetActivity(); a != nil && a.GetSubject().GetId() == subject {
			out[a.GetSignal()] = a
		}
	}
	return out
}

func (c *capture) count(pick func(*collectorv1.CollectResponse) bool) int {
	n := 0
	for _, e := range c.events {
		if pick(e) {
			n++
		}
	}
	return n
}

// completion is the marker the SDK would end the stream with: the verdict the
// collection returned, the counts of what was sent, and one outcome for each scope
// it reported.
func (c *capture) completion() *collectorv1.Completion {
	var counts collectorv1.Counters
	for _, e := range c.events {
		switch {
		case e.GetNode() != nil:
			counts.CountNode(e.GetNode())
		case e.GetEdge() != nil:
			counts.Edges++
		case e.GetActivity() != nil:
			counts.Activities++
		}
	}
	done := &collectorv1.Completion{Counts: counts.Proto(), Verdict: collectorv1.Verdict_VERDICT_COMPLETE}
	whole := true
	for _, r := range c.scopes {
		o := &collectorv1.ScopeOutcome{Scope: r.Scope, Status: r.Status}
		if r.Err != nil {
			o.Error = &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_SOURCE_ERROR, Message: r.Err.Error()}
		}
		if r.Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED && r.Status != collectorv1.ScopeStatus_SCOPE_STATUS_SKIPPED {
			whole = false
		}
		done.Scopes = append(done.Scopes, o)
	}
	if inc, ok := collector.AsIncomplete(c.err); ok {
		done.Verdict, done.Cause = collectorv1.Verdict_VERDICT_INCOMPLETE, inc.Cause
	} else if !whole {
		done.Verdict, done.Cause = collectorv1.Verdict_VERDICT_INCOMPLETE, collector.ScopeUnreachable
	}
	return done
}

// assertContract holds the stream to the rules the host and the conformance
// suite hold it to: every record valid, every referenced node emitted, every
// hop of every path an edge that was stated, and the completion the SDK would
// end each stream with agrees with what was sent.
func (c *capture) assertContract(extra ...*capture) {
	c.t.Helper()
	checker := collectorv1.NewStreamChecker()
	for _, cp := range append([]*capture{c}, extra...) {
		for _, e := range cp.events {
			for _, v := range collectorv1.ValidateEvent(e) {
				c.t.Errorf("%s", v)
			}
			for _, v := range checker.Event(e) {
				c.t.Errorf("%s", v)
			}
		}
		done := cp.completion()
		for _, v := range collectorv1.ValidateCompletion(done) {
			c.t.Errorf("%s", v)
		}
		for _, v := range checker.Event(&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: done}}) {
			c.t.Errorf("%s", v)
		}
		for _, v := range checker.EndStream() {
			c.t.Errorf("%s", v)
		}
	}
	for _, v := range checker.Close() {
		c.t.Errorf("%s", v)
	}
}

type world struct {
	t      *testing.T
	srv    *fakegraph.Server
	client *graph.Client
	// waited is every pause the collector asked for, instead of making it.
	waited []time.Duration
}

// newWorld starts a fake Graph around a tenant and signs in to it.
func newWorld(t *testing.T, tenant *fakegraph.Tenant) *world {
	t.Helper()
	srv := fakegraph.New(t, tenant)
	srv.AcceptSecret(harnessClient, harnessSecret)
	client, err := graph.Dial(context.Background(), graph.Config{
		TenantID: tenant.ID, ClientID: harnessClient, ClientSecret: harnessSecret,
		Endpoints: graph.Endpoints{Login: srv.URL, Graph: srv.URL},
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return &world{t: t, srv: srv, client: client}
}

// config is a valid configuration with the collect flags as given.
func config(t *testing.T, collectFlags string) collect.Config {
	t.Helper()
	body := fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":"env:S"`, tenantGUID, harnessClient)
	if collectFlags != "" {
		body += `,"collect":` + collectFlags
	}
	cfg, issues := collect.Validate([]byte(body + "}"))
	if got := errorsOf(issues); len(got) != 0 {
		t.Fatalf("config: %v", got)
	}
	return cfg
}

// runner is a Run against the fake, whose pauses are recorded and not made.
func (w *world) runner(flags string) collect.Run {
	return collect.Run{
		Graph: w.client, Config: config(w.t, flags),
		Now: func() time.Time { return now },
		Wait: func(_ context.Context, d time.Duration) error {
			w.waited = append(w.waited, d)
			return nil
		},
	}
}

// run collects with the given flags.
func (w *world) run(flags string, req collector.CollectRequest) (*capture, error) {
	w.t.Helper()
	out := &capture{t: w.t}
	out.err = w.runner(flags).Collect(context.Background(), req, out)
	return out, out.err
}

func (w *world) mustRun(flags string) *capture {
	w.t.Helper()
	out, err := w.run(flags, collector.CollectRequest{})
	if err != nil {
		w.t.Fatalf("Collect: %v", err)
	}
	return out
}

// partFailed says the failure names a part as one that failed. Each reason the
// tenant is not whole starts with the part, and the reasons are joined a line at
// a time.
func partFailed(err error, part string) bool {
	if err == nil {
		return false
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), part+": ") {
			return true
		}
	}
	return false
}
