package collect_test

import (
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// capture records what the collector emitted and validates every record on the
// way past, as the host would. internal/collect's tests have a fuller one; this
// module cannot import another package's test files.
type capture struct {
	t      *testing.T
	events []*collectorv1.CollectResponse
}

func (c *capture) Node(n *collectorv1.Node) error {
	if vs := collectorv1.ValidateNode(n); len(vs) > 0 {
		c.t.Errorf("invalid node %q: %s", n.GetName(), vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Node{Node: n}})
	return nil
}

func (c *capture) Edge(e *collectorv1.Edge) error {
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 {
		c.t.Errorf("invalid edge: %s", vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Edge{Edge: e}})
	return nil
}

func (c *capture) Activity(a *collectorv1.Activity) error {
	if vs := collectorv1.ValidateActivity(a); len(vs) > 0 {
		c.t.Errorf("invalid activity for %s: %s", a.GetSubject().GetId(), vs[0])
	}
	return nil
}

func (c *capture) Checkpoint([]byte) error                               { return nil }
func (c *capture) Progress(string, *collector.RateLimit) error           { return nil }
func (c *capture) ScopeDone(collector.ScopeResult) error                 { return nil }
func (c *capture) Diagnostic(collectorv1.Severity, string, string) error { return nil }

func (c *capture) nodes() map[string]*collectorv1.Node {
	out := map[string]*collectorv1.Node{}
	for _, e := range c.events {
		if n := e.GetNode(); n != nil {
			out[n.GetKey().GetId()] = n
		}
	}
	return out
}

// holdsFrom returns the ids of everything a subject holds, by any route.
func (c *capture) holdsFrom(subject string) map[string]bool {
	out := map[string]bool{}
	for _, e := range c.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_HOLDS ||
			edge.GetFrom().GetId() != subject {
			continue
		}
		out[edge.GetTo().GetId()] = true
	}
	return out
}
