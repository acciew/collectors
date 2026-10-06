// Stream-level contract rules: the ones that are properties of a whole
// collection rather than of any single record.
//
// R15. A stream that ends without a completion marker is not a short stream,
// it is an unfinished one, and over gRPC the two look identical. A path that
// names a route nobody emitted is a resolution bug the plugin cannot see. A
// count that disagrees with what arrived means the plugin does not know what
// it sent. None of these can be detected one record at a time.
//
// See docs/adr/0006-collector-contract-shape.md.

package collectorv1

import (
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"
)

const (
	ruleCompletionOnce     = "completion-exactly-once"
	ruleCompletionLast     = "completion-must-be-last"
	ruleCompletionMissing  = "completion-required"
	ruleCountsAgree        = "counts-must-match-what-was-sent"
	ruleNodeUnknown        = "referenced-node-was-never-emitted"
	ruleDuplicateNode      = "duplicate-node-key-must-be-identical"
	rulePathHopNotEmitted  = "path-hop-must-be-an-emitted-edge"
	rulePathHopDerived     = "path-hop-must-be-stated-not-derived"
	ruleEdgeTypeUnroutable = "path-hop-has-no-valid-edge-type"
	ruleActivityDuplicate  = "activity-must-be-unique-per-subject-and-signal"
	ruleCheckpointRequired = "checkpoint-required"
)

// StreamChecker validates a collection as a whole.
//
// Where it belongs. This is for the conformance suite, for tests, and for any
// caller working over a bounded collection. It is deliberately not the shape
// of a production host check: referential integrity and path walks cannot be
// answered until every record has arrived, so the checker retains a digest per
// node and every path-bearing edge, and that is linear in the size of the
// tenant. Measured at roughly 270 bytes per edge, which is fine for a
// conformance fixture and wrong for a fifty-thousand-user tenant on top of the
// host's own copy of the same graph.
//
// A production host should validate each record as it streams (ValidateEvent
// is O(1) and holds nothing), enforce the completion and count rules per
// stream, and defer referential integrity and path walks to the store, where
// they are a foreign key and a recursive query over data that is on disk
// anyway. See docs/adr/0006-collector-contract-shape.md.
//
// Usage, including across a resumed collection:
//
//	c := NewStreamChecker()
//	for each stream {
//	    for each event { c.Event(ev) }
//	    c.EndStream()
//	}
//	violations := c.Close()
//
// Event and EndStream report what can be known at that point. Close reports
// the rest: referential integrity and path walks cannot be checked until every
// record has arrived, because a plugin may legitimately emit an edge before
// the nodes it connects.
type StreamChecker struct {
	// A digest rather than the node: all this map is for is knowing that a key
	// arrived and noticing if it arrived twice saying different things.
	// Retaining the whole message would mean holding the inventory in memory
	// beside the host's own copy of it.
	nodes map[string]nodeDigest
	// stated holds edges emitted with no path, which is what "the source said
	// so" means here; derived holds edges that carry one. A path hop must be
	// found in stated. Keeping derived separately is what lets the checker say
	// "you routed through a derivation" instead of the much less useful "no
	// such edge".
	stated  map[string]bool
	derived map[string]bool

	// per-stream
	observed  Counters
	completed *Completion
	afterDone bool

	// accumulated across streams. Only references that are still unresolved
	// and only edges that carry a path: everything else is answered as it
	// arrives and does not need keeping.
	pendingKeys []keyRef
	pendingEdge []*Edge
	checkpoints int
	records     int
	activities  map[string]bool
	streams     int
}

type keyRef struct {
	key   string
	where string
}

// nodeDigest identifies a node's content without retaining it.
type nodeDigest [16]byte

func digestOf(n *Node) nodeDigest {
	// Deterministic marshalling so two encodings of the same node compare
	// equal; map field ordering would otherwise vary within a single run.
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(n)
	if err != nil {
		return nodeDigest{}
	}
	sum := sha256.Sum256(b)
	var d nodeDigest
	copy(d[:], sum[:])
	return d
}

// NewStreamChecker returns a checker ready for the first stream.
func NewStreamChecker() *StreamChecker {
	return &StreamChecker{
		nodes:      map[string]nodeDigest{},
		stated:     map[string]bool{},
		derived:    map[string]bool{},
		activities: map[string]bool{},
	}
}

// Event records one stream event and reports anything detectable immediately.
func (c *StreamChecker) Event(e *CollectResponse) []Violation {
	if e == nil {
		return missingRecord("event")
	}
	if c.afterDone {
		// The completion marker is the promise that nothing follows it. A
		// consumer that has already acted on it cannot un-act.
		if _, second := e.GetEvent().(*CollectResponse_Completion); second {
			return []Violation{{
				Field:   "completion",
				Rule:    ruleCompletionOnce,
				Message: "a second completion marker arrived",
			}}
		}
		return []Violation{{
			Field:   "event",
			Rule:    ruleCompletionLast,
			Message: "an event arrived after the completion marker",
		}}
	}

	switch event := e.GetEvent().(type) {
	case *CollectResponse_Node:
		return c.node(event.Node)
	case *CollectResponse_Edge:
		return c.edge(event.Edge)
	case *CollectResponse_Activity:
		return c.activity(event.Activity)
	case *CollectResponse_Checkpoint:
		c.checkpoints++
	case *CollectResponse_Completion:
		return c.completion(event.Completion)
	}
	return nil
}

func (c *StreamChecker) node(n *Node) []Violation {
	if n == nil || n.GetKey() == nil {
		return nil // ValidateNode's job; nothing to accumulate.
	}
	c.observed.CountNode(n)

	c.records++
	id := keyString(n.GetKey())
	// A repeated key is expected across a resumed collection: a plugin that
	// cannot use a cursor may restart from the beginning, which the contract
	// allows. Harmless as long as it says the same thing; two different
	// answers to the same question is a defect the host cannot resolve.
	d := digestOf(n)
	if prev, seen := c.nodes[id]; seen && prev != d {
		return []Violation{{
			Field:   "node",
			Rule:    ruleDuplicateNode,
			Message: fmt.Sprintf("node %s was emitted twice with different content", id),
		}}
	}
	c.nodes[id] = d
	return nil
}

// refer records a key that some record points at, unless the node it names has
// already arrived. Most streams emit nodes before the things that reference
// them, so this keeps the pending list near empty in the common case.
func (c *StreamChecker) refer(k *Key, where string) {
	if k == nil {
		return
	}
	id := keyString(k)
	if _, known := c.nodes[id]; known {
		return
	}
	c.pendingKeys = append(c.pendingKeys, keyRef{id, where})
}

func (c *StreamChecker) edge(e *Edge) []Violation {
	if e == nil {
		return nil
	}
	c.observed.Edges++
	c.records++
	if len(e.GetPath().GetVia()) > 0 {
		// Only path-bearing edges are re-examined at Close. Keeping the rest
		// would retain the whole graph to check nothing.
		c.pendingEdge = append(c.pendingEdge, e)
	}
	// What makes an edge a derivation is that it carries a path, not what its
	// fidelity says. Keying on fidelity made the rule inert for AWS: every AWS
	// grant is COARSE (ADR-0003), so a chain of COARSE-with-a-path edges would
	// each be filed as a fact the source stated and launder itself.
	hop := edgeString(e.GetFrom(), e.GetTo())
	if len(e.GetPath().GetVia()) > 0 {
		c.derived[hop] = true
	} else {
		c.stated[hop] = true
	}
	c.refer(e.GetFrom(), "edge.from")
	c.refer(e.GetTo(), "edge.to")
	for i, via := range e.GetPath().GetVia() {
		c.refer(via, fmt.Sprintf("edge.path.via[%d]", i))
	}
	return nil
}

func (c *StreamChecker) activity(a *Activity) []Violation {
	c.observed.Activities++
	c.records++
	c.refer(a.GetSubject(), "activity.subject")

	// One record per (subject, signal). Two answers for the same question let
	// a consumer pick whichever it saw last.
	if a.GetSubject() != nil && a.GetSignal() != "" {
		id := keyString(a.GetSubject()) + "\x00" + a.GetSignal()
		if c.activities[id] {
			return []Violation{{
				Field: "activity",
				Rule:  ruleActivityDuplicate,
				Message: fmt.Sprintf("a second %q record arrived for %s",
					a.GetSignal(), keyString(a.GetSubject())),
			}}
		}
		c.activities[id] = true
	}
	return nil
}

func (c *StreamChecker) completion(done *Completion) []Violation {
	c.completed = done
	c.afterDone = true
	return nil
}

// EndStream closes one stream and reports what only its ending reveals.
func (c *StreamChecker) EndStream() []Violation {
	c.streams++
	var vs []Violation

	if c.completed == nil {
		// This is the rule the whole file exists for. Over gRPC a truncated
		// stream closes cleanly and looks successful; a truncated population
		// presented as whole is worse than a failure.
		vs = append(vs, Violation{
			Field:   "completion",
			Rule:    ruleCompletionMissing,
			Message: "the stream ended without a completion marker, so its population cannot be trusted",
		})
	} else {
		if declared := c.completed.GetCounts(); declared != nil {
			vs = append(vs, c.observed.Disagreements(declared)...)
		}
		for i, s := range c.completed.GetScopes() {
			// A verdict of COLLECTED for a scope no node was ever emitted for
			// is a claim about a place we have no evidence of visiting.
			c.refer(s.GetScope(), fmt.Sprintf("completion.scopes[%d].scope", i))
		}
		// Resume is mandatory, so a stream that sent records without ever
		// offering a resume point cannot be resumed and has not honoured it.
		if c.records > 0 && c.checkpoints == 0 {
			vs = append(vs, Violation{
				Field:   "checkpoint",
				Rule:    ruleCheckpointRequired,
				Message: "a stream that emits records must offer at least one checkpoint to resume from",
			})
		}
	}

	c.observed = Counters{}
	c.completed = nil
	c.afterDone = false
	c.checkpoints = 0
	c.records = 0
	return vs
}

// Close reports the checks that need every record to have arrived.
func (c *StreamChecker) Close() []Violation {
	var vs []Violation

	for _, ref := range c.pendingKeys {
		if _, ok := c.nodes[ref.key]; !ok {
			vs = append(vs, Violation{
				Field: ref.where,
				Rule:  ruleNodeUnknown,
				Message: fmt.Sprintf("%s refers to %s, which was never emitted as a node",
					ref.where, ref.key),
			})
		}
	}
	for _, e := range c.pendingEdge {
		vs = append(vs, c.checkPath(e)...)
	}
	return vs
}

// checkPath enforces the rule that makes R3 checkable: a path is a walk over
// edges the plugin actually emitted, each stated by the source rather than
// derived. It turns "the resolution logic is correct" into something a fixture
// can assert, instead of something a reviewer discovers from wrong evidence.
func (c *StreamChecker) checkPath(e *Edge) []Violation {
	via := e.GetPath().GetVia()
	if len(via) == 0 {
		return nil
	}
	var vs []Violation

	hops := make([]*Key, 0, len(via)+2)
	hops = append(hops, e.GetFrom())
	hops = append(hops, via...)
	hops = append(hops, e.GetTo())

	for i := 0; i < len(hops)-1; i++ {
		from, to := hops[i], hops[i+1]
		if from == nil || to == nil {
			continue
		}
		at := fmt.Sprintf("edge.path[%d]", i)

		if !canRoute(from.GetType(), to.GetType()) {
			vs = append(vs, Violation{
				Field: at,
				Rule:  ruleEdgeTypeUnroutable,
				Message: fmt.Sprintf("no edge type connects %v to %v, so this hop cannot exist",
					from.GetType(), to.GetType()),
			})
			continue
		}
		hop := edgeString(from, to)
		switch {
		case c.stated[hop]:
			// The hop is a fact the source asserted. Good.
		case c.derived[hop]:
			vs = append(vs, Violation{
				Field: at,
				Rule:  rulePathHopDerived,
				Message: fmt.Sprintf("the hop %s to %s exists only as a derivation; a path is a walk over facts the source stated",
					keyString(from), keyString(to)),
			})
		default:
			vs = append(vs, Violation{
				Field: at,
				Rule:  rulePathHopNotEmitted,
				Message: fmt.Sprintf("the path claims %s to %s, but no such edge was emitted",
					keyString(from), keyString(to)),
			})
		}
	}
	return vs
}

// canRoute reports whether any edge type connects these two node types. It is
// the reverse of the endpoint table in validate.go, which is why Path stores no
// per-hop type that could disagree with the nodes at its ends.
func canRoute(from, to NodeType) bool {
	for _, shape := range edgeShapes {
		if contains(shape.to, to) && contains(shape.from, from) {
			return true
		}
	}
	return false
}

func keyString(k *Key) string {
	return fmt.Sprintf("%s\x00%d\x00%s", k.GetScope(), int32(k.GetType()), k.GetId())
}

func edgeString(from, to *Key) string { return keyString(from) + "\x00>\x00" + keyString(to) }
