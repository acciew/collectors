package collectorv1_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// rulesOf reduces violations to their rule names so tests assert on what was
// broken rather than on how the message is worded.
func rulesOf(vs []collectorv1.Violation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Rule)
	}
	return out
}

func wantRules(t *testing.T, got []collectorv1.Violation, want ...string) {
	t.Helper()
	rules := rulesOf(got)
	if len(rules) != len(want) {
		t.Fatalf("got %d violations %v, want %d %v", len(rules), got, len(want), want)
	}
	for i := range rules {
		if rules[i] != want[i] {
			t.Errorf("violation %d: rule %q, want %q (field %q)", i, rules[i], want[i], got[i].Field)
		}
	}
}

func scopeKey(id string) *collectorv1.Key {
	return &collectorv1.Key{Scope: id, Type: collectorv1.NodeType_NODE_TYPE_SCOPE, Id: id}
}

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name string
		key  *collectorv1.Key
		want []string
	}{
		{
			name: "a complete key is valid",
			key:  &collectorv1.Key{Scope: "realm-a", Type: collectorv1.NodeType_NODE_TYPE_IDENTITY, Id: "u1"},
		},
		{
			name: "a scope key whose scope equals its id is valid",
			key:  scopeKey("realm-a"),
		},
		{
			name: "the enum zero value is never valid on the wire",
			key:  &collectorv1.Key{Scope: "realm-a", Type: collectorv1.NodeType_NODE_TYPE_UNSPECIFIED, Id: "u1"},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "an empty scope is invalid",
			key:  &collectorv1.Key{Scope: "", Type: collectorv1.NodeType_NODE_TYPE_IDENTITY, Id: "u1"},
			want: []string{"key-fields-required"},
		},
		{
			name: "an empty id is invalid",
			key:  &collectorv1.Key{Scope: "realm-a", Type: collectorv1.NodeType_NODE_TYPE_IDENTITY, Id: ""},
			want: []string{"key-fields-required"},
		},
		{
			name: "a scope node keyed under a different scope is invalid",
			key:  &collectorv1.Key{Scope: "realm-a", Type: collectorv1.NodeType_NODE_TYPE_SCOPE, Id: "realm-b"},
			want: []string{"scope-key-is-self-referential"},
		},
		{
			name: "a nil key is invalid rather than a panic",
			key:  nil,
			want: []string{"key-required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantRules(t, collectorv1.ValidateKey(tt.key, "key"), tt.want...)
		})
	}
}

func humanFacts() *collectorv1.IdentityFacts {
	return &collectorv1.IdentityFacts{
		Kind:   collectorv1.IdentityKind_IDENTITY_KIND_HUMAN,
		Status: collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE,
	}
}

func identityNode() *collectorv1.Node {
	return &collectorv1.Node{
		Key:        &collectorv1.Key{Scope: "realm-a", Type: collectorv1.NodeType_NODE_TYPE_IDENTITY, Id: "u1"},
		Name:       "alice",
		SourceType: "user",
		Provenance: collectorv1.Provenance_PROVENANCE_OBSERVED,
		Identity:   humanFacts(),
	}
}

func TestValidateNode(t *testing.T) {
	tests := []struct {
		name string
		node func(*collectorv1.Node)
		want []string
	}{
		{name: "a complete identity node is valid", node: func(*collectorv1.Node) {}},
		{
			name: "an entitlement node carries no identity facts",
			node: func(n *collectorv1.Node) {
				n.Key.Type = collectorv1.NodeType_NODE_TYPE_ENTITLEMENT
				n.SourceType = "realm_role"
				n.Identity = nil
			},
		},
		{
			name: "identity facts on a non-identity node are invalid",
			node: func(n *collectorv1.Node) { n.Key.Type = collectorv1.NodeType_NODE_TYPE_GROUPING },
			want: []string{"identity-facts-iff-identity"},
		},
		{
			name: "an identity node without facts is invalid",
			node: func(n *collectorv1.Node) { n.Identity = nil },
			want: []string{"identity-facts-iff-identity"},
		},
		{
			name: "a node must have a display name",
			node: func(n *collectorv1.Node) { n.Name = "" },
			want: []string{"node-name-required"},
		},
		{
			name: "a node must carry the source's own type name",
			node: func(n *collectorv1.Node) { n.SourceType = "" },
			want: []string{"node-source-type-required"},
		},
		{
			name: "provenance must be stated",
			node: func(n *collectorv1.Node) { n.Provenance = collectorv1.Provenance_PROVENANCE_UNSPECIFIED },
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "identity kind must be stated, and unknown is not the zero value",
			node: func(n *collectorv1.Node) { n.Identity.Kind = collectorv1.IdentityKind_IDENTITY_KIND_UNSPECIFIED },
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "IDENTITY_KIND_UNKNOWN is an honest answer and is valid",
			node: func(n *collectorv1.Node) { n.Identity.Kind = collectorv1.IdentityKind_IDENTITY_KIND_UNKNOWN },
		},
		{
			name: "identity status must be stated",
			node: func(n *collectorv1.Node) {
				n.Identity.Status = collectorv1.IdentityStatus_IDENTITY_STATUS_UNSPECIFIED
			},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "a broken key is reported against the node's key path",
			node: func(n *collectorv1.Node) { n.Key.Id = "" },
			want: []string{"key-fields-required"},
		},
		{
			name: "a nil node is invalid rather than a panic",
			node: nil,
			want: []string{"record-required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n *collectorv1.Node
			if tt.node != nil {
				n = identityNode()
				tt.node(n)
			}
			wantRules(t, collectorv1.ValidateNode(n), tt.want...)
		})
	}
}

func TestValidateNodeReportsTheFieldPath(t *testing.T) {
	n := identityNode()
	n.Identity.Kind = collectorv1.IdentityKind_IDENTITY_KIND_UNSPECIFIED
	got := collectorv1.ValidateNode(n)
	if len(got) != 1 {
		t.Fatalf("got %v, want one violation", got)
	}
	if got[0].Field != "node.identity.kind" {
		t.Errorf("Field = %q, want %q", got[0].Field, "node.identity.kind")
	}
}

func key(t collectorv1.NodeType, id string) *collectorv1.Key {
	return &collectorv1.Key{Scope: "realm-a", Type: t, Id: id}
}

const (
	identity    = collectorv1.NodeType_NODE_TYPE_IDENTITY
	grouping    = collectorv1.NodeType_NODE_TYPE_GROUPING
	entitlement = collectorv1.NodeType_NODE_TYPE_ENTITLEMENT
	resource    = collectorv1.NodeType_NODE_TYPE_RESOURCE
)

func holdsEdge() *collectorv1.Edge {
	return &collectorv1.Edge{
		Type:     collectorv1.EdgeType_EDGE_TYPE_HOLDS,
		From:     key(identity, "u1"),
		To:       key(entitlement, "r1"),
		Fidelity: collectorv1.Fidelity_FIDELITY_DIRECT,
	}
}

func TestValidateEdgeEndpointTypes(t *testing.T) {
	tests := []struct {
		name     string
		edgeType collectorv1.EdgeType
		from, to collectorv1.NodeType
		want     []string
	}{
		{"member_of runs identity to grouping", collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, identity, grouping, nil},
		{"member_of the other way round is invalid", collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, grouping, identity, []string{"edge-endpoint-types"}},
		{"child_of runs grouping to grouping", collectorv1.EdgeType_EDGE_TYPE_CHILD_OF, grouping, grouping, nil},
		{"holds runs identity to entitlement", collectorv1.EdgeType_EDGE_TYPE_HOLDS, identity, entitlement, nil},
		{"holds also runs grouping to entitlement", collectorv1.EdgeType_EDGE_TYPE_HOLDS, grouping, entitlement, nil},
		{"holds does not run to a resource", collectorv1.EdgeType_EDGE_TYPE_HOLDS, identity, resource, []string{"edge-endpoint-types"}},
		{"includes runs entitlement to entitlement", collectorv1.EdgeType_EDGE_TYPE_INCLUDES, entitlement, entitlement, nil},
		{"applies_to runs entitlement to resource", collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, entitlement, resource, nil},
		// Without this edge the AWS role's two nodes are unrelated and the
		// assume chain has no walk. R1.
		{"acts_as runs entitlement to identity", collectorv1.EdgeType_EDGE_TYPE_ACTS_AS, entitlement, identity, nil},
		{"acts_as does not run identity to entitlement", collectorv1.EdgeType_EDGE_TYPE_ACTS_AS, identity, entitlement, []string{"edge-endpoint-types"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := holdsEdge()
			e.Type, e.From, e.To = tt.edgeType, key(tt.from, "a"), key(tt.to, "b")
			wantRules(t, collectorv1.ValidateEdge(e), tt.want...)
		})
	}
}

func TestValidateEdgeFidelityAndPath(t *testing.T) {
	via := &collectorv1.Path{Via: []*collectorv1.Key{key(grouping, "g1")}}

	tests := []struct {
		name string
		edit func(*collectorv1.Edge)
		want []string
	}{
		{name: "direct with no path is valid", edit: func(*collectorv1.Edge) {}},
		{
			name: "direct with a path is invalid: a stated fact has no route",
			edit: func(e *collectorv1.Edge) { e.Path = via },
			want: []string{"fidelity-path-agreement"},
		},
		{
			name: "effective with a path is valid",
			edit: func(e *collectorv1.Edge) {
				e.Fidelity = collectorv1.Fidelity_FIDELITY_EFFECTIVE
				e.Path = via
			},
		},
		{
			name: "effective without a path is invalid: derived from what?",
			edit: func(e *collectorv1.Edge) { e.Fidelity = collectorv1.Fidelity_FIDELITY_EFFECTIVE },
			want: []string{"fidelity-path-agreement"},
		},
		{
			name: "coarse is allowed either way, with a path",
			edit: func(e *collectorv1.Edge) {
				e.Fidelity = collectorv1.Fidelity_FIDELITY_COARSE
				e.Path = via
			},
		},
		{
			name: "coarse is allowed either way, without one",
			edit: func(e *collectorv1.Edge) { e.Fidelity = collectorv1.Fidelity_FIDELITY_COARSE },
		},
		{
			name: "fidelity must be stated: this is the rule the whole file exists for",
			edit: func(e *collectorv1.Edge) { e.Fidelity = collectorv1.Fidelity_FIDELITY_UNSPECIFIED },
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "a structural edge is never effective: nothing derives membership",
			edit: func(e *collectorv1.Edge) {
				e.Type, e.From, e.To = collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, key(identity, "u1"), key(grouping, "g1")
				e.Fidelity = collectorv1.Fidelity_FIDELITY_EFFECTIVE
				e.Path = via
			},
			want: []string{"structural-edge-not-effective"},
		},
		{
			name: "a key inside the path is validated too",
			edit: func(e *collectorv1.Edge) {
				e.Fidelity = collectorv1.Fidelity_FIDELITY_EFFECTIVE
				e.Path = &collectorv1.Path{Via: []*collectorv1.Key{{Scope: "realm-a", Type: grouping, Id: ""}}}
			},
			want: []string{"key-fields-required"},
		},
		{
			name: "the edge type must be stated",
			edit: func(e *collectorv1.Edge) { e.Type = collectorv1.EdgeType_EDGE_TYPE_UNSPECIFIED },
			want: []string{"enum-must-not-be-unspecified"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := holdsEdge()
			tt.edit(e)
			wantRules(t, collectorv1.ValidateEdge(e), tt.want...)
		})
	}
}

func TestValidateEdgeRejectsNil(t *testing.T) {
	wantRules(t, collectorv1.ValidateEdge(nil), "record-required")
}

func seenActivity() *collectorv1.Activity {
	return &collectorv1.Activity{
		Subject:    key(identity, "u1"),
		Signal:     "login_event",
		ObservedAt: timestamppb.New(time.Unix(1e9, 0)),
		Coverage: &collectorv1.CoverageWindow{
			Since: timestamppb.New(time.Unix(1e9-2592000, 0)),
			Until: timestamppb.New(time.Unix(1e9, 0)),
		},
		SourceLag: durationpb.New(0),
		Result: &collectorv1.Activity_Seen{Seen: &collectorv1.Seen{
			LastSeen:   timestamppb.New(time.Unix(1e9-100, 0)),
			Confidence: collectorv1.Confidence_CONFIDENCE_EXACT,
		}},
	}
}

func TestValidateActivity(t *testing.T) {
	tests := []struct {
		name string
		edit func(*collectorv1.Activity)
		want []string
	}{
		{name: "a seen record is valid", edit: func(*collectorv1.Activity) {}},
		{
			name: "not_seen is valid and still carries a confidence",
			edit: func(a *collectorv1.Activity) {
				a.Result = &collectorv1.Activity_NotSeen{NotSeen: &collectorv1.NotSeen{
					Confidence: collectorv1.Confidence_CONFIDENCE_APPROXIMATE,
				}}
			},
		},
		{
			name: "unavailable needs neither coverage nor lag: the source cannot answer at all",
			edit: func(a *collectorv1.Activity) {
				a.Result = &collectorv1.Activity_Unavailable{Unavailable: &collectorv1.Unavailable{
					Code: "keycloak.events.disabled", Reason: "event storage is off for this realm",
				}}
				a.Coverage, a.SourceLag = nil, nil
			},
		},
		{
			name: "no result arm at all is a violation, not an implied never",
			edit: func(a *collectorv1.Activity) { a.Result = nil },
			want: []string{"activity-result-required"},
		},
		{
			name: "a signal name is required and must be one Describe declared",
			edit: func(a *collectorv1.Activity) { a.Signal = "" },
			want: []string{"activity-signal-required"},
		},
		{
			name: "observed_at is required: freshness of our reading, not of the data",
			edit: func(a *collectorv1.Activity) { a.ObservedAt = nil },
			want: []string{"activity-observed-at-required"},
		},
		{
			name: "coverage is required when the source can answer",
			edit: func(a *collectorv1.Activity) { a.Coverage = nil },
			want: []string{"activity-coverage-required"},
		},
		{
			name: "a coverage window with no lower bound would read as seeing everything",
			edit: func(a *collectorv1.Activity) { a.Coverage.Since = nil },
			want: []string{"coverage-bounds-required"},
		},
		{
			name: "a coverage window with no upper bound is equally unusable",
			edit: func(a *collectorv1.Activity) { a.Coverage.Until = nil },
			want: []string{"coverage-bounds-required"},
		},
		{
			name: "an inverted coverage window is invalid",
			edit: func(a *collectorv1.Activity) {
				a.Coverage.Since = timestamppb.New(time.Unix(1e9+10, 0))
			},
			want: []string{"coverage-bounds-ordered"},
		},
		{
			name: "source_lag is required, and zero is a value rather than an absence",
			edit: func(a *collectorv1.Activity) { a.SourceLag = nil },
			want: []string{"activity-source-lag-required"},
		},
		{
			name: "confidence must be stated on seen",
			edit: func(a *collectorv1.Activity) {
				a.GetSeen().Confidence = collectorv1.Confidence_CONFIDENCE_UNSPECIFIED
			},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "confidence must be stated on not_seen too: an absence has a precision",
			edit: func(a *collectorv1.Activity) {
				a.Result = &collectorv1.Activity_NotSeen{NotSeen: &collectorv1.NotSeen{}}
			},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "seen without a timestamp is not seen",
			edit: func(a *collectorv1.Activity) { a.GetSeen().LastSeen = nil },
			want: []string{"activity-last-seen-required"},
		},
		{
			name: "unavailable must say why",
			edit: func(a *collectorv1.Activity) {
				a.Result = &collectorv1.Activity_Unavailable{Unavailable: &collectorv1.Unavailable{}}
				a.Coverage, a.SourceLag = nil, nil
			},
			want: []string{"unavailable-code-required"},
		},
		{
			name: "the subject key is validated",
			edit: func(a *collectorv1.Activity) { a.Subject = nil },
			want: []string{"key-required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := seenActivity()
			tt.edit(a)
			wantRules(t, collectorv1.ValidateActivity(a), tt.want...)
		})
	}
}

func TestValidateActivityRejectsNil(t *testing.T) {
	wantRules(t, collectorv1.ValidateActivity(nil), "record-required")
}

func completeCompletion() *collectorv1.Completion {
	return &collectorv1.Completion{
		Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
		Counts:  &collectorv1.Counts{Identities: 1},
		Scopes: []*collectorv1.ScopeOutcome{{
			Scope:  scopeKey("realm-a"),
			Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED,
		}},
	}
}

func TestValidateCompletion(t *testing.T) {
	rateLimited := collectorv1.IncompleteCause_INCOMPLETE_CAUSE_RATE_LIMITED

	tests := []struct {
		name string
		edit func(*collectorv1.Completion)
		want []string
	}{
		{name: "a complete verdict with collected scopes is valid", edit: func(*collectorv1.Completion) {}},
		{
			name: "a skipped scope does not make the collection incomplete",
			edit: func(c *collectorv1.Completion) {
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_SKIPPED
			},
		},
		{
			name: "complete may not carry a cause",
			edit: func(c *collectorv1.Completion) { c.Cause = rateLimited },
			want: []string{"completion-cause-iff-incomplete"},
		},
		{
			name: "complete may not carry a resume cursor: there is nothing to resume",
			edit: func(c *collectorv1.Completion) {
				c.ResumeCursor = &collectorv1.Cursor{Token: []byte("x")}
			},
			want: []string{"completion-cursor-forbidden-when-complete"},
		},
		{
			name: "an unreachable scope contradicts a complete verdict",
			edit: func(c *collectorv1.Completion) {
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_UNREACHABLE
				c.Scopes[0].Error = &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Message: "probe fixture"}
			},
			want: []string{"complete-requires-every-scope-accounted"},
		},
		{
			name: "a partial scope contradicts a complete verdict too",
			edit: func(c *collectorv1.Completion) {
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL
				c.Scopes[0].Error = &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED, Message: "probe fixture"}
			},
			want: []string{"complete-requires-every-scope-accounted"},
		},
		{
			name: "incomplete must say why",
			edit: func(c *collectorv1.Completion) {
				c.Verdict = collectorv1.Verdict_VERDICT_INCOMPLETE
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL
				c.Scopes[0].Error = &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED, Message: "probe fixture"}
			},
			want: []string{"completion-cause-iff-incomplete"},
		},
		{
			name: "incomplete with a cause and a cursor is valid",
			edit: func(c *collectorv1.Completion) {
				c.Verdict = collectorv1.Verdict_VERDICT_INCOMPLETE
				c.Cause = rateLimited
				c.ResumeCursor = &collectorv1.Cursor{Token: []byte("page-2")}
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL
				c.Scopes[0].Error = &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED, Message: "probe fixture"}
			},
		},
		{
			name: "the verdict must be stated",
			edit: func(c *collectorv1.Completion) { c.Verdict = collectorv1.Verdict_VERDICT_UNSPECIFIED },
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "counts must be stated, so that the host can check them",
			edit: func(c *collectorv1.Completion) { c.Counts = nil },
			want: []string{"completion-counts-required"},
		},
		{
			name: "a scope status must be stated",
			edit: func(c *collectorv1.Completion) {
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_UNSPECIFIED
			},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "an unreachable scope must say why it was unreachable",
			edit: func(c *collectorv1.Completion) {
				c.Verdict = collectorv1.Verdict_VERDICT_INCOMPLETE
				c.Cause = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_SCOPE_UNREACHABLE
				c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_UNREACHABLE
			},
			want: []string{"scope-outcome-error-required"},
		},
		{
			name: "the scope key is validated",
			edit: func(c *collectorv1.Completion) { c.Scopes[0].Scope = key(identity, "u1") },
			want: []string{"scope-outcome-key-type"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := completeCompletion()
			tt.edit(c)
			wantRules(t, collectorv1.ValidateCompletion(c), tt.want...)
		})
	}
}

func TestValidateEventDispatchesOnTheArm(t *testing.T) {
	bad := identityNode()
	bad.Name = ""

	tests := []struct {
		name  string
		event *collectorv1.CollectResponse
		want  []string
	}{
		{
			name:  "a node arm is validated as a node",
			event: &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: bad}},
			want:  []string{"node-name-required"},
		},
		{
			name:  "an edge arm is validated as an edge",
			event: &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Edge{Edge: holdsEdge()}},
		},
		{
			name:  "a completion arm is validated as a completion",
			event: &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: completeCompletion()}},
		},
		{
			// Unknown non-zero enum values and unrecognised arms are tolerated,
			// never rejected: that is what lets a newer plugin talk to an older
			// host without either side failing.
			name:  "an event with no arm set is tolerated, not rejected",
			event: &collectorv1.CollectResponse{},
		},
		{
			name:  "a nil event is a violation",
			event: nil,
			want:  []string{"record-required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantRules(t, collectorv1.ValidateEvent(tt.event), tt.want...)
		})
	}
}

// Tolerating what we do not recognise is what lets a newer plugin talk to an
// older host. The rule is narrow: the zero value is always invalid, but any
// other unknown value is preserved and passed on.
func TestUnknownEnumValuesAreToleratedButZeroIsNot(t *testing.T) {
	e := holdsEdge()
	e.Type = collectorv1.EdgeType(99)
	if got := collectorv1.ValidateEdge(e); len(got) != 0 {
		t.Errorf("an unknown edge type should be tolerated, got %v", got)
	}

	e.Type = collectorv1.EdgeType_EDGE_TYPE_UNSPECIFIED
	wantRules(t, collectorv1.ValidateEdge(e), "enum-must-not-be-unspecified")
}

func TestValidateEventDispatchesActivity(t *testing.T) {
	a := seenActivity()
	a.Signal = ""
	wantRules(t,
		collectorv1.ValidateEvent(&collectorv1.CollectResponse{
			Event: &collectorv1.CollectResponse_Activity{Activity: a},
		}),
		"activity-signal-required")
}

func TestValidateCompletionRejectsANilScopeOutcome(t *testing.T) {
	c := completeCompletion()
	c.Scopes = append(c.Scopes, nil)
	wantRules(t, collectorv1.ValidateCompletion(c), "record-required")
}

func TestViolationStringNamesTheFieldAndTheRule(t *testing.T) {
	n := identityNode()
	n.Provenance = collectorv1.Provenance_PROVENANCE_UNSPECIFIED
	got := collectorv1.ValidateNode(n)
	if len(got) != 1 {
		t.Fatalf("got %v, want one violation", got)
	}
	s := got[0].String()
	for _, want := range []string{"node.provenance", "enum-must-not-be-unspecified", "Provenance"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, want it to contain %q", s, want)
		}
	}
}

// --- the enums nothing validated ------------------------------------------

func TestValidateErrorRejectsAnEmptyOne(t *testing.T) {
	tests := []struct {
		name string
		err  *collectorv1.Error
		want []string
	}{
		{
			name: "a complete error is valid",
			err:  &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Message: "no admin role"},
		},
		{
			// "The scope must say why" is worth nothing if Error{} satisfies it.
			name: "an empty error says nothing",
			err:  &collectorv1.Error{},
			want: []string{"enum-must-not-be-unspecified", "error-message-required"},
		},
		{
			name: "an error code must be stated",
			err:  &collectorv1.Error{Message: "something"},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			name: "an error message must be stated",
			err:  &collectorv1.Error{Code: collectorv1.ErrorCode_ERROR_CODE_RATE_LIMITED},
			want: []string{"error-message-required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantRules(t, collectorv1.ValidateError(tt.err, "error"), tt.want...)
		})
	}
}

func TestValidateDiagnostic(t *testing.T) {
	ok := &collectorv1.Diagnostic{
		Severity: collectorv1.Severity_SEVERITY_WARNING,
		Code:     "keycloak.events.partial",
		Message:  "event storage is on but LOGIN is not in enabledEventTypes",
	}
	wantRules(t, collectorv1.ValidateDiagnostic(ok))

	wantRules(t, collectorv1.ValidateDiagnostic(&collectorv1.Diagnostic{}),
		"enum-must-not-be-unspecified", "diagnostic-code-required", "diagnostic-message-required")
}

func TestValidateEventDispatchesDiagnostic(t *testing.T) {
	wantRules(t,
		collectorv1.ValidateEvent(&collectorv1.CollectResponse{
			Event: &collectorv1.CollectResponse_Diagnostic{Diagnostic: &collectorv1.Diagnostic{}},
		}),
		"enum-must-not-be-unspecified", "diagnostic-code-required", "diagnostic-message-required")
}

func TestScopeOutcomeErrorMustBeMeaningful(t *testing.T) {
	c := completeCompletion()
	c.Verdict = collectorv1.Verdict_VERDICT_INCOMPLETE
	c.Cause = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_SCOPE_UNREACHABLE
	c.Scopes[0].Status = collectorv1.ScopeStatus_SCOPE_STATUS_UNREACHABLE
	c.Scopes[0].Error = &collectorv1.Error{}
	wantRules(t, collectorv1.ValidateCompletion(c), "enum-must-not-be-unspecified", "error-message-required")
}

// --- the responses nothing validated --------------------------------------

func describeResponse() *collectorv1.DescribeResponse {
	return &collectorv1.DescribeResponse{
		Kind:            "collector",
		ProtocolVersion: 1,
		Name:            "keycloak",
		Version:         "0.1.0",
		Description:     "Collects identities, groups and roles from a Keycloak realm.",
		Capabilities: &collectorv1.Capabilities{
			Fidelities: []collectorv1.Fidelity{collectorv1.Fidelity_FIDELITY_DIRECT},
			NodeTypes:  []collectorv1.NodeType{identity},
			EdgeTypes:  []collectorv1.EdgeType{collectorv1.EdgeType_EDGE_TYPE_HOLDS},
		},
	}
}

func TestValidateDescribeResponse(t *testing.T) {
	tests := []struct {
		name string
		edit func(*collectorv1.DescribeResponse)
		want []string
	}{
		{name: "a complete description is valid", edit: func(*collectorv1.DescribeResponse) {}},
		{
			name: "the kind must be the one this package defines",
			edit: func(d *collectorv1.DescribeResponse) { d.Kind = "notifier" },
			want: []string{"describe-kind-mismatch"},
		},
		{
			name: "the protocol version must be the one this package defines",
			edit: func(d *collectorv1.DescribeResponse) { d.ProtocolVersion = 2 },
			want: []string{"describe-protocol-version-mismatch"},
		},
		{
			name: "a plugin must name itself",
			edit: func(d *collectorv1.DescribeResponse) { d.Name = "" },
			want: []string{"describe-name-required"},
		},
		{
			name: "capabilities are required: the host degrades against them",
			edit: func(d *collectorv1.DescribeResponse) { d.Capabilities = nil },
			want: []string{"describe-capabilities-required"},
		},
		{
			name: "a declared fidelity must not be the zero value",
			edit: func(d *collectorv1.DescribeResponse) {
				d.Capabilities.Fidelities = []collectorv1.Fidelity{collectorv1.Fidelity_FIDELITY_UNSPECIFIED}
			},
			want: []string{"enum-must-not-be-unspecified"},
		},
		{
			// ADR-0003 must be stated in the contract, not only in a README.
			name: "declaring coarse entitlements requires declaring the limitation",
			edit: func(d *collectorv1.DescribeResponse) {
				d.Capabilities.Fidelities = append(d.Capabilities.Fidelities, collectorv1.Fidelity_FIDELITY_COARSE)
			},
			want: []string{"coarse-requires-a-declared-limitation"},
		},
		{
			name: "declaring coarse with a limitation is valid",
			edit: func(d *collectorv1.DescribeResponse) {
				d.Capabilities.Fidelities = append(d.Capabilities.Fidelities, collectorv1.Fidelity_FIDELITY_COARSE)
				d.Limitations = []*collectorv1.Limitation{{
					Code:    "aws.coarse-entitlements",
					Summary: "An entitlement is a policy attachment, not an evaluated permission.",
				}}
			},
		},
		{
			name: "claiming activity without naming a signal is not a claim a consumer can use",
			edit: func(d *collectorv1.DescribeResponse) { d.Capabilities.Activity = true },
			want: []string{"activity-requires-a-declared-signal"},
		},
		{
			name: "a limitation must carry a code and a summary",
			edit: func(d *collectorv1.DescribeResponse) {
				d.Limitations = []*collectorv1.Limitation{{}}
			},
			want: []string{"limitation-code-required", "limitation-summary-required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := describeResponse()
			tt.edit(d)
			wantRules(t, collectorv1.ValidateDescribeResponse(d), tt.want...)
		})
	}
}

func TestValidateTestConnectionResponse(t *testing.T) {
	reachable := &collectorv1.TestConnectionResponse{
		Scopes: []*collectorv1.ScopeProbe{{
			Scope: scopeKey("realm-a"), Name: "realm-a", Reachable: true,
			Activity: collectorv1.ActivityAvailability_ACTIVITY_AVAILABILITY_AVAILABLE,
		}},
	}
	wantRules(t, collectorv1.ValidateTestConnectionResponse(reachable))

	silent := &collectorv1.TestConnectionResponse{
		Scopes: []*collectorv1.ScopeProbe{{Scope: scopeKey("realm-a"), Name: "realm-a"}},
	}
	wantRules(t, collectorv1.ValidateTestConnectionResponse(silent), "scope-probe-error-required")

	unnamed := &collectorv1.TestConnectionResponse{
		Scopes: []*collectorv1.ScopeProbe{{Scope: scopeKey("realm-a"), Reachable: true}},
	}
	wantRules(t, collectorv1.ValidateTestConnectionResponse(unnamed), "scope-probe-name-required")
}

func TestValidateRevokeResponse(t *testing.T) {
	wantRules(t, collectorv1.ValidateRevokeResponse(&collectorv1.RevokeResponse{
		Outcome: collectorv1.RevokeOutcome_REVOKE_OUTCOME_NOT_SUPPORTED,
	}))

	wantRules(t, collectorv1.ValidateRevokeResponse(&collectorv1.RevokeResponse{}),
		"enum-must-not-be-unspecified")

	wantRules(t, collectorv1.ValidateRevokeResponse(&collectorv1.RevokeResponse{
		Outcome: collectorv1.RevokeOutcome_REVOKE_OUTCOME_FAILED,
	}), "revoke-failure-error-required")
}

func TestValidateConfigResponse(t *testing.T) {
	wantRules(t, collectorv1.ValidateConfigIssues([]*collectorv1.ConfigIssue{{
		Field: "/realms/0", Severity: collectorv1.Severity_SEVERITY_ERROR,
		Code: "keycloak.realm.unknown", Message: "no such realm",
	}}))

	wantRules(t, collectorv1.ValidateConfigIssues([]*collectorv1.ConfigIssue{{}}),
		"enum-must-not-be-unspecified", "config-issue-code-required", "config-issue-message-required")

	// The empty string addresses the whole document, so it is valid; anything
	// that is not a JSON Pointer is not.
	wantRules(t, collectorv1.ValidateConfigIssues([]*collectorv1.ConfigIssue{{
		Field: "realms[0]", Severity: collectorv1.Severity_SEVERITY_ERROR,
		Code: "x", Message: "y",
	}}), "config-issue-field-must-be-a-json-pointer")
}

// --- an activity timestamp outside its own window --------------------------

func TestSeenMustFallInsideTheCoverageWindow(t *testing.T) {
	a := seenActivity()
	a.GetSeen().LastSeen = timestamppb.New(time.Unix(1e9+500, 0)) // after `until`
	wantRules(t, collectorv1.ValidateActivity(a), "last-seen-outside-coverage")

	b := seenActivity()
	b.GetSeen().LastSeen = timestamppb.New(time.Unix(1e9-9999999, 0)) // before `since`
	wantRules(t, collectorv1.ValidateActivity(b), "last-seen-outside-coverage")
}

// GitHub's organization base permission grants every member a level on every
// repository from a single source fact. Fabricating one edge per repository
// would be M x R edges the source never stated; the honest shape is one
// entitlement that applies to the whole scope.
func TestAnEntitlementMayApplyToAWholeScope(t *testing.T) {
	base := key(entitlement, "base:write")

	toScope := &collectorv1.Edge{
		Type:     collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO,
		From:     base,
		To:       scopeKey("realm-a"),
		Fidelity: collectorv1.Fidelity_FIDELITY_DIRECT,
	}
	wantRules(t, collectorv1.ValidateEdge(toScope))

	toResource := &collectorv1.Edge{
		Type:     collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO,
		From:     base,
		To:       key(resource, "repo-1"),
		Fidelity: collectorv1.Fidelity_FIDELITY_DIRECT,
	}
	wantRules(t, collectorv1.ValidateEdge(toResource))

	// Everything else it could point at is still wrong.
	toIdentity := &collectorv1.Edge{
		Type:     collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO,
		From:     base,
		To:       key(identity, "u1"),
		Fidelity: collectorv1.Fidelity_FIDELITY_DIRECT,
	}
	wantRules(t, collectorv1.ValidateEdge(toIdentity), "edge-endpoint-types")
}

// R14. A referenced node exists only because something pointed at it. Claiming
// to know when it was last active is a claim about a principal in an account
// we have never read.
func TestAReferencedNodeMakesNoActivityClaim(t *testing.T) {
	n := node(identity, "external", "arn:aws:iam::999:root", "external_principal")
	n.Provenance = collectorv1.Provenance_PROVENANCE_REFERENCED
	wantRules(t, collectorv1.ValidateNode(n))
}
