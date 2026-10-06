package collectorv1_test

import (
	"fmt"
	"runtime"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// --- fixture helpers -------------------------------------------------------

func nodeEvent(n *collectorv1.Node) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Node{Node: n}}
}

func edgeEvent(e *collectorv1.Edge) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Edge{Edge: e}}
}

func checkpointEvent(token string) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Checkpoint{
		Checkpoint: &collectorv1.Checkpoint{Cursor: &collectorv1.Cursor{Token: []byte(token)}},
	}}
}

func completionEvent(c *collectorv1.Completion) *collectorv1.CollectResponse {
	return &collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Completion{Completion: c}}
}

func node(t collectorv1.NodeType, id, name, srcType string) *collectorv1.Node {
	n := &collectorv1.Node{
		Key:        key(t, id),
		Name:       name,
		SourceType: srcType,
		Provenance: collectorv1.Provenance_PROVENANCE_OBSERVED,
	}
	if t == identity {
		n.Identity = humanFacts()
	}
	return n
}

func scopeNode() *collectorv1.Node {
	return &collectorv1.Node{
		Key:        scopeKey("realm-a"),
		Name:       "realm-a",
		SourceType: "realm",
		Provenance: collectorv1.Provenance_PROVENANCE_OBSERVED,
	}
}

func edge(t collectorv1.EdgeType, from, to *collectorv1.Key, f collectorv1.Fidelity, via ...*collectorv1.Key) *collectorv1.Edge {
	e := &collectorv1.Edge{Type: t, From: from, To: to, Fidelity: f}
	if len(via) > 0 {
		e.Path = &collectorv1.Path{Via: via}
	}
	return e
}

func counts(c *collectorv1.Counts) *collectorv1.Counts { return c }

// run feeds one stream and returns everything the checker found.
func run(events ...*collectorv1.CollectResponse) []collectorv1.Violation {
	c := collectorv1.NewStreamChecker()
	var vs []collectorv1.Violation
	for _, e := range events {
		vs = append(vs, c.Event(e)...)
	}
	vs = append(vs, c.EndStream()...)
	return append(vs, c.Close()...)
}

// --- the Keycloak shape, which is the case that matters --------------------

// keycloakStream is the fixture the path rule exists for: alice is a member of
// subgroup Platform, Platform is a child of Engineering, and Engineering holds
// the role. The effective grant must walk exactly that route.
func keycloakStream(t *testing.T) []*collectorv1.CollectResponse {
	t.Helper()
	alice := node(identity, "u1", "alice", "user")
	platform := node(grouping, "g-platform", "Platform", "group")
	engineering := node(grouping, "g-engineering", "Engineering", "group")
	role := node(entitlement, "r-admin", "admin", "realm_role")

	return []*collectorv1.CollectResponse{
		nodeEvent(scopeNode()),
		nodeEvent(alice), nodeEvent(platform), nodeEvent(engineering), nodeEvent(role),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, alice.Key, platform.Key, collectorv1.Fidelity_FIDELITY_DIRECT)),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_CHILD_OF, platform.Key, engineering.Key, collectorv1.Fidelity_FIDELITY_DIRECT)),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, engineering.Key, role.Key, collectorv1.Fidelity_FIDELITY_DIRECT)),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice.Key, role.Key,
			collectorv1.Fidelity_FIDELITY_EFFECTIVE, platform.Key, engineering.Key)),
		checkpointEvent("realm-a:done"),
		completionEvent(&collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
			Counts:  counts(&collectorv1.Counts{Identities: 1, Groupings: 2, Entitlements: 1, Scopes: 1, Edges: 4}),
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey("realm-a"), Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED,
			}},
		}),
	}
}

func TestAWellFormedStreamPasses(t *testing.T) {
	if got := run(keycloakStream(t)...); len(got) != 0 {
		t.Fatalf("a well-formed stream should pass, got %v", got)
	}
}

func TestStreamRules(t *testing.T) {
	tests := []struct {
		name string
		edit func([]*collectorv1.CollectResponse) []*collectorv1.CollectResponse
		want []string
	}{
		{
			// The rule the file exists for: over gRPC a truncated stream
			// closes cleanly and looks exactly like a finished one.
			name: "a stream that ends without a completion marker is not trusted",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse { return s[:len(s)-1] },
			want: []string{"completion-required"},
		},
		{
			name: "nothing may follow the completion marker",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				return append(s, nodeEvent(node(identity, "u2", "bob", "user")))
			},
			want: []string{"completion-must-be-last"},
		},
		{
			// Distinguished from the rule above on purpose: "you sent two
			// completions" is a more useful thing to be told than "something
			// arrived afterwards".
			name: "a second completion marker names its own rule",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				return append(s[:len(s)-1], s[len(s)-1], s[len(s)-1])
			},
			want: []string{"completion-exactly-once"},
		},
		{
			name: "declared counts must match what actually arrived",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				s[len(s)-1].GetCompletion().Counts.Identities = 7
				return s
			},
			want: []string{"counts-must-match-what-was-sent"},
		},
		{
			name: "an edge to a node that was never emitted is a dangling reference",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				ghost := key(entitlement, "r-does-not-exist")
				s[len(s)-1].GetCompletion().Counts.Edges = 5
				return append(s[:len(s)-1],
					edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, key(identity, "u1"), ghost,
						collectorv1.Fidelity_FIDELITY_DIRECT)),
					s[len(s)-1])
			},
			want: []string{"referenced-node-was-never-emitted"},
		},
		{
			// This is what catches a Keycloak group-inheritance bug in the
			// test suite rather than in front of a reviewer.
			name: "a path hop nobody emitted is a resolution bug",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				// Drop the Platform -> Engineering edge the effective grant
				// walks through, keeping the effective edge that claims it.
				out := make([]*collectorv1.CollectResponse, 0, len(s))
				for _, e := range s {
					if e.GetEdge().GetType() == collectorv1.EdgeType_EDGE_TYPE_CHILD_OF {
						continue
					}
					out = append(out, e)
				}
				out[len(out)-1].GetCompletion().Counts.Edges = 3
				return out
			},
			want: []string{"path-hop-must-be-an-emitted-edge"},
		},
		{
			name: "the same node key twice with different content is unresolvable",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				renamed := node(identity, "u1", "alice-renamed", "user")
				s[len(s)-1].GetCompletion().Counts.Identities = 2
				return append(s[:len(s)-1], nodeEvent(renamed), s[len(s)-1])
			},
			want: []string{"duplicate-node-key-must-be-identical"},
		},
		{
			name: "the same node key twice with identical content is fine on resume",
			edit: func(s []*collectorv1.CollectResponse) []*collectorv1.CollectResponse {
				again := node(identity, "u1", "alice", "user")
				s[len(s)-1].GetCompletion().Counts.Identities = 2
				return append(s[:len(s)-1], nodeEvent(again), s[len(s)-1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.edit(keycloakStream(t))...)
			rules := rulesOf(got)
			if len(rules) != len(tt.want) {
				t.Fatalf("got %d violations %v, want %d %v", len(rules), rules, len(tt.want), tt.want)
			}
			for i := range rules {
				if rules[i] != tt.want[i] {
					t.Errorf("violation %d: rule %q, want %q", i, rules[i], tt.want[i])
				}
			}
		})
	}
}

// A resumed collection is two streams whose union must satisfy every rule that
// one stream would. This is what makes resume safe to rely on.
func TestResumeAcrossTwoStreams(t *testing.T) {
	alice := node(identity, "u1", "alice", "user")
	role := node(entitlement, "r-admin", "admin", "realm_role")

	first := []*collectorv1.CollectResponse{
		nodeEvent(scopeNode()),
		nodeEvent(alice),
		checkpointEvent("page-2"),
		completionEvent(&collectorv1.Completion{
			Verdict:      collectorv1.Verdict_VERDICT_INCOMPLETE,
			Cause:        collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED,
			ResumeCursor: &collectorv1.Cursor{Token: []byte("page-2")},
			Counts:       counts(&collectorv1.Counts{Identities: 1, Scopes: 1}),
		}),
	}
	second := []*collectorv1.CollectResponse{
		nodeEvent(role),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice.Key, role.Key, collectorv1.Fidelity_FIDELITY_DIRECT)),
		checkpointEvent("done"),
		completionEvent(&collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
			Counts:  counts(&collectorv1.Counts{Entitlements: 1, Edges: 1}),
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey("realm-a"), Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED,
			}},
		}),
	}

	c := collectorv1.NewStreamChecker()
	var vs []collectorv1.Violation
	for _, stream := range [][]*collectorv1.CollectResponse{first, second} {
		for _, e := range stream {
			vs = append(vs, c.Event(e)...)
		}
		vs = append(vs, c.EndStream()...)
	}
	vs = append(vs, c.Close()...)

	// The edge in the second stream refers to a node emitted in the first.
	// Checking referential integrity per stream would reject a correct resume.
	if len(vs) != 0 {
		t.Fatalf("a correct resumed collection should pass, got %v", vs)
	}
}

func TestStreamCheckerRejectsANilEvent(t *testing.T) {
	c := collectorv1.NewStreamChecker()
	wantRules(t, c.Event(nil), "record-required")
}

// The AWS assume chain, which is where a path walks through several hops of
// different kinds: Alice holds the right to assume a role, the role acts as a
// principal, and that principal holds a policy.
func awsStream() []*collectorv1.CollectResponse {
	alice := node(identity, "u-alice", "alice", "iam_user")
	assume := node(entitlement, "e-assume-orgadmin", "sts:AssumeRole OrgAdmin", "assumable_role")
	orgAdmin := node(identity, "i-orgadmin", "OrgAdmin", "role_principal")
	policy := node(entitlement, "e-admin-policy", "AdministratorAccess", "managed_policy")

	direct := collectorv1.Fidelity_FIDELITY_DIRECT
	coarse := collectorv1.Fidelity_FIDELITY_COARSE
	return []*collectorv1.CollectResponse{
		nodeEvent(scopeNode()),
		nodeEvent(alice), nodeEvent(assume), nodeEvent(orgAdmin), nodeEvent(policy),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice.Key, assume.Key, direct)),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_ACTS_AS, assume.Key, orgAdmin.Key, direct)),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, orgAdmin.Key, policy.Key, coarse)),
		edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice.Key, policy.Key, coarse,
			assume.Key, orgAdmin.Key)),
		checkpointEvent("account:done"),
		completionEvent(&collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
			Counts:  counts(&collectorv1.Counts{Identities: 2, Entitlements: 2, Scopes: 1, Edges: 4}),
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey("realm-a"), Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED,
			}},
		}),
	}
}

func TestTheAWSAssumeChainWalks(t *testing.T) {
	if got := run(awsStream()...); len(got) != 0 {
		t.Fatalf("the assume chain should walk cleanly, got %v", got)
	}
}

// Every AWS grant is COARSE (ADR-0003), so if "derived" is decided by
// fidelity rather than by whether the edge carries a path, the path rule can
// never fire for AWS at all. A chain of derivations then launders itself: each
// hop is COARSE-with-a-path, which is a derivation, and none of them is a fact
// the source stated.
func TestACoarseDerivationIsNotAStatedFact(t *testing.T) {
	alice := node(identity, "u-alice", "alice", "iam_user")
	assume1 := node(entitlement, "e-assume-r1", "sts:AssumeRole R1", "assumable_role")
	r1 := node(identity, "i-r1", "R1", "role_principal")
	assume2 := node(entitlement, "e-assume-r2", "sts:AssumeRole R2", "assumable_role")
	r2 := node(identity, "i-r2", "R2", "role_principal")
	policy := node(entitlement, "e-policy", "AdministratorAccess", "managed_policy")

	direct := collectorv1.Fidelity_FIDELITY_DIRECT
	coarse := collectorv1.Fidelity_FIDELITY_COARSE
	E := collectorv1.EdgeType_EDGE_TYPE_HOLDS
	A := collectorv1.EdgeType_EDGE_TYPE_ACTS_AS

	events := []*collectorv1.CollectResponse{
		nodeEvent(scopeNode()),
		nodeEvent(alice), nodeEvent(assume1), nodeEvent(r1),
		nodeEvent(assume2), nodeEvent(r2), nodeEvent(policy),
		edgeEvent(edge(E, alice.Key, assume1.Key, direct)),
		edgeEvent(edge(A, assume1.Key, r1.Key, direct)),
		edgeEvent(edge(E, r1.Key, assume2.Key, direct)),
		edgeEvent(edge(A, assume2.Key, r2.Key, direct)),
		edgeEvent(edge(E, r2.Key, policy.Key, coarse)),
		// A derivation: alice can reach assume2 through the first role.
		edgeEvent(edge(E, alice.Key, assume2.Key, coarse, assume1.Key, r1.Key)),
		// A second derivation that walks through the first one. The hop
		// alice -> assume2 is not a fact the source stated; it is something
		// the plugin worked out, so this path rests on a claim.
		edgeEvent(edge(E, alice.Key, policy.Key, coarse, assume2.Key, r2.Key)),
		checkpointEvent("account:done"),
		completionEvent(&collectorv1.Completion{
			Verdict: collectorv1.Verdict_VERDICT_COMPLETE,
			Counts:  counts(&collectorv1.Counts{Identities: 3, Entitlements: 3, Scopes: 1, Edges: 7}),
			Scopes: []*collectorv1.ScopeOutcome{{
				Scope: scopeKey("realm-a"), Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED,
			}},
		}),
	}

	wantRules(t, run(events...), "path-hop-must-be-stated-not-derived")
}

func TestAnActivitySubjectMustHaveBeenEmitted(t *testing.T) {
	s := keycloakStream(t)
	ghost := seenActivity()
	ghost.Subject = key(identity, "u-never-emitted")
	s[len(s)-1].GetCompletion().Counts.Activities = 1
	s = append(s[:len(s)-1],
		&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Activity{Activity: ghost}},
		s[len(s)-1])
	wantRules(t, run(s...), "referenced-node-was-never-emitted")
}

// The node types at a hop's ends determine its edge type. A pair no edge type
// connects is a hop that cannot exist, and saying so is more useful than
// reporting it as merely missing.
func TestAPathHopBetweenUnconnectableTypesIsRejected(t *testing.T) {
	s := keycloakStream(t)
	resourceNode := node(resource, "c-app", "app", "client")
	for _, e := range s {
		if edge := e.GetEdge(); edge.GetFidelity() == collectorv1.Fidelity_FIDELITY_EFFECTIVE {
			// A resource cannot be a member of, or a child of, anything.
			edge.Path = &collectorv1.Path{Via: []*collectorv1.Key{resourceNode.Key}}
		}
	}
	s[len(s)-1].GetCompletion().Counts.Resources = 1
	s = append(s[:len(s)-1], nodeEvent(resourceNode), s[len(s)-1])
	got := rulesOf(run(s...))
	found := false
	for _, r := range got {
		if r == "path-hop-has-no-valid-edge-type" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a path-hop-has-no-valid-edge-type violation, got %v", got)
	}
}

// A realistic realm shape, used to keep the checker's footprint honest. This
// is not a benchmark of speed; it is the memory question the review raised.
func TestStreamCheckerFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation shape only")
	}
	const users, groups, roles = 5000, 200, 300

	c := collectorv1.NewStreamChecker()
	feed := func(e *collectorv1.CollectResponse) {
		if vs := c.Event(e); len(vs) != 0 {
			t.Fatalf("unexpected violation: %v", vs)
		}
	}

	feed(nodeEvent(scopeNode()))
	groupKeys := make([]*collectorv1.Key, groups)
	for i := range groupKeys {
		n := node(grouping, fmt.Sprintf("g%d", i), fmt.Sprintf("group-%d", i), "group")
		groupKeys[i] = n.Key
		feed(nodeEvent(n))
	}
	roleKeys := make([]*collectorv1.Key, roles)
	for i := range roleKeys {
		n := node(entitlement, fmt.Sprintf("r%d", i), fmt.Sprintf("role-%d", i), "realm_role")
		roleKeys[i] = n.Key
		feed(nodeEvent(n))
	}
	for i := 0; i < groups; i++ {
		feed(edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, groupKeys[i], roleKeys[i%roles],
			collectorv1.Fidelity_FIDELITY_DIRECT)))
	}
	for u := 0; u < users; u++ {
		n := node(identity, fmt.Sprintf("u%d", u), fmt.Sprintf("user-%d", u), "user")
		feed(nodeEvent(n))
		g := groupKeys[u%groups]
		feed(edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, n.Key, g, collectorv1.Fidelity_FIDELITY_DIRECT)))
		for k := 0; k < 10; k++ {
			feed(edgeEvent(edge(collectorv1.EdgeType_EDGE_TYPE_HOLDS, n.Key, roleKeys[(u*10+k)%roles],
				collectorv1.Fidelity_FIDELITY_EFFECTIVE, g)))
		}
	}

	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	retained := m.HeapAlloc
	runtime.KeepAlive(c)

	edges := uint64(groups + users*11)
	perEdge := retained / edges
	t.Logf("retained %d MB for %d nodes and %d edges (%d B/edge)",
		retained/(1<<20), 1+groups+roles+users, edges, perEdge)

	// A loose ceiling, not a target. Heap measurement is noisy, so this is
	// here to catch a regression that changes the order of magnitude -- such
	// as retaining whole messages again -- rather than to police bytes.
	const ceiling = 600
	if perEdge > ceiling {
		t.Errorf("retaining %d B/edge, ceiling is %d; the checker is holding more than a digest per node and the path-bearing edges",
			perEdge, ceiling)
	}
}

// Resume is mandatory, so a stream that sends records and never offers a point
// to resume from has not honoured it, whatever its completion says.
func TestAStreamThatEmitsRecordsMustOfferACheckpoint(t *testing.T) {
	s := keycloakStream(t)
	out := make([]*collectorv1.CollectResponse, 0, len(s))
	for _, e := range s {
		if e.GetCheckpoint() != nil {
			continue
		}
		out = append(out, e)
	}
	wantRules(t, run(out...), "checkpoint-required")
}

// A completion that reports a scope as collected, when no node for that scope
// was ever emitted, is a claim about a place we have no evidence of visiting.
func TestACompletionMayNotNameAScopeThatWasNeverEmitted(t *testing.T) {
	s := keycloakStream(t)
	s[len(s)-1].GetCompletion().Scopes = append(s[len(s)-1].GetCompletion().Scopes,
		&collectorv1.ScopeOutcome{
			Scope:  scopeKey("realm-never-visited"),
			Status: collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED,
		})
	wantRules(t, run(s...), "referenced-node-was-never-emitted")
}

// One record per (subject, signal): two answers to the same question let a
// consumer pick whichever it happened to see last.
func TestActivityIsUniquePerSubjectAndSignal(t *testing.T) {
	s := keycloakStream(t)
	a := seenActivity()
	a.Subject = key(identity, "u1")
	again := seenActivity()
	again.Subject = key(identity, "u1")

	s[len(s)-1].GetCompletion().Counts.Activities = 2
	s = append(s[:len(s)-1],
		&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Activity{Activity: a}},
		&collectorv1.CollectResponse{Event: &collectorv1.CollectResponse_Activity{Activity: again}},
		s[len(s)-1])
	wantRules(t, run(s...), "activity-must-be-unique-per-subject-and-signal")
}
