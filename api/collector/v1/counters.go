package collectorv1

import "fmt"

// Counters tallies what a stream carried.
//
// It exists because the obvious thing — keeping a Counts message and
// assigning to it — copies a protobuf message by value, and a protobuf
// message contains a mutex. Both the SDK and the host need this tally, and
// both had the same latent bug, so it lives here once.

// Counters is a plain tally, safe to copy and compare.
type Counters struct {
	Identities   uint64
	Groupings    uint64
	Entitlements uint64
	Resources    uint64
	Scopes       uint64
	Edges        uint64
	Activities   uint64
}

// CountNode tallies one node against its type.
func (c *Counters) CountNode(n *Node) {
	switch n.GetKey().GetType() {
	case NodeType_NODE_TYPE_IDENTITY:
		c.Identities++
	case NodeType_NODE_TYPE_GROUPING:
		c.Groupings++
	case NodeType_NODE_TYPE_ENTITLEMENT:
		c.Entitlements++
	case NodeType_NODE_TYPE_RESOURCE:
		c.Resources++
	case NodeType_NODE_TYPE_SCOPE:
		c.Scopes++
	}
}

// Proto renders the tally as a contract message.
func (c Counters) Proto() *Counts {
	return &Counts{
		Identities:   c.Identities,
		Groupings:    c.Groupings,
		Entitlements: c.Entitlements,
		Resources:    c.Resources,
		Scopes:       c.Scopes,
		Edges:        c.Edges,
		Activities:   c.Activities,
	}
}

// Disagreements reports, per field, where a declared count differs from what
// was actually counted. Empty means they agree.
//
// A mismatch is a contract violation rather than a rounding difference: it
// means the plugin does not know what it sent, which is a reason not to trust
// the rest of it.
func (c Counters) Disagreements(declared *Counts) []Violation {
	fields := []struct {
		name             string
		declared, actual uint64
	}{
		{"identities", declared.GetIdentities(), c.Identities},
		{"groupings", declared.GetGroupings(), c.Groupings},
		{"entitlements", declared.GetEntitlements(), c.Entitlements},
		{"resources", declared.GetResources(), c.Resources},
		{"scopes", declared.GetScopes(), c.Scopes},
		{"edges", declared.GetEdges(), c.Edges},
		{"activities", declared.GetActivities(), c.Activities},
	}
	var vs []Violation
	for _, f := range fields {
		if f.declared != f.actual {
			vs = append(vs, Violation{
				Field: "completion.counts." + f.name,
				Rule:  ruleCountsAgree,
				Message: fmt.Sprintf("the plugin declared %d %s but sent %d",
					f.declared, f.name, f.actual),
			})
		}
	}
	return vs
}
