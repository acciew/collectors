// Package collector is the Go SDK for writing an Acciew collector plugin.
//
// A collector implements the Collector interface and calls Serve. Everything
// else — handshake, transport, streaming, error mapping, log passthrough — is
// handled here. You should never need to know what the transport is; if you
// do, that is a defect in this package rather than something to work around.
//
// The constructors in this package exist so that the common case is one
// obvious line. A plugin author writes these all day, and an API where
// building a single record takes a paragraph produces collectors that are
// written badly or not at all.
//
// Every constructed record is checked against the contract before it goes on
// the wire, so a mistake surfaces as an error to you rather than as a
// collection the host rejects. See sdk/go/README.md for the compatibility
// policy this SDK commits to, and docs/plugins/ for the authoring guide.
//
// The package lives one level below the module root because the module path
// ends in "go", which is a keyword and cannot be a package name.
package collector

import (
	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// The contract's vocabulary, re-exported so that a plugin author imports this
// package and nothing else. These are the contract's own values, not a
// parallel set that could drift from it.
const (
	// Fidelity: how much a consumer may trust a grant.
	Direct    = collectorv1.Fidelity_FIDELITY_DIRECT
	Effective = collectorv1.Fidelity_FIDELITY_EFFECTIVE
	Coarse    = collectorv1.Fidelity_FIDELITY_COARSE

	// IdentityKind. Unknown is an honest answer; there is deliberately no
	// value meaning "I did not think about it".
	Human       = collectorv1.IdentityKind_IDENTITY_KIND_HUMAN
	ServiceKind = collectorv1.IdentityKind_IDENTITY_KIND_SERVICE
	MachineKind = collectorv1.IdentityKind_IDENTITY_KIND_MACHINE
	UnknownKind = collectorv1.IdentityKind_IDENTITY_KIND_UNKNOWN

	// IdentityStatus.
	Active        = collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE
	Disabled      = collectorv1.IdentityStatus_IDENTITY_STATUS_DISABLED
	UnknownStatus = collectorv1.IdentityStatus_IDENTITY_STATUS_UNKNOWN

	// Confidence: how precise an activity claim is.
	Exact       = collectorv1.Confidence_CONFIDENCE_EXACT
	Approximate = collectorv1.Confidence_CONFIDENCE_APPROXIMATE
)

// Key builders. The node type is part of a key because one source object can
// be two nodes — an AWS role is a principal and an assumable entitlement at
// once — so there is a builder per type rather than one that takes the type as
// an argument and can be passed the wrong one.

// IdentityKey names a principal.
func IdentityKey(scope, id string) *collectorv1.Key {
	return key(scope, collectorv1.NodeType_NODE_TYPE_IDENTITY, id)
}

// GroupingKey names a container of identities.
func GroupingKey(scope, id string) *collectorv1.Key {
	return key(scope, collectorv1.NodeType_NODE_TYPE_GROUPING, id)
}

// EntitlementKey names a permission.
func EntitlementKey(scope, id string) *collectorv1.Key {
	return key(scope, collectorv1.NodeType_NODE_TYPE_ENTITLEMENT, id)
}

// ResourceKey names something access is to.
func ResourceKey(scope, id string) *collectorv1.Key {
	return key(scope, collectorv1.NodeType_NODE_TYPE_RESOURCE, id)
}

// Scope names an isolation boundary. A scope is keyed under itself, which the
// contract requires and which this builder makes it impossible to get wrong.
func Scope(scope, id string) *collectorv1.Key {
	return key(scope, collectorv1.NodeType_NODE_TYPE_SCOPE, id)
}

func key(scope string, t collectorv1.NodeType, id string) *collectorv1.Key {
	return &collectorv1.Key{Scope: scope, Type: t, Id: id}
}

// Node builders.
//
// sourceType is your own word for what this is — "user", "realm_role",
// "managed_policy". It is never normalised and never interpreted; a reviewer
// UI renders it as the badge that tells them what kind of thing they are
// looking at.

// Identity emits a principal. Kind and status are positional because a
// reviewer's decision depends on both, and a default for either would be a
// guess presented as a fact.
func Identity(k *collectorv1.Key, name, sourceType string,
	kind collectorv1.IdentityKind, status collectorv1.IdentityStatus) *collectorv1.Node {
	n := node(k, name, sourceType)
	n.Identity = &collectorv1.IdentityFacts{Kind: kind, Status: status}
	return n
}

// Grouping emits a container of identities.
func Grouping(k *collectorv1.Key, name, sourceType string) *collectorv1.Node {
	return node(k, name, sourceType)
}

// Entitlement emits a permission.
func Entitlement(k *collectorv1.Key, name, sourceType string) *collectorv1.Node {
	return node(k, name, sourceType)
}

// Resource emits something access is to.
func Resource(k *collectorv1.Key, name, sourceType string) *collectorv1.Node {
	return node(k, name, sourceType)
}

// ScopeNode emits an isolation boundary.
func ScopeNode(k *collectorv1.Key, name, sourceType string) *collectorv1.Node {
	return node(k, name, sourceType)
}

// Reference emits a node you did not enumerate and only saw named by
// something else — an external principal in an AWS trust policy, a federated
// provider. It makes no claim beyond existing as the subject of a grant, and
// its absence from a later collection is not evidence that anything changed.
//
// A referenced identity still carries identity facts, because the vocabulary
// requires every identity to have them, and they say Unknown for both kind and
// status. That is the honest encoding: "this is a principal, and we do not
// know what kind of principal or whether it is enabled, because we never
// looked inside the account it lives in." Omitting the facts entirely would
// force every consumer to special-case a node that has none, and would make
// "we did not look" indistinguishable from "the plugin forgot".
func Reference(k *collectorv1.Key, name, sourceType string) *collectorv1.Node {
	n := node(k, name, sourceType)
	n.Provenance = collectorv1.Provenance_PROVENANCE_REFERENCED
	if k.GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY {
		n.Identity = &collectorv1.IdentityFacts{
			Kind:   collectorv1.IdentityKind_IDENTITY_KIND_UNKNOWN,
			Status: collectorv1.IdentityStatus_IDENTITY_STATUS_UNKNOWN,
		}
	}
	return n
}

func node(k *collectorv1.Key, name, sourceType string) *collectorv1.Node {
	return &collectorv1.Node{
		Key:        k,
		Name:       name,
		SourceType: sourceType,
		Provenance: collectorv1.Provenance_PROVENANCE_OBSERVED,
	}
}

// WithContext attaches source-vocabulary detail to a node: realm, client_id,
// policy_arn, permission_level. The core never interprets it.
func WithContext(n *collectorv1.Node, kv map[string]string) *collectorv1.Node {
	n.Context = kv
	return n
}

// HowGranted records the source's own word for how a grant is expressed:
// "group_role_mapping", "composite", "managed_policy_attachment". It
// describes the grant rather than the entitlement, and a reviewer deciding
// what to revoke acts on this rather than on what the entitlement is.
func HowGranted(e *collectorv1.Edge, sourceType string) *collectorv1.Edge {
	e.SourceType = sourceType
	return e
}

// Edge builders.

// MemberOf records that an identity belongs to a grouping.
func MemberOf(identity, grouping *collectorv1.Key) *collectorv1.Edge {
	return structural(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, identity, grouping)
}

// ChildOf records that a grouping sits under another, child first.
func ChildOf(child, parent *collectorv1.Key) *collectorv1.Edge {
	return structural(collectorv1.EdgeType_EDGE_TYPE_CHILD_OF, child, parent)
}

// Includes records that one entitlement contains another, as a Keycloak
// composite role does.
func Includes(composite, member *collectorv1.Key) *collectorv1.Edge {
	return structural(collectorv1.EdgeType_EDGE_TYPE_INCLUDES, composite, member)
}

// AppliesTo records what an entitlement is scoped to: a specific resource, or
// a whole scope when the source grants against everything in it, as GitHub's
// organization base permission does.
func AppliesTo(entitlement, target *collectorv1.Key) *collectorv1.Edge {
	return structural(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, entitlement, target)
}

// ActsAs records that holding an entitlement lets the holder act as a
// principal, as an AWS assumable role does. Without this edge the two nodes
// for one role are unrelated and the assume chain has no path.
func ActsAs(entitlement, identity *collectorv1.Key) *collectorv1.Edge {
	return structural(collectorv1.EdgeType_EDGE_TYPE_ACTS_AS, entitlement, identity)
}

// Holds records a grant.
//
// Fidelity is positional and there is no overload without it. It is the one
// thing a plugin author must never leave to a default: a reviewer shown an
// unevaluated policy attachment and a resolved role as though they were the
// same claim is being misled, and no type system catches that afterwards.
//
// Pass the path for a derived grant. Every hop must be an edge you also
// emitted, stated directly, or the conformance suite will say so.
func Holds(subject, entitlement *collectorv1.Key, fidelity collectorv1.Fidelity,
	path ...*collectorv1.Key) *collectorv1.Edge {
	e := &collectorv1.Edge{
		Type:     collectorv1.EdgeType_EDGE_TYPE_HOLDS,
		From:     subject,
		To:       entitlement,
		Fidelity: fidelity,
	}
	if len(path) > 0 {
		e.Path = &collectorv1.Path{Via: path}
	}
	return e
}

// Via reads better than a bare slice at a call site:
//
//	Holds(alice, admin, Effective, Via(platform, engineering)...)
func Via(keys ...*collectorv1.Key) []*collectorv1.Key { return keys }

// structural edges state how the source is arranged. Nothing derives them, so
// they are always DIRECT and the SDK does not offer the choice.
func structural(t collectorv1.EdgeType, from, to *collectorv1.Key) *collectorv1.Edge {
	return &collectorv1.Edge{
		Type: t, From: from, To: to,
		Fidelity: collectorv1.Fidelity_FIDELITY_DIRECT,
	}
}
