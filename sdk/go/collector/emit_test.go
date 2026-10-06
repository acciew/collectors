package collector_test

import (
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// The measure of this API is whether the common case is one obvious line. A
// plugin author writes these all day; if building a record takes a paragraph,
// collectors get written badly or not at all.
func TestBuildingTheCommonRecordsTakesOneLine(t *testing.T) {
	realm := collector.Scope("realm-a", "realm-a")
	alice := collector.IdentityKey("realm-a", "u1")
	platform := collector.GroupingKey("realm-a", "g-platform")
	admin := collector.EntitlementKey("realm-a", "r-admin")

	nodes := []*collectorv1.Node{
		collector.ScopeNode(realm, "realm-a", "realm"),
		collector.Identity(alice, "alice", "user", collector.Human, collector.Active),
		collector.Grouping(platform, "Platform", "group"),
		collector.Entitlement(admin, "admin", "realm_role"),
	}
	for _, n := range nodes {
		if vs := collectorv1.ValidateNode(n); len(vs) != 0 {
			t.Errorf("%s: %v", n.GetName(), vs)
		}
	}

	edges := []*collectorv1.Edge{
		collector.MemberOf(alice, platform),
		collector.Holds(platform, admin, collector.Direct),
		collector.Holds(alice, admin, collector.Effective, collector.Via(platform)...),
	}
	for _, e := range edges {
		if vs := collectorv1.ValidateEdge(e); len(vs) != 0 {
			t.Errorf("%v: %v", e.GetType(), vs)
		}
	}
}

// Fidelity is positional rather than an option, so it cannot be forgotten.
// This is the rule the whole contract turns on: a reviewer must be able to
// tell a resolved grant from an unevaluated one.
func TestFidelityIsPositionalAndCannotBeOmitted(t *testing.T) {
	alice := collector.IdentityKey("realm-a", "u1")
	admin := collector.EntitlementKey("realm-a", "r-admin")

	// There is no Holds(from, to) overload. The compiler is the enforcement.
	e := collector.Holds(alice, admin, collector.Coarse)
	if e.GetFidelity() != collectorv1.Fidelity_FIDELITY_COARSE {
		t.Errorf("Fidelity = %v", e.GetFidelity())
	}
}

func TestAReferencedNodeMakesNoClaimBeyondExisting(t *testing.T) {
	external := collector.Reference(
		collector.IdentityKey("account-1", "AIDAEXTERNAL"),
		"arn:aws:iam::999:root", "external_principal")

	if external.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("Provenance = %v", external.GetProvenance())
	}
	// It still carries facts, because the vocabulary requires every identity to
	// have them -- and they say Unknown, which is the honest answer. "We did
	// not look inside that account" is a different statement from a missing
	// field, which reads as a plugin that forgot.
	facts := external.GetIdentity()
	if facts == nil {
		t.Fatal("a referenced identity still carries facts; omitting them reads as an omission")
	}
	if facts.GetKind() != collectorv1.IdentityKind_IDENTITY_KIND_UNKNOWN {
		t.Errorf("Kind = %v, want the explicit unknown", facts.GetKind())
	}
	if facts.GetStatus() != collectorv1.IdentityStatus_IDENTITY_STATUS_UNKNOWN {
		t.Errorf("Status = %v, want the explicit unknown", facts.GetStatus())
	}
	if facts.GetCreatedAt() != nil {
		t.Error("we did not observe a creation time, so we must not state one")
	}

	// A referenced node that is not an identity has no facts to state.
	refRole := collector.Reference(
		collector.EntitlementKey("account-1", "arn:aws:iam::999:role/Ext"), "Ext", "external_role")
	if refRole.GetIdentity() != nil {
		t.Error("only an identity carries identity facts")
	}
	if vs := collectorv1.ValidateNode(refRole); len(vs) != 0 {
		t.Errorf("a referenced entitlement should be valid: %v", vs)
	}
	if vs := collectorv1.ValidateNode(external); len(vs) != 0 {
		t.Errorf("a referenced node should be valid: %v", vs)
	}
}

func TestActivityConstructorsCarryTheirOwnFreshness(t *testing.T) {
	subject := collector.IdentityKey("realm-a", "u1")
	now := time.Unix(1e9, 0).UTC()
	window := collector.Window(now.Add(-30*24*time.Hour), now)

	seen := collector.Seen(subject, "login_event", now, window, 0,
		now.Add(-time.Hour), collector.Exact)
	notSeen := collector.NotSeen(subject, "role_last_used", now, window, 4*time.Hour,
		collector.Approximate)
	unavailable := collector.Unavailable(subject, "client_login_event", now,
		"keycloak.events.disabled", "event storage is off for this realm")

	for _, a := range []*collectorv1.Activity{seen, notSeen, unavailable} {
		if vs := collectorv1.ValidateActivity(a); len(vs) != 0 {
			t.Errorf("%s: %v", a.GetSignal(), vs)
		}
	}
	if seen.GetSeen().GetLastSeen().AsTime() != now.Add(-time.Hour) {
		t.Error("last seen did not survive")
	}
	// An unavailable answer needs no window: there is no window to describe.
	if unavailable.GetCoverage() != nil {
		t.Error("an unavailable result should not claim a coverage window")
	}
}

// The core cannot check that a plugin references its secrets rather than
// embedding them, so the SDK refuses to build the wrong thing in the first
// place. It is a discipline, not a guarantee, and it says so.
func TestASecretMustBeAReferenceNotALiteral(t *testing.T) {
	for _, good := range []string{"env:GITHUB_TOKEN", "file:/var/run/secrets/kc"} {
		if _, err := collector.ParseSecret(good); err != nil {
			t.Errorf("ParseSecret(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"ghp_realtokenvalue", "", "env:", "unknown:thing", "file:"} {
		if _, err := collector.ParseSecret(bad); err == nil {
			t.Errorf("ParseSecret(%q) should be refused", bad)
		}
	}

	s, err := collector.ParseSecret("env:GITHUB_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	// A secret must not print itself, because the whole point is that a
	// config can be logged without per-plugin redaction rules.
	if strings.Contains(s.String(), "GITHUB_TOKEN") {
		t.Errorf("String() = %q; a secret reference must not render its target", s.String())
	}
}

// Structural edges say how the source is arranged; nothing derives them, so
// the SDK does not offer the choice and they are always stated directly.
func TestStructuralEdgesAreAlwaysStatedDirectly(t *testing.T) {
	realm := "realm-a"
	child := collector.GroupingKey(realm, "g-platform")
	parent := collector.GroupingKey(realm, "g-engineering")
	composite := collector.EntitlementKey(realm, "r-admin")
	member := collector.EntitlementKey(realm, "r-read")
	client := collector.ResourceKey(realm, "c-account")
	scope := collector.Scope(realm, realm)
	role := collector.IdentityKey(realm, "i-orgadmin")

	edges := []*collectorv1.Edge{
		collector.ChildOf(child, parent),
		collector.Includes(composite, member),
		collector.AppliesTo(composite, client),
		// GitHub's organization base permission and an AWS policy naming
		// Resource "*" both grant against everything in a scope.
		collector.AppliesTo(composite, scope),
		collector.ActsAs(composite, role),
		collector.MemberOf(collector.IdentityKey(realm, "u1"), child),
	}
	for _, e := range edges {
		if e.GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT {
			t.Errorf("%v: fidelity = %v, want direct", e.GetType(), e.GetFidelity())
		}
		if e.GetPath() != nil {
			t.Errorf("%v carries a path; a stated fact has no route", e.GetType())
		}
		if vs := collectorv1.ValidateEdge(e); len(vs) != 0 {
			t.Errorf("%v: %v", e.GetType(), vs)
		}
	}
}

func TestSourceContextRidesAlongWithoutBeingInterpreted(t *testing.T) {
	n := collector.WithContext(
		collector.Entitlement(collector.EntitlementKey("realm-a", "r1"), "admin", "client_role"),
		map[string]string{"realm": "realm-a", "client_id": "account", "role_type": "client"})

	if n.GetContext()["client_id"] != "account" {
		t.Errorf("Context = %v", n.GetContext())
	}
	if vs := collectorv1.ValidateNode(n); len(vs) != 0 {
		t.Errorf("%v", vs)
	}
}

func TestASecretReportsHowItResolvesWithoutRevealingWhat(t *testing.T) {
	s, err := collector.ParseSecret("file:/var/run/secrets/kc")
	if err != nil {
		t.Fatal(err)
	}
	if s.Scheme() != "file" {
		t.Errorf("Scheme() = %q", s.Scheme())
	}
	if strings.Contains(s.String(), "/var/run/secrets") {
		t.Errorf("String() = %q; the target must not appear", s.String())
	}
}

// A grant's source type says how the access is expressed — a group role
// mapping is a different thing to revoke than a direct one — and it is a
// different fact from what the entitlement is. Without it a reviewer reading
// "effective" knows the claim is resolved and not what to act on.
func TestHowGrantedRecordsTheSourcesOwnWordForTheGrant(t *testing.T) {
	subject := collector.IdentityKey("realm-a", "alice")
	entitlement := collector.EntitlementKey("realm-a", "admin")
	group := collector.GroupingKey("realm-a", "platform")

	e := collector.HowGranted(
		collector.Holds(subject, entitlement, collector.Effective, group),
		"group_role_mapping")

	if e.GetSourceType() != "group_role_mapping" {
		t.Errorf("source type = %q", e.GetSourceType())
	}
	// It decorates rather than replaces: everything the grant already said
	// has to survive.
	if e.GetFidelity() != collector.Effective {
		t.Errorf("fidelity = %v", e.GetFidelity())
	}
	if len(e.GetPath().GetVia()) != 1 {
		t.Errorf("the route did not survive: %v", e.GetPath())
	}
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 {
		t.Errorf("the edge is invalid: %s", vs[0])
	}
}
