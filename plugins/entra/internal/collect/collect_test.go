package collect_test

import (
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
)

// Identifiers are made up. Reading a test, "alice" is a person and the GUID is
// whatever she is called in a directory.
var (
	alice, bob, carol, dave = fakegraph.Alice, fakegraph.Bob, fakegraph.Carol, fakegraph.Dave

	engineering, platform = fakegraph.Engineering, fakegraph.Platform
	sales, admins         = fakegraph.Sales, fakegraph.Admins

	globalAdmin, helpdesk = fakegraph.GlobalAdmin, fakegraph.Helpdesk
	unitA                 = fakegraph.UnitA
)

// directory is the sample tenant every collection test starts from.
func directory() *fakegraph.Tenant { return fakegraph.Example() }

func TestTheTenantIsTheOneScope(t *testing.T) {
	w := newWorld(t, directory())
	out := w.mustRun("")

	scope := w.srv.Tenant.ID
	n := out.node(scope, "NODE_TYPE_SCOPE", scope)
	if n == nil {
		t.Fatal("the tenant is not emitted as a scope keyed under itself")
	}
	if n.GetName() != "Example Corp" || n.GetSourceType() != "tenant" {
		t.Errorf("scope = %q (%s), want the organisation's name and the badge tenant", n.GetName(), n.GetSourceType())
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope outcomes = %+v, want the tenant collected", out.scopes)
	}
	out.assertContract()
}

func TestUsersAreHumansWithTheStatusTheSourceStates(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	for _, c := range []struct {
		id         string
		status     collectorv1.IdentityStatus
		sourceType string
	}{
		{alice, collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE, "user"},
		{bob, collectorv1.IdentityStatus_IDENTITY_STATUS_DISABLED, "user"},
		{carol, collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE, "guest_user"},
		// Graph did not say. Calling a user it did not describe disabled would
		// turn every grant they hold into one a reviewer skips.
		{dave, collectorv1.IdentityStatus_IDENTITY_STATUS_UNKNOWN, "user"},
	} {
		n := out.node("", "NODE_TYPE_IDENTITY", c.id)
		if n == nil {
			t.Errorf("%s: not emitted", c.id)
			continue
		}
		if n.GetIdentity().GetKind() != collectorv1.IdentityKind_IDENTITY_KIND_HUMAN ||
			n.GetIdentity().GetStatus() != c.status || n.GetSourceType() != c.sourceType {
			t.Errorf("%s = %v/%v/%s, want human/%v/%s", n.GetName(), n.GetIdentity().GetKind(),
				n.GetIdentity().GetStatus(), n.GetSourceType(), c.status, c.sourceType)
		}
	}
	a := out.node("", "NODE_TYPE_IDENTITY", alice)
	if a.GetContext()["upn"] != "alice@example.onmicrosoft.com" || a.GetContext()["user_type"] != "Member" ||
		a.GetContext()["on_premises_sid"] != "S-1-5-21-1-2-3-1001" {
		t.Errorf("alice context = %v; the SID is the handle that will correlate with on-premises AD later", a.GetContext())
	}
}

// Either marker is enough: a guest Entra types as Guest whose UPN is not marked,
// and one whose type is missing but whose UPN is.
func TestAGuestIsRecognisedByItsTypeAloneToo(t *testing.T) {
	d := directory()
	d.Users = append(d.Users, fakegraph.User{ID: fakegraph.GUID("frank"), DisplayName: "Frank",
		UPN: "frank@partner.example", UserType: "Guest", Enabled: fakegraph.Enabled(true)})
	out := newWorld(t, d).mustRun("")

	if got := out.node("", "NODE_TYPE_IDENTITY", fakegraph.GUID("frank")).GetSourceType(); got != "guest_user" {
		t.Errorf("a user typed Guest is %q, want guest_user", got)
	}
	if got := out.node("", "NODE_TYPE_IDENTITY", alice).GetSourceType(); got != "user" {
		t.Errorf("a member is %q, want user", got)
	}
}

func TestAGuestIsRecognisedByItsTypeAndByItsUPN(t *testing.T) {
	d := directory()
	// userType missing but the UPN has the guest marker.
	d.Users = append(d.Users, fakegraph.User{ID: fakegraph.GUID("erin"), DisplayName: "Erin",
		UPN: "erin_partner.example#EXT#@example.onmicrosoft.com", Enabled: fakegraph.Enabled(true)})
	out := newWorld(t, d).mustRun("")

	if got := out.node("", "NODE_TYPE_IDENTITY", fakegraph.GUID("erin")).GetSourceType(); got != "guest_user" {
		t.Errorf("a #EXT# user is %q, want guest_user", got)
	}
}

func TestGroupsCarryHowTheirMembershipIsDecided(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	e := out.node("", "NODE_TYPE_GROUPING", engineering)
	if e.GetSourceType() != "group" || e.GetContext()["membership"] != "static" {
		t.Errorf("Engineering = %s %v, want a static group", e.GetSourceType(), e.GetContext())
	}
	s := out.node("", "NODE_TYPE_GROUPING", sales)
	if s.GetSourceType() != "dynamic_group" || s.GetContext()["membership"] != "dynamic" ||
		s.GetContext()["membership_rule"] != `(user.department -eq "Sales")` ||
		s.GetContext()["membership_rule_state"] != "On" {
		t.Errorf("Sales = %s %v, want a dynamic group carrying its rule", s.GetSourceType(), s.GetContext())
	}
	a := out.node("", "NODE_TYPE_GROUPING", admins)
	if a.GetContext()["is_assignable_to_role"] != "true" {
		t.Errorf("Admins context = %v, want it marked role-assignable", a.GetContext())
	}
}

func TestMembershipIsDirectAndNestingIsAChildOfEdge(t *testing.T) {
	w := newWorld(t, directory())
	out := w.mustRun("")

	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, alice, engineering)) != 1 {
		t.Error("alice is not a member of Engineering")
	}
	// Dynamic membership is the source's materialised answer, so a stated fact.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, dave, sales)) != 1 {
		t.Error("dave is not a member of the dynamic group Sales")
	}
	// Child first.
	child := out.edges(collectorv1.EdgeType_EDGE_TYPE_CHILD_OF, platform, engineering)
	if len(child) != 1 || child[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT {
		t.Errorf("Platform inside Engineering = %v, want one DIRECT child-of edge", child)
	}
	// Nothing says carol is in Engineering; she is in Platform, which is.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, carol, engineering)) != 0 {
		t.Error("nested membership was flattened into a direct edge")
	}
	// transitiveMembers is a flat list with no path, so nothing could route a
	// grant through it. It must not even be asked for.
	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "transitiveMembers") {
			t.Errorf("asked for %s", p)
		}
	}
}

func TestMembersThatAreNotPeopleOrGroupsAreCountedNotCollected(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	d := out.diag("entra.skipped")
	if d == nil || !strings.Contains(d.GetMessage(), "1 device") {
		t.Fatalf("diagnostic = %v, want it to say one device member was not collected", d)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, fakegraph.Laptop, admins)) != 0 {
		t.Error("a device became a member edge from a node that was never emitted")
	}
	out.assertContract()
}

func TestDirectoryRolesAreEntitlementsAndAssignmentsAreDirectGrants(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	ga := out.node("", "NODE_TYPE_ENTITLEMENT", "role:"+globalAdmin)
	if ga == nil || ga.GetName() != "Global Administrator" || ga.GetSourceType() != "directory_role" {
		t.Fatalf("Global Administrator = %v", ga)
	}
	if ga.GetContext()["built_in"] != "true" {
		t.Errorf("context = %v, want built_in recorded so a custom role can be told from one Microsoft ships", ga.GetContext())
	}

	held := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, "role:"+globalAdmin)
	var direct *collectorv1.Edge
	for _, e := range held {
		if e.GetFidelity() == collectorv1.Fidelity_FIDELITY_DIRECT {
			direct = e
		}
	}
	if direct == nil || direct.GetSourceType() != "directory_role_assignment" {
		t.Fatalf("alice's direct grant = %v among %v", direct, held)
	}
	// Assigned at the root, so it applies to the tenant.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, "role:"+globalAdmin, w0(out))) != 1 {
		t.Error("a tenant-wide role does not apply to the tenant scope")
	}
}

// w0 is the tenant id as the stream names it.
func w0(out *capture) string {
	for _, e := range out.events {
		if n := e.GetNode(); n != nil && n.GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_SCOPE {
			return n.GetKey().GetId()
		}
	}
	return ""
}

// A role-assignable group cannot be dynamic and cannot nest, so what its
// members hold is one hop away and exactly known.
func TestARoleHeldByAGroupIsHeldDirectlyByTheGroupAndEffectivelyByItsMembers(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	if g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, admins, "role:"+globalAdmin); len(g) != 1 ||
		g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT {
		t.Fatalf("the group's own grant = %v, want one DIRECT edge", g)
	}
	var effective *collectorv1.Edge
	for _, e := range out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, "role:"+globalAdmin) {
		if e.GetFidelity() == collectorv1.Fidelity_FIDELITY_EFFECTIVE {
			effective = e
		}
	}
	if effective == nil {
		t.Fatal("alice, a member of the group, does not hold the role effectively")
	}
	via := effective.GetPath().GetVia()
	if len(via) != 1 || via[0].GetId() != admins || via[0].GetType() != collectorv1.NodeType_NODE_TYPE_GROUPING {
		t.Errorf("path = %v, want exactly the group", via)
	}
	if effective.GetSourceType() != "role_assignable_group" {
		t.Errorf("how granted = %q", effective.GetSourceType())
	}
	// The device in the group holds nothing we can name.
	out.assertContract()
}

func TestARoleScopedToAnAdministrativeUnitIsItsOwnEntitlementThatAppliesToTheUnit(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	id := "role:" + helpdesk + ":au:" + unitA
	e := out.node("", "NODE_TYPE_ENTITLEMENT", id)
	if e == nil || !strings.Contains(e.GetName(), "Helpdesk Administrator") || !strings.Contains(e.GetName(), "administrative unit") {
		t.Fatalf("scoped entitlement = %v; Bob's helpdesk role is over one unit and must not read as the tenant-wide role", e)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, bob, id)) != 1 {
		t.Error("bob does not hold the scoped role")
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, bob, "role:"+helpdesk)) != 0 {
		t.Error("an administrative-unit assignment was filed under the tenant-wide role")
	}
	// The unit is named but not read: administrative units are off by default,
	// so it is a referenced resource and says so.
	unit := out.node("", "NODE_TYPE_RESOURCE", "au:"+unitA)
	if unit == nil || unit.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("unit = %v, want a referenced resource", unit)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, id, "au:"+unitA)) != 1 {
		t.Error("the scoped role does not apply to its unit")
	}
	out.assertContract()
}

func TestThePageSizeBoundsEveryRequestAndNothingIsLostToPaging(t *testing.T) {
	d := directory()
	for i := range 11 {
		id := fakegraph.GUID("extra" + string(rune('a'+i)))
		d.Users = append(d.Users, fakegraph.User{ID: id, DisplayName: "Extra " + id[:4], UPN: id[:4] + "@example.onmicrosoft.com", Enabled: fakegraph.Enabled(true)})
	}
	w := newWorld(t, d)
	w.srv.PageSize = 2
	out := w.mustRun("")

	users := out.count(func(e *collectorv1.CollectResponse) bool {
		n := e.GetNode()
		return n.GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_IDENTITY && strings.HasSuffix(n.GetSourceType(), "user")
	})
	if users != 15 {
		t.Errorf("%d users collected, want all 15", users)
	}
	out.assertContract()
}
