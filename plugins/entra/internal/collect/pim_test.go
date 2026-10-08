package collect_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

var soon = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

// privileged is the sample tenant plus what PIM adds: Dave is eligible for
// Global Administrator, Bob holds Helpdesk for a limited time, and Alice has
// just activated a role she is eligible for.
func privileged() *fakegraph.Tenant {
	d := directory()
	d.Eligible = []fakegraph.ScheduleInstance{
		{ID: "e1", Principal: dave, PrincipalType: "user", PrincipalName: "Dave", RoleDefID: globalAdmin, Scope: "/", MemberType: "Direct"},
		{ID: "e2", Principal: fakegraph.GUID("g-elig"), PrincipalType: "group", PrincipalName: "Eligible admins", RoleDefID: helpdesk, Scope: "/", MemberType: "Direct"},
		{ID: "e3", Principal: carol, PrincipalType: "user", PrincipalName: "Carol", RoleDefID: helpdesk,
			Scope: "/administrativeUnits/" + unitA, MemberType: "Direct"},
		// The same eligibility seen from a member of the group: it is derived
		// here, from the group's own instance, and not read twice.
		{ID: "e4", Principal: alice, PrincipalType: "user", PrincipalName: "Alice", RoleDefID: helpdesk, Scope: "/", MemberType: "Group"},
		{ID: "e5", Principal: bob, PrincipalType: "user", PrincipalName: "Bob", RoleDefID: helpdesk, Scope: "/", MemberType: "Inherited"},
	}
	d.Groups = append(d.Groups, fakegraph.Group{
		ID: fakegraph.GUID("g-elig"), DisplayName: "Eligible admins", AssignableToRole: true,
		Members: []fakegraph.Member{{ID: alice, Type: "user", DisplayName: "Alice Example"}},
	})
	d.ActiveInstances = []fakegraph.ScheduleInstance{
		{ID: "a1", Principal: bob, PrincipalType: "user", PrincipalName: "Bob", RoleDefID: helpdesk, Scope: "/",
			MemberType: "Direct", AssignmentType: "Assigned", End: soon},
		// Permanent, so already among the role assignments.
		{ID: "a2", Principal: alice, PrincipalType: "user", PrincipalName: "Alice", RoleDefID: globalAdmin, Scope: "/",
			MemberType: "Direct", AssignmentType: "Assigned"},
		// The same time-bound grant seen through a group: the group's own
		// instance says it, and this one is not a second route.
		{ID: "a4", Principal: carol, PrincipalType: "user", PrincipalName: "Carol", RoleDefID: helpdesk, Scope: "/",
			MemberType: "Group", AssignmentType: "Assigned", End: soon},
		// An activation of an eligibility, which lasts hours.
		{ID: "a3", Principal: dave, PrincipalType: "user", PrincipalName: "Dave", RoleDefID: globalAdmin, Scope: "/",
			MemberType: "Direct", AssignmentType: "Activated", End: soon},
	}
	return d
}

// Eligible and active to one entitlement would be one edge: edge identity is
// type, ends and path, so the history would merge them and a reviewer could
// not tell who can become a Global Administrator from who is one.
func TestEligibleAndActiveAreEntitlementsOfTheirOwnAndNeverTheRolesThemselves(t *testing.T) {
	out := newWorld(t, privileged()).mustRun("")

	e := out.node("", "NODE_TYPE_ENTITLEMENT", "role:"+globalAdmin+":eligible")
	if e == nil || e.GetName() != "Global Administrator (eligible)" || e.GetSourceType() != "directory_role" {
		t.Fatalf("eligible entitlement = %v", e)
	}
	g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, dave, "role:"+globalAdmin+":eligible")
	if len(g) != 1 || g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT || g[0].GetSourceType() != "pim_eligible_assignment" {
		t.Errorf("dave's eligibility = %v", g)
	}
	// Eligible is not held: nothing says dave has the role itself.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, dave, "role:"+globalAdmin)) != 0 {
		t.Error("an eligibility was filed as the role itself")
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, "role:"+globalAdmin+":eligible", w0(out))) != 1 {
		t.Error("the eligible role does not apply to the tenant")
	}
	out.assertContract()
}

func TestAnEligibilityHeldByAGroupIsEligibleForItsDirectMembersThroughIt(t *testing.T) {
	out := newWorld(t, privileged()).mustRun("")

	role := "role:" + helpdesk + ":eligible"
	group := fakegraph.GUID("g-elig")
	if g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, group, role); len(g) != 1 || g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT {
		t.Fatalf("the group's eligibility = %v", g)
	}
	var viaGroup *collectorv1.Edge
	for _, e := range out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, role) {
		viaGroup = e
	}
	if viaGroup == nil || viaGroup.GetFidelity() != collectorv1.Fidelity_FIDELITY_EFFECTIVE ||
		len(viaGroup.GetPath().GetVia()) != 1 || viaGroup.GetPath().GetVia()[0].GetId() != group {
		t.Errorf("alice's eligibility = %v, want one effective edge through the group", viaGroup)
	}
	// The per-member instances Graph may also list are not a second route.
	if n := len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, role)); n != 1 {
		t.Errorf("%d edges from alice, want the one through the group", n)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, bob, role)) != 0 {
		t.Error("an inherited instance became a grant of its own")
	}
	out.assertContract()
}

func TestAnEligibilityOverAnAdministrativeUnitIsItsOwnEntitlementThatAppliesToTheUnit(t *testing.T) {
	out := newWorld(t, privileged()).mustRun("")

	id := "role:" + helpdesk + ":au:" + unitA + ":eligible"
	if e := out.node("", "NODE_TYPE_ENTITLEMENT", id); e == nil || !strings.Contains(e.GetName(), "(eligible)") ||
		!strings.Contains(e.GetName(), "administrative unit") {
		t.Fatalf("entitlement = %v", e)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, id, "au:"+unitA)) != 1 || len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, carol, id)) != 1 {
		t.Error("carol's scoped eligibility is incomplete")
	}
}

// Only a grant that is both made by an administrator and bounded in time is
// new. A permanent one is already among the role assignments, and an
// activation derives from an eligibility that is collected.
func TestOnlyATimeBoundAssignmentIsAnActiveGrantOfItsOwn(t *testing.T) {
	out := newWorld(t, privileged()).mustRun("")

	active := "role:" + helpdesk + ":active"
	e := out.node("", "NODE_TYPE_ENTITLEMENT", active)
	if e == nil || e.GetName() != "Helpdesk Administrator (active, time-bound)" {
		t.Fatalf("active entitlement = %v", e)
	}
	if g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, bob, active); len(g) != 1 || g[0].GetSourceType() != "pim_active_assignment" {
		t.Errorf("bob's time-bound grant = %v", g)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, carol, active)) != 0 {
		t.Error("a time-bound instance that is not direct became a grant of its own")
	}
	for _, id := range []string{"role:" + globalAdmin + ":active"} {
		if out.node("", "NODE_TYPE_ENTITLEMENT", id) != nil {
			t.Errorf("%s: a permanent or activated instance became an active grant", id)
		}
	}
	d := out.diag("entra.pim.skipped")
	if d == nil || !strings.Contains(d.GetMessage(), "1 activated") || !strings.Contains(d.GetMessage(), "1 permanent") ||
		!strings.Contains(d.GetMessage(), "3 not direct") {
		t.Errorf("diagnostic = %v, want it to count what was left out and why", d)
	}
	out.assertContract()
}

func TestThePIMFlagDecidesWhetherSchedulesAreRead(t *testing.T) {
	w := newWorld(t, privileged())
	out := w.mustRun(`{"pim":false}`)

	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "ScheduleInstances") {
			t.Errorf("asked for %s with PIM off", p)
		}
	}
	if out.node("", "NODE_TYPE_ENTITLEMENT", "role:"+globalAdmin+":eligible") != nil {
		t.Error("an eligibility was collected with PIM off")
	}
}

// PIM is on by default and a tenant need not be licensed for it. A refusal
// Graph is known to use for a missing licence is a tenant with nothing to
// collect here, and says so.
func TestATenantWithoutThePIMLicenceHasNothingToCollectAndSaysSo(t *testing.T) {
	w := newWorld(t, privileged())
	w.srv.Refuse("/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", http.StatusForbidden,
		"AadPremiumLicenseRequired", "The tenant needs a premium licence.")
	w.srv.Refuse("/v1.0/roleManagement/directory/roleAssignmentScheduleInstances", http.StatusForbidden,
		"AadPremiumLicenseRequired", "The tenant needs a premium licence.")
	out := w.mustRun("")

	d := out.diag("entra.pim.unlicensed")
	if d == nil || !strings.Contains(d.GetMessage(), "AadPremiumLicenseRequired") {
		t.Fatalf("diagnostic = %v, want it to say PIM is not licensed and what Graph said", d)
	}
	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v: a tenant that does not use PIM is whole", out.scopes[0].Status)
	}
}

// Whatever else Graph says is not a licence, and a collection that skipped the
// eligible administrators because it did not recognise the answer would be
// wrong in the direction an auditor asks about.
func TestAnyOtherRefusalOfPIMFailsTheTenantAndSaysHowToTurnItOff(t *testing.T) {
	w := newWorld(t, privileged())
	w.srv.Refuse("/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", http.StatusForbidden,
		"Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil {
		t.Fatal("a refused PIM read was passed over")
	}
	for _, want := range []string{"RoleEligibilitySchedule.Read.Directory", `"pim"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not say %s: %v", want, err)
		}
	}
}

func TestTheCheckAsksForThePIMPermissionOnlyWhenPIMIsReadAndToleratesALicenceRefusal(t *testing.T) {
	w := newWorld(t, privileged())
	w.srv.Refuse("/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", http.StatusForbidden,
		"Authorization_RequestDenied", "Insufficient privileges.")

	if p := w.probe(`{"pim":false}`); !p.Reachable {
		t.Errorf("PIM off, and the check still wants its permission: %+v", p)
	}
	if p := w.probe(""); p.Reachable || p.Err == nil || !strings.Contains(p.Err.Error(), "RoleEligibilitySchedule.Read.Directory") {
		t.Errorf("probe = %+v, want the PIM permission named", p)
	}

	w2 := newWorld(t, privileged())
	w2.srv.Refuse("/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", http.StatusForbidden,
		"AadPremiumLicenseRequired", "The tenant needs a premium licence.")
	if p := w2.probe(""); !p.Reachable {
		t.Errorf("a tenant without PIM is reachable: %+v", p)
	}
}
