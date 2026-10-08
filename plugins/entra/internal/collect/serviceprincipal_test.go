package collect_test

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

var (
	payroll, automation = fakegraph.Payroll, fakegraph.Automation
	vmIdentity, legacy  = fakegraph.VMIdentity, fakegraph.LegacyApp
	payrollReader       = fakegraph.PayrollReader
	payrollAdmin        = fakegraph.PayrollAdmin
)

func TestAnApplicationIsAServiceAndAManagedIdentityIsAMachine(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	for _, c := range []struct {
		id         string
		kind       collectorv1.IdentityKind
		status     collectorv1.IdentityStatus
		sourceType string
	}{
		{payroll, collectorv1.IdentityKind_IDENTITY_KIND_SERVICE, collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE, "service_principal"},
		{vmIdentity, collectorv1.IdentityKind_IDENTITY_KIND_MACHINE, collectorv1.IdentityStatus_IDENTITY_STATUS_ACTIVE, "managed_identity"},
		// A type Entra describes as internal or legacy is not something to
		// guess a kind for.
		{legacy, collectorv1.IdentityKind_IDENTITY_KIND_UNKNOWN, collectorv1.IdentityStatus_IDENTITY_STATUS_DISABLED, "service_principal"},
	} {
		n := out.node("", "NODE_TYPE_IDENTITY", c.id)
		if n == nil {
			t.Errorf("%s: not emitted", c.id)
			continue
		}
		if n.GetIdentity().GetKind() != c.kind || n.GetIdentity().GetStatus() != c.status || n.GetSourceType() != c.sourceType {
			t.Errorf("%s = %v/%v/%s, want %v/%v/%s", n.GetName(), n.GetIdentity().GetKind(),
				n.GetIdentity().GetStatus(), n.GetSourceType(), c.kind, c.status, c.sourceType)
		}
	}
	if got := out.node("", "NODE_TYPE_IDENTITY", payroll).GetContext()["service_principal_type"]; got != "Application" {
		t.Errorf("service_principal_type = %q", got)
	}
	out.assertContract()
}

// Their sign-ins are a separate surface that is not read, and silence about an
// application is what a reviewer reads as "never used".
func TestEveryApplicationSaysItsSignInsAreNotCollected(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	for _, id := range []string{payroll, automation, vmIdentity, legacy} {
		a := out.activities(id)["service_principal_sign_in"]
		if a == nil || a.GetUnavailable().GetCode() != "entra.sp-sign-in-not-collected" {
			t.Errorf("%s: activity = %v", id[:4], a)
		}
	}
}

func TestEachAppRoleIsAnEntitlementOfItsApplicationThatAppliesToIt(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	id := "app-role:" + payroll + ":" + payrollAdmin
	e := out.node("", "NODE_TYPE_ENTITLEMENT", id)
	if e == nil || e.GetSourceType() != "app_role" || !strings.Contains(e.GetName(), "Administrator") ||
		!strings.Contains(e.GetName(), "Payroll") {
		t.Fatalf("app role = %v", e)
	}
	if e.GetContext()["value"] != "Payroll.Admin" {
		t.Errorf("context = %v, want the role's claim value", e.GetContext())
	}
	app := out.node("", "NODE_TYPE_RESOURCE", payroll)
	if app == nil || app.GetSourceType() != "application" || app.GetContext()["assignment_required"] != "true" {
		t.Errorf("application = %v", app)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, id, payroll)) != 1 {
		t.Error("the role does not apply to its application")
	}
}

func TestAnAppRoleAssignedDirectlyIsADirectGrant(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	role := "app-role:" + payroll + ":" + payrollAdmin
	g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, role)
	if len(g) != 1 || g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT || g[0].GetSourceType() != "app_role_assignment" {
		t.Errorf("alice's grant = %v", g)
	}
	// An application holding another's role is an app-only permission.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, automation, "app-role:"+payroll+":"+payrollReader)) != 1 {
		t.Error("an application assigned a role does not hold it")
	}
}

// Microsoft says the direct members of a group are assigned a role the group
// is assigned. It does not say the members of a group inside that group are,
// so those are not claimed.
func TestAGroupHoldsItsAppRoleAndItsDirectMembersHoldItThroughTheGroup(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	role := "app-role:" + payroll + ":" + payrollReader
	if g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, engineering, role); len(g) != 1 ||
		g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT {
		t.Fatalf("the group's grant = %v", g)
	}
	for _, member := range []string{alice, bob} {
		var viaGroup *collectorv1.Edge
		for _, e := range out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, member, role) {
			if e.GetFidelity() == collectorv1.Fidelity_FIDELITY_EFFECTIVE {
				viaGroup = e
			}
		}
		if viaGroup == nil || len(viaGroup.GetPath().GetVia()) != 1 || viaGroup.GetPath().GetVia()[0].GetId() != engineering {
			t.Errorf("%s: effective grant = %v, want one hop through Engineering", member[:4], viaGroup)
		}
	}
	// Carol is in Platform, which is inside Engineering.
	for _, e := range out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, carol, role) {
		t.Errorf("a member of a nested group was given the role: %v", e)
	}
	d := out.diag("entra.app-roles.nested-not-expanded")
	if d == nil || !strings.Contains(d.GetMessage(), "1 ") {
		t.Errorf("diagnostic = %v, want it to say one nested group was not expanded", d)
	}
	out.assertContract()
}

func TestTheDefaultAccessRoleIsAnEntitlementOfItsOwn(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")

	id := "app-role:" + legacy + ":00000000-0000-0000-0000-000000000000"
	e := out.node("", "NODE_TYPE_ENTITLEMENT", id)
	if e == nil || !strings.Contains(e.GetName(), "Default access") {
		t.Fatalf("default access = %v", e)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, carol, id)) != 1 {
		t.Error("carol does not hold default access to the legacy app")
	}
}

func TestTheServicePrincipalFlagDecidesWhetherApplicationsAreIdentities(t *testing.T) {
	out := newWorld(t, directory()).mustRun(`{"service_principals":false}`)

	if n := out.node("", "NODE_TYPE_IDENTITY", payroll); n != nil {
		t.Errorf("an application became an identity with the flag off: %v", n)
	}
	// But Automation holds a role of Payroll's, so it is named, and said to be
	// only referenced.
	n := out.node("", "NODE_TYPE_IDENTITY", automation)
	if n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("Automation = %v, want a referenced identity", n)
	}
	// The roles themselves are still collected.
	if out.node("", "NODE_TYPE_ENTITLEMENT", "app-role:"+payroll+":"+payrollAdmin) == nil {
		t.Error("app roles were lost with the application identities")
	}
	out.assertContract()
}

func TestTheAppRolesFlagDecidesWhetherRolesAreCollected(t *testing.T) {
	w := newWorld(t, directory())
	out := w.mustRun(`{"app_roles":false}`)

	if out.node("", "NODE_TYPE_IDENTITY", payroll) == nil {
		t.Error("applications were lost with the app roles")
	}
	for _, e := range out.events {
		if n := e.GetNode(); n != nil && strings.HasPrefix(n.GetKey().GetId(), "app-role:") {
			t.Errorf("an app role was collected with the flag off: %s", n.GetName())
		}
	}
	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "appRoleAssignedTo") {
			t.Errorf("asked for %s with app roles off", p)
		}
	}
}

func TestNeitherFlagMeansNoApplicationsAreRead(t *testing.T) {
	w := newWorld(t, directory())
	w.mustRun(`{"service_principals":false,"app_roles":false}`)

	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "servicePrincipals") {
			t.Errorf("asked for %s with both off", p)
		}
	}
}

// Graph returns at most a hundred service principals a page, a tenth of what
// it returns for users.
func TestServicePrincipalsAreReadInPagesOfAtMostAHundred(t *testing.T) {
	w := newWorld(t, directory())
	w.mustRun(`{}`)

	seen := false
	for _, p := range w.srv.Paths() {
		if !strings.HasPrefix(p, "/v1.0/servicePrincipals?") {
			continue
		}
		seen = true
		q, _ := url.ParseQuery(p[strings.Index(p, "?")+1:])
		if top, _ := strconv.Atoi(q.Get("$top")); top == 0 || top > 100 {
			t.Errorf("service principals asked for in pages of %d: %s", top, p)
		}
	}
	if !seen {
		t.Error("no service principal list was read")
	}
}

func TestAnIDOnlyMemberOfAGroupThatHoldsAnAppRoleIsCheckedToo(t *testing.T) {
	d := directory()
	d.Groups[0].Members[1].IDOnly = true // bob, in Engineering
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/users/"+bob, 403, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "User.Read.All") {
		t.Errorf("err = %v, want User.Read.All named", err)
	}
}

func TestAnApplicationTheListNeverReturnedIsStillNamedWhenARoleIsHeldBy(t *testing.T) {
	d := directory()
	d.AppRoleAssignments[payroll] = append(d.AppRoleAssignments[payroll], fakegraph.AppRoleAssignment{
		ID: "ara9", AppRoleID: fakegraph.GUID("ar-gone"), Principal: dave, PrincipalType: "User", PrincipalName: "Dave",
	})
	out := newWorld(t, d).mustRun("")

	// The role is not among the application's roles (it has been deleted),
	// so it is named by its id, and still held.
	id := "app-role:" + payroll + ":" + fakegraph.GUID("ar-gone")
	if e := out.node("", "NODE_TYPE_ENTITLEMENT", id); e == nil {
		t.Fatal("an assignment to a role the application no longer has was dropped")
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, dave, id)) != 1 {
		t.Error("dave does not hold the role")
	}
	out.assertContract()
}
