package collect_test

import (
	"net/http"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// A hidden-membership group that holds a role is still a group whose members
// are refused for want of Member.Read.Hidden, and that is not a reason to lose
// every application and app role.
func TestAHiddenGroupThatHoldsAnAppRoleDoesNotCostTheApplications(t *testing.T) {
	d := directory()
	d.Groups[0].Visibility = "HiddenMembership" // Engineering holds Payroll's Reader role
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !strings.Contains(err.Error(), "Member.Read.Hidden") {
		t.Fatalf("cause = %v, err = %v; want Member.Read.Hidden named", inc.Cause, err)
	}
	if strings.Contains(err.Error(), "Group.Read.All") {
		t.Errorf("the advice names a permission that is held: %v", err)
	}
	for _, id := range []string{payroll, automation, vmIdentity, legacy} {
		if out.node("", "NODE_TYPE_IDENTITY", id) == nil {
			t.Errorf("%s: an application was lost to one hidden group", id[:4])
		}
	}
	role := "app-role:" + payroll + ":" + payrollReader
	if out.node("", "NODE_TYPE_ENTITLEMENT", role) == nil || len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, engineering, role)) != 1 {
		t.Error("the group's own grant of the app role was lost")
	}
}

func TestAHiddenGroupThatHoldsADirectoryRoleDoesNotCostTheAssignments(t *testing.T) {
	d := directory()
	d.Groups[3].Visibility = "HiddenMembership" // Admins holds Global Administrator
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/groups/"+admins+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	out, err := w.run(`{"service_principals":false,"app_roles":false}`, collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "Member.Read.Hidden") || strings.Contains(err.Error(), "Group.Read.All") {
		t.Fatalf("err = %v, want Member.Read.Hidden and not the group permission", err)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, admins, "role:"+globalAdmin)) != 1 ||
		len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, bob, "role:"+helpdesk+":au:"+unitA)) != 1 {
		t.Error("the role assignments were lost to one hidden group")
	}
}

// A group that is not hidden and is refused is the group permission, as before.
func TestAnOrdinaryGroupThatHoldsARoleAndIsRefusedStillNamesTheGroupPermission(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups/"+admins+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run(`{"service_principals":false,"app_roles":false}`, collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "Group.Read.All") || strings.Contains(err.Error(), "Member.Read.Hidden") {
		t.Errorf("err = %v", err)
	}
}

// An application that is a member of a group is a member, a holder through the
// group, and the hop between them is an edge that was stated. Skipping it in
// one place and counting it in another broke the path.
func TestAnApplicationInAGroupThatHoldsARoleIsAMemberAndNotJustAHolder(t *testing.T) {
	for _, flags := range []string{"", `{"service_principals":false}`} {
		t.Run("flags "+flags, func(t *testing.T) {
			d := directory()
			d.Groups[0].Members = append(d.Groups[0].Members, fakegraph.Member{ID: automation, Type: "servicePrincipal", DisplayName: "Automation"})
			d.Groups[3].Members = append(d.Groups[3].Members, fakegraph.Member{ID: automation, Type: "servicePrincipal", DisplayName: "Automation"})
			out := newWorld(t, d).mustRun(flags)

			if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, automation, engineering)) != 1 {
				t.Error("an application in a group is not a member of it")
			}
			for _, diag := range out.diags {
				if diag.GetCode() == "entra.skipped" && strings.Contains(diag.GetMessage(), "servicePrincipal") {
					t.Errorf("an application was both a member and skipped: %v", diag.GetMessage())
				}
			}
			// Through the group, for an app role and for a directory role.
			if g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, automation, "role:"+globalAdmin); len(g) != 1 ||
				g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_EFFECTIVE {
				t.Errorf("the application's grant through the role-assignable group = %v", g)
			}
			// And the contract holds: every hop of every path was stated.
			out.assertContract()
		})
	}
}

// Principal null is not principal gone. The id is known, and a privileged grant
// that vanishes reads as revoked.
func TestAnAssignmentWhosePrincipalCameBackNullIsResolvedByItsID(t *testing.T) {
	d := directory()
	d.RoleAssignments = append(d.RoleAssignments,
		fakegraph.RoleAssignment{ID: "n1", Principal: dave, RoleDefID: globalAdmin, Scope: "/"},    // a user
		fakegraph.RoleAssignment{ID: "n2", Principal: platform, RoleDefID: helpdesk, Scope: "/"},   // a group
		fakegraph.RoleAssignment{ID: "n3", Principal: automation, RoleDefID: helpdesk, Scope: "/"}, // an application
	)
	out := newWorld(t, d).mustRun("")

	if g := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, dave, "role:"+globalAdmin); len(g) != 1 || g[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT {
		t.Errorf("dave's grant, whose principal came back null = %v", g)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, platform, "role:"+helpdesk)) != 1 ||
		len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, carol, "role:"+helpdesk)) != 1 {
		t.Error("a group whose principal came back null did not hold its role through its members")
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, automation, "role:"+helpdesk)) != 1 {
		t.Error("an application whose principal came back null did not hold its role")
	}
	if out.diag("entra.role-assignment.principal-gone") != nil {
		t.Error("principals that exist were reported gone")
	}
	out.assertContract()
}

func TestAnAssignmentToAPrincipalThatIsGoneHoldsNothingAndSaysSo(t *testing.T) {
	d := directory()
	gone := fakegraph.GUID("deleted-admin")
	d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{ID: "n4", Principal: gone, RoleDefID: globalAdmin, Scope: "/"})
	out := newWorld(t, d).mustRun("")

	diag := out.diag("entra.role-assignment.principal-gone")
	if diag == nil || !strings.Contains(diag.GetMessage(), gone) {
		t.Fatalf("diagnostic = %v, want the principal named", diag)
	}
	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v: a grant to nobody leaves the tenant whole", out.scopes[0].Status)
	}
}

// If the principal cannot be told, it is not known to be gone, and the tenant
// is not whole.
func TestAnAssignmentWhosePrincipalCannotBeReadMakesTheTenantNotWhole(t *testing.T) {
	d := directory()
	d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{ID: "n5", Principal: dave, RoleDefID: globalAdmin, Scope: "/"})
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/users/"+dave, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	out, err := w.run("", collector.CollectRequest{})
	if inc := incomplete(t, err); inc.Cause != collector.ScopeUnreachable || !strings.Contains(err.Error(), "User.Read.All") {
		t.Fatalf("cause = %v, err = %v; want User.Read.All named", inc.Cause, err)
	}
	if out.scopes[0].Status == collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Error("an assignment was dropped and the scope called collected")
	}
}

// Whatever was left out is said, in the part that left it out.
func TestWhatEveryPartLeavesOutIsSaid(t *testing.T) {
	d := directory()
	d.RoleAssignments = append(d.RoleAssignments,
		fakegraph.RoleAssignment{ID: "d1", Principal: fakegraph.Laptop, PrincipalType: "device", RoleDefID: helpdesk, Scope: "/"},
		fakegraph.RoleAssignment{ID: "d2", Principal: fakegraph.GUID("untyped"), PrincipalType: "orgContact", RoleDefID: helpdesk, Scope: "/"},
	)
	d.AppRoleAssignments[payroll] = append(d.AppRoleAssignments[payroll],
		fakegraph.AppRoleAssignment{ID: "d3", AppRoleID: payrollReader, Principal: fakegraph.Laptop, PrincipalType: "Device", PrincipalName: "LAPTOP-1"})
	out := newWorld(t, d).mustRun("")

	var said []string
	for _, diag := range out.diags {
		if diag.GetCode() == "entra.skipped" {
			said = append(said, diag.GetMessage())
		}
	}
	joined := strings.Join(said, "\n")
	for _, want := range []string{"role_assignments", "1 device", "1 orgContact", "app_role_assignments", "1 Device", "group_members"} {
		if !strings.Contains(joined, want) {
			t.Errorf("nothing says %q was left out:\n%s", want, joined)
		}
	}
	// And it is said once, not repeated by every part that follows.
	if n := strings.Count(joined, "1 device"); n != 2 { // the group member in the members part, the holder in the roles
		t.Errorf("\"1 device\" appears %d times:\n%s", n, joined)
	}
}

func TestAnObjectWithNoTypeAtAllIsSaidAndNotLeftOutInSilence(t *testing.T) {
	d := directory()
	d.Groups[0].Members = append(d.Groups[0].Members, fakegraph.Member{ID: fakegraph.GUID("mystery"), Type: "", DisplayName: "?"})
	out := newWorld(t, d).mustRun("")

	var said string
	for _, diag := range out.diags {
		if diag.GetCode() == "entra.skipped" && strings.Contains(diag.GetMessage(), "group_members") {
			said = diag.GetMessage()
		}
	}
	if !strings.Contains(said, "unknown type") {
		t.Errorf("diagnostic = %q, want an object of no type counted as such", said)
	}
}
