package collect_test

import (
	"net/http"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Graph answers a missing permission with a 403, not an empty list, but an
// object of a type the application may not read is the silent form: a 200,
// with the object as its type and id and every property null. A collection
// that took that for a member would report a population that reads as whole.
func TestAnIDOnlyMemberOfATypeThatCannotBeReadMakesTheTenantPartial(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true // alice, in Engineering
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/users/"+alice, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Errorf("cause = %v, want ScopeUnreachable", inc.Cause)
	}
	if !strings.Contains(err.Error(), "User.Read.All") || !strings.Contains(err.Error(), "id and nothing else") {
		t.Errorf("the failure does not name the permission and what was seen: %v", err)
	}
	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL {
		t.Errorf("scope = %v, want partial", out.scopes[0].Status)
	}
	// The id is enough to say who is in the group, so the edge is still there.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, alice, engineering)) != 1 {
		t.Error("an id-only member was dropped from its group")
	}
}

// A null name is also what an object with no name looks like. Only a refusal
// on reading the object itself says the permission is missing, and without one
// the tenant would be reported partial for a permission the operator holds and
// cannot grant again.
func TestANullNameOnAnObjectThatCanBeReadIsNotAMissingPermission(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true
	out := newWorld(t, d).mustRun("")

	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v, want collected: alice can be read", out.scopes[0].Status)
	}
}

// Graph silently ignores a query parameter it does not support. A member that
// came back with no name at all, rather than a null one, was not refused.
func TestAMemberWithNoNamePropertyAtAllWasNotRefused(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].NoName = true
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/users/"+alice, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	if out := w.mustRun(""); out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v", out.scopes[0].Status)
	}
}

// The members of a role-assignable group are what a role is held through, so
// they are held to the same rule as any other group's.
func TestTheMembersOfAGroupThatHoldsARoleAreCheckedToo(t *testing.T) {
	d := directory()
	d.Groups[3].Members[0].IDOnly = true // alice, in Admins
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/users/"+alice, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "User.Read.All") {
		t.Fatalf("err = %v, want User.Read.All named", err)
	}
	// Once, however many groups say it.
	if n := strings.Count(err.Error(), "grant the application permission User.Read.All"); n != 1 {
		t.Errorf("the permission is named %d times, want once", n)
	}
}

func TestADynamicGroupWhoseRuleIsPausedIsAWarning(t *testing.T) {
	d := directory()
	d.Groups[2].RuleState = "Paused" // Sales
	out := newWorld(t, d).mustRun("")

	diag := out.diag("entra.membership.paused")
	if diag == nil || !strings.Contains(diag.GetMessage(), "Sales") || diag.GetSeverity() != collectorv1.Severity_SEVERITY_WARNING {
		t.Fatalf("diagnostic = %v, want a warning naming the group", diag)
	}
	// The members are still the source's answer, and still collected.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, dave, sales)) != 1 {
		t.Error("a paused group's members were dropped")
	}
}

func TestAnActiveDynamicGroupIsNotWarnedAbout(t *testing.T) {
	if diag := newWorld(t, directory()).mustRun("").diag("entra.membership.paused"); diag != nil {
		t.Errorf("a group whose rule is on was warned about: %v", diag)
	}
}

func TestAGroupWithHiddenMembershipThatIsRefusedIsTheOnlyThingUnread(t *testing.T) {
	d := directory()
	d.Groups[0].Visibility = "HiddenMembership"
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !strings.Contains(err.Error(), "Member.Read.Hidden") {
		t.Fatalf("cause = %v, err = %v; want Member.Read.Hidden named", inc.Cause, err)
	}
	// Every other group was collected, and so was everything after the groups.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, dave, sales)) != 1 ||
		out.node("", "NODE_TYPE_ENTITLEMENT", "role:"+globalAdmin) == nil {
		t.Error("one hidden group cost the rest of the tenant")
	}
	// The group itself is there, with nobody in it that we could see.
	if out.node("", "NODE_TYPE_GROUPING", engineering) == nil {
		t.Error("the hidden group was not emitted")
	}
}

// A refusal on a group that is not hidden is the group permission, and fails
// the groups, as it did before.
func TestARefusedMemberListOfAnOrdinaryGroupFailsTheGroups(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "Group.Read.All") || strings.Contains(err.Error(), "Member.Read.Hidden") {
		t.Errorf("err = %v, want the group permission and not the hidden one", err)
	}
}

// Devices and contacts are not collected, and an id-only one is not a missing
// permission worth failing a tenant over: nothing here reads them.
func TestAnIDOnlyDeviceIsNotAPermissionTheCollectorWants(t *testing.T) {
	d := directory()
	d.Groups[3].Members[1].IDOnly = true // the laptop
	out := newWorld(t, d).mustRun("")

	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v", out.scopes[0].Status)
	}
	_ = fakegraph.Laptop
}
