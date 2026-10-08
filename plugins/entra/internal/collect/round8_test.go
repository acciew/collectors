package collect_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// An application gains a role, and someone is assigned it, between the
// applications part and the part that reads who holds the roles. The grant names
// a role no part wrote.
func TestAnAppRoleAddedAfterTheApplicationsPartWroteTheApplicationIsWrittenWithItsGrant(t *testing.T) {
	role := fakegraph.GUID("late-role-on-payroll")
	w := newWorld(t, directory())
	var once atomic.Bool
	w.srv.Intercept("/v1.0/groups", func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1.0/groups" && once.CompareAndSwap(false, true) {
			ten := w.srv.Tenant
			for i := range ten.ServicePrincipals {
				if ten.ServicePrincipals[i].ID == payroll {
					ten.ServicePrincipals[i].AppRoles = append(ten.ServicePrincipals[i].AppRoles,
						fakegraph.AppRole{ID: role, DisplayName: "Approver", Value: "Payroll.Approve", Enabled: true})
				}
			}
			ten.AppRoleAssignments[payroll] = append(ten.AppRoleAssignments[payroll], fakegraph.AppRoleAssignment{
				ID: "late2", AppRoleID: role, Principal: alice, PrincipalType: "User", PrincipalName: "Alice Example"})
		}
		return false
	})
	out := w.mustRun("")

	key := "app-role:" + payroll + ":" + role
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, key)) != 1 {
		t.Fatal("the assignment was not stated")
	}
	n := out.node("", "NODE_TYPE_ENTITLEMENT", key)
	if n == nil {
		t.Fatal("HOLDS names a role that was never written")
	}
	if n.GetContext()["value"] != "Payroll.Approve" || n.GetName() != "Approver (Payroll)" {
		t.Errorf("role = %q %v, want it written as the application lists it", n.GetName(), n.GetContext())
	}
	out.assertContract()
}

// A group too big to keep is read again for each role it holds, and says each
// membership once.
func TestAGroupTooBigToKeepSendsItsMembershipsOnce(t *testing.T) {
	d := directory()
	d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{
		ID: "ra4", Principal: admins, PrincipalType: "group", PrincipalName: "Admins", RoleDefID: helpdesk, Scope: "/",
	})
	w := newWorld(t, d)
	defer collect.LowerLimits(-1, 1, -1)()
	out := w.mustRun(noApplications)

	if dup := duplicates(out); len(dup) > 0 {
		t.Errorf("%d records sent more than once, e.g. %v", len(dup), dup)
	}
	reads := 0
	for _, p := range w.srv.Paths() {
		if strings.HasPrefix(p, "/v1.0/groups/"+admins+"/members?") {
			reads++
		}
	}
	if reads != 3 {
		t.Errorf("%d reads of the group, want 3: it is read again for each role and not remembered", reads)
	}
	// And the member added between the reads is still stated where it was found.
	out.assertContract()
}

// A tenant that has been read as PIM-licensed is not unlicensed because the
// other PIM read is refused with a licence code.
func TestALicenceRefusalOfOnePIMPartAfterTheOtherReadPagesIsNotUnlicensed(t *testing.T) {
	d := directory()
	d.Eligible = []fakegraph.ScheduleInstance{{ID: "e1", Principal: alice, PrincipalType: "user", PrincipalName: "Alice Example",
		RoleDefID: globalAdmin, Scope: "/", MemberType: "Direct"}}
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/roleManagement/directory/roleAssignmentScheduleInstances", http.StatusForbidden, "AadPremiumLicenseRequired", "x")
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "pim_active") {
		t.Fatalf("cause %v: %v, want the time-bound part failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.pim.unlicensed") != nil {
		t.Error("a tenant whose eligibilities were just read was called unlicensed")
	}
}

// Every request site honours the one throttle rule: a throttle that will not end
// ends the stream, whatever the request was for.
func TestAThrottleOnTheOrganizationThatWillNotEndEndsTheStream(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/organization", 100, 3600)
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v: %v, want RATE_LIMITED", inc.Cause, inc.Err)
	}
	out.assertContract()
}

func TestAThrottleOnANameLookupThatWillNotEndEndsTheStream(t *testing.T) {
	d := directory()
	d.OAuth2Grants = []fakegraph.OAuth2Grant{{ID: "o1", ClientID: payroll, ResourceID: automation, ConsentType: "AllPrincipals", Scope: "x"}}
	w := newWorld(t, d)
	for _, sp := range w.srv.Tenant.ServicePrincipals {
		w.srv.Throttle("/v1.0/servicePrincipals/"+sp.ID, 100, 3600)
	}
	out, err := w.run(`{"oauth2_grants":true,"app_roles":false,"service_principals":false}`, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v: %v, want RATE_LIMITED", inc.Cause, inc.Err)
	}
	out.assertContract()
}

// The read that tells whether a group's members are hidden is a request like the
// others: throttled for good, the stream ends, and the user is not told to grant
// Group.Read.All for a group whose members were refused for another reason.
func TestAThrottleOnTheHiddenGroupCheckThatWillNotEndEndsTheStream(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups/"+admins+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	group := "/v1.0/groups/" + admins
	w.srv.Intercept(group, func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != group {
			return false
		}
		rw.Header().Set("Retry-After", "3600")
		rw.WriteHeader(http.StatusTooManyRequests)
		return true
	})
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v: %v, want RATE_LIMITED", inc.Cause, inc.Err)
	}
	out.assertContract()
}

// A scope that was asked for and not reached is a scope node, so the outcome that
// names it names something that was sent.
func TestTheOutcomeOfAScopeThatWasAskedForAndNotReachedNamesANodeThatWasSent(t *testing.T) {
	w := newWorld(t, directory())
	out, err := w.run("", collector.CollectRequest{Scopes: []string{"someone-elses-tenant.example.com"}})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Fatalf("cause = %v", inc.Cause)
	}
	out.assertContract()
}

// An application deleted between the two listings has no one holding its roles,
// and the others are still read.
func TestAnApplicationDeletedBetweenTheListingsDoesNotFailThePart(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/servicePrincipals/"+payroll+"/appRoleAssignedTo", http.StatusNotFound, "Request_ResourceNotFound", "gone")
	out, err := w.run("", collector.CollectRequest{})
	if err != nil {
		t.Fatalf("an application that was deleted failed the collection: %v", err)
	}
	said := 0
	for _, d := range out.diags {
		if d.GetCode() == "entra.application.gone" {
			said++
			if !strings.Contains(d.GetMessage(), "Payroll") {
				t.Errorf("diagnostic = %q, want the application named", d.GetMessage())
			}
		}
	}
	if said != 1 {
		t.Errorf("%d diagnostics that an application was gone, want one", said)
	}
	// Legacy's assignment is on a later application and is still read.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, carol, "app-role:"+fakegraph.LegacyApp+":00000000-0000-0000-0000-000000000000")) != 1 {
		t.Error("the applications after the deleted one were not read")
	}
	out.assertContract()
}

// The service refuses a collection of more than a million events, and every
// retry would meet the same wall. A stream that reaches its allowance of events
// stops reading, says so, and is not complete; it never sends one past the limit.
func TestAStreamThatReachesTheEventLimitStopsAndIsNotComplete(t *testing.T) {
	defer collect.LowerEventLimit(80, 10)()
	w := newWorld(t, directory())
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Fatalf("cause = %v: %v, want the scope not fully collected", inc.Cause, inc.Err)
	}
	if out.total() >= 80 {
		t.Errorf("%d events sent, want fewer than the 80 the service allows, with room for the completion", out.total())
	}
	records := out.count(func(e *collectorv1.CollectResponse) bool {
		return e.GetNode() != nil || e.GetEdge() != nil || e.GetActivity() != nil
	})
	if records > 70 {
		t.Errorf("%d records sent, want no more than the 70 left once 10 are held back", records)
	}
	d := out.diag("entra.limit.events")
	if d == nil {
		t.Fatal("the limit was not said")
	}
	for _, want := range []string{"80", "pim", "AuditLog.Read.All"} {
		if !strings.Contains(d.GetMessage(), want) {
			t.Errorf("diagnostic = %q, want it to say %q", d.GetMessage(), want)
		}
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL {
		t.Errorf("scopes = %+v, want the tenant partial", out.scopes)
	}
	var faulty interface{ Fault() collector.Fault }
	if !errors.As(inc.Err, &faulty) || faulty.Fault() != collector.FaultConfig {
		t.Errorf("err = %v, want it classed as a configuration to lower", inc.Err)
	}
	out.assertContract()
}

// Under the limit nothing changes.
func TestAStreamUnderTheEventLimitIsComplete(t *testing.T) {
	defer collect.LowerEventLimit(10_000, 100)()
	out := newWorld(t, directory()).mustRun("")
	if out.diag("entra.limit.events") != nil {
		t.Error("the limit was said to be reached")
	}
}

// What every event costs is counted, not only the records: progress, diagnostics
// and the checkpoint go to the same limit.
func TestEveryKindOfEventCountsTowardTheLimit(t *testing.T) {
	defer collect.LowerEventLimit(40, 5)()
	d := directory()
	for i := 0; i < 20; i++ {
		d.Users = append(d.Users, fakegraph.User{ID: fakegraph.GUID(fmt.Sprintf("u%d", i)), DisplayName: "U", UPN: "u@x"})
	}
	out, _ := newWorld(t, d).run(noApplications, collector.CollectRequest{})
	if out.total() >= 40 {
		t.Errorf("%d events", out.total())
	}
}

// Whatever the limit, a stream never sends an event past it: not a record, and
// not a progress event or a diagnostic either, which are dropped when there is no
// room for them.
func TestNoEventIsEverSentPastTheLimit(t *testing.T) {
	for _, held := range []int{0, 3} {
		for limit := 6; limit <= 60; limit++ {
			restore := collect.LowerEventLimit(limit, held)
			out, _ := newWorld(t, directory()).run("", collector.CollectRequest{})
			restore()
			// One is kept for the completion the SDK adds.
			if got := out.total(); got >= limit {
				t.Fatalf("limit %d, %d held back: %d events sent", limit, held, got)
			}
		}
	}
}
