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

// The members of a group are read by the groups part, and again by whatever
// reads a role the group holds. A directory changes between the two reads, and
// the edge that says a member holds the role through the group is only a path
// if the edge that says the member is in the group was stated, so every read
// that finds a member states it.

func addMember(w *world, group string, m fakegraph.Member) {
	for i := range w.srv.Tenant.Groups {
		if w.srv.Tenant.Groups[i].ID == group {
			w.srv.Tenant.Groups[i].Members = append(w.srv.Tenant.Groups[i].Members, m)
		}
	}
}

// onMembersRead runs fn as the nth read of a group's members arrives.
func onMembersRead(w *world, group string, nth int64, fn func()) {
	path := "/v1.0/groups/" + group + "/members"
	var calls atomic.Int64
	w.srv.Intercept(path, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == path && calls.Add(1) == nth {
			fn()
		}
		return false
	})
}

func memberOf(out *capture, member, group string) int {
	return len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, member, group))
}

func effective(out *capture, member, role string) []*collectorv1.Edge {
	var got []*collectorv1.Edge
	for _, e := range out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, member, role) {
		if e.GetFidelity() == collectorv1.Fidelity_FIDELITY_EFFECTIVE {
			got = append(got, e)
		}
	}
	return got
}

func TestAMemberAddedToARoleGroupBetweenTheReadsIsStatedWhereItIsFound(t *testing.T) {
	defer collect.LowerLimits(-1, 0, 0)() // nothing is kept, so the group is read again
	w := newWorld(t, directory())
	onMembersRead(w, admins, 2, func() {
		addMember(w, admins, fakegraph.Member{ID: carol, Type: "user", DisplayName: "Carol Guest"})
	})
	out := w.mustRun(noApplications)

	if len(effective(out, carol, "role:"+globalAdmin)) != 1 {
		t.Error("carol, found in the group by the read that gave her the role, does not hold it through the group")
	}
	if memberOf(out, carol, admins) == 0 {
		t.Error("her place in the group was not stated")
	}
	out.assertContract()
}

func TestAUserCreatedAfterTheUsersWereReadAndPutInARoleGroupIsNamedAsReferenced(t *testing.T) {
	defer collect.LowerLimits(-1, 0, 0)()
	zed := fakegraph.GUID("zed")
	w := newWorld(t, directory())
	onMembersRead(w, admins, 2, func() {
		addMember(w, admins, fakegraph.Member{ID: zed, Type: "user", DisplayName: "Zed New"})
	})
	out := w.mustRun(noApplications)

	n := out.node("", "NODE_TYPE_IDENTITY", zed)
	if n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED || n.GetName() != "Zed New" {
		t.Fatalf("node = %v, want the user named, as referenced: the users part never saw it", n)
	}
	if len(effective(out, zed, "role:"+globalAdmin)) != 1 || memberOf(out, zed, admins) == 0 {
		t.Error("the role and the membership it goes through are not both stated")
	}
	out.assertContract()
}

func TestAUserCreatedAfterTheUsersWereReadAndPutInAGroupIsNamedAsReferenced(t *testing.T) {
	zed := fakegraph.GUID("zed")
	w := newWorld(t, directory())
	groups := "/v1.0/groups"
	var once atomic.Bool
	w.srv.Intercept(groups, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == groups && once.CompareAndSwap(false, true) {
			addMember(w, engineering, fakegraph.Member{ID: zed, Type: "user", DisplayName: "Zed New"})
		}
		return false
	})
	out := w.mustRun(noApplications)

	if n := out.node("", "NODE_TYPE_IDENTITY", zed); n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Fatalf("node = %v, want the user named, as referenced", n)
	}
	out.assertContract()
}

// A group inside a group that was made after the groups were listed.
func TestAGroupCreatedAfterTheGroupsWereListedAndNestedInOneIsNamedAsReferenced(t *testing.T) {
	late := fakegraph.GUID("g-late")
	w := newWorld(t, directory())
	groups := "/v1.0/groups"
	var once atomic.Bool
	w.srv.Intercept(groups, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == groups && once.CompareAndSwap(false, true) {
			addMember(w, sales, fakegraph.Member{ID: late, Type: "group", DisplayName: "Late"})
		}
		return false
	})
	out := w.mustRun(noApplications)

	if n := out.node("", "NODE_TYPE_GROUPING", late); n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Fatalf("node = %v, want the group named, as referenced", n)
	}
	out.assertContract()
}

// A group deleted between the list and its members is gone, not unread: the
// part is whole, the group says what is known of it, and nothing that follows
// names a node that was not written.
func TestAGroupDeletedBetweenTheListAndItsMembersLeavesThePartWhole(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusNotFound, "Request_ResourceNotFound", "gone")
	out, err := w.run("", collector.CollectRequest{})
	if err != nil {
		t.Fatalf("a group that no longer exists failed the collection: %v", err)
	}
	if out.node("", "NODE_TYPE_GROUPING", engineering) == nil || out.node("", "NODE_TYPE_GROUPING", admins) == nil {
		t.Error("the groups part did not go on past the group that was gone")
	}
	n := 0
	for _, d := range out.diags {
		if d.GetCode() == "entra.group.gone" {
			n++
			if !strings.Contains(d.GetMessage(), "Engineering") {
				t.Errorf("diagnostic = %q, want the group named", d.GetMessage())
			}
		}
	}
	if n != 1 {
		t.Errorf("%d diagnostics that a group was gone, want one: the app role asks for the same group's members", n)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, engineering, "app-role:"+fakegraph.Payroll+":"+fakegraph.PayrollReader)) == 0 {
		t.Error("what the group holds, which the source states, is gone with its members")
	}
	out.assertContract()
}

// A part that did not complete wrote some of its nodes and not others. Edges
// that name what it would have written are left out and said, not left to name
// what nobody emitted.
func TestAnEdgeNeverNamesAGroupWhoseGroupsPartFailed(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "groups") {
		t.Fatalf("cause %v: %v; want the groups failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.edges.left-out") == nil {
		t.Error("the edges left out were not said")
	}
	out.assertContract()
}

func TestAnEdgeNeverNamesAUserWhoseUsersPartFailed(t *testing.T) {
	w := newWorld(t, privileged())
	w.srv.Refuse("/v1.0/users", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "users") {
		t.Fatalf("cause %v: %v; want the users failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.edges.left-out") == nil {
		t.Error("the edges left out were not said")
	}
	out.assertContract()
}

func TestAnEdgeNeverNamesAServicePrincipalWhoseServicePrincipalsPartFailed(t *testing.T) {
	w := newWorld(t, withGrants())
	w.srv.Refuse("/v1.0/servicePrincipals", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	out, err := w.run(`{"oauth2_grants":true}`, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "service_principals") {
		t.Fatalf("cause %v: %v; want the service principals failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.edges.left-out") == nil {
		t.Error("the edges left out were not said")
	}
	out.assertContract()
}

func TestAnEdgeNeverNamesAnAdministrativeUnitWhosePartFailed(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/directory/administrativeUnits", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	out, err := w.run(`{"administrative_units":true}`, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "administrative_units") {
		t.Fatalf("cause %v: %v; want the units failed", inc.Cause, inc.Err)
	}
	out.assertContract()
}

// A read inside a part is held to a ceiling of its own. A next link that is
// never the same twice and never ends, on pages that are never the same either,
// is a source that is not behaving, and reading on would never finish.
func TestAMembersReadWhoseLinksNeverRepeatAndNeverEndIsStopped(t *testing.T) {
	defer collect.LowerLimits(50, -1, -1)()
	w := newWorld(t, directory())
	var calls atomic.Int64
	path := "/v1.0/groups/" + engineering + "/members"
	w.srv.Intercept(path, func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != path {
			return false
		}
		n := calls.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(rw, `{"value":[{"@odata.type":"#microsoft.graph.user","id":%q,"displayName":"A"}],"@odata.nextLink":%q}`,
			fakegraph.GUID(fmt.Sprintf("endless-%d", n)), w.srv.URL+path+fmt.Sprintf("?$skiptoken=t%d", n))
		return true
	})
	_, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "group_members") {
		t.Fatalf("cause %v: %v; want the group members part failed, not complete", inc.Cause, inc.Err)
	}
	if got := calls.Load(); got != 50 {
		t.Errorf("%d pages read, want it stopped at the ceiling of 50", got)
	}
	if !strings.Contains(inc.Err.Error(), "pages") {
		t.Errorf("err = %v, want it to say why", inc.Err)
	}
}

// The ceiling is on pages: a read that reaches its end on the last page it is
// allowed is a read that ended.
func TestAGroupOfExactlyTheCeilingIsReadToItsEnd(t *testing.T) {
	defer collect.LowerLimits(50, -1, -1)()
	d := directory()
	for i := 0; i < 47; i++ { // three members already: fifty pages of one
		d.Groups[0].Members = append(d.Groups[0].Members, fakegraph.Member{ID: fakegraph.GUID(fmt.Sprintf("extra-%d", i)), Type: "device"})
	}
	w := newWorld(t, d)
	w.srv.PageSize = 1
	out, err := w.run(noApplications, collector.CollectRequest{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	out.assertContract()
}

// A group is read once when it fits in memory, and the roles it holds are
// derived from that read, and again for each when it does not, a page at a time. Either way the members that
// hold the role are the ones its read found, and each is stated as being in it.
func TestAGroupTooBigToKeepIsReadAgainForEachRoleAndStillAgrees(t *testing.T) {
	build := func() *world {
		d := directory()
		d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{
			ID: "ra4", Principal: admins, PrincipalType: "group", PrincipalName: "Admins", RoleDefID: helpdesk, Scope: "/",
		})
		return newWorld(t, d)
	}
	reads := func(w *world) int {
		n := 0
		for _, p := range w.srv.Paths() {
			if strings.HasPrefix(p, "/v1.0/groups/"+admins+"/members?") {
				n++
			}
		}
		return n
	}
	check := func(out *capture) {
		t.Helper()
		for _, r := range []string{globalAdmin, helpdesk} {
			if len(effective(out, alice, "role:"+r)) != 1 {
				t.Errorf("alice does not hold %s through the group", r)
			}
		}
		out.assertContract()
	}

	keeps := build()
	check(keeps.mustRun(noApplications))
	reread := build()
	restore := collect.LowerLimits(-1, 1, -1)
	check(reread.mustRun(noApplications))
	restore()

	if got, want := reads(keeps), 1; got != want {
		t.Errorf("a group that fits was read %d times, want %d: the groups part's read serves both roles", got, want)
	}
	if got, want := reads(reread), 3; got != want {
		t.Errorf("a group too big to keep was read %d times, want %d: for the groups part and for each role", got, want)
	}
}

// What is kept across groups is bounded too.
func TestWhatIsKeptOfGroupsAllToldIsBounded(t *testing.T) {
	d := directory()
	d.RoleAssignments = append(d.RoleAssignments,
		fakegraph.RoleAssignment{ID: "ra4", Principal: admins, PrincipalType: "group", PrincipalName: "Admins", RoleDefID: helpdesk, Scope: "/"})
	w := newWorld(t, d)
	defer collect.LowerLimits(-1, 100, 1)()
	out := w.mustRun(noApplications)
	n := 0
	for _, p := range w.srv.Paths() {
		if strings.HasPrefix(p, "/v1.0/groups/"+admins+"/members?") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d reads of the group, want 3: nothing fits under a total of one", n)
	}
	out.assertContract()
}

// A licence refusal says the tenant has nothing to read only when nothing was
// read. After a page it says the read stopped, and the part is not whole.
func TestALicenceRefusalAfterAPageWasReadIsAPartThatIsNotWhole(t *testing.T) {
	w := newWorld(t, privileged())
	w.srv.PageSize = 1
	p := "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
	w.srv.Intercept(p, func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != p || r.URL.Query().Get("$skiptoken") == "" {
			return false
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"error":{"code":"AadPremiumLicenseRequired","message":"x"}}`))
		return true
	})
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "pim_eligible") {
		t.Fatalf("cause %v: %v; want the eligibility part failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.pim.unlicensed") != nil {
		t.Error("a tenant that answered with a page was called unlicensed")
	}
	if !strings.Contains(inc.Err.Error(), "after") {
		t.Errorf("err = %v, want it to say the read stopped part-way", inc.Err)
	}
	var faulty interface{ Fault() collector.Fault }
	if !errors.As(inc.Err, &faulty) || faulty.Fault() == collector.FaultPermission {
		t.Errorf("err = %v: a licence refused part-way is not a permission to grant", inc.Err)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, dave, "role:"+globalAdmin+":eligible")) != 1 {
		t.Error("what the first page said was not kept")
	}
	out.assertContract()
}

// A member of a kind that is not collected is counted once, however many times
// the group is read.
func TestAMemberOfAKindNotCollectedIsCountedOnceWhenAGroupIsReadAgain(t *testing.T) {
	defer collect.LowerLimits(-1, 0, 0)()
	out := newWorld(t, directory()).mustRun(noApplications)
	total := 0
	for _, d := range out.diags {
		if d.GetCode() == "entra.skipped" && strings.Contains(d.GetMessage(), "device") {
			total++
			if !strings.Contains(d.GetMessage(), "1 device") {
				t.Errorf("diagnostic = %q, want one device", d.GetMessage())
			}
		}
	}
	if total != 1 {
		t.Errorf("%d diagnostics about the device, want one", total)
	}
}
