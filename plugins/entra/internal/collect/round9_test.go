package collect_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

const proxy404 = "<html>blocked by proxy</html>"

// A 403 whose body is not Graph's is told from a refusal, because a proxy answers
// for Graph. A 404 is told the same way: only Graph's own not-found means that a
// group, an application or a principal is gone. Anything else is a read that
// failed, and the part with it.

func TestA404ThatIsNotGraphsIsNotADeletedGroup(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Respond("/v1.0/groups/"+engineering+"/members", http.StatusNotFound, "text/html", proxy404)
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "group_members") {
		t.Fatalf("cause %v: %v, want the group members part failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.group.gone") != nil {
		t.Error("a proxy's 404 was said to be a deleted group")
	}
	out.assertContract()
}

func TestA404ThatIsNotGraphsIsNotADeletedApplication(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Respond("/v1.0/servicePrincipals/"+payroll+"/appRoleAssignedTo", http.StatusNotFound, "text/html", proxy404)
	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "app_role_assignments") {
		t.Fatalf("cause %v: %v, want the assignments part failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.application.gone") != nil {
		t.Error("a proxy's 404 was said to be a deleted application")
	}
	out.assertContract()
}

func TestA404ThatIsNotGraphsIsNotAPrincipalThatIsGone(t *testing.T) {
	d := directory()
	// A privileged grant whose principal came back null: the id is resolved by
	// reading it as a user, a group and a service principal.
	d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{
		ID: "ra9", Principal: alice, PrincipalType: "", RoleDefID: globalAdmin, Scope: "/"})
	w := newWorld(t, d)
	for _, p := range []string{"/v1.0/users/" + alice, "/v1.0/groups/" + alice, "/v1.0/servicePrincipals/" + alice} {
		w.srv.Respond(p, http.StatusNotFound, "text/html", proxy404)
	}
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "role_assignments") {
		t.Fatalf("cause %v: %v, want the role assignments part failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.role-assignment.principal-gone") != nil {
		t.Error("a proxy's 404 was said to be a principal that is gone")
	}
	out.assertContract()
}

// A 404 whose body is Graph-shaped but whose code is not a not-found code, a
// refusal's say, is not a thing that is gone either.
func TestA404WithAGraphBodyAndARefusalCodeIsNotGone(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusNotFound, "Authorization_RequestDenied", "Insufficient privileges.")
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "group_members") {
		t.Fatalf("cause %v: %v, want the group members part failed", inc.Cause, inc.Err)
	}
	if out.diag("entra.group.gone") != nil {
		t.Error("a 404 with a refusal's code was said to be a deleted group")
	}
}

// Graph's own not-found, whatever its documented code and whatever its case, is
// still a thing that is gone.
func TestAGraphNotFoundWithAnyDocumentedCodeIsStillGone(t *testing.T) {
	for _, code := range []string{"Request_ResourceNotFound", "ResourceNotFound", "ErrorItemNotFound", "itemNotFound", "RESOURCENOTFOUND"} {
		w := newWorld(t, directory())
		w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusNotFound, code, "gone")
		out, err := w.run("", collector.CollectRequest{})
		if err != nil {
			t.Fatalf("%s: %v, want the collection whole", code, err)
		}
		if out.diag("entra.group.gone") == nil {
			t.Errorf("%s: the deleted group was not said", code)
		}
	}
}

// An application made after the applications part ran, with roles of its own that
// no one is assigned: the roles are written with the application, because nothing
// else will write them.
func TestTheRolesNoOneHoldsOfAnApplicationMadeSinceAreStillWritten(t *testing.T) {
	late := fakegraph.GUID("sp-late")
	held, unheld := fakegraph.GUID("late-held"), fakegraph.GUID("late-unheld")
	w := newWorld(t, directory())
	onGroupsListed(w, func() {
		ten := w.srv.Tenant
		ten.ServicePrincipals = append(ten.ServicePrincipals, fakegraph.ServicePrincipal{
			ID: late, AppID: fakegraph.GUID("app-late"), DisplayName: "Late", Type: "Application", Enabled: fakegraph.Enabled(true),
			AppRoles: []fakegraph.AppRole{
				{ID: held, DisplayName: "Held", Value: "Late.Held", Enabled: true},
				{ID: unheld, DisplayName: "Unheld", Value: "Late.Unheld", Enabled: true},
			}})
		ten.AppRoleAssignments[late] = []fakegraph.AppRoleAssignment{
			{ID: "late1", AppRoleID: held, Principal: alice, PrincipalType: "User", PrincipalName: "Alice Example"}}
	})
	out := w.mustRun("")

	key := "app-role:" + late + ":" + unheld
	if out.node("", "NODE_TYPE_ENTITLEMENT", key) == nil {
		t.Fatal("a role the new application lists, and no one holds, was never written")
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, key, late)) != 1 {
		t.Error("the role does not apply to its application")
	}
	out.assertContract()
}

// onGroupsListed runs fn as the groups are first listed: after the parts that
// write users, applications and units, and before the parts that name them.
func onGroupsListed(w *world, fn func()) {
	var done bool
	w.srv.Intercept("/v1.0/groups", func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1.0/groups" && !done {
			done = true
			fn()
		}
		return false
	})
}

// The service also refuses a stream over two gibibytes. A stream that reaches its
// allowance of bytes stops reading and ends as it does for events: not complete,
// saying which limit, and never past it.
func TestAStreamThatReachesTheByteLimitStopsAndIsNotComplete(t *testing.T) {
	defer collect.LowerByteLimit(20_000, 2_000)()
	d := directory()
	for i := 0; i < 200; i++ {
		d.Users = append(d.Users, fakegraph.User{ID: fakegraph.GUID(fmt.Sprintf("bulk-%d", i)),
			DisplayName: strings.Repeat("N", 100), UPN: fmt.Sprintf("u%d@example.onmicrosoft.com", i)})
	}
	out, err := newWorld(t, d).run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Fatalf("cause = %v: %v, want the scope not fully collected", inc.Cause, inc.Err)
	}
	dg := out.diag("entra.limit.bytes")
	if dg == nil {
		t.Fatal("the limit was not said")
	}
	for _, want := range []string{"20000", "bytes", "AuditLog.Read.All"} {
		if !strings.Contains(dg.GetMessage(), want) {
			t.Errorf("diagnostic = %q, want it to say %q", dg.GetMessage(), want)
		}
	}
	if out.diag("entra.limit.events") != nil {
		t.Error("the byte limit was said to be the event limit")
	}
	// Tight on both sides: records stop where the reserve begins, 18000 bytes, and
	// not before the next record would not fit. A stream that ignored the reserve
	// and the framing would run to the limit.
	if got := out.bytes(); got > 18_000 || got < 16_000 {
		t.Errorf("%d bytes of records sent, want between 16000 and the 18000 that leave the reserve intact", got)
	}
	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL {
		t.Errorf("scope = %+v, want partial", out.scopes[0])
	}
	out.assertContract()
}

// Under the byte limit nothing changes.
func TestAStreamUnderTheByteLimitIsComplete(t *testing.T) {
	defer collect.LowerByteLimit(10_000_000, 1_000)()
	out := newWorld(t, directory()).mustRun("")
	if out.diag("entra.limit.bytes") != nil {
		t.Error("the limit was said to be reached")
	}
}

// Whatever the reserve, even none, the diagnostic that says why the stream
// stopped, and the completion after it, always fit: the reserve is counted
// against the events as they are sent, not assumed.
func TestTheDiagnosticAndTheCompletionAlwaysFitWhateverTheReserve(t *testing.T) {
	builds := []func() *fakegraph.Tenant{directory, privileged, withGrants, signedIn}
	for _, held := range []int{0, 2, 5} {
		for limit := 6; limit <= 60; limit++ {
			for bi, build := range builds {
				restore := collect.LowerEventLimit(limit, held)
				out, err := newWorld(t, build()).run("", collector.CollectRequest{})
				restore()
				name := fmt.Sprintf("tenant %d, limit %d, %d held back", bi, limit, held)
				if got := out.total(); got >= limit {
					t.Fatalf("%s: %d events sent, no room for the completion", name, got)
				}
				if err == nil {
					continue
				}
				inc, ok := collector.AsIncomplete(err)
				if !ok {
					t.Fatalf("%s: %v, want an incomplete collection and not a defect", name, err)
				}
				// Stopped for the limit: said, and said before the end.
				if inc.Cause == collector.ScopeUnreachable && strings.Contains(inc.Err.Error(), "events a collection may send") &&
					out.diag("entra.limit.events") == nil {
					t.Fatalf("%s: the limit was reached and the diagnostic did not fit: %v", name, inc.Err)
				}
				if len(out.scopes) != 1 {
					t.Fatalf("%s: %d scope outcomes", name, len(out.scopes))
				}
				out.assertContract()
				if t.Failed() {
					t.Fatalf("%s: the stream breaks the stream check", name)
				}
			}
		}
	}
}
