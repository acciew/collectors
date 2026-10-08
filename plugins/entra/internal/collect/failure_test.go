package collect_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// A part the application may not read does not abandon the others: an operator
// needs the whole picture to fix one thing. What was read is kept, the failure
// says which permission to grant, and the verdict says the tenant is not whole.
func TestAPartThatIsRefusedFailsTheTenantButNotTheOtherParts(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Errorf("cause = %v, want ScopeUnreachable", inc.Cause)
	}
	for _, want := range []string{"Group.Read.All", "grant the application permission"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not say %q: %v", want, err)
		}
	}
	// Users and roles were still read.
	if out.node("", "NODE_TYPE_IDENTITY", alice) == nil || out.node("", "NODE_TYPE_ENTITLEMENT", "role:"+globalAdmin) == nil {
		t.Error("a refused groups read cost the users and the roles")
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL || out.scopes[0].Err == nil {
		t.Errorf("scopes = %+v, want the tenant partial, with the reason", out.scopes)
	}
	if !partFailed(inc.Err, "groups") {
		t.Errorf("err = %v, want the groups named as the part that failed", err)
	}
}

func TestOnlyARefusalIsAdviceToGrantSomething(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/users", http.StatusServiceUnavailable, "serviceNotAvailable", "Try again.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil || strings.Contains(err.Error(), "grant the application permission") {
		t.Errorf("err = %v; an unwell Graph is not a permission to grant", err)
	}
}

// A credential that stops working part-way is not a part to skip: nothing
// after it can succeed, and the cursor says where to start once it is fixed.
func TestACredentialThatStopsWorkingEndsTheCollectionAsAFailureOfTheSource(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.ExpireTokens()
	w.srv.AcceptSecret(harnessClient, "a-rotated-secret")

	out, err := w.run("", collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.SourceFailed || !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Errorf("cause = %v, err = %v; want a source failure carrying Entra's code", inc.Cause, err)
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL {
		t.Errorf("scopes = %+v", out.scopes)
	}
}

// A failure of the stream itself is this code's, or the host's, and is not a
// statement about the tenant.
func TestAFailureToWriteIsNotBlamedOnTheTenant(t *testing.T) {
	w := newWorld(t, directory())
	boom := errors.New("the host went away")
	r := collect.Run{Graph: w.client, Config: config(t, ""), Now: func() time.Time { return now }}

	err := r.Collect(context.Background(), collector.CollectRequest{}, &failingStream{capture: &capture{t: t}, err: boom})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the stream's own error", err)
	}
	if _, ok := collector.AsIncomplete(err); ok {
		t.Error("a broken stream was reported as an incomplete collection")
	}
}

type failingStream struct {
	*capture
	err error
}

func (f *failingStream) Node(*collectorv1.Node) error { return f.err }

func TestATenantWhoseOrganizationCannotBeReadIsNamedByItsID(t *testing.T) {
	d := directory()
	d.Name = "" // the fake refuses to serve the organization
	w := newWorld(t, d)
	out := w.mustRun("")

	n := out.node("", "NODE_TYPE_SCOPE", d.ID)
	if n == nil || n.GetName() != d.ID {
		t.Fatalf("scope = %v, want it named by the tenant ID", n)
	}
	diag := out.diag("entra.organization.unreadable")
	if diag == nil || !strings.Contains(diag.GetMessage(), "Organization.Read.All") {
		t.Errorf("diagnostic = %v, want it to say which permission allows the name", diag)
	}
	// A convenience that is missing is not a tenant that is partial.
	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v, want collected", out.scopes[0].Status)
	}
}

// The host picks scopes from what the check reported, which is the tenant's
// ID; an operator may as well write the tenant as they configured it.
func TestTheCallerMayNameTheTenantByItsIDOrAsItWasConfigured(t *testing.T) {
	for _, scope := range []string{fakegraph.NewTenant().ID, strings.ToUpper(tenantGUID)} {
		w := newWorld(t, directory())
		if _, err := w.run("", collector.CollectRequest{Scopes: []string{scope}}); err != nil {
			t.Errorf("scope %q was refused: %v", scope, err)
		}
	}
}

func TestRolesOverOtherScopesAndUnknownRolesAreStillGrants(t *testing.T) {
	d := directory()
	appObject := fakegraph.GUID("app-object")
	d.RoleAssignments = append(d.RoleAssignments,
		// A role over a single directory object, such as an app registration.
		fakegraph.RoleAssignment{ID: "ra4", Principal: dave, PrincipalType: "user", PrincipalName: "Dave",
			RoleDefID: helpdesk, Scope: "/" + appObject},
		// A role definition the definitions list does not have.
		fakegraph.RoleAssignment{ID: "ra5", Principal: dave, PrincipalType: "user", PrincipalName: "Dave",
			RoleDefID: fakegraph.GUID("role-unlisted"), Scope: "/"},
		// An application holding a role.
		fakegraph.RoleAssignment{ID: "ra6", Principal: fakegraph.GUID("sp"), PrincipalType: "servicePrincipal",
			PrincipalName: "Some App", RoleDefID: helpdesk, Scope: "/"},
		// A principal Graph returned no object for.
		fakegraph.RoleAssignment{ID: "ra7", Principal: fakegraph.GUID("gone"), RoleDefID: helpdesk, Scope: "/"},
		// A principal of a kind that cannot hold a directory role here.
		fakegraph.RoleAssignment{ID: "ra8", Principal: fakegraph.GUID("dev"), PrincipalType: "device", RoleDefID: helpdesk, Scope: "/"},
	)
	out := newWorld(t, d).mustRun(`{"service_principals":false}`)

	scoped := "role:" + helpdesk + ":scope:" + appObject
	if e := out.node("", "NODE_TYPE_ENTITLEMENT", scoped); e == nil || len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, dave, scoped)) != 1 {
		t.Errorf("a role over a directory object is not a grant of its own: %v", e)
	}
	if res := out.node("", "NODE_TYPE_RESOURCE", "scope:"+appObject); res == nil ||
		res.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("the scope = %v, want a referenced resource", res)
	}
	// The role has no definition to name it, so it is named by its id and
	// still held.
	unlisted := "role:" + fakegraph.GUID("role-unlisted")
	if e := out.node("", "NODE_TYPE_ENTITLEMENT", unlisted); e == nil || e.GetName() != fakegraph.GUID("role-unlisted") {
		t.Errorf("unlisted role = %v", e)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, fakegraph.GUID("sp"), "role:"+helpdesk)) != 1 {
		t.Error("an application holding a directory role is not a grant")
	}
	if d := out.diag("entra.role-assignment.principal-gone"); d == nil {
		t.Error("an assignment to a principal that no longer exists was dropped without a word")
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, fakegraph.GUID("dev"), "role:"+helpdesk)) != 0 {
		t.Error("a device became a holder")
	}
	out.assertContract()
}

func TestAnEmptyTenantIsAScopeWithNothingInIt(t *testing.T) {
	out := newWorld(t, fakegraph.NewTenant()).mustRun("")
	out.assertContract()
	if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope = %v", out.scopes[0].Status)
	}
}

func TestAnOrganizationThatCouldNotBeReadForWantOfAServiceIsNotBlamedOnAPermission(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/organization", http.StatusServiceUnavailable, "serviceNotAvailable", "Try again.")
	out := w.mustRun("")

	d := out.diag("entra.organization.unreadable")
	if d == nil || strings.Contains(d.GetMessage(), "Organization.Read.All") {
		t.Errorf("diagnostic = %v; an outage is not a permission to grant", d)
	}
}
