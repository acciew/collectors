package collect_test

import (
	"net/http"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

func withUnits() *fakegraph.Tenant {
	d := directory()
	d.AdminUnits = []fakegraph.AdminUnit{
		{ID: unitA, DisplayName: "Sales offices", Description: "Everyone in a sales office", Visibility: "HiddenMembership"},
		{ID: fakegraph.GUID("au-b"), DisplayName: "Warehouse"},
	}
	return d
}

func TestAdministrativeUnitsAreNotReadByDefault(t *testing.T) {
	w := newWorld(t, withUnits())
	out := w.mustRun("")

	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "administrativeUnits") {
			t.Errorf("asked for %s", p)
		}
	}
	// The unit a role is scoped to is named by the assignment, and only that.
	if n := out.node("", "NODE_TYPE_RESOURCE", "au:"+unitA); n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("unit = %v, want a referenced resource", n)
	}
}

// With the flag on the unit is read, and read once: the same key emitted as a
// reference by the role and as observed by the unit would be two answers to
// one question.
func TestWithAdministrativeUnitsOnEachUnitIsReadAndNamedOnce(t *testing.T) {
	out := newWorld(t, withUnits()).mustRun(`{"administrative_units":true}`)

	n := out.node("", "NODE_TYPE_RESOURCE", "au:"+unitA)
	if n == nil || n.GetName() != "Sales offices" || n.GetSourceType() != "administrative_unit" ||
		n.GetProvenance() != collectorv1.Provenance_PROVENANCE_OBSERVED || n.GetContext()["visibility"] != "HiddenMembership" {
		t.Fatalf("unit = %v", n)
	}
	if out.node("", "NODE_TYPE_RESOURCE", "au:"+fakegraph.GUID("au-b")) == nil {
		t.Error("a unit no role names was not collected")
	}
	units := out.count(func(e *collectorv1.CollectResponse) bool {
		return e.GetNode().GetKey().GetId() == "au:"+unitA
	})
	if units != 1 {
		t.Errorf("the unit was emitted %d times", units)
	}
	// And the role scoped to it still applies to it.
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, "role:"+helpdesk+":au:"+unitA, "au:"+unitA)) != 1 {
		t.Error("the scoped role does not apply to its unit")
	}
	out.assertContract()
}

func TestAnAdministrativeUnitReadThatIsRefusedNamesThePermission(t *testing.T) {
	w := newWorld(t, withUnits())
	w.srv.Refuse("/v1.0/directory/administrativeUnits", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run(`{"administrative_units":true}`, collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "AdministrativeUnit.Read.All") {
		t.Errorf("err = %v, want AdministrativeUnit.Read.All named", err)
	}
	if p := w.probe(`{"administrative_units":true}`); p.Reachable || !strings.Contains(p.Err.Error(), "AdministrativeUnit.Read.All") {
		t.Errorf("probe = %+v", p)
	}
	if p := w.probe(""); !p.Reachable {
		t.Errorf("the permission was wanted with the flag off: %+v", p)
	}
}

func withGrants() *fakegraph.Tenant {
	d := directory()
	graphAPI := fakegraph.GUID("sp-graph")
	d.ServicePrincipals = append(d.ServicePrincipals, fakegraph.ServicePrincipal{
		ID: graphAPI, AppID: fakegraph.GUID("app-graph"), DisplayName: "Microsoft Graph", Type: "Application", Enabled: fakegraph.Enabled(true),
	})
	d.OAuth2Grants = []fakegraph.OAuth2Grant{
		{ID: "g1", ClientID: payroll, ResourceID: graphAPI, ConsentType: "AllPrincipals", Scope: "User.Read Mail.Read"},
		{ID: "g2", ClientID: automation, ResourceID: graphAPI, ConsentType: "Principal", Principal: alice, Scope: "Files.Read"},
	}
	return d
}

// Directory.Read.All is far broader than anything else the collector asks for,
// so it is never asked for unless this is turned on.
func TestDelegatedGrantsAreNotReadByDefault(t *testing.T) {
	w := newWorld(t, withGrants())
	out := w.mustRun("")

	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "oauth2PermissionGrants") {
			t.Errorf("asked for %s", p)
		}
	}
	for _, e := range out.events {
		if n := e.GetNode(); n != nil && strings.HasPrefix(n.GetKey().GetId(), "oauth2-grant:") {
			t.Errorf("a grant was collected by default: %s", n.GetName())
		}
	}
	if p := w.probe(""); !p.Reachable {
		t.Errorf("the check wants Directory.Read.All with the flag off: %+v", p)
	}
}

func TestADelegatedGrantIsHeldByItsClientAndAppliesToItsResource(t *testing.T) {
	out := newWorld(t, withGrants()).mustRun(`{"oauth2_grants":true}`)

	id := "oauth2-grant:g1"
	e := out.node("", "NODE_TYPE_ENTITLEMENT", id)
	if e == nil || e.GetSourceType() != "oauth2_permission_grant" || !strings.Contains(e.GetName(), "Mail.Read") ||
		!strings.Contains(e.GetName(), "Microsoft Graph") {
		t.Fatalf("grant = %v, want its scopes and the name of the API", e)
	}
	if e.GetContext()["consent_type"] != "AllPrincipals" || e.GetContext()["scope"] != "User.Read Mail.Read" {
		t.Errorf("context = %v", e.GetContext())
	}
	if h := out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, payroll, id); len(h) != 1 ||
		h[0].GetFidelity() != collectorv1.Fidelity_FIDELITY_DIRECT || h[0].GetSourceType() != "oauth2_permission_grant" {
		t.Errorf("the client's grant = %v", h)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO, id, fakegraph.GUID("sp-graph"))) != 1 {
		t.Error("the grant does not apply to the API it is against")
	}
	// One user's consent is recorded as such, and is still the client's.
	if p := out.node("", "NODE_TYPE_ENTITLEMENT", "oauth2-grant:g2"); p == nil || p.GetContext()["consent_type"] != "Principal" ||
		p.GetContext()["principal_id"] != alice {
		t.Errorf("a one-user grant = %v", p)
	}
	out.assertContract()
}

func TestGrantsAreCleanWhateverElseIsSwitchedOff(t *testing.T) {
	for _, flags := range []string{
		`{"oauth2_grants":true,"service_principals":false}`,
		`{"oauth2_grants":true,"app_roles":false}`,
		`{"oauth2_grants":true,"service_principals":false,"app_roles":false}`,
	} {
		t.Run(flags, func(t *testing.T) {
			out := newWorld(t, withGrants()).mustRun(flags)
			// The contract check is the point: the client and the API are
			// named once each, as referenced where nothing else reads them.
			out.assertContract()
			if out.node("", "NODE_TYPE_ENTITLEMENT", "oauth2-grant:g1") == nil {
				t.Error("the grant was lost")
			}
		})
	}
}

func TestADelegatedGrantReadThatIsRefusedNamesTheBroadPermission(t *testing.T) {
	w := newWorld(t, withGrants())
	w.srv.Refuse("/v1.0/oauth2PermissionGrants", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run(`{"oauth2_grants":true}`, collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "Directory.Read.All") {
		t.Errorf("err = %v, want Directory.Read.All named", err)
	}
	if p := w.probe(`{"oauth2_grants":true}`); p.Reachable || !strings.Contains(p.Err.Error(), "Directory.Read.All") {
		t.Errorf("probe = %+v", p)
	}
}
