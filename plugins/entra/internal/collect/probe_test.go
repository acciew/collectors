package collect_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

func (w *world) probe(flags string) collect.Probe {
	w.t.Helper()
	probes := w.runner(flags).Probes(context.Background())
	if len(probes) != 1 {
		w.t.Fatalf("%d probes, want the one tenant", len(probes))
	}
	return probes[0]
}

func TestAPermittedTenantIsReachableAndNamedAndAnswersAboutActivity(t *testing.T) {
	w := newWorld(t, directory())
	p := w.probe("")

	if !p.Reachable || p.Err != nil {
		t.Fatalf("probe = %+v, want reachable", p)
	}
	if p.Name != "Example Corp" || p.Tenant != w.srv.Tenant.ID {
		t.Errorf("name = %q, tenant = %q", p.Name, p.Tenant)
	}
	if p.Activity.State != collect.ActivityAvailable || p.Activity.Note != "" {
		t.Errorf("activity = %+v, want available with nothing to explain", p.Activity)
	}
}

// A check asks whether a read is allowed, not what it returns: a tenant of a
// hundred thousand users should not be downloaded to learn one thing about a
// token.
func TestACheckReadsOnePageOfEachThingAndNeverTheWholeTenant(t *testing.T) {
	d := directory()
	for i := range 40 {
		id := fakegraph.GUID("bulk" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
		d.Users = append(d.Users, fakegraph.User{ID: id, DisplayName: id[:6], UPN: id[:6] + "@example.onmicrosoft.com"})
	}
	w := newWorld(t, d)
	w.srv.PageSize = 2
	w.probe("")

	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "skiptoken") {
			t.Errorf("a check followed a nextLink: %s", p)
		}
	}
}

func TestEachMissingPermissionIsOneSentenceNamingWhatToGrant(t *testing.T) {
	w := newWorld(t, directory())
	for _, prefix := range []string{"/v1.0/users", "/v1.0/groups"} {
		w.srv.Refuse(prefix, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	}
	p := w.probe("")

	if p.Reachable || p.Err == nil {
		t.Fatalf("probe = %+v, want unreachable and why", p)
	}
	msg := p.Err.Error()
	for _, want := range []string{"User.Read.All", "Group.Read.All"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the check does not name %s: %s", want, msg)
		}
	}
	// Roles were readable, so no sentence about them.
	if strings.Contains(msg, "RoleManagement.Read.Directory") {
		t.Errorf("the check asks for a permission that is held: %s", msg)
	}
	if lines := strings.Split(msg, "\n"); len(lines) != 2 {
		t.Errorf("%d lines for two missing permissions, want one each:\n%s", len(lines), msg)
	}
}

func TestOnlyARefusalIsAdviceToGrantSomethingInACheck(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/roleManagement", http.StatusServiceUnavailable, "serviceNotAvailable", "Try later.")
	p := w.probe("")

	if p.Reachable || p.Err == nil || strings.Contains(p.Err.Error(), "grant") {
		t.Errorf("probe = %+v; an unwell Graph is not a permission to grant", p)
	}
}

// Graph answers an object of a type the caller may not read as its type and
// id, every property null, and a 200. It is the silent form of a missing
// permission: nothing fails, and the population is smaller than it looks.
func TestAnIDOnlyMemberOfATypeThatCannotBeReadMakesTheScopeUnreachableNamingThePermission(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true // alice, in Engineering
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/users/"+alice, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	p := w.probe("")

	if p.Reachable || p.Err == nil || !strings.Contains(p.Err.Error(), "User.Read.All") {
		t.Fatalf("probe = %+v, want unreachable and User.Read.All named", p)
	}
}

func TestAHiddenMembershipGroupNeedsItsOwnPermission(t *testing.T) {
	d := directory()
	d.Groups[0].Visibility = "HiddenMembership"
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/groups/"+engineering+"/members", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	p := w.probe("")

	if p.Reachable || p.Err == nil || !strings.Contains(p.Err.Error(), "Member.Read.Hidden") {
		t.Fatalf("probe = %+v, want Member.Read.Hidden named", p)
	}
}

func TestATenantWithoutTheLicenceForSignInActivityIsTold(t *testing.T) {
	d := directory()
	d.ActivityRefusal = &fakegraph.Refusal{
		Status: http.StatusForbidden, Code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
		Message: "Neither tenant is B2C or tenant doesn't have premium license",
	}
	p := newWorld(t, d).probe("")

	if !p.Reachable {
		t.Errorf("a tenant without the licence is still reachable: %+v", p)
	}
	if p.Activity.State != collect.ActivityUnavailable || !strings.Contains(p.Activity.Note, "Entra ID P1") {
		t.Errorf("activity = %+v, want unavailable and a note that says it needs Entra ID P1 or P2", p.Activity)
	}
}

// Not knowing is not the same as knowing there is none, and it sends an
// operator to a different place: to check a credential, not to buy a licence.
func TestAnyOtherFailureToProbeActivityIsUndeterminedNotUnavailable(t *testing.T) {
	for _, c := range []struct {
		name   string
		refuse fakegraph.Refusal
		says   string
	}{
		{"a missing permission", fakegraph.Refusal{Status: http.StatusForbidden, Code: "Authorization_RequestDenied", Message: "Insufficient privileges."}, "AuditLog.Read.All"},
		{"an unwell Graph", fakegraph.Refusal{Status: http.StatusServiceUnavailable, Code: "serviceNotAvailable", Message: "Try later."}, "could not find out"},
		// A 403 whose shape is not one we know is not taken for a licence.
		{"a refusal of a shape nobody has seen", fakegraph.Refusal{Status: http.StatusForbidden, Code: "SomethingNew", Message: "Not allowed."}, "could not find out"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := directory()
			d.ActivityRefusal = &c.refuse
			p := newWorld(t, d).probe("")

			if p.Activity.State != collect.ActivityUndetermined || !strings.Contains(p.Activity.Note, c.says) {
				t.Errorf("activity = %+v, want undetermined saying %q", p.Activity, c.says)
			}
		})
	}
}

func TestTheActivityCheckAsksForOneUserAndNothingElse(t *testing.T) {
	w := newWorld(t, directory())
	w.probe("")

	var asked int
	for _, p := range w.srv.Paths() {
		if strings.Contains(p, "signInActivity") {
			asked++
			if !strings.Contains(p, "%24top=1") && !strings.Contains(p, "$top=1") {
				t.Errorf("the activity check is not bounded to one user: %s", p)
			}
		}
	}
	if asked != 1 {
		t.Errorf("%d requests carried signInActivity, want exactly the one probe", asked)
	}
}

func TestTheApplicationPermissionIsCheckedOnlyWhenApplicationsAreRead(t *testing.T) {
	for _, c := range []struct {
		flags string
		named bool
	}{
		{"", true},
		{`{"app_roles":false}`, true},
		{`{"service_principals":false}`, true},
		{`{"service_principals":false,"app_roles":false}`, false},
	} {
		w := newWorld(t, directory())
		w.srv.Refuse("/v1.0/servicePrincipals", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
		p := w.probe(c.flags)

		named := p.Err != nil && strings.Contains(p.Err.Error(), "Application.Read.All")
		if named != c.named || p.Reachable == c.named {
			t.Errorf("collect %s: probe = %+v, want Application.Read.All named: %v", c.flags, p, c.named)
		}
	}
}

// $top is documented for users, groups and service principals. For the rest it
// is not, and Graph silently ignores a query parameter it does not support or
// refuses the request, so a check bounds its reads only where it may.
func TestTheCheckBoundsItsReadsOnlyWhereGraphDocumentsTop(t *testing.T) {
	w := newWorld(t, privileged())
	w.probe(`{"administrative_units":true,"oauth2_grants":true}`)

	bounded := map[string]bool{"/v1.0/users": true, "/v1.0/groups": true, "/v1.0/servicePrincipals": true}
	seen := map[string]bool{}
	for _, r := range w.srv.Requests() {
		if !strings.HasPrefix(r.Path, "/v1.0/") || strings.Contains(r.Path, "/members") || r.Query.Get("$select") != "" && r.Path == "/v1.0/organization" {
			continue
		}
		seen[r.Path] = true
		hasTop := r.Query.Get("$top") != ""
		if bounded[r.Path] != hasTop {
			t.Errorf("%s: $top present = %v, want %v", r.Path, hasTop, bounded[r.Path])
		}
	}
	for _, p := range []string{
		"/v1.0/roleManagement/directory/roleDefinitions", "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances",
		"/v1.0/roleManagement/directory/roleAssignments", "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
		"/v1.0/directory/administrativeUnits", "/v1.0/oauth2PermissionGrants",
	} {
		if !seen[p] {
			t.Errorf("the check never read %s", p)
		}
	}
}

// The check passes only if the collection will: every collection read has a
// permission the check names when it is refused.
func TestTheCheckTestsEveryReadTheCollectionMakes(t *testing.T) {
	const all = `{"administrative_units":true,"oauth2_grants":true}`
	for _, c := range []struct{ path, permission string }{
		{"/v1.0/users", "User.Read.All"},
		{"/v1.0/groups", "Group.Read.All"},
		{"/v1.0/roleManagement/directory/roleDefinitions", "RoleManagement.Read.Directory"},
		{"/v1.0/roleManagement/directory/roleAssignments", "RoleManagement.Read.Directory"},
		{"/v1.0/servicePrincipals", "Application.Read.All"},
		{"/v1.0/directory/administrativeUnits", "AdministrativeUnit.Read.All"},
		{"/v1.0/oauth2PermissionGrants", "Directory.Read.All"},
		{"/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", "RoleEligibilitySchedule.Read.Directory"},
		{"/v1.0/roleManagement/directory/roleAssignmentScheduleInstances", "RoleAssignmentSchedule.Read.Directory"},
	} {
		t.Run(c.path, func(t *testing.T) {
			w := newWorld(t, privileged())
			w.srv.Refuse(c.path, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
			p := w.probe(all)

			if p.Reachable || p.Err == nil || !strings.Contains(p.Err.Error(), c.permission) {
				t.Errorf("probe = %+v, want %s named", p, c.permission)
			}
		})
	}
}

// A 200 that is not a page is not a collection that can be read.
func TestABodyThatIsNotAPageFailsTheCheck(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Respond("/v1.0/users", http.StatusOK, "application/json", `{}`)
	p := w.probe("")

	if p.Reachable || p.Err == nil || !strings.Contains(p.Err.Error(), "did not return a page") {
		t.Errorf("probe = %+v, want it to say the users did not come back as a page", p)
	}
}

// And the same in a collection: a tenant of users must not read as none.
func TestAUsersAnswerThatIsNotAPageIsAFailureAndNotAnEmptyTenant(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Respond("/v1.0/users", http.StatusOK, "application/json", `{}`)

	out, err := w.run("", collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "did not return a page") {
		t.Fatalf("err = %v, want the users part failed", err)
	}
	if out.scopes[0].Status == collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Error("a tenant whose users came back as {} was reported collected")
	}
}
