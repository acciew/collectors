package collect_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// ---------------------------------------------------------------------------
// Fuzz: every flag combination, a richer tenant, objects made between the parts.

func allFlagSets() []string {
	names := []string{"service_principals", "app_roles", "pim", "administrative_units", "oauth2_grants"}
	var out []string
	for bits := 0; bits < 1<<len(names); bits++ {
		var parts []string
		for i, n := range names {
			parts = append(parts, fmt.Sprintf("%q:%v", n, bits&(1<<i) != 0))
		}
		out = append(out, "{"+strings.Join(parts, ",")+"}")
	}
	return out
}

// richTenant is a directory of random shape with more of what a tenant has than
// randomTenant: dynamic and paused groups, hidden membership, nested groups,
// applications and devices as members, members that come back as an id alone,
// principals of every kind on role assignments and PIM instances, instances of
// every memberType and assignmentType, roles over units and other scopes,
// applications with and without roles, and delegated grants to applications
// nothing lists.
type rich struct {
	t                       *fakegraph.Tenant
	users, groups, sps, aus []string
	roles                   []string
	nameOf                  map[string]string
}

func richTenant(r *rand.Rand) *rich {
	rt := &rich{t: fakegraph.NewTenant(), nameOf: map[string]string{}}
	t := rt.t
	nu, ng, ns, na := 1+r.IntN(7), 1+r.IntN(5), r.IntN(4), r.IntN(3)
	for i := 0; i < nu; i++ {
		id := fakegraph.GUID(fmt.Sprintf("u%d", i))
		rt.users = append(rt.users, id)
		rt.nameOf[id] = "U" + fmt.Sprint(i)
		u := fakegraph.User{ID: id, DisplayName: "U" + fmt.Sprint(i), UPN: fmt.Sprintf("u%d@x", i)}
		switch r.IntN(4) {
		case 0:
			u.Enabled = fakegraph.Enabled(false)
		case 1:
			u.UserType = "Guest"
			u.Enabled = fakegraph.Enabled(true)
		case 2:
			u.Enabled = fakegraph.Enabled(true)
			u.SignIn = &fakegraph.SignIn{Interactive: now.Add(-time.Duration(r.IntN(1000)) * time.Hour)}
			if r.IntN(2) == 0 {
				u.SignIn.Successful = now.Add(time.Duration(r.IntN(48)) * time.Hour) // ahead of the clock
			}
		}
		t.Users = append(t.Users, u)
	}
	for i := 0; i < ns; i++ {
		id := fakegraph.GUID(fmt.Sprintf("sp%d", i))
		rt.sps = append(rt.sps, id)
		rt.nameOf[id] = "SP" + fmt.Sprint(i)
		sp := fakegraph.ServicePrincipal{ID: id, AppID: fakegraph.GUID(fmt.Sprintf("app%d", i)), DisplayName: "SP" + fmt.Sprint(i),
			Type: []string{"Application", "ManagedIdentity", "Legacy"}[r.IntN(3)]}
		if r.IntN(3) > 0 {
			sp.Enabled = fakegraph.Enabled(r.IntN(2) == 0)
		}
		for j := 0; j < r.IntN(3); j++ {
			sp.AppRoles = append(sp.AppRoles, fakegraph.AppRole{ID: fakegraph.GUID(fmt.Sprintf("ar%d-%d", i, j)), DisplayName: "R" + fmt.Sprint(j),
				Value: "R" + fmt.Sprint(j), Enabled: r.IntN(2) == 0, MemberTypes: []string{"User", "Application"}})
		}
		t.ServicePrincipals = append(t.ServicePrincipals, sp)
	}
	for i := 0; i < ng; i++ {
		id := fakegraph.GUID(fmt.Sprintf("g%d", i))
		rt.groups = append(rt.groups, id)
		rt.nameOf[id] = "G" + fmt.Sprint(i)
	}
	for i := 0; i < 1+na; i++ {
		id := fakegraph.GUID(fmt.Sprintf("au%d", i))
		rt.aus = append(rt.aus, id)
		if r.IntN(3) > 0 {
			t.AdminUnits = append(t.AdminUnits, fakegraph.AdminUnit{ID: id, DisplayName: "AU" + fmt.Sprint(i)})
		}
	}
	member := func() fakegraph.Member {
		var m fakegraph.Member
		switch r.IntN(7) {
		case 0:
			g := rt.groups[r.IntN(len(rt.groups))]
			m = fakegraph.Member{ID: g, Type: "group", DisplayName: rt.nameOf[g]}
		case 1:
			if len(rt.sps) == 0 {
				return fakegraph.Member{ID: fakegraph.GUID("dev0"), Type: "device", DisplayName: "D"}
			}
			sp := rt.sps[r.IntN(len(rt.sps))]
			m = fakegraph.Member{ID: sp, Type: "servicePrincipal", DisplayName: rt.nameOf[sp]}
		case 2:
			m = fakegraph.Member{ID: fakegraph.GUID(fmt.Sprintf("dev%d", r.IntN(3))), Type: "device", DisplayName: "D"}
		case 3:
			m = fakegraph.Member{ID: fakegraph.GUID(fmt.Sprintf("oc%d", r.IntN(2))), Type: "orgContact", DisplayName: "C"}
		default:
			u := rt.users[r.IntN(len(rt.users))]
			m = fakegraph.Member{ID: u, Type: "user", DisplayName: rt.nameOf[u]}
		}
		switch r.IntN(8) {
		case 0:
			m.IDOnly = true
		case 1:
			m.NoName = true
		}
		return m
	}
	for i, id := range rt.groups {
		g := fakegraph.Group{ID: id, DisplayName: "G" + fmt.Sprint(i), AssignableToRole: r.IntN(2) == 0}
		switch r.IntN(5) {
		case 0:
			g.Types = []string{"DynamicMembership"}
			g.MembershipRule = `(user.department -eq "Sales")`
			g.RuleState = []string{"On", "Paused"}[r.IntN(2)]
		case 1:
			g.Visibility = "HiddenMembership"
		case 2:
			g.Types = []string{"Unified"}
		}
		seen := map[string]bool{}
		for j := 0; j < r.IntN(6); j++ {
			m := member()
			if m.ID == id || seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			g.Members = append(g.Members, m)
		}
		t.Groups = append(t.Groups, g)
	}
	for i := 0; i < 2+r.IntN(2); i++ {
		id := fakegraph.GUID(fmt.Sprintf("rd%d", i))
		rt.roles = append(rt.roles, id)
		t.RoleDefs = append(t.RoleDefs, fakegraph.RoleDef{ID: id, DisplayName: "Role" + fmt.Sprint(i), BuiltIn: i == 0, Enabled: true})
	}
	scope := func() string {
		switch r.IntN(4) {
		case 0:
			return "/administrativeUnits/" + rt.aus[r.IntN(len(rt.aus))]
		case 1:
			return "/some/other/scope"
		}
		return "/"
	}
	role := func() string {
		if r.IntN(10) == 0 {
			return fakegraph.GUID("rd-unlisted")
		}
		return rt.roles[r.IntN(len(rt.roles))]
	}
	// principal is an id and a type; the type is "" for a principal Graph cannot
	// expand, and the id is sometimes one that does not exist anywhere.
	principal := func() (string, string) {
		switch r.IntN(7) {
		case 0:
			return rt.groups[r.IntN(len(rt.groups))], "group"
		case 1:
			if len(rt.sps) > 0 {
				return rt.sps[r.IntN(len(rt.sps))], "servicePrincipal"
			}
		case 2:
			return rt.users[r.IntN(len(rt.users))], ""
		case 3:
			return fakegraph.GUID("nobody"), ""
		case 4:
			return fakegraph.GUID("dev0"), "device"
		}
		return rt.users[r.IntN(len(rt.users))], "user"
	}
	for i := 0; i < r.IntN(6); i++ {
		p, pt := principal()
		t.RoleAssignments = append(t.RoleAssignments, fakegraph.RoleAssignment{ID: fmt.Sprintf("ra%d", i), Principal: p, PrincipalType: pt,
			PrincipalName: rt.nameOf[p], RoleDefID: role(), Scope: scope()})
	}
	memberTypes := []string{"Direct", "Group", "Inherited", ""}
	for i := 0; i < r.IntN(5); i++ {
		p, pt := principal()
		t.Eligible = append(t.Eligible, fakegraph.ScheduleInstance{ID: fmt.Sprintf("e%d", i), Principal: p, PrincipalType: pt, PrincipalName: rt.nameOf[p],
			RoleDefID: role(), Scope: scope(), MemberType: memberTypes[r.IntN(len(memberTypes))]})
	}
	for i := 0; i < r.IntN(5); i++ {
		p, pt := principal()
		in := fakegraph.ScheduleInstance{ID: fmt.Sprintf("a%d", i), Principal: p, PrincipalType: pt, PrincipalName: rt.nameOf[p],
			RoleDefID: role(), Scope: scope(), MemberType: memberTypes[r.IntN(len(memberTypes))],
			AssignmentType: []string{"Assigned", "Activated"}[r.IntN(2)]}
		if r.IntN(3) > 0 {
			in.End = now.Add(24 * time.Hour)
		}
		t.ActiveInstances = append(t.ActiveInstances, in)
	}
	t.AppRoleAssignments = map[string][]fakegraph.AppRoleAssignment{}
	for i, sp := range rt.sps {
		for j := 0; j < r.IntN(4); j++ {
			p, pt := principal()
			gt, ok := map[string]string{"user": "User", "group": "Group", "servicePrincipal": "ServicePrincipal", "device": "Device"}[pt]
			if !ok {
				gt, p = "User", rt.users[r.IntN(len(rt.users))]
			}
			ar := "00000000-0000-0000-0000-000000000000"
			switch nroles := len(t.ServicePrincipals[i].AppRoles); {
			case nroles > 0 && r.IntN(3) > 0:
				ar = t.ServicePrincipals[i].AppRoles[r.IntN(nroles)].ID
			case r.IntN(4) == 0:
				ar = fakegraph.GUID("ar-deleted")
			}
			t.AppRoleAssignments[sp] = append(t.AppRoleAssignments[sp], fakegraph.AppRoleAssignment{ID: fmt.Sprintf("a%d-%d", i, j), AppRoleID: ar,
				Principal: p, PrincipalType: gt, PrincipalName: rt.nameOf[p]})
		}
	}
	for i := 0; i < r.IntN(4) && len(rt.sps) > 0; i++ {
		client := rt.sps[r.IntN(len(rt.sps))]
		resource := rt.sps[r.IntN(len(rt.sps))]
		if r.IntN(3) == 0 {
			resource = fakegraph.GUID("sp-unlisted")
		}
		if r.IntN(3) == 0 {
			client = fakegraph.GUID("sp-unlisted-client")
		}
		g := fakegraph.OAuth2Grant{ID: fmt.Sprintf("o%d", i), ClientID: client, ResourceID: resource, ConsentType: "AllPrincipals", Scope: "a.b c.d"}
		if r.IntN(2) == 0 {
			g.ConsentType, g.Principal = "Principal", rt.users[0]
		}
		t.OAuth2Grants = append(t.OAuth2Grants, g)
	}
	return rt
}

// madeSince adds objects to the tenant between the parts: users, applications
// and units when the groups are first listed (after the parts that write them
// ran), and a group, with grants to all of them, when the groups are listed again
// for their members.
func madeSince(w *world, rt *rich, r *rand.Rand) {
	t := rt.t
	var a, b atomic.Bool
	var mu sync.Mutex
	newUser, newSP, newAU, newGroup := fakegraph.GUID("u-new"), fakegraph.GUID("sp-new"), fakegraph.GUID("au-new"), fakegraph.GUID("g-new")
	newRole := fakegraph.GUID("ar-new")
	w.srv.Intercept("/v1.0/groups", func(_ http.ResponseWriter, req *http.Request) bool {
		if req.URL.Path != "/v1.0/groups" {
			return false
		}
		sel := req.URL.Query().Get("$select")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(sel, "groupTypes") && a.CompareAndSwap(false, true):
			t.Users = append(t.Users, fakegraph.User{ID: newUser, DisplayName: "New User", UPN: "new@x", Enabled: fakegraph.Enabled(true)})
			t.ServicePrincipals = append(t.ServicePrincipals, fakegraph.ServicePrincipal{ID: newSP, AppID: fakegraph.GUID("app-new"), DisplayName: "New App",
				Type: "Application", AppRoles: []fakegraph.AppRole{{ID: newRole, DisplayName: "NewRole", Value: "New", Enabled: true}}})
			t.AdminUnits = append(t.AdminUnits, fakegraph.AdminUnit{ID: newAU, DisplayName: "New Unit"})
			t.AppRoleAssignments[newSP] = []fakegraph.AppRoleAssignment{
				{ID: "an1", AppRoleID: newRole, Principal: newUser, PrincipalType: "User", PrincipalName: "New User"},
				{ID: "an2", AppRoleID: newRole, Principal: rt.groups[0], PrincipalType: "Group", PrincipalName: rt.nameOf[rt.groups[0]]},
			}
			t.RoleAssignments = append(t.RoleAssignments,
				fakegraph.RoleAssignment{ID: "ra-new1", Principal: newUser, PrincipalType: "user", PrincipalName: "New User", RoleDefID: rt.roles[0], Scope: "/administrativeUnits/" + newAU},
				fakegraph.RoleAssignment{ID: "ra-new2", Principal: newSP, PrincipalType: "servicePrincipal", PrincipalName: "New App", RoleDefID: rt.roles[1], Scope: "/"},
				fakegraph.RoleAssignment{ID: "ra-new3", Principal: newUser, PrincipalType: "", RoleDefID: rt.roles[1], Scope: "/"})
			t.Eligible = append(t.Eligible, fakegraph.ScheduleInstance{ID: "e-new", Principal: newSP, PrincipalType: "servicePrincipal", PrincipalName: "New App",
				RoleDefID: rt.roles[0], Scope: "/", MemberType: "Direct"})
			if r.IntN(2) == 0 {
				// A role an existing application gained, and someone was assigned.
				if len(rt.sps) > 0 {
					sp := rt.sps[0]
					late := fakegraph.GUID("ar-late")
					for i := range t.ServicePrincipals {
						if t.ServicePrincipals[i].ID == sp {
							t.ServicePrincipals[i].AppRoles = append(t.ServicePrincipals[i].AppRoles, fakegraph.AppRole{ID: late, DisplayName: "Late", Value: "Late", Enabled: true})
						}
					}
					t.AppRoleAssignments[sp] = append(t.AppRoleAssignments[sp], fakegraph.AppRoleAssignment{ID: "a-late", AppRoleID: late, Principal: rt.users[0], PrincipalType: "User", PrincipalName: rt.nameOf[rt.users[0]]})
				}
			}
		case sel == "id,displayName,visibility" && b.CompareAndSwap(false, true):
			t.Groups = append(t.Groups, fakegraph.Group{ID: newGroup, DisplayName: "New Group", AssignableToRole: true, Members: []fakegraph.Member{
				{ID: newUser, Type: "user", DisplayName: "New User"},
				{ID: rt.users[0], Type: "user", DisplayName: rt.nameOf[rt.users[0]]},
				{ID: newSP, Type: "servicePrincipal", DisplayName: "New App"},
				{ID: rt.groups[0], Type: "group", DisplayName: rt.nameOf[rt.groups[0]]},
			}})
			t.RoleAssignments = append(t.RoleAssignments,
				fakegraph.RoleAssignment{ID: "ra-new4", Principal: newGroup, PrincipalType: "group", PrincipalName: "New Group", RoleDefID: rt.roles[0], Scope: "/"})
			t.Eligible = append(t.Eligible, fakegraph.ScheduleInstance{ID: "e-new2", Principal: newGroup, PrincipalType: "group", PrincipalName: "New Group",
				RoleDefID: rt.roles[1], Scope: "/administrativeUnits/" + newAU, MemberType: "Direct"})
			t.ActiveInstances = append(t.ActiveInstances, fakegraph.ScheduleInstance{ID: "a-new", Principal: newGroup, PrincipalType: "group", PrincipalName: "New Group",
				RoleDefID: rt.roles[0], Scope: "/", MemberType: "Direct", AssignmentType: "Assigned", End: now.Add(time.Hour)})
			t.AppRoleAssignments[newSP] = append(t.AppRoleAssignments[newSP], fakegraph.AppRoleAssignment{ID: "an3", AppRoleID: newRole, Principal: newGroup, PrincipalType: "Group", PrincipalName: "New Group"})
			t.OAuth2Grants = append(t.OAuth2Grants, fakegraph.OAuth2Grant{ID: "o-new", ClientID: newSP, ResourceID: newSP, ConsentType: "AllPrincipals", Scope: "x"})
		}
		return false
	})
}

func TestEveryFlagCombinationOfARichTenantIsOneCleanStream(t *testing.T) {
	flagsets := allFlagSets()
	for seed := uint64(0); seed < 400; seed++ {
		r := rand.New(rand.NewPCG(seed, 9))
		rt := richTenant(r)
		w := newWorld(t, rt.t)
		w.srv.PageSize = 1 + int(seed%3)
		if seed%2 == 1 {
			madeSince(w, rt, r)
		}
		flags := flagsets[int(seed)%len(flagsets)]
		name := fmt.Sprintf("seed=%d flags=%s page=%d since=%v", seed, flags, w.srv.PageSize, seed%2 == 1)
		out, err := w.run(flags, collector.CollectRequest{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out.assertContract()
		if t.Failed() {
			t.Fatalf("%s: the stream breaks the stream check", name)
		}
		if dup := duplicates(out); len(dup) > 0 {
			t.Fatalf("%s: %d records sent twice, e.g. %s", name, len(dup), dup[0])
		}
		if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
			t.Fatalf("%s: scope = %+v", name, out.scopes)
		}
	}
}

// ---------------------------------------------------------------------------
// Fuzz: one read fails, somewhere, somehow. The stream still passes the host's
// check, sends nothing twice, and never says COMPLETE once a read was refused,
// went away, or led off the host.

type injected struct {
	mode  string
	path  string
	at    int
	fired atomic.Int32
}

func inject(w *world, rt *rich, r *rand.Rand) *injected {
	paths := []string{"/v1.0/users", "/v1.0/servicePrincipals", "/v1.0/directory/administrativeUnits", "/v1.0/groups",
		"/v1.0/roleManagement/directory/roleDefinitions", "/v1.0/roleManagement/directory/roleAssignments",
		"/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
		"/v1.0/oauth2PermissionGrants", "/v1.0/organization"}
	for _, g := range rt.groups {
		paths = append(paths, "/v1.0/groups/"+g+"/members", "/v1.0/groups/"+g)
	}
	for _, sp := range rt.sps {
		paths = append(paths, "/v1.0/servicePrincipals/"+sp+"/appRoleAssignedTo", "/v1.0/servicePrincipals/"+sp)
	}
	for _, u := range rt.users {
		paths = append(paths, "/v1.0/users/"+u)
	}
	in := &injected{path: paths[r.IntN(len(paths))], at: r.IntN(3)}
	in.mode = []string{"refused", "outage", "foreign", "notjson", "novalue", "loop", "badrequest"}[r.IntN(7)]
	var n atomic.Int32
	w.srv.Intercept(in.path, func(rw http.ResponseWriter, req *http.Request) bool {
		if req.URL.Path != in.path || req.URL.Query().Get("$top") == "1" {
			return false
		}
		k := int(n.Add(1)) - 1
		if k < in.at || (k > in.at && in.mode != "outage") {
			return false
		}
		in.fired.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		switch in.mode {
		case "refused":
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`))
		case "badrequest":
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = rw.Write([]byte(`{"error":{"code":"Request_BadRequest","message":"Invalid filter clause."}}`))
		case "outage":
			rw.WriteHeader(http.StatusServiceUnavailable)
			_, _ = rw.Write([]byte(`{"error":{"code":"serviceNotAvailable","message":"The service is unavailable."}}`))
		case "foreign":
			_ = json.NewEncoder(rw).Encode(map[string]any{"value": []any{}, "@odata.nextLink": "https://evil.example/v1.0" + strings.TrimPrefix(in.path, "/v1.0") + "?$skiptoken=1"})
		case "notjson":
			_, _ = rw.Write([]byte(`<html>gateway</html>`))
		case "novalue":
			_, _ = rw.Write([]byte(`{"@odata.context":"x"}`))
		case "loop":
			_ = json.NewEncoder(rw).Encode(map[string]any{"value": []any{}, "@odata.nextLink": w.srv.URL + req.URL.Path + "?" + req.URL.RawQuery})
		}
		return true
	})
	return in
}

func TestAFailedReadAnywhereNeverLeavesACompleteOrMalformedStream(t *testing.T) {
	flagsets := allFlagSets()
	for seed := uint64(0); seed < 600; seed++ {
		r := rand.New(rand.NewPCG(seed, 11))
		rt := richTenant(r)
		w := newWorld(t, rt.t)
		w.srv.PageSize = 1 + int(seed%3)
		in := inject(w, rt, r)
		flags := flagsets[int(seed)%len(flagsets)]
		name := fmt.Sprintf("seed=%d flags=%s page=%d %s %s #%d", seed, flags, w.srv.PageSize, in.mode, in.path, in.at)
		out, err := w.run(flags, collector.CollectRequest{})
		out.assertContract()
		if t.Failed() {
			t.Fatalf("%s: the stream breaks the stream check", name)
		}
		if dup := duplicates(out); len(dup) > 0 {
			t.Fatalf("%s: %d records sent twice, e.g. %s", name, len(dup), dup[0])
		}
		if in.fired.Load() == 0 {
			continue
		}
		// What may be swallowed: a name lookup (the grant is worth more with an
		// id than not at all), the organization's name, the activity probe, and
		// the read that asks whether a group's membership is hidden or whether a
		// type of member can be read. Everything else is a read of the tenant.
		single := !strings.HasSuffix(in.path, "/members") && !strings.HasSuffix(in.path, "/appRoleAssignedTo") &&
			(strings.HasPrefix(in.path, "/v1.0/users/") || strings.HasPrefix(in.path, "/v1.0/groups/") || strings.HasPrefix(in.path, "/v1.0/servicePrincipals/"))
		if in.path == "/v1.0/organization" || single {
			continue
		}
		if err == nil {
			t.Fatalf("%s: COMPLETE after the read was answered %s (fired %d)", name, in.mode, in.fired.Load())
		}
	}
}

// ---------------------------------------------------------------------------
// Fuzz: the event limit, at every size, on every shape.

func TestTheEventLimitHoldsOnEveryTenantAndEveryFlag(t *testing.T) {
	flagsets := allFlagSets()
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 13))
		rt := richTenant(r)
		// A reserve of at least the non-record events two parts can put between
		// two records (skipped, left-out, PIM and nested diagnostics, a progress),
		// as the real reserve of 10,000 is.
		held := 8 + r.IntN(4)
		limit := held + 12 + r.IntN(150)
		restore := collect.LowerEventLimit(limit, held)
		w := newWorld(t, rt.t)
		w.srv.PageSize = 1 + int(seed%3)
		flags := flagsets[int(seed)%len(flagsets)]
		name := fmt.Sprintf("seed=%d flags=%s limit=%d held=%d", seed, flags, limit, held)
		out, err := w.run(flags, collector.CollectRequest{})
		restore()
		out.assertContract()
		if t.Failed() {
			t.Fatalf("%s: the stream breaks the stream check", name)
		}
		if got := out.total(); got >= limit {
			t.Fatalf("%s: %d events sent, no room for the completion", name, got)
		}
		d := out.diag("entra.limit.events")
		switch {
		case d != nil && err == nil:
			t.Fatalf("%s: the limit was said and the collection is COMPLETE", name)
		case d != nil && out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL:
			t.Fatalf("%s: the limit was said and the scope is %v", name, out.scopes[0].Status)
		case d == nil && err != nil:
			inc := incomplete(t, err)
			if strings.Contains(inc.Err.Error(), "events a collection may send") {
				t.Fatalf("%s: the limit was reached and not said: %v", name, inc.Err)
			}
		}
		if dup := duplicates(out); len(dup) > 0 {
			t.Fatalf("%s: %d records sent twice", name, len(dup))
		}
	}
}

// ---------------------------------------------------------------------------
// Retry-After, however absurd, never makes the stream wait more than a minute
// at a time or more than four times.

func TestAnAbsurdRetryAfterIsBounded(t *testing.T) {
	for _, h := range []string{"9999999999", "99999999999999999999", "-5", "garbage", time.Now().Add(24 * 365 * time.Hour).UTC().Format(http.TimeFormat)} {
		w := newWorld(t, directory())
		w.srv.Intercept("/v1.0/users", func(rw http.ResponseWriter, req *http.Request) bool {
			if req.URL.Query().Get("$top") == "1" {
				return false
			}
			rw.Header().Set("Retry-After", h)
			rw.WriteHeader(http.StatusTooManyRequests)
			return true
		})
		out, err := w.run(noApplications, collector.CollectRequest{})
		inc := incomplete(t, err)
		if inc.Cause != collector.RateLimited {
			t.Fatalf("Retry-After %q: cause = %v", h, inc.Cause)
		}
		if len(w.waited) > 4 {
			t.Errorf("Retry-After %q: waited %d times", h, len(w.waited))
		}
		for _, d := range w.waited {
			if d > time.Minute || d <= 0 {
				t.Errorf("Retry-After %q: waited %v", h, d)
			}
		}
		out.assertContract()
	}
}
