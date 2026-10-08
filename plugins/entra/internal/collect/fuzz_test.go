package collect_test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// randomTenant is a directory of random shape: users, groups that hold users,
// applications, groups and devices, roles held by all of them, units that are
// sometimes not listed, and the assignments of every application.
func randomTenant(r *rand.Rand) *fakegraph.Tenant {
	t := fakegraph.NewTenant()
	nu, ng, ns := 2+r.IntN(6), 1+r.IntN(5), 1+r.IntN(4)
	var users, groups, sps, aus []string
	for i := 0; i < nu; i++ {
		id := fakegraph.GUID(fmt.Sprintf("u%d", i))
		users = append(users, id)
		t.Users = append(t.Users, fakegraph.User{ID: id, DisplayName: "U" + fmt.Sprint(i), UPN: fmt.Sprintf("u%d@x", i), Enabled: fakegraph.Enabled(true)})
	}
	for i := 0; i < ns; i++ {
		id := fakegraph.GUID(fmt.Sprintf("sp%d", i))
		sps = append(sps, id)
		t.ServicePrincipals = append(t.ServicePrincipals, fakegraph.ServicePrincipal{ID: id, AppID: fakegraph.GUID(fmt.Sprintf("app%d", i)),
			DisplayName: "SP" + fmt.Sprint(i), Type: "Application", Enabled: fakegraph.Enabled(true),
			AppRoles: []fakegraph.AppRole{{ID: fakegraph.GUID(fmt.Sprintf("ar%d", i)), DisplayName: "R", Value: "R", Enabled: true}}})
	}
	for i := 0; i < ng; i++ {
		groups = append(groups, fakegraph.GUID(fmt.Sprintf("g%d", i)))
	}
	for i := 0; i < 1+r.IntN(2); i++ {
		id := fakegraph.GUID(fmt.Sprintf("au%d", i))
		aus = append(aus, id)
		if r.IntN(3) > 0 {
			t.AdminUnits = append(t.AdminUnits, fakegraph.AdminUnit{ID: id, DisplayName: "AU" + fmt.Sprint(i)})
		}
	}
	nameOf := map[string]string{}
	for i, u := range users {
		nameOf[u] = "U" + fmt.Sprint(i)
	}
	for i, u := range sps {
		nameOf[u] = "SP" + fmt.Sprint(i)
	}
	for i, u := range groups {
		nameOf[u] = "G" + fmt.Sprint(i)
	}
	member := func() fakegraph.Member {
		switch r.IntN(5) {
		case 0:
			g := groups[r.IntN(len(groups))]
			return fakegraph.Member{ID: g, Type: "group", DisplayName: nameOf[g]}
		case 1:
			sp := sps[r.IntN(len(sps))]
			return fakegraph.Member{ID: sp, Type: "servicePrincipal", DisplayName: nameOf[sp]}
		case 2:
			return fakegraph.Member{ID: fakegraph.GUID(fmt.Sprintf("dev%d", r.IntN(3))), Type: "device", DisplayName: "D"}
		}
		u := users[r.IntN(len(users))]
		return fakegraph.Member{ID: u, Type: "user", DisplayName: nameOf[u]}
	}
	for i, id := range groups {
		g := fakegraph.Group{ID: id, DisplayName: "G" + fmt.Sprint(i), AssignableToRole: r.IntN(2) == 0}
		seen := map[string]bool{}
		for j := 0; j < r.IntN(5); j++ {
			m := member()
			if m.ID == id || seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			g.Members = append(g.Members, m)
		}
		t.Groups = append(t.Groups, g)
	}
	roles := []string{fakegraph.GUID("rd0"), fakegraph.GUID("rd1")}
	for i, id := range roles {
		t.RoleDefs = append(t.RoleDefs, fakegraph.RoleDef{ID: id, DisplayName: "Role" + fmt.Sprint(i), BuiltIn: true, Enabled: true})
	}
	scope := func() string {
		if r.IntN(2) == 0 {
			return "/"
		}
		return "/administrativeUnits/" + aus[r.IntN(len(aus))]
	}
	principal := func() (string, string) {
		switch r.IntN(4) {
		case 0:
			return groups[r.IntN(len(groups))], "group"
		case 1:
			return sps[r.IntN(len(sps))], "servicePrincipal"
		}
		return users[r.IntN(len(users))], "user"
	}
	for i := 0; i < r.IntN(5); i++ {
		p, pt := principal()
		t.RoleAssignments = append(t.RoleAssignments, fakegraph.RoleAssignment{ID: fmt.Sprintf("ra%d", i), Principal: p, PrincipalType: pt,
			PrincipalName: nameOf[p], RoleDefID: roles[r.IntN(2)], Scope: scope()})
	}
	for i := 0; i < r.IntN(4); i++ {
		p, pt := principal()
		t.Eligible = append(t.Eligible, fakegraph.ScheduleInstance{ID: fmt.Sprintf("e%d", i), Principal: p, PrincipalType: pt, PrincipalName: nameOf[p],
			RoleDefID: roles[r.IntN(2)], Scope: scope(), MemberType: "Direct"})
	}
	t.AppRoleAssignments = map[string][]fakegraph.AppRoleAssignment{}
	for i, sp := range sps {
		for j := 0; j < r.IntN(4); j++ {
			p, pt := principal()
			gt := map[string]string{"user": "User", "group": "Group", "servicePrincipal": "ServicePrincipal"}[pt]
			role := fakegraph.GUID(fmt.Sprintf("ar%d", i))
			if r.IntN(3) == 0 {
				role = "00000000-0000-0000-0000-000000000000"
			}
			t.AppRoleAssignments[sp] = append(t.AppRoleAssignments[sp], fakegraph.AppRoleAssignment{ID: fmt.Sprintf("a%d-%d", i, j), AppRoleID: role,
				Principal: p, PrincipalType: gt, PrincipalName: nameOf[p]})
		}
	}
	if len(sps) > 1 {
		t.OAuth2Grants = []fakegraph.OAuth2Grant{{ID: "o1", ClientID: sps[0], ResourceID: sps[1], ConsentType: "Principal", Principal: users[0], Scope: "x"}}
	}
	return t
}

// A directory of random shape, whatever flags and whatever page size: the one
// stream passes the host's check, sends nothing twice, and says it collected the
// tenant.
func TestRandomTenantsAreOneCleanStream(t *testing.T) {
	flagsets := []string{"", noApplications, `{"service_principals":false}`, `{"app_roles":false}`,
		`{"oauth2_grants":true,"administrative_units":true}`,
		`{"oauth2_grants":true,"administrative_units":true,"service_principals":false}`, `{"pim":false}`}
	for seed := uint64(0); seed < 300; seed++ {
		flags := flagsets[int(seed)%len(flagsets)]
		w := newWorld(t, randomTenant(rand.New(rand.NewPCG(seed, 2))))
		w.srv.PageSize = 1 + int(seed%3)
		out, err := w.run(flags, collector.CollectRequest{})
		name := fmt.Sprintf("seed=%d flags=%s page=%d", seed, flags, w.srv.PageSize)
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
		if out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
			t.Fatalf("%s: scope = %+v", name, out.scopes[0])
		}
	}
}
