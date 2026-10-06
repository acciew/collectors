package collect_test

import (
	"context"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
)

// These are the five ways this collector was producing grants that looked
// right and were not. Each was confirmed against a real Keycloak 26.4 before
// being written down here.

func collectWith(t *testing.T, src *fakeSource, r admin.Realm) *capture {
	t.Helper()
	out := &capture{t: t}
	if _, err := collect.Realm(context.Background(), src, r, now, out); err != nil {
		t.Fatalf("Realm: %v", err)
	}
	return out
}

// holdsFrom returns the ids of everything a subject holds, by any route.
func (c *capture) holdsFrom(subject string) map[string]bool {
	out := map[string]bool{}
	for _, e := range c.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_HOLDS ||
			edge.GetFrom().GetId() != subject {
			continue
		}
		out[edge.GetTo().GetId()] = true
	}
	return out
}

// Keycloak's own account client ships a composite client role, so every realm
// in existence hits this: default-roles-<realm> includes account/manage-account,
// which itself includes manage-account-links. Walking only realm composites
// shows a reviewer the container and never its contents.
func TestCompositeClientRolesAreWalked(t *testing.T) {
	src := realm()
	src.clientRls["c-app"] = []admin.Role{
		{ID: "cr-manage", Name: "manage-account", ClientRole: true, Composite: true},
		{ID: "cr-links", Name: "manage-account-links", ClientRole: true},
	}
	src.comps["cr-manage"] = []admin.Role{{ID: "cr-links", Name: "manage-account-links", ClientRole: true}}
	src.userRole["u-alice"] = []admin.Role{{ID: "cr-manage", Name: "manage-account", ClientRole: true, Composite: true}}

	held := collectWith(t, src, admin.Realm{Realm: "probe", Enabled: live()}).holdsFrom("u-alice")
	if !held["cr-manage"] {
		t.Fatal("alice does not hold the composite client role at all")
	}
	if !held["cr-links"] {
		t.Error("a composite client role was emitted without walking what it contains")
	}
}

// The default role was matched by rebuilding its name from the realm name.
// Keycloak lowercases the realm in that name, so realm "Corp" has
// "default-roles-corp" and the tag never matched; a renamed default role
// never matches either. The realm representation names it outright.
func TestTheDefaultRoleIsIdentifiedByWhatTheRealmSaysItIs(t *testing.T) {
	src := realm()
	src.realm = append(src.realm, admin.Role{ID: "r-defaults", Name: "the-defaults", Composite: true})

	nodes := collectWith(t, src, admin.Realm{
		Realm: "Corp", Enabled: live(),
		DefaultRole: &admin.Role{ID: "r-defaults", Name: "the-defaults"},
	}).nodes()
	n, ok := nodes["r-defaults"]
	if !ok {
		t.Fatal("the default role was not emitted")
	}
	if n.GetContext()["default_grant"] != "true" {
		t.Errorf("the default role is not tagged: %v", n.GetContext())
	}
}

// Keycloak does not populate serviceAccountClientId on either the
// service-account-user endpoint or GET /users/{id}: both return null on 26.4.
// The collector read that field, so the context it claims to set was never
// set on a real source. We know which client we asked through.
func TestAServiceAccountNamesItsClient(t *testing.T) {
	src := realm()
	// As a real Keycloak answers: the field is absent.
	src.svcUsers["c-app"] = &admin.User{ID: "u-svc", Username: "service-account-app", Enabled: true}

	nodes := collectWith(t, src, admin.Realm{Realm: "probe", Enabled: live()}).nodes()
	n, ok := nodes["u-svc"]
	if !ok {
		t.Fatal("the service account was not emitted")
	}
	if got := n.GetContext()["service_account_of"]; got != "app" {
		t.Errorf("service_account_of = %q, want the client it belongs to", got)
	}
}

// A composite cycle produced a second, phantom route to a role the subject
// already held directly: revoking what the route names would not remove the
// access, which is exactly the claim a grant makes.
func TestACompositeCycleDoesNotManufactureAnExtraRoute(t *testing.T) {
	src := realm()
	src.realm = []admin.Role{
		{ID: "r-a", Name: "a", Composite: true},
		{ID: "r-b", Name: "b", Composite: true},
	}
	src.comps = map[string][]admin.Role{
		"r-a": {{ID: "r-b", Name: "b"}},
		"r-b": {{ID: "r-a", Name: "a"}},
	}
	src.userRole = map[string][]admin.Role{"u-alice": {{ID: "r-a", Name: "a", Composite: true}}}
	src.groupRole = map[string][]admin.Role{}

	out := collectWith(t, src, admin.Realm{Realm: "probe", Enabled: live()})
	if routes := out.routes("u-alice", "r-a"); len(routes) != 0 {
		t.Errorf("a role held directly also came back by a route through itself: %v", routes)
	}
	if routes := out.routes("u-alice", "r-b"); len(routes) != 1 {
		t.Errorf("routes to b = %v, want exactly one", routes)
	}
}

// "Effective" says the claim is resolved; it does not say what a reviewer
// would have to revoke. A grant reached by group membership and one reached
// through a composite role are different actions.
func TestEveryGrantSaysHowItIsExpressed(t *testing.T) {
	out := collectRealm(t)
	want := map[string]string{
		// alice holds admin directly, and read through admin's composite.
		"r-admin": "user_role_mapping",
		"r-read":  "composite_role",
		// engineer comes from the group her subgroup sits under.
		"r-eng": "group_membership",
	}
	got := map[string]string{}
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_HOLDS ||
			edge.GetFrom().GetId() != "u-alice" {
			continue
		}
		got[edge.GetTo().GetId()] = edge.GetSourceType()
	}
	for id, expected := range want {
		if got[id] != expected {
			t.Errorf("%s granted as %q, want %q", id, got[id], expected)
		}
	}
	for id, how := range got {
		if how == "" {
			t.Errorf("the grant of %s does not say how it is expressed", id)
		}
	}
}

// A realm or a client that is switched off does not confer live access, and
// a reviewer reading the inventory has no other way to tell.
func TestWhetherAThingIsEnabledSurvivesIntoTheInventory(t *testing.T) {
	src := realm()
	src.clients[0].Enabled = false
	nodes := collectWith(t, src, admin.Realm{Realm: "probe", Enabled: dead()}).nodes()

	if got := nodes["probe"].GetContext()["enabled"]; got != "false" {
		t.Errorf("the realm's enabled state = %q, want false", got)
	}
	if got := nodes["c-app"].GetContext()["enabled"]; got != "false" {
		t.Errorf("the client's enabled state = %q, want false", got)
	}
}

// Two runs of the same collection emit the same records in the same order, or
// every snapshot diff is churn rather than change.
func TestTheEmissionOrderIsTheSameEveryRun(t *testing.T) {
	var first []string
	for range 8 {
		var got []string
		for _, e := range collectRealm(t).events {
			if edge := e.GetEdge(); edge != nil {
				got = append(got, edge.GetFrom().GetId()+">"+edge.GetTo().GetId())
			}
		}
		if first == nil {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run lengths differ: %d then %d", len(first), len(got))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("edge %d differs between runs: %s then %s", i, first[i], got[i])
			}
		}
	}
}
