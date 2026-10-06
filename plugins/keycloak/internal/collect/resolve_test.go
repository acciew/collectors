package collect

import (
	"strings"
	"testing"
)

// The fixture is the shape the collector has to get right, and it is the
// shape a real realm takes: a person in a subgroup of a group that holds a
// role, a composite role that contains another, and a second person who holds
// something directly.
//
//	alice ──member──▶ platform ──child──▶ engineering ──holds──▶ r-eng
//	alice ──holds───▶ r-admin ──includes──▶ r-read ──includes──▶ r-audit
//	bob   ──holds───▶ r-read
func fixture() *realmGraph {
	g := newRealmGraph()
	g.groupParent["platform"] = "engineering"
	g.groupRoles["engineering"] = []string{"r-eng"}
	g.userGroups["alice"] = []string{"platform"}
	g.userRoles["alice"] = []string{"r-admin"}
	g.userRoles["bob"] = []string{"r-read"}
	g.roleComposites["r-admin"] = []string{"r-read"}
	g.roleComposites["r-read"] = []string{"r-audit"}
	return g
}

func routesFor(grants []grant, roleID string) []string {
	var out []string
	for _, gr := range grants {
		if gr.roleID != roleID {
			continue
		}
		var ids []string
		for _, s := range gr.via {
			ids = append(ids, s.id)
		}
		out = append(out, strings.Join(ids, ">"))
	}
	return out
}

func TestADirectGrantHasNoRoute(t *testing.T) {
	grants := fixture().effectiveGrants("alice")

	var found bool
	for _, gr := range grants {
		if gr.roleID == "r-admin" {
			found = true
			if !gr.direct {
				t.Error("a role mapped on the user is stated by Keycloak, not derived")
			}
			if len(gr.via) != 0 {
				t.Errorf("a stated fact has no route, got %v", routesFor(grants, "r-admin"))
			}
		}
	}
	if !found {
		t.Fatal("alice's directly mapped role is missing")
	}
}

// This is the rule a collector that trusts GET /groups/{id}/members gets
// wrong: alice is only in platform, and the role is mapped on its parent.
func TestARoleOnAnAncestorGroupIsInherited(t *testing.T) {
	grants := fixture().effectiveGrants("alice")

	routes := routesFor(grants, "r-eng")
	if len(routes) != 1 {
		t.Fatalf("r-eng routes = %v, want exactly one", routes)
	}
	// The route names every hop, so a reviewer can see that removing alice
	// from platform ends this and removing the role from engineering ends it
	// for everyone under engineering.
	if routes[0] != "platform>engineering" {
		t.Errorf("route = %q, want the full chain through the parent", routes[0])
	}
}

func TestCompositesAreWalkedTransitively(t *testing.T) {
	grants := fixture().effectiveGrants("alice")

	if got := routesFor(grants, "r-read"); len(got) != 1 || got[0] != "r-admin" {
		t.Errorf("r-read routes = %v, want one through r-admin", got)
	}
	// Two levels down: r-admin contains r-read contains r-audit.
	if got := routesFor(grants, "r-audit"); len(got) != 1 || got[0] != "r-admin>r-read" {
		t.Errorf("r-audit routes = %v, want the full composite chain", got)
	}
}

// A person can hold the same role by more than one route, and revoking one
// leaves the others standing. A model that collapses them tells a reviewer
// that removing a group membership ends access when it does not.
func TestTheSameRoleByTwoRoutesIsTwoGrants(t *testing.T) {
	g := fixture()
	// Now engineering also holds r-read, which alice already has through the
	// composite chain.
	g.groupRoles["engineering"] = append(g.groupRoles["engineering"], "r-read")

	routes := routesFor(g.effectiveGrants("alice"), "r-read")
	if len(routes) != 2 {
		t.Fatalf("r-read routes = %v, want two: one composite, one group", routes)
	}
	var viaComposite, viaGroup bool
	for _, r := range routes {
		switch r {
		case "r-admin":
			viaComposite = true
		case "platform>engineering":
			viaGroup = true
		}
	}
	if !viaComposite || !viaGroup {
		t.Errorf("routes = %v, want both routes reported", routes)
	}
}

// Inheritance composes: a role reached through a group may itself be a
// composite, and the route has to carry both halves.
func TestAGroupRoleThatIsCompositeCarriesBothHalvesOfTheRoute(t *testing.T) {
	g := fixture()
	g.roleComposites["r-eng"] = []string{"r-deploy"}

	routes := routesFor(g.effectiveGrants("alice"), "r-deploy")
	if len(routes) != 1 {
		t.Fatalf("r-deploy routes = %v, want one", routes)
	}
	if routes[0] != "platform>engineering>r-eng" {
		t.Errorf("route = %q, want the group chain then the composite", routes[0])
	}
}

// Keycloak permits a composite cycle. It must not hang the collector, and
// everything reachable should still be reported.
func TestACompositeCycleTerminates(t *testing.T) {
	g := newRealmGraph()
	g.userRoles["alice"] = []string{"a"}
	g.roleComposites["a"] = []string{"b"}
	g.roleComposites["b"] = []string{"c"}
	g.roleComposites["c"] = []string{"a"}

	done := make(chan []grant, 1)
	go func() { done <- g.effectiveGrants("alice") }()

	select {
	case grants := <-done:
		held := map[string]bool{}
		for _, gr := range grants {
			held[gr.roleID] = true
		}
		for _, want := range []string{"a", "b", "c"} {
			if !held[want] {
				t.Errorf("role %q was not reported", want)
			}
		}
	case <-timeoutAfterASecond():
		t.Fatal("a composite cycle hung the resolver")
	}
}

func TestAUserWithNothingHoldsNothing(t *testing.T) {
	if grants := fixture().effectiveGrants("nobody"); len(grants) != 0 {
		t.Errorf("got %v, want nothing", grants)
	}
}

func TestGrantsAreOrderedSoOutputIsStable(t *testing.T) {
	first := fixture().effectiveGrants("alice")
	second := fixture().effectiveGrants("alice")
	if len(first) != len(second) {
		t.Fatalf("%d vs %d grants", len(first), len(second))
	}
	for i := range first {
		if first[i].roleID != second[i].roleID || routeKey(first[i].via) != routeKey(second[i].via) {
			t.Fatalf("ordering is not stable at %d: %v vs %v", i, first[i], second[i])
		}
	}
}
