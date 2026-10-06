// Package collect turns a Keycloak realm into the contract's vocabulary.
//
// The work that matters here is resolution: who effectively holds what, and
// by which route. Keycloak will tell you the answer — one call to the
// composite endpoint returns a user's realm roles with composites, group
// ancestry and realm defaults already applied — but it will not tell you the
// route, and the route is what a reviewer needs. "Alice has admin" is not a
// decision anyone can make; "Alice has admin because she is in Platform,
// which is under Engineering, which holds it" is.
//
// So the collector resolves the graph itself and uses Keycloak's answer as a
// check on its own. See docs/design/three-source-mapping.md, R3.
package collect

import "sort"

// realmGraph is a realm's structure, as collected, before any resolution.
//
// Plain data with no Keycloak types in it, so that the resolution below can
// be tested against a fixture rather than a container. Resolution bugs are
// the expensive kind: they produce a grant that looks right and is not.
type realmGraph struct {
	// group id -> its parent's id. A root group is absent.
	groupParent map[string]string
	// group id -> roles mapped onto that group.
	groupRoles map[string][]string
	// user id -> the groups they are a DIRECT member of.
	userGroups map[string][]string
	// user id -> roles mapped directly onto them.
	userRoles map[string][]string
	// role id -> the roles it contains, one level down.
	roleComposites map[string][]string
	// every principal collected, in the order they were collected, with
	// whether they are a service account.
	people []principal
}

func newRealmGraph() *realmGraph {
	return &realmGraph{
		groupParent:    map[string]string{},
		groupRoles:     map[string][]string{},
		userGroups:     map[string][]string{},
		userRoles:      map[string][]string{},
		roleComposites: map[string][]string{},
	}
}

// grant is one effective holding and the route to it.
type grant struct {
	// roleID the user effectively holds.
	roleID string
	// via is the route from the user to the role, exclusive of both ends.
	// Each entry is a node this collector also emitted as a direct edge, so
	// the path is a walk over facts Keycloak stated.
	via []step
	// direct is true when Keycloak states this grant on the user itself, in
	// which case via is empty.
	direct bool
}

// step is one hop in a route: a group the user inherits through, or a
// composite role that contains the next one.
type step struct {
	id      string
	isGroup bool
}

// effectiveGrants resolves everything a user holds, with the route to each.
//
// Two sources of inheritance, and they compose: a user is in a group, groups
// nest upwards, and any role reached that way may itself be a composite that
// contains more. A grant is reported once per distinct route, because
// revoking one route does not remove the others and a reviewer deciding what
// to revoke needs to see that.
func (g *realmGraph) effectiveGrants(userID string) []grant {
	var out []grant
	seen := map[string]bool{}

	add := func(gr grant) {
		key := gr.roleID + "|" + routeKey(gr.via)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, gr)
	}

	// Directly mapped roles, and whatever they contain.
	for _, roleID := range g.userRoles[userID] {
		add(grant{roleID: roleID, direct: true})
		for _, reached := range g.composedFrom(roleID, nil) {
			add(grant{roleID: reached.roleID, via: reached.via})
		}
	}

	// Roles reached through group membership. The group chain is walked
	// upwards because a role mapped on an ancestor is held by members of its
	// descendants -- which is the rule a collector that trusts
	// GET /groups/{id}/members gets wrong, since that endpoint is direct only.
	for _, groupID := range g.userGroups[userID] {
		chain := []step{}
		for id := groupID; id != ""; id = g.groupParent[id] {
			chain = append(chain, step{id: id, isGroup: true})
			for _, roleID := range g.groupRoles[id] {
				route := append([]step(nil), chain...)
				add(grant{roleID: roleID, via: route})
				for _, reached := range g.composedFrom(roleID, route) {
					add(grant{roleID: reached.roleID, via: reached.via})
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].roleID != out[j].roleID {
			return out[i].roleID < out[j].roleID
		}
		return routeKey(out[i].via) < routeKey(out[j].via)
	})
	return out
}

// composedFrom walks a composite role's contents transitively, carrying the
// route. A cycle is possible in Keycloak and is not an error here: it just
// stops, having already reported everything reachable.
//
// A member already on the route is skipped rather than merely not descended
// into. Emitting it would manufacture a grant "a via a > b" for a role the
// subject reaches at the start of that very route: a second, phantom way to
// hold something, which is exactly the claim a reviewer would act on by
// revoking the wrong thing.
func (g *realmGraph) composedFrom(roleID string, prefix []step) []grant {
	var out []grant
	var walk func(id string, route []step, visiting map[string]bool)

	walk = func(id string, route []step, visiting map[string]bool) {
		visiting[id] = true
		defer delete(visiting, id)

		for _, member := range g.roleComposites[id] {
			if visiting[member] {
				continue
			}
			next := append(append([]step(nil), route...), step{id: id})
			out = append(out, grant{roleID: member, via: next})
			walk(member, next, visiting)
		}
	}
	walk(roleID, prefix, map[string]bool{})
	return out
}

func routeKey(via []step) string {
	out := ""
	for _, s := range via {
		out += s.id + ">"
	}
	return out
}
