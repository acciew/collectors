package collect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/sdk/go/collector"
)

// Source is what a realm collection reads. The admin client satisfies it;
// tests use a fake, which is what keeps the emission logic testable without a
// container.
type Source interface {
	Users(ctx context.Context, realm string) ([]admin.User, error)
	ServiceAccountUser(ctx context.Context, realm, clientUUID string) (*admin.User, error)
	TopLevelGroups(ctx context.Context, realm string) ([]admin.Group, error)
	Subgroups(ctx context.Context, realm, groupID string) ([]admin.Group, error)
	GroupMembers(ctx context.Context, realm, groupID string) ([]admin.User, error)
	GroupRoleMappings(ctx context.Context, realm, groupID string) (admin.MappingsRepresentation, error)
	RealmRoles(ctx context.Context, realm string) ([]admin.Role, error)
	Clients(ctx context.Context, realm string) ([]admin.ClientApp, error)
	ClientRoles(ctx context.Context, realm, clientUUID string) ([]admin.Role, error)
	RoleComposites(ctx context.Context, realm, roleID string) ([]admin.Role, error)
	UserRoleMappings(ctx context.Context, realm, userID string) (admin.MappingsRepresentation, error)
	EventsConfig(ctx context.Context, realm string) (admin.EventsConfig, error)
	Events(ctx context.Context, realm string, types []string, limit int) ([]admin.Event, error)
}

// Realm collects one realm into the stream.
//
// The order is not arbitrary. Nodes go before the edges that reference them,
// so a consumer reading the stream in order never sees a key it has not been
// told about; and the direct edges go before the derived ones, so every hop
// of a path has already been stated by the time the path claims it.
func Realm(ctx context.Context, src Source, r admin.Realm, now time.Time, out collector.Stream) (ActivityAvailable, error) {
	realm := r.Realm
	scope := collector.Scope(realm, realm)
	// A realm that did not say whether it is enabled is one this token
	// cannot read. Recording the absence as "disabled" would turn every live
	// grant in it into one a reviewer skips, which is the promise inverted.
	if r.Enabled == nil {
		return ActivityUndetermined, fmt.Errorf("realm %s did not say whether it is enabled, "+
			"which means this token cannot read the realm itself. Grant its service account "+
			"view-realm or manage-realm from the %s client", realm, managementClient(src, realm))
	}
	// Whether the realm is enabled decides whether any of the access below is
	// live. A disabled realm is still collected — an operator needs to see it
	// exists — but a reviewer must not read its grants as current.
	if err := out.Node(collector.WithContext(
		collector.ScopeNode(scope, realm, "realm"),
		map[string]string{"enabled": strconv.FormatBool(*r.Enabled)},
	)); err != nil {
		return ActivityUndetermined, err
	}

	g := newRealmGraph()
	roles := map[string]admin.Role{}

	clients, err := src.Clients(ctx, realm)
	err = needsRole(err, "view-clients", "list the clients")
	if err != nil {
		return ActivityUndetermined, err
	}
	if err := emitClientsAndTheirRoles(ctx, src, realm, clients, out, roles); err != nil {
		return ActivityUndetermined, err
	}
	if err := emitRealmRoles(ctx, src, r, out, g, roles); err != nil {
		return ActivityUndetermined, err
	}
	if err := emitUsers(ctx, src, realm, clients, out, g); err != nil {
		return ActivityUndetermined, err
	}
	if err := emitGroups(ctx, src, realm, out, g); err != nil {
		return ActivityUndetermined, err
	}
	if err := emitEffectiveGrants(realm, out, g); err != nil {
		return ActivityUndetermined, err
	}

	answer, err := activityFor(ctx, src, realm, now, g.people, out)
	if err != nil {
		return ActivityUndetermined, err
	}

	// Last, and after everything has been emitted, because what was found is
	// worth keeping either way. Keycloak narrows /users, /groups and /clients
	// to an empty or partial list for a token without the roles that read
	// them, rather than refusing — so nothing above can fail, and the scope
	// would be reported collected with a population that is not the realm's.
	//
	// The check makes this same call before anybody waits on a collection.
	// This is here because a scheduled run never calls the check, and a
	// promise kept only at the front door is not kept.
	// The activity answer was found out by now and stays true of the realm.
	if why := untrustedPopulation(src, realm); why != "" {
		return answer, errors.New(why)
	}
	return answer, nil
}

// untrustedPopulation is the doubt rule as the collection needs it: one
// sentence, or empty when there is nothing to doubt.
func untrustedPopulation(src Source, realm string) string {
	var unsure []subject
	unsure = append(unsure, subject{"user and group", readsUsers}, subject{"client", readsClients})
	found := doubt(src, realm, unsure)
	if len(found) == 0 {
		return ""
	}
	// Naming the client too, and only when a role was named: which client
	// holds these roles depends on where the collector authenticated, and an
	// answer nobody could corroborate is not fixed by granting anything. A
	// scheduled run that says less than the check did, or something the
	// check would not have said, is the same disagreement in a quieter form.
	remedy := ""
	if slices.ContainsFunc(found, func(s string) bool { return strings.HasPrefix(s, "view-") }) {
		remedy = ". Grant any role named here to the service account from the " +
			managementClient(src, realm) + " client"
	}
	return "this realm was read with a token that cannot see all of it, so what was collected " +
		"is not the realm: " + strings.Join(found, "; ") + remedy
}

// ActivityAvailable is what a realm can answer about last activity. It is
// reported once for the scope rather than once per person, which is what
// stops a realm with event storage off producing one identical "we cannot
// see" record per user.
//
// Three answers, not two: a realm that records nothing and a realm whose
// event log we were refused both yield no activity, but only the first is
// fixed by turning event storage on.
type ActivityAvailable int

const (
	// ActivityUnavailable: the realm records nothing we can answer from.
	ActivityUnavailable ActivityAvailable = iota
	// ActivityAvailableForScope: the realm answers for everyone in it.
	ActivityAvailableForScope
	// ActivityUndetermined: the read that would have told us was refused, or
	// the realm failed before it was asked.
	ActivityUndetermined
)

func emitClientsAndTheirRoles(ctx context.Context, src Source, realm string,
	clients []admin.ClientApp, out collector.Stream, roles map[string]admin.Role) error {
	for _, c := range clients {
		resource := collector.ResourceKey(realm, c.ID)
		name := c.ClientID
		if c.Name != "" {
			name = c.Name
		}
		if err := out.Node(collector.WithContext(
			collector.Resource(resource, name, "client"),
			map[string]string{
				"realm": realm, "client_id": c.ClientID,
				"enabled": strconv.FormatBool(c.Enabled),
			},
		)); err != nil {
			return err
		}

		clientRoles, err := src.ClientRoles(ctx, realm, c.ID)
		err = needsRole(err, "view-clients", "list a client's roles")
		if err != nil {
			return err
		}
		for _, r := range clientRoles {
			roles[r.ID] = r
			if err := out.Node(collector.WithContext(
				collector.Entitlement(collector.EntitlementKey(realm, r.ID), r.Name, "client_role"),
				map[string]string{
					"realm": realm, "client_id": c.ClientID, "role_type": "client",
				},
			)); err != nil {
				return err
			}
			// A client role means something only in relation to its client,
			// and a reviewer looking at "manage-account" needs to know which
			// application that is.
			if err := out.Edge(collector.AppliesTo(
				collector.EntitlementKey(realm, r.ID), resource)); err != nil {
				return err
			}
		}
	}
	return nil
}

func emitRealmRoles(ctx context.Context, src Source, r admin.Realm,
	out collector.Stream, g *realmGraph, roles map[string]admin.Role) error {
	realm := r.Realm
	realmRoles, err := src.RealmRoles(ctx, realm)
	err = needsRole(err, "view-realm", "list the realm roles")
	if err != nil {
		return err
	}
	for _, role := range realmRoles {
		roles[role.ID] = role
		ctxAttrs := map[string]string{"realm": realm, "role_type": "realm"}
		// Every user in every realm carries this one, and nobody decided to
		// grant it. Untagged it turns every review into four entitlements of
		// noise per person before the real ones start. Matched by the id the
		// realm gives us rather than by rebuilding the name: Keycloak
		// lowercases the realm in that name, so realm "Corp" has
		// "default-roles-corp", and the role can be renamed.
		if r.DefaultRole != nil && role.ID == r.DefaultRole.ID {
			// Source-agnostic: the core reads this one key to tell a grant
			// nobody chose to make from one somebody did, and it must not
			// have to know a Keycloak word to do it.
			ctxAttrs["default_grant"] = "true"
		}
		if err := out.Node(collector.WithContext(
			collector.Entitlement(collector.EntitlementKey(realm, role.ID), role.Name, "realm_role"),
			ctxAttrs,
		)); err != nil {
			return err
		}
	}

	// Composites last, so both ends of every INCLUDES edge already exist, and
	// over every role in the realm rather than only the realm roles. A client
	// role can be composite too — Keycloak's own account client ships one —
	// and walking only half of them shows a reviewer the container and never
	// its contents.
	return emitComposites(ctx, src, realm, out, g, roles)
}

func emitComposites(ctx context.Context, src Source, realm string,
	out collector.Stream, g *realmGraph, roles map[string]admin.Role) error {
	ids := make([]string, 0, len(roles))
	for id := range roles {
		ids = append(ids, id)
	}
	// Map iteration order is not an order, and the stream is read in order.
	sort.Strings(ids)

	for _, id := range ids {
		if !roles[id].Composite {
			continue
		}
		members, err := src.RoleComposites(ctx, realm, id)
		err = needsRole(err, "view-realm", "resolve a composite role")
		if err != nil {
			return err
		}
		for _, m := range members {
			g.roleComposites[id] = append(g.roleComposites[id], m.ID)
			if err := out.Edge(collector.Includes(
				collector.EntitlementKey(realm, id),
				collector.EntitlementKey(realm, m.ID))); err != nil {
				return err
			}
		}
	}
	return nil
}

func emitUsers(ctx context.Context, src Source, realm string, clients []admin.ClientApp,
	out collector.Stream, g *realmGraph) error {
	users, err := src.Users(ctx, realm)
	err = needsRole(err, "view-users", "list the users")
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := emitUser(ctx, src, realm, u, collector.Human, out, g, ""); err != nil {
			return err
		}
	}

	// Service accounts are principals too, and GET /users does not return
	// them. A collector that stops at the users endpoint misses every
	// non-human identity in the realm.
	for _, c := range clients {
		if !c.ServiceAccountsEnabled {
			continue
		}
		sa, err := src.ServiceAccountUser(ctx, realm, c.ID)
		err = needsRole(err, "view-clients", "read a client's service account")
		if err != nil {
			return err
		}
		if sa == nil {
			continue
		}
		// Keycloak does not populate serviceAccountClientId on either the
		// service-account-user endpoint or GET /users/{id}: both answer null.
		// We know which client we asked through, so we say so ourselves.
		if err := emitUser(ctx, src, realm, *sa, collector.ServiceKind, out, g, c.ClientID); err != nil {
			return err
		}
	}
	return nil
}

// emitUser emits one principal. serviceAccountOf names the client a service
// account belongs to, empty for a person.
func emitUser(ctx context.Context, src Source, realm string, u admin.User,
	kind collectorv1.IdentityKind, out collector.Stream, g *realmGraph,
	serviceAccountOf string) error {
	status := collector.Active
	if !u.Enabled {
		// A disabled principal that still holds grants is a review finding,
		// not a non-event, so it is collected rather than skipped.
		status = collector.Disabled
	}
	attrs := map[string]string{"realm": realm}
	if u.Email != "" {
		attrs["email"] = u.Email
	}
	if serviceAccountOf != "" {
		attrs["service_account_of"] = serviceAccountOf
	}
	sourceType := "user"
	if kind == collector.ServiceKind {
		sourceType = "service_account"
	}
	key := collector.IdentityKey(realm, u.ID)
	if err := out.Node(collector.WithContext(
		collector.Identity(key, u.Username, sourceType, kind, status), attrs)); err != nil {
		return err
	}
	g.people = append(g.people, principal{id: u.ID, service: kind == collector.ServiceKind})

	mappings, err := src.UserRoleMappings(ctx, realm, u.ID)
	err = needsRole(err, "view-users", "read a user's roles")
	if err != nil {
		return err
	}
	for _, r := range allMapped(mappings) {
		g.userRoles[u.ID] = append(g.userRoles[u.ID], r.ID)
		if err := out.Edge(collector.HowGranted(collector.Holds(
			key, collector.EntitlementKey(realm, r.ID), collector.Direct),
			"user_role_mapping")); err != nil {
			return err
		}
	}
	return nil
}

// allMapped flattens a mappings representation. Both halves matter: the
// endpoint carries client roles as well as realm roles, which is easy to miss
// if the user you test with happens to have none.
func allMapped(m admin.MappingsRepresentation) []admin.Role {
	out := append([]admin.Role(nil), m.RealmMappings...)
	for _, client := range m.ClientMappings {
		out = append(out, client.Mappings...)
	}
	return out
}

func emitGroups(ctx context.Context, src Source, realm string, out collector.Stream, g *realmGraph) error {
	top, err := src.TopLevelGroups(ctx, realm)
	err = needsRole(err, "view-users", "list the groups")
	if err != nil {
		return err
	}
	for _, root := range top {
		if err := walkGroup(ctx, src, realm, root, "", out, g); err != nil {
			return err
		}
	}
	return nil
}

// walkGroup descends the tree. The children need their own request: Keycloak
// returns an empty subGroups with a count beside it, so a collector that
// reads the response as a tree sees only the roots.
func walkGroup(ctx context.Context, src Source, realm string, grp admin.Group, parentID string,
	out collector.Stream, g *realmGraph) error {
	key := collector.GroupingKey(realm, grp.ID)
	if err := out.Node(collector.WithContext(
		collector.Grouping(key, grp.Name, "group"),
		map[string]string{"realm": realm, "path": grp.Path},
	)); err != nil {
		return err
	}
	if parentID != "" {
		g.groupParent[grp.ID] = parentID
		if err := out.Edge(collector.ChildOf(key, collector.GroupingKey(realm, parentID))); err != nil {
			return err
		}
	}

	mappings, err := src.GroupRoleMappings(ctx, realm, grp.ID)
	err = needsRole(err, "view-users", "read a group's roles")
	if err != nil {
		return err
	}
	for _, r := range allMapped(mappings) {
		g.groupRoles[grp.ID] = append(g.groupRoles[grp.ID], r.ID)
		if err := out.Edge(collector.HowGranted(collector.Holds(
			key, collector.EntitlementKey(realm, r.ID), collector.Direct),
			"group_role_mapping")); err != nil {
			return err
		}
	}

	// Direct members only. Everyone below inherits, and working that out is
	// this collector's job rather than Keycloak's.
	members, err := src.GroupMembers(ctx, realm, grp.ID)
	err = needsRole(err, "view-users", "list a group's members")
	if err != nil {
		return err
	}
	for _, m := range members {
		g.userGroups[m.ID] = append(g.userGroups[m.ID], grp.ID)
		if err := out.Edge(collector.MemberOf(collector.IdentityKey(realm, m.ID), key)); err != nil {
			return err
		}
	}

	if grp.SubGroupCount == 0 {
		return nil
	}
	children, err := src.Subgroups(ctx, realm, grp.ID)
	err = needsRole(err, "view-users", "list a group's subgroups")
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := walkGroup(ctx, src, realm, child, grp.ID, out, g); err != nil {
			return err
		}
	}
	return nil
}

// howReached names the kind of route a derived grant came by, so a reviewer
// reading "effective" can tell a group inheritance from a composite role
// without walking the path themselves.
func howReached(gr grant) string {
	groups, roles := false, false
	for _, s := range gr.via {
		if s.isGroup {
			groups = true
			continue
		}
		roles = true
	}
	switch {
	case groups && roles:
		return "group_membership_and_composite"
	case groups:
		return "group_membership"
	case roles:
		return "composite_role"
	}
	return "derived"
}

// emitEffectiveGrants is the point of the whole collection: what each person
// actually holds, and by which route.
func emitEffectiveGrants(realm string, out collector.Stream, g *realmGraph) error {
	// In the order the principals were collected, not the order two maps
	// happen to iterate. These are the collector's central output, and an
	// evidence product that diffs one collection against the next should see
	// changes rather than churn.
	for _, p := range g.people {
		if err := emitGrantsFor(realm, p.id, out, g); err != nil {
			return err
		}
	}
	return nil
}

func emitGrantsFor(realm, userID string, out collector.Stream, g *realmGraph) error {
	subject := collector.IdentityKey(realm, userID)
	for _, gr := range g.effectiveGrants(userID) {
		if gr.direct {
			// Already emitted as a stated fact when the user was collected.
			continue
		}
		via := make([]*collectorv1.Key, 0, len(gr.via))
		for _, s := range gr.via {
			if s.isGroup {
				via = append(via, collector.GroupingKey(realm, s.id))
				continue
			}
			via = append(via, collector.EntitlementKey(realm, s.id))
		}
		if err := out.Edge(collector.HowGranted(collector.Holds(
			subject, collector.EntitlementKey(realm, gr.roleID),
			collector.Effective, via...), howReached(gr))); err != nil {
			return fmt.Errorf("emitting an effective grant for %s: %w", userID, err)
		}
	}
	return nil
}

// needsRole names the role a refused read wants, so that a collection says
// what the check says about the same failure.
//
// A scheduled run is the only thing that runs the collection, and nobody is
// watching it. Handing it "permission denied: /realms/acme/users (HTTP 403)"
// where the check would have said "view-users (to list the users)" leaves
// whoever reads the log to map an endpoint onto a role themselves.
//
// Only a refusal. Everything else is not about a grant, and saying a role
// would send somebody to change a permission that was never the problem.
func needsRole(err error, role, what string) error {
	if err == nil || !denied(err) {
		return err
	}
	return fmt.Errorf("%s (to %s): %w", role, what, err)
}
