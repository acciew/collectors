package collect

import (
	"context"
	"errors"
	"strconv"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Entitlement ids for directory roles are composed, and the grammar is part of
// what a snapshot history keys on:
//
//	role:<roleDefinitionId>[:au:<unitId> | :scope:<directoryPath>][:eligible | :active]
//
//	role:<id>                  the role, held, over the whole tenant
//	role:<id>:au:<unit>        the role, held, over one administrative unit
//	role:<id>:scope:<path>     the role, held, over any other directory scope
//	role:<id>[...]:eligible    the role, eligible for through PIM and not held
//	role:<id>[...]:active      the role, held for a limited time through PIM
//
// Each (role, scope, state) is its own entitlement. The same role over the
// whole tenant and over one unit are not the same thing to hold, and an
// eligibility is not a grant: edge identity is type, ends and path, so
// eligible and held to one entitlement would be one edge, and the history
// would merge who can become an administrator with who is one.

// variant is the state in which a role is held.
type variant struct {
	// idSuffix and nameSuffix extend the entitlement's id and name.
	idSuffix, nameSuffix string
	// how and groupHow are the source's words for a grant made to the principal
	// and one made to a group the principal is in.
	how, groupHow string
}

var (
	held = variant{
		how: "directory_role_assignment", groupHow: "role_assignable_group",
	}
	eligible = variant{
		idSuffix: ":eligible", nameSuffix: " (eligible)",
		how: "pim_eligible_assignment", groupHow: "pim_eligible_group",
	}
	active = variant{
		idSuffix: ":active", nameSuffix: " (active, time-bound)",
		how: "pim_active_assignment", groupHow: "pim_active_group",
	}
)

// dirScope is where a directory role assignment applies.
type dirScope struct {
	kind string // "tenant", "au" or "other"
	id   string // the unit id, or the directory path
}

// parseScope reads directoryScopeId: "/" is the whole tenant, and
// "/administrativeUnits/<id>" is one unit.
func parseScope(s string) dirScope {
	switch {
	case s == "" || s == "/":
		return dirScope{kind: "tenant"}
	case strings.HasPrefix(s, "/administrativeUnits/"):
		return dirScope{kind: "au", id: strings.TrimPrefix(s, "/administrativeUnits/")}
	}
	return dirScope{kind: "other", id: strings.TrimPrefix(s, "/")}
}

// idSuffix is the scope's part of an entitlement id.
func (d dirScope) idSuffix() string {
	switch d.kind {
	case "au":
		return ":au:" + d.id
	case "other":
		return ":scope:" + d.id
	}
	return ""
}

// resourceID is the id of the resource node a scoped role applies to.
func (d dirScope) resourceID() string {
	if d.kind == "au" {
		return "au:" + d.id
	}
	return "scope:" + d.id
}

func (st *state) roleDefinitions(ctx context.Context) error {
	err := walk(ctx, st, func(ds []graph.RoleDefinition) error {
		for _, d := range ds {
			key := collector.EntitlementKey(st.tenant, "role:"+d.ID)
			if err := st.emitRole(key, d, dirScope{kind: "tenant"}, held); err != nil {
				return err
			}
		}
		return nil
	})
	return needs(err, "RoleManagement.Read.Directory", "list the directory roles")
}

// roleDefs reads the role definitions once. The assignments need their names, and
// the parts that read them are not the one that wrote them.
func (st *state) roleDefs(ctx context.Context) (map[string]graph.RoleDefinition, error) {
	if st.roles != nil {
		return st.roles, nil
	}
	defs := map[string]graph.RoleDefinition{}
	err := pages(ctx, st, graph.RoleDefinitionsPath(), func(ds []graph.RoleDefinition) error {
		for _, d := range ds {
			defs[d.ID] = d
		}
		return nil
	})
	if err != nil {
		return nil, needs(err, "RoleManagement.Read.Directory", "list the directory roles")
	}
	st.roles = defs
	return defs, nil
}

// emitRole writes a directory role as an entitlement over a scope, once.
func (st *state) emitRole(key *collectorv1.Key, d graph.RoleDefinition, sc dirScope, v variant) error {
	if !st.once(key) {
		return nil
	}
	name := d.DisplayName
	if name == "" {
		name = d.ID
	}
	if sc.kind != "tenant" {
		name += " (over " + sc.describe() + ")"
	}
	name += v.nameSuffix
	attrs := map[string]string{
		"role_definition_id": d.ID,
		"built_in":           strconv.FormatBool(d.IsBuiltIn),
		"enabled":            strconv.FormatBool(d.IsEnabled),
	}
	if sc.kind != "tenant" {
		attrs["directory_scope"] = sc.id
	}
	if v != held {
		attrs["state"] = strings.TrimPrefix(v.idSuffix, ":")
	}
	if err := st.out.Node(collector.WithContext(collector.Entitlement(key, name, "directory_role"), attrs)); err != nil {
		return err
	}
	if sc.kind == "tenant" {
		return st.out.Edge(collector.AppliesTo(key, st.scope))
	}
	res := collector.ResourceKey(st.tenant, sc.resourceID())
	if sc.kind == "au" && st.wants.AdministrativeUnits {
		// A unit the administrative units part reads is emitted there, observed.
		ok, _, err := st.named("administrative_units", res, sc.describe(), "administrative_unit")
		if err != nil || !ok {
			return err
		}
	} else if st.once(res) {
		// Named by the assignment and never read: administrative units are
		// collected only on request, and what is known of this one is its id.
		kind := "administrative_unit"
		if sc.kind == "other" {
			kind = "directory_scope"
		}
		if err := st.out.Node(collector.Reference(res, sc.describe(), kind)); err != nil {
			return err
		}
	}
	return st.out.Edge(collector.AppliesTo(key, res))
}

func (d dirScope) describe() string {
	if d.kind == "au" {
		return "administrative unit " + d.id
	}
	return "directory scope /" + d.id
}

func (st *state) roleAssignments(ctx context.Context) error {
	defs, err := st.roleDefs(ctx)
	if err != nil {
		return err
	}
	err = walk(ctx, st, func(as []graph.RoleAssignment) error {
		for _, a := range as {
			if err := st.emitGrant(ctx, defs, held, grant{
				id: a.ID, principalID: a.PrincipalID, principal: a.Principal,
				roleDefinitionID: a.RoleDefinitionID, scope: a.DirectoryScopeID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return needs(err, "RoleManagement.Read.Directory", "list the directory role assignments")
}

// grant is a role a principal holds or may hold, however Graph said so.
type grant struct {
	id               string
	principalID      string
	principal        *graph.DirectoryObject
	roleDefinitionID string
	scope            string
}

func (st *state) emitGrant(ctx context.Context, defs map[string]graph.RoleDefinition, v variant, g grant) error {
	def, ok := defs[g.roleDefinitionID]
	if !ok {
		def = graph.RoleDefinition{ID: g.roleDefinitionID}
	}
	sc := parseScope(g.scope)
	key := collector.EntitlementKey(st.tenant, "role:"+def.ID+sc.idSuffix()+v.idSuffix)
	if err := st.emitRole(key, def, sc, v); err != nil {
		return err
	}

	// A principal that came back null is not a principal that is gone: the id
	// is known, and a privileged grant that disappears reads as revoked.
	if g.principal == nil {
		p, status, err := st.resolvePrincipal(ctx, g.principalID)
		switch {
		case err != nil:
			return err
		case status == principalGone:
			return st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.role-assignment.principal-gone",
				"a role assignment names principal "+g.principalID+", which no longer exists as a user, a group or a "+
					"service principal, so it holds nothing and was left out")
		case status == principalUnreadable:
			return nil // the tenant is not whole, and the problem says why
		}
		g.principal = p
	}
	switch g.principal.Kind() {
	case "user", "servicePrincipal":
		subject, ok, err := st.holder(*g.principal)
		if err != nil || !ok {
			return err
		}
		return st.sendOnce(collector.HowGranted(collector.Holds(subject, key, collector.Direct), v.how))
	case "group":
		return st.emitGroupGrant(ctx, v, g.principalID, key)
	}
	st.skipped[g.principal.Kind()]++
	return nil
}

type principalStatus int

const (
	principalFound principalStatus = iota
	principalGone
	principalUnreadable
)

type principalAnswer struct {
	obj    *graph.DirectoryObject
	status principalStatus
}

// resolvePrincipal finds what an id names, by asking for it as a user, a group
// and a service principal in turn, with the permissions the collector already
// holds. Gone means every one of them said it does not exist. Unreadable means
// one was refused, and that is a reason the tenant is not whole.
func (st *state) resolvePrincipal(ctx context.Context, id string) (*graph.DirectoryObject, principalStatus, error) {
	if a, ok := st.principals[id]; ok {
		return a.obj, a.status, nil
	}
	for _, kind := range []string{"user", "group", "servicePrincipal"} {
		path, _ := graph.ObjectPath(kind, id)
		var obj graph.DirectoryObject
		err := st.retrying(ctx, func() error {
			var err error
			obj, err = graph.Get[graph.DirectoryObject](ctx, st.Graph, path)
			return err
		})
		var ge *graph.Error
		switch {
		case err == nil:
			obj.Type, obj.ID = odataType(kind), id
			a := principalAnswer{obj: &obj, status: principalFound}
			st.principals[id] = a
			return a.obj, a.status, nil
		case errors.As(err, &ge) && ge.Kind == graph.KindNotFound:
			continue
		case errors.As(err, &ge) && ge.Kind == graph.KindPermission:
			st.problem("principal:"+kind, refused("grant the application permission %s (admin consent) to read %s "+
				"objects: a role assignment names a principal that came back with no object, and reading it was refused",
				permissionToRead[kind], kind))
			st.principals[id] = principalAnswer{status: principalUnreadable}
			return nil, principalUnreadable, nil
		}
		return nil, principalUnreadable, err
	}
	st.principals[id] = principalAnswer{status: principalGone}
	return nil, principalGone, nil
}

func odataType(kind string) string { return "#microsoft.graph." + kind }

// emitGroupGrant writes a role held by a group: the group holds it as the
// source states, and each direct member holds it effectively, through the
// group.
//
// One hop, and exact. A group can hold a directory role only if it is
// role-assignable, and a role-assignable group cannot be dynamic and cannot
// nest, so its direct members are everyone who holds the role through it.
func (st *state) emitGroupGrant(ctx context.Context, v variant, groupID string, role *collectorv1.Key) error {
	group, ok, err := st.groupHolder(groupID)
	if err != nil || !ok {
		return err
	}
	if err := st.sendOnce(collector.HowGranted(collector.Holds(group, role, collector.Direct), v.how)); err != nil {
		return err
	}
	err = st.groupMembers(ctx, groupID, groupID, func() (bool, string, error) { return st.hiddenGroup(ctx, groupID) },
		func(m graph.DirectoryObject) error {
			if m.Kind() != "user" && m.Kind() != "servicePrincipal" {
				return nil
			}
			subject, ok, err := st.holder(m)
			if err != nil || !ok {
				return err
			}
			return st.sendOnce(collector.HowGranted(collector.Holds(
				subject, role, collector.Effective, collector.Via(group)...), v.groupHow))
		})
	return needs(err, "Group.Read.All", "read the members of a group that holds a role")
}

// groupHolder is the key of a group an edge names, and false if the groups part
// failed and the edge is to be left out.
func (st *state) groupHolder(id string) (*collectorv1.Key, bool, error) {
	key := collector.GroupingKey(st.tenant, id)
	ok, _, err := st.named("groups", key, "", "group")
	return key, ok, err
}

// hiddenGroup says whether a group's membership is hidden, by reading the
// group. A group that cannot be read is not known to be; a throttle that will
// not end is the stream's to stop at, not a group that is not hidden.
func (st *state) hiddenGroup(ctx context.Context, groupID string) (bool, string, error) {
	var g graph.Group
	err := st.retrying(ctx, func() error {
		var err error
		g, err = graph.Get[graph.Group](ctx, st.Graph, graph.GroupVisibilityPath(groupID))
		return err
	})
	var halt *stopError
	if errors.As(err, &halt) {
		return false, "", err
	}
	if err != nil {
		return false, "", nil
	}
	name := g.DisplayName
	if name == "" {
		name = groupID
	}
	return g.Visibility == hiddenMembership, name, nil
}

// What is held in memory of the members of the groups read in a stream, so a
// group is read once whichever parts need it: no more than this many for one
// group, and this many all told. A group past either is read again each time it
// is needed, page by page, and never held.
var (
	maxCachedMembers = 10_000
	maxCachedTotal   = 100_000
)

// holder is the identity a role is held by, and false if the part that writes
// it failed and the edge is to be left out. A user was written by the users
// part, and an application by the service principals part if that is on; one it
// did not write, or all of them when it is off, is named here, as referenced:
// seen as the subject of a grant and not read.
func (st *state) holder(p graph.DirectoryObject) (*collectorv1.Key, bool, error) {
	key := collector.IdentityKey(st.tenant, p.ID)
	name := p.DisplayName
	if name == "" {
		name = p.ID
	}
	if p.Kind() != "servicePrincipal" {
		ok, _, err := st.named("users", key, name, "user")
		return key, ok, err
	}
	wrote := false
	if st.wants.ServicePrincipals {
		ok, referenced, err := st.named("service_principals", key, name, "service_principal")
		if err != nil || !ok {
			return key, ok, err
		}
		wrote = referenced
	} else if st.once(key) {
		if err := st.out.Node(collector.Reference(key, name, "service_principal")); err != nil {
			return nil, false, err
		}
		wrote = true
	}
	// Said when the node is written, which is once in the collection.
	if wrote {
		return key, true, st.emitUnreadSPActivity(key)
	}
	return key, true, nil
}
