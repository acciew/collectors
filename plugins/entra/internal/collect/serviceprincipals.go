package collect

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// App role entitlements are keyed by the application and the role together:
//
//	app-role:<servicePrincipalId>:<appRoleId>
//
// A role id is only unique within its application, and the all-zeros id is the
// "default access" that every application without roles of its own has.
const defaultAccess = "00000000-0000-0000-0000-000000000000"

// servicePrincipals writes the applications and the roles they list. Who holds
// the roles is read by a part of its own, after the groups, because a role is
// held by groups, and an edge may only name a group that has been written.
func (st *state) servicePrincipals(ctx context.Context) error {
	err := walk(ctx, st, func(sps []graph.ServicePrincipal) error {
		for _, sp := range sps {
			st.note("service_principals", sp.ID)
			if st.wants.ServicePrincipals {
				if err := st.emitServicePrincipal(sp); err != nil {
					return err
				}
			}
			if st.wants.AppRoles {
				if err := st.emitAppRoles(sp); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return needs(err, "Application.Read.All", "list the service principals")
}

// appRoleAssignments reads who holds the roles of each application. Each is
// read from the service principals listed again, with the roles they list.
func (st *state) appRoleAssignments(ctx context.Context) error {
	if st.failed["service_principals"] {
		return st.skipFor("app_role_assignments", "service_principals", "assignments")
	}
	err := walk(ctx, st, func(sps []graph.ServicePrincipal) error {
		for _, sp := range sps {
			if err := st.emitAssignmentsOf(ctx, sp); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		err = st.reportNested()
	}
	return needs(err, "Application.Read.All", "list who is assigned the app roles")
}

func (st *state) emitAssignmentsOf(ctx context.Context, sp graph.ServicePrincipal) error {
	app := collector.ResourceKey(st.tenant, sp.ID)
	// The application and its roles belong to the service principals part. One
	// made since it ran is named here, with the roles it lists.
	ok, referenced, err := st.named("service_principals", app, spName(sp), "application")
	if err != nil || !ok {
		return err
	}
	if referenced {
		if err := st.emitListedRoles(sp, app); err != nil {
			return err
		}
	}
	listed := map[string]graph.AppRole{}
	for _, r := range sp.AppRoles {
		listed[r.ID] = r
	}
	var inside error
	err = pages(ctx, st, graph.AppRoleAssignedToPath(sp.ID), func(as []graph.AppRoleAssignment) error {
		for _, a := range as {
			if inside = st.emitAppRoleAssignment(ctx, sp, app, a, listed); inside != nil {
				return inside
			}
		}
		return nil
	})
	// Listed, then deleted before its assignments were read: no one holds its
	// roles, and the others are still read. An error from the assignments being
	// written is not this.
	var ge *graph.Error
	if err != nil && inside == nil && errors.As(err, &ge) && ge.Kind == graph.KindNotFound {
		return st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.application.gone",
			fmt.Sprintf("application %q was deleted between listing it and reading who holds its roles, so no one holds "+
				"them here", spName(sp)))
	}
	return err
}

func spName(sp graph.ServicePrincipal) string {
	if sp.DisplayName != "" {
		return sp.DisplayName
	}
	return sp.ID
}

// emitServicePrincipal writes an application or a managed identity as an
// identity.
func (st *state) emitServicePrincipal(sp graph.ServicePrincipal) error {
	kind, sourceType := collector.UnknownKind, "service_principal"
	switch sp.ServicePrincipalType {
	case "Application":
		kind = collector.ServiceKind
	case "ManagedIdentity":
		kind, sourceType = collector.MachineKind, "managed_identity"
	}
	status := collector.UnknownStatus
	switch {
	case sp.AccountEnabled == nil:
	case *sp.AccountEnabled:
		status = collector.Active
	default:
		status = collector.Disabled
	}
	attrs := map[string]string{"app_id": sp.AppID, "service_principal_type": sp.ServicePrincipalType}
	setIf(attrs, "app_owner_organization_id", sp.AppOwnerOrganizationID)
	key := collector.IdentityKey(st.tenant, sp.ID)
	if err := st.out.Node(collector.WithContext(
		collector.Identity(key, spName(sp), sourceType, kind, status), attrs)); err != nil {
		return err
	}
	return st.emitUnreadSPActivity(key)
}

// emitAppRoles writes an application as a resource, and the roles it lists as
// entitlements that apply to it.
func (st *state) emitAppRoles(sp graph.ServicePrincipal) error {
	app := collector.ResourceKey(st.tenant, sp.ID)
	attrs := map[string]string{"app_id": sp.AppID}
	if sp.AppRoleAssignmentRequired != nil {
		attrs["assignment_required"] = strconv.FormatBool(*sp.AppRoleAssignmentRequired)
	}
	if err := st.out.Node(collector.WithContext(collector.Resource(app, spName(sp), "application"), attrs)); err != nil {
		return err
	}
	return st.emitListedRoles(sp, app)
}

// emitListedRoles writes the roles an application lists.
func (st *state) emitListedRoles(sp graph.ServicePrincipal, app *collectorv1.Key) error {
	for _, r := range sp.AppRoles {
		if err := st.emitListedRole(sp, app, r); err != nil {
			return err
		}
	}
	return nil
}

// emitListedRole writes one role an application lists, once in the stream.
func (st *state) emitListedRole(sp graph.ServicePrincipal, app *collectorv1.Key, r graph.AppRole) error {
	return st.emitAppRole(sp, app, r.ID, r.DisplayName, map[string]string{
		"value":        r.Value,
		"enabled":      strconv.FormatBool(r.IsEnabled),
		"member_types": strings.Join(r.AllowedMemberTypes, ","),
	})
}

// emitAppRole writes one role of an application, once.
func (st *state) emitAppRole(sp graph.ServicePrincipal, app *collectorv1.Key, id, name string, attrs map[string]string) error {
	key := collector.EntitlementKey(st.tenant, "app-role:"+sp.ID+":"+id)
	if !st.once(key) {
		return nil
	}
	if name == "" {
		name = id
	}
	attrs["app_role_id"] = id
	attrs["application"] = spName(sp)
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	if err := st.out.Node(collector.WithContext(
		collector.Entitlement(key, name+" ("+spName(sp)+")", "app_role"), attrs)); err != nil {
		return err
	}
	return st.out.Edge(collector.AppliesTo(key, app))
}

func (st *state) emitAppRoleAssignment(ctx context.Context, sp graph.ServicePrincipal, app *collectorv1.Key, a graph.AppRoleAssignment, listed map[string]graph.AppRole) error {
	// A role the application lists is written once, with the application if the
	// applications part saw it and here if it did not: a role added since that
	// part ran, and assigned. One it does not list is either the default access
	// every application has, or one that has been deleted since it was assigned.
	// Either way it is held, and it is named by what is known.
	switch r, isListed := listed[a.AppRoleID]; {
	case isListed:
		if err := st.emitListedRole(sp, app, r); err != nil {
			return err
		}
	case a.AppRoleID == defaultAccess:
		if err := st.emitAppRole(sp, app, defaultAccess, "Default access", map[string]string{}); err != nil {
			return err
		}
	default:
		if err := st.emitAppRole(sp, app, a.AppRoleID, "", map[string]string{"note": "not among the roles the application lists"}); err != nil {
			return err
		}
	}
	role := collector.EntitlementKey(st.tenant, "app-role:"+sp.ID+":"+a.AppRoleID)

	switch a.PrincipalType {
	case "User":
		user, ok, err := st.holder(graph.DirectoryObject{
			Type: "#microsoft.graph.user", ID: a.PrincipalID, DisplayName: a.PrincipalDisplayName,
		})
		if err != nil || !ok {
			return err
		}
		return st.sendOnce(collector.HowGranted(collector.Holds(user, role, collector.Direct), "app_role_assignment"))
	case "ServicePrincipal":
		holder, ok, err := st.holder(graph.DirectoryObject{
			Type: "#microsoft.graph.servicePrincipal", ID: a.PrincipalID, DisplayName: a.PrincipalDisplayName,
		})
		if err != nil || !ok {
			return err
		}
		return st.sendOnce(collector.HowGranted(collector.Holds(holder, role, collector.Direct), "app_role_assignment"))
	case "Group":
		return st.emitGroupAppRole(ctx, a, role)
	}
	st.skipped[a.PrincipalType]++
	return nil
}

// emitGroupAppRole writes an app role held by a group: the group holds it as
// the source states, and each direct member holds it through the group.
//
// Direct members only. Microsoft says the direct members of a group are
// assigned the roles the group is, and says nothing of the members of a group
// inside it, so those are not claimed.
func (st *state) emitGroupAppRole(ctx context.Context, a graph.AppRoleAssignment, role *collectorv1.Key) error {
	group, ok, err := st.groupHolder(a.PrincipalID)
	if err != nil || !ok {
		return err
	}
	if err := st.sendOnce(collector.HowGranted(
		collector.Holds(group, role, collector.Direct), "app_role_assignment")); err != nil {
		return err
	}
	err = st.groupMembers(ctx, a.PrincipalID, a.PrincipalID, func() (bool, string, error) { return st.hiddenGroup(ctx, a.PrincipalID) },
		func(m graph.DirectoryObject) error {
			switch m.Kind() {
			case "user", "servicePrincipal":
				subject, ok, err := st.holder(m)
				if err != nil || !ok {
					return err
				}
				return st.sendOnce(collector.HowGranted(collector.Holds(
					subject, role, collector.Effective, collector.Via(group)...), "group_app_role_assignment"))
			case "group":
				st.nested++
			}
			return nil
		})
	return needs(err, "Group.Read.All", "read the members of a group that holds an app role")
}

// reportNested says that groups inside groups holding an app role were not
// expanded.
func (st *state) reportNested() error {
	if st.nested == 0 {
		return nil
	}
	return st.out.Diagnostic(collectorv1.Severity_SEVERITY_INFO, "entra.app-roles.nested-not-expanded",
		fmt.Sprintf("%d group(s) inside a group that holds an app role were not expanded: Microsoft states "+
			"that the direct members of a group are assigned its roles and does not state that members of "+
			"a nested group are, so none are claimed", st.nested))
}
