package graph

import (
	"net/url"
	"strconv"
)

// Each function here names one read: the path, and exactly the properties
// asked for. Graph returns a resource's default properties unless $select says
// otherwise, and the defaults leave out most of what a review needs.

// DefaultPageSize is the largest page Graph returns for users and groups.
const DefaultPageSize = 999

// ServicePrincipalPageSize is the largest page Graph returns for service
// principals, which is a tenth of what users get.
const ServicePrincipalPageSize = 100

// SignInActivityPageSize is the largest page Graph returns when
// signInActivity is selected.
const SignInActivityPageSize = 500

func query(path string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	// Graph's own examples write $select and $top unescaped; the encoded form
	// is the same request.
	return path + "?" + q.Encode()
}

func top(size, limit int) string {
	if size <= 0 || size > limit {
		size = limit
	}
	return strconv.Itoa(size)
}

// OrganizationPath reads the tenant's own record.
func OrganizationPath() string {
	return query("/organization", "$select", "id,displayName,createdDateTime")
}

// UsersPath lists users, with sign-in activity when asked for. Activity caps
// the page size, which is why it is a choice and not always on.
func UsersPath(pageSize int, withActivity bool) string {
	sel := "id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSecurityIdentifier"
	limit := DefaultPageSize
	if withActivity {
		sel += ",signInActivity"
		limit = SignInActivityPageSize
	}
	return query("/users", "$select", sel, "$top", top(pageSize, limit))
}

// GroupsPath lists groups.
func GroupsPath(pageSize int) string {
	return query("/groups",
		"$select", "id,displayName,groupTypes,membershipRule,membershipRuleProcessingState,"+
			"isAssignableToRole,visibility,onPremisesSyncEnabled,onPremisesSecurityIdentifier",
		"$top", top(pageSize, DefaultPageSize))
}

// GroupRefsPath lists the groups again for the part that reads their members,
// which needs no more of each than its id, its name and whether its members are
// hidden.
func GroupRefsPath(pageSize int) string {
	return query("/groups", "$select", "id,displayName,visibility", "$top", top(pageSize, DefaultPageSize))
}

// MembersPath lists a group's direct members. Never transitiveMembers: that is
// a flat list with no path, so nothing could say through what a member got
// where they are.
func MembersPath(groupID string, pageSize int) string {
	return query("/groups/"+url.PathEscape(groupID)+"/members",
		"$select", "id,displayName", "$top", top(pageSize, DefaultPageSize))
}

// RoleDefinitionsPath lists directory roles, custom ones included.
func RoleDefinitionsPath() string {
	return query("/roleManagement/directory/roleDefinitions",
		"$select", "id,displayName,description,isBuiltIn,isEnabled")
}

// RoleAssignmentsPath lists directory role assignments with their principals,
// whose type is what says whether a principal is a person, a group or an
// application.
func RoleAssignmentsPath() string {
	return query("/roleManagement/directory/roleAssignments", "$expand", "principal")
}

// ActivityProbePath asks for one user's signInActivity and nothing else: it is
// the cheapest question whose answer says whether the tenant will give it.
func ActivityProbePath() string {
	return query("/users", "$select", "id,signInActivity", "$top", "1")
}

// ObjectPath reads one object by id, for the question "may this application
// read objects of this type". kind is a directory object type: user, group or
// servicePrincipal.
func ObjectPath(kind, id string) (string, bool) {
	collection, ok := map[string]string{
		"user": "/users/", "group": "/groups/", "servicePrincipal": "/servicePrincipals/",
	}[kind]
	if !ok {
		return "", false
	}
	return query(collection+url.PathEscape(id), "$select", "id,displayName"), true
}

// ProbePath reads one item of a collection, for a check that asks whether a
// read is allowed and not what it returns.
func ProbePath(path string) string { return query(path, "$top", "1") }

// ServicePrincipalsPath lists service principals, with the roles each exposes.
func ServicePrincipalsPath(pageSize int) string {
	return query("/servicePrincipals",
		"$select", "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,"+
			"appRoleAssignmentRequired,appRoles",
		"$top", top(pageSize, ServicePrincipalPageSize))
}

// AppRoleHoldersPath lists the service principals again for the part that reads
// who is assigned their roles: each with the roles it lists, so that a role it
// lists is told from one that is assigned and not listed.
func AppRoleHoldersPath(pageSize int) string {
	return query("/servicePrincipals", "$select", "id,displayName,appRoles",
		"$top", top(pageSize, ServicePrincipalPageSize))
}

// AppRoleAssignedToPath lists who holds which of an application's roles: the
// users, groups and other service principals assigned to it.
func AppRoleAssignedToPath(servicePrincipalID string) string {
	return "/servicePrincipals/" + url.PathEscape(servicePrincipalID) + "/appRoleAssignedTo"
}

// EligibilityInstancesPath lists what principals are eligible for, as it
// stands: the roles they could activate.
func EligibilityInstancesPath() string {
	return query("/roleManagement/directory/roleEligibilityScheduleInstances", "$expand", "principal")
}

// AssignmentInstancesPath lists the role assignments that are active now,
// whether made directly or through PIM.
func AssignmentInstancesPath() string {
	return query("/roleManagement/directory/roleAssignmentScheduleInstances", "$expand", "principal")
}

// AdministrativeUnitsPath lists administrative units.
func AdministrativeUnitsPath() string {
	return query("/directory/administrativeUnits", "$select", "id,displayName,description,visibility")
}

// OAuth2PermissionGrantsPath lists delegated permission grants.
func OAuth2PermissionGrantsPath() string { return "/oauth2PermissionGrants" }

// NamePath reads the display name of a service principal.
func NamePath(servicePrincipalID string) string {
	return query("/servicePrincipals/"+url.PathEscape(servicePrincipalID), "$select", "id,displayName")
}

// GroupVisibilityPath reads a group's name and whether its membership is
// hidden.
func GroupVisibilityPath(groupID string) string {
	return query("/groups/"+url.PathEscape(groupID), "$select", "id,displayName,visibility")
}
