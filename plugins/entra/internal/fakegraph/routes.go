package fakegraph

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1.0")
	if path == r.URL.Path {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "Only v1.0 is served.")
		return
	}
	t := s.Tenant
	switch {
	case path == "/organization":
		s.organization(w, r)
	case path == "/users" || strings.HasPrefix(path, "/users/"):
		s.users(w, r, strings.TrimPrefix(strings.TrimPrefix(path, "/users"), "/"))
	case path == "/groups":
		s.page(w, r, t.groupItems(r))
	case strings.HasPrefix(path, "/groups/") && !strings.Contains(strings.TrimPrefix(path, "/groups/"), "/"):
		s.object(w, r, t.groupItems(r), strings.TrimPrefix(path, "/groups/"))
	case strings.HasPrefix(path, "/groups/") && strings.HasSuffix(path, "/members"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/groups/"), "/members")
		g := t.group(id)
		if g == nil {
			writeError(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource '"+id+"' does not exist.")
			return
		}
		s.page(w, r, g.memberItems(r))
	case path == "/servicePrincipals":
		s.page(w, r, t.servicePrincipalItems(r))
	case strings.HasPrefix(path, "/servicePrincipals/") && strings.HasSuffix(path, "/appRoleAssignedTo"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/servicePrincipals/"), "/appRoleAssignedTo")
		if t.servicePrincipal(id) == nil {
			writeError(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource '"+id+"' does not exist.")
			return
		}
		s.page(w, r, t.appRoleAssignmentItems(r, id))
	case strings.HasPrefix(path, "/servicePrincipals/") && !strings.Contains(strings.TrimPrefix(path, "/servicePrincipals/"), "/"):
		s.object(w, r, t.servicePrincipalItems(r), strings.TrimPrefix(path, "/servicePrincipals/"))
	case path == "/roleManagement/directory/roleDefinitions":
		s.page(w, r, t.roleDefItems(r))
	case path == "/directory/administrativeUnits":
		s.page(w, r, t.adminUnitItems(r))
	case path == "/oauth2PermissionGrants":
		s.page(w, r, t.oauth2Items(r))
	case path == "/roleManagement/directory/roleEligibilityScheduleInstances":
		s.page(w, r, scheduleItems(r, t.Eligible, false))
	case path == "/roleManagement/directory/roleAssignmentScheduleInstances":
		s.page(w, r, scheduleItems(r, t.ActiveInstances, true))
	case path == "/roleManagement/directory/roleAssignments":
		s.page(w, r, t.roleAssignmentItems(r))
	default:
		writeError(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource not found for the segment '"+path+"'.")
	}
}

// users serves the collection, or one user when an id is given.
func (s *Server) users(w http.ResponseWriter, r *http.Request, id string) {
	t := s.Tenant
	if ref := t.ActivityRefusal; ref != nil && strings.Contains(r.URL.Query().Get("$select"), "signInActivity") &&
		(!ref.ProbeOnly || r.URL.Query().Get("$top") == "1") {
		writeError(w, t.ActivityRefusal.Status, t.ActivityRefusal.Code, t.ActivityRefusal.Message)
		return
	}
	if id == "" {
		s.page(w, r, t.userItems(r))
		return
	}
	s.object(w, r, t.userItems(r), id)
}

// object serves one resource of a collection by id.
func (s *Server) object(w http.ResponseWriter, r *http.Request, items []map[string]any, id string) {
	for _, it := range items {
		if it["id"] == id {
			writeJSON(w, it)
			return
		}
	}
	writeError(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource '"+id+"' does not exist or one of its queried reference-property objects are not present.")
}

func (s *Server) organization(w http.ResponseWriter, r *http.Request) {
	t := s.Tenant
	if t.Name == "" {
		// A token that may not read the organisation is refused, not given an
		// empty one.
		writeError(w, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
		return
	}
	org := map[string]any{"id": t.ID, "displayName": t.Name, "createdDateTime": ts(t.Created)}
	writeJSON(w, map[string]any{"value": []map[string]any{selected(r, org, "displayName")}})
}

func (t *Tenant) group(id string) *Group {
	for i := range t.Groups {
		if t.Groups[i].ID == id {
			return &t.Groups[i]
		}
	}
	return nil
}

func (t *Tenant) userItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, u := range t.Users {
		all := map[string]any{
			"@odata.type": "#microsoft.graph.user", "id": u.ID, "displayName": u.DisplayName,
			"userPrincipalName": u.UPN, "mail": nilIfEmpty(u.Mail), "userType": nilIfEmpty(u.UserType),
			"onPremisesSecurityIdentifier": nilIfEmpty(u.OnPremSID),
		}
		if u.Enabled != nil {
			all["accountEnabled"] = *u.Enabled
		}
		if u.SignIn != nil {
			all["signInActivity"] = map[string]any{
				"lastSignInDateTime":               ts(u.SignIn.Interactive),
				"lastNonInteractiveSignInDateTime": ts(u.SignIn.NonInteractive),
				"lastSuccessfulSignInDateTime":     ts(u.SignIn.Successful),
			}
		}
		out = append(out, selected(r, all, "displayName", "userPrincipalName", "mail"))
	}
	return out
}

func (t *Tenant) groupItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, g := range t.Groups {
		types := g.Types
		if types == nil {
			types = []string{}
		}
		all := map[string]any{
			"@odata.type": "#microsoft.graph.group", "id": g.ID, "displayName": g.DisplayName,
			"groupTypes": types, "membershipRule": nilIfEmpty(g.MembershipRule),
			"membershipRuleProcessingState": nilIfEmpty(g.RuleState),
			"isAssignableToRole":            g.AssignableToRole,
			"visibility":                    nilIfEmpty(g.Visibility),
			"onPremisesSyncEnabled":         trueOrNil(g.OnPremSync),
			"onPremisesSecurityIdentifier":  nilIfEmpty(g.OnPremSID),
		}
		out = append(out, selected(r, all, "displayName"))
	}
	return out
}

func (g *Group) memberItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, m := range g.Members {
		all := map[string]any{"@odata.type": "#microsoft.graph." + m.Type, "id": m.ID, "displayName": m.DisplayName}
		if m.IDOnly {
			all["displayName"] = nil
		}
		if m.NoName {
			delete(all, "displayName")
		}
		out = append(out, selected(r, all, "displayName"))
	}
	return out
}

func (t *Tenant) servicePrincipal(id string) *ServicePrincipal {
	for i := range t.ServicePrincipals {
		if t.ServicePrincipals[i].ID == id {
			return &t.ServicePrincipals[i]
		}
	}
	return nil
}

func (t *Tenant) servicePrincipalItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, sp := range t.ServicePrincipals {
		roles := []map[string]any{}
		for _, ar := range sp.AppRoles {
			types := ar.MemberTypes
			if types == nil {
				types = []string{"User"}
			}
			roles = append(roles, map[string]any{
				"id": ar.ID, "displayName": ar.DisplayName, "value": nilIfEmpty(ar.Value),
				"isEnabled": ar.Enabled, "allowedMemberTypes": types,
			})
		}
		all := map[string]any{
			"@odata.type": "#microsoft.graph.servicePrincipal", "id": sp.ID, "displayName": sp.DisplayName,
			"appId": sp.AppID, "servicePrincipalType": sp.Type,
			"appOwnerOrganizationId": nilIfEmpty(sp.OwnerTenant), "appRoles": roles,
			"appRoleAssignmentRequired": sp.AssignmentRequired,
		}
		if sp.Enabled != nil {
			all["accountEnabled"] = *sp.Enabled
		}
		out = append(out, selected(r, all, "displayName"))
	}
	return out
}

func (t *Tenant) appRoleAssignmentItems(r *http.Request, resource string) []map[string]any {
	var out []map[string]any
	for _, a := range t.AppRoleAssignments[resource] {
		all := map[string]any{
			"id": a.ID, "appRoleId": a.AppRoleID, "principalId": a.Principal,
			"principalType": a.PrincipalType, "principalDisplayName": a.PrincipalName,
			"resourceId": resource,
		}
		out = append(out, selected(r, all, "appRoleId", "principalId", "principalType", "principalDisplayName", "resourceId"))
	}
	return out
}

func (t *Tenant) roleDefItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, d := range t.RoleDefs {
		all := map[string]any{
			"id": d.ID, "displayName": d.DisplayName, "description": nil,
			"isBuiltIn": d.BuiltIn, "isEnabled": d.Enabled,
		}
		out = append(out, selected(r, all, "displayName"))
	}
	return out
}

func (t *Tenant) roleAssignmentItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, a := range t.RoleAssignments {
		item := map[string]any{
			"id": a.ID, "principalId": a.Principal, "roleDefinitionId": a.RoleDefID,
			"directoryScopeId": a.Scope, "resourceScope": a.Scope,
		}
		if r.URL.Query().Get("$expand") == "principal" {
			item["principal"] = nil // one that cannot be expanded, such as a deleted one
			if a.PrincipalType != "" {
				item["principal"] = map[string]any{
					"@odata.type": "#microsoft.graph." + a.PrincipalType,
					"id":          a.Principal, "displayName": a.PrincipalName,
				}
			}
		}
		out = append(out, item)
	}
	return out
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// trueOrNil is how Graph answers a flag that only means something when set.
func trueOrNil(v bool) any {
	if !v {
		return nil
	}
	return true
}

func ts(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func scheduleItems(r *http.Request, instances []ScheduleInstance, active bool) []map[string]any {
	var out []map[string]any
	for _, in := range instances {
		item := map[string]any{
			"id": in.ID, "principalId": in.Principal, "roleDefinitionId": in.RoleDefID,
			"directoryScopeId": in.Scope, "appScopeId": nil,
			"startDateTime": "2026-01-01T00:00:00Z", "endDateTime": ts(in.End),
			"memberType": nilIfEmpty(in.MemberType),
		}
		if active {
			item["assignmentType"] = in.AssignmentType
		}
		if r.URL.Query().Get("$expand") == "principal" {
			item["principal"] = nil
			if in.PrincipalType != "" {
				item["principal"] = map[string]any{
					"@odata.type": "#microsoft.graph." + in.PrincipalType,
					"id":          in.Principal, "displayName": in.PrincipalName,
				}
			}
		}
		out = append(out, item)
	}
	return out
}

func (t *Tenant) adminUnitItems(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, au := range t.AdminUnits {
		all := map[string]any{
			"id": au.ID, "displayName": au.DisplayName, "description": nilIfEmpty(au.Description),
			"visibility": nilIfEmpty(au.Visibility),
		}
		out = append(out, selected(r, all, "displayName", "description", "visibility"))
	}
	return out
}

func (t *Tenant) oauth2Items(r *http.Request) []map[string]any {
	var out []map[string]any
	for _, g := range t.OAuth2Grants {
		all := map[string]any{
			"id": g.ID, "clientId": g.ClientID, "consentType": g.ConsentType,
			"principalId": nilIfEmpty(g.Principal), "resourceId": g.ResourceID, "scope": g.Scope,
		}
		out = append(out, selected(r, all, "clientId", "consentType", "principalId", "resourceId", "scope"))
	}
	return out
}
