package graph

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// User is the part of a Graph user the collector reads.
type User struct {
	ID                           string          `json:"id"`
	DisplayName                  string          `json:"displayName"`
	UserPrincipalName            string          `json:"userPrincipalName"`
	Mail                         string          `json:"mail"`
	UserType                     string          `json:"userType"`
	AccountEnabled               *bool           `json:"accountEnabled"`
	OnPremisesSecurityIdentifier string          `json:"onPremisesSecurityIdentifier"`
	SignInActivity               *SignInActivity `json:"signInActivity"`
}

// SignInActivity is a user's signInActivity. A nil time is a sign-in Graph
// holds no record of, which is not the same as one that never happened.
type SignInActivity struct {
	LastSignIn               *time.Time `json:"lastSignInDateTime"`
	LastNonInteractiveSignIn *time.Time `json:"lastNonInteractiveSignInDateTime"`
	LastSuccessfulSignIn     *time.Time `json:"lastSuccessfulSignInDateTime"`
}

// Organization is the tenant itself.
type Organization struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName"`
	Created     *time.Time `json:"createdDateTime"`
}

// Group is the part of a Graph group the collector reads.
type Group struct {
	ID                            string   `json:"id"`
	DisplayName                   string   `json:"displayName"`
	GroupTypes                    []string `json:"groupTypes"`
	MembershipRule                string   `json:"membershipRule"`
	MembershipRuleProcessingState string   `json:"membershipRuleProcessingState"`
	IsAssignableToRole            *bool    `json:"isAssignableToRole"`
	Visibility                    string   `json:"visibility"`
	OnPremisesSyncEnabled         *bool    `json:"onPremisesSyncEnabled"`
	OnPremisesSecurityIdentifier  string   `json:"onPremisesSecurityIdentifier"`
}

// Dynamic says the group's members are decided by a rule.
func (g Group) Dynamic() bool {
	for _, t := range g.GroupTypes {
		if t == "DynamicMembership" {
			return true
		}
	}
	return false
}

// DirectoryObject is what a collection of mixed objects, such as a group's
// members, returns for each of them.
type DirectoryObject struct {
	Type        string
	ID          string
	DisplayName string

	// nameNull is set when displayName was present and null. Absent is not the
	// same: Graph silently ignores a query parameter it does not support, and an
	// object that came back without a name because $select was ignored is not
	// one the caller was refused.
	nameNull bool
}

// UnmarshalJSON reads the three properties the collector uses and notices
// whether the name was null rather than missing.
func (o *DirectoryObject) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*o = DirectoryObject{}
	for key, into := range map[string]*string{"@odata.type": &o.Type, "id": &o.ID, "displayName": &o.DisplayName} {
		v, ok := raw[key]
		if !ok {
			continue
		}
		if string(v) == "null" {
			o.nameNull = o.nameNull || key == "displayName"
			continue
		}
		if err := json.Unmarshal(v, into); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

const odataPrefix = "#microsoft.graph."

// Kind is the object's type without the namespace: user, group,
// servicePrincipal, device, orgContact.
func (o DirectoryObject) Kind() string { return strings.TrimPrefix(o.Type, odataPrefix) }

// IDOnly says the object came back as its type and id with the name null,
// which is how Graph returns an object of a type the caller holds no
// permission to read.
func (o DirectoryObject) IDOnly() bool { return o.Type != "" && o.nameNull }

// RoleDefinition is a directory role: built in or custom.
type RoleDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	IsBuiltIn   bool   `json:"isBuiltIn"`
	IsEnabled   bool   `json:"isEnabled"`
}

// RoleAssignment is a directory role held by a principal over a scope.
type RoleAssignment struct {
	ID               string           `json:"id"`
	PrincipalID      string           `json:"principalId"`
	RoleDefinitionID string           `json:"roleDefinitionId"`
	DirectoryScopeID string           `json:"directoryScopeId"`
	Principal        *DirectoryObject `json:"principal"`
}

// ServicePrincipal is the part of a Graph service principal the collector reads.
type ServicePrincipal struct {
	ID                        string    `json:"id"`
	AppID                     string    `json:"appId"`
	DisplayName               string    `json:"displayName"`
	AccountEnabled            *bool     `json:"accountEnabled"`
	ServicePrincipalType      string    `json:"servicePrincipalType"`
	AppOwnerOrganizationID    string    `json:"appOwnerOrganizationId"`
	AppRoleAssignmentRequired *bool     `json:"appRoleAssignmentRequired"`
	AppRoles                  []AppRole `json:"appRoles"`
}

// AppRole is a role an application exposes.
type AppRole struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"displayName"`
	Value              string   `json:"value"`
	IsEnabled          bool     `json:"isEnabled"`
	AllowedMemberTypes []string `json:"allowedMemberTypes"`
}

// AppRoleAssignment is a principal's assignment to an app role of a resource
// application.
type AppRoleAssignment struct {
	ID                   string `json:"id"`
	AppRoleID            string `json:"appRoleId"`
	PrincipalID          string `json:"principalId"`
	PrincipalType        string `json:"principalType"`
	PrincipalDisplayName string `json:"principalDisplayName"`
	ResourceID           string `json:"resourceId"`
}

// ScheduleInstance is an instance of a PIM schedule: a role a principal is
// eligible for, or one it holds right now.
type ScheduleInstance struct {
	ID               string           `json:"id"`
	PrincipalID      string           `json:"principalId"`
	RoleDefinitionID string           `json:"roleDefinitionId"`
	DirectoryScopeID string           `json:"directoryScopeId"`
	EndDateTime      *time.Time       `json:"endDateTime"`
	MemberType       string           `json:"memberType"`
	AssignmentType   string           `json:"assignmentType"`
	Principal        *DirectoryObject `json:"principal"`
}

// AdministrativeUnit is a container that scopes roles to part of a directory.
type AdministrativeUnit struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"`
}

// OAuth2PermissionGrant is a delegated permission grant: a client application
// allowed to act on behalf of users against a resource application.
type OAuth2PermissionGrant struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	ConsentType string `json:"consentType"`
	PrincipalID string `json:"principalId"`
	ResourceID  string `json:"resourceId"`
	Scope       string `json:"scope"`
}
