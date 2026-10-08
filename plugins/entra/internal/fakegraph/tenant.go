package fakegraph

import "time"

// Tenant is the directory a fake serves. Fields are plain data a test builds
// and may change between requests.
type Tenant struct {
	// ID is the tenant GUID. Name and Created describe the organisation; leave
	// Name empty to make the organisation unreadable.
	ID      string
	Name    string
	Created time.Time

	Users           []User
	Groups          []Group
	RoleDefs        []RoleDef
	RoleAssignments []RoleAssignment

	// Eligible and ActiveInstances are PIM's schedule instances: what
	// principals are eligible for, and what they hold right now.
	Eligible        []ScheduleInstance
	ActiveInstances []ScheduleInstance

	AdminUnits   []AdminUnit
	OAuth2Grants []OAuth2Grant

	ServicePrincipals []ServicePrincipal
	// AppRoleAssignments are the assignments of each resource service
	// principal, by its id: who holds which of its app roles.
	AppRoleAssignments map[string][]AppRoleAssignment

	// ActivityRefusal, when set, is how the fake answers any request that
	// selects signInActivity. The shape is the test's to choose: what Graph
	// answers a tenant without the licence is not something this fake claims
	// to know.
	ActivityRefusal *Refusal
}

// Refusal is an error Graph answers with.
type Refusal struct {
	Status        int
	Code, Message string
	// ProbeOnly refuses only a request for a single item ($top=1), which is
	// how a probe asks, and answers the pages of users as usual.
	ProbeOnly bool
}

// NewTenant is an empty tenant with a made-up identity.
func NewTenant() *Tenant {
	return &Tenant{
		ID:      GUID("tenant"),
		Name:    "Example Corp",
		Created: time.Date(2021, 3, 9, 0, 0, 0, 0, time.UTC),
	}
}

// User is a user as the fake serves it.
type User struct {
	ID          string
	DisplayName string
	UPN         string
	Mail        string
	// UserType is "Member", "Guest" or empty for a user Graph gives none.
	UserType string
	// Enabled is nil when the fake should leave accountEnabled out, as Graph
	// does for a caller that may not read it.
	Enabled   *bool
	OnPremSID string
	// SignIn is nil for a user with no sign-in activity at all.
	SignIn *SignIn
}

// SignIn is a user's signInActivity. A zero time is served as null, which is
// how Graph answers for a sign-in it has no record of.
type SignIn struct {
	Interactive, NonInteractive, Successful time.Time
}

// Group is a group as the fake serves it.
type Group struct {
	ID          string
	DisplayName string
	// Types is groupTypes: "Unified", "DynamicMembership".
	Types          []string
	MembershipRule string
	// RuleState is membershipRuleProcessingState: "On" or "Paused".
	RuleState        string
	AssignableToRole bool
	Visibility       string
	OnPremSync       bool
	OnPremSID        string
	Members          []Member
}

// Member is a member of a group as the members collection serves it.
type Member struct {
	ID string
	// Type is the directory object type: "user", "group", "servicePrincipal",
	// "device" or "orgContact".
	Type        string
	DisplayName string
	// IDOnly serves the member the way Graph serves an object of a type the
	// caller holds no permission for: its type and id, every property null.
	IDOnly bool
	// NoName leaves displayName out altogether, which is what a query
	// parameter Graph silently ignored looks like.
	NoName bool
}

// RoleDef is a directory role definition.
type RoleDef struct {
	ID          string
	DisplayName string
	BuiltIn     bool
	Enabled     bool
}

// RoleAssignment is a directory role assignment. Scope is "/" for the whole
// tenant or an administrative unit's path.
type RoleAssignment struct {
	ID        string
	Principal string
	// PrincipalType is the type of the object named by Principal, the same
	// vocabulary as Member.Type. Empty serves a principal that cannot be read.
	PrincipalType string
	PrincipalName string
	RoleDefID     string
	Scope         string
}

// Enabled is a *bool literal for building users.
func Enabled(b bool) *bool { return &b }

// ServicePrincipal is a service principal as the fake serves it.
type ServicePrincipal struct {
	ID          string
	AppID       string
	DisplayName string
	// Type is servicePrincipalType: Application, ManagedIdentity, Legacy.
	Type string
	// Enabled is nil when the fake should leave accountEnabled out.
	Enabled     *bool
	OwnerTenant string
	AppRoles    []AppRole
	// AssignmentRequired is appRoleAssignmentRequired.
	AssignmentRequired bool
}

// AppRole is a role an application exposes.
type AppRole struct {
	ID          string
	DisplayName string
	Value       string
	Enabled     bool
	MemberTypes []string
}

// AppRoleAssignment is a principal's assignment to an app role.
type AppRoleAssignment struct {
	ID        string
	AppRoleID string
	Principal string
	// PrincipalType is User, Group or ServicePrincipal, as Graph spells it.
	PrincipalType string
	PrincipalName string
}

// ScheduleInstance is a PIM schedule instance, eligible or active.
type ScheduleInstance struct {
	ID            string
	Principal     string
	PrincipalType string
	PrincipalName string
	RoleDefID     string
	Scope         string
	// End is zero for an instance that does not expire.
	End time.Time
	// MemberType is Direct, Group or Inherited; empty serves none.
	MemberType string
	// AssignmentType is Assigned or Activated, for active instances.
	AssignmentType string
}

// AdminUnit is an administrative unit.
type AdminUnit struct {
	ID, DisplayName, Description string
	// Visibility is HiddenMembership or empty.
	Visibility string
}

// OAuth2Grant is a delegated permission grant: a client application allowed
// to act on behalf of users against a resource application.
type OAuth2Grant struct {
	ID string
	// ClientID and ResourceID are service principal ids.
	ClientID, ResourceID string
	// ConsentType is AllPrincipals (an administrator consented for everyone) or
	// Principal (one user did).
	ConsentType string
	Principal   string
	// Scope is the space-separated permissions.
	Scope string
}
