package fakegraph

import "time"

// Identifiers of the sample tenant. They are made up, and stable, so a test
// can name a person without a table.
var (
	Alice = GUID("alice")
	Bob   = GUID("bob")
	Carol = GUID("carol")
	Dave  = GUID("dave")

	Engineering = GUID("g-engineering")
	Platform    = GUID("g-platform")
	Sales       = GUID("g-sales")
	Admins      = GUID("g-admins")

	Laptop = GUID("laptop")

	Payroll    = GUID("sp-payroll")
	Automation = GUID("sp-automation")
	VMIdentity = GUID("sp-vm")
	LegacyApp  = GUID("sp-legacy")

	PayrollReader = GUID("ar-reader")
	PayrollAdmin  = GUID("ar-admin")

	GlobalAdmin = GUID("role-ga")
	Helpdesk    = GUID("role-hd")
	UnitA       = GUID("au-a")
)

// Example is a small tenant with a little of everything: members and a guest,
// static and dynamic groups, one group inside another, a role-assignable group
// holding a role, and a role scoped to an administrative unit.
func Example() *Tenant {
	t := NewTenant()
	t.Users = []User{
		{ID: Alice, DisplayName: "Alice Example", UPN: "alice@example.onmicrosoft.com", UserType: "Member",
			Enabled: Enabled(true), OnPremSID: "S-1-5-21-1-2-3-1001"},
		{ID: Bob, DisplayName: "Bob Example", UPN: "bob@example.onmicrosoft.com", UserType: "Member",
			Enabled: Enabled(false)},
		{ID: Carol, DisplayName: "Carol Guest", UPN: "carol_partner.example#EXT#@example.onmicrosoft.com",
			UserType: "Guest", Enabled: Enabled(true)},
		// Graph left accountEnabled out: the token may not read it.
		{ID: Dave, DisplayName: "Dave Example", UPN: "dave@example.onmicrosoft.com"},
	}
	// Alice has signed in every way; Carol has only tried; Bob and Dave have
	// nothing recorded, which is not the same as never.
	t.Users[0].SignIn = &SignIn{
		Interactive:    time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC),
		NonInteractive: time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC),
		Successful:     time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC),
	}
	t.Users[2].SignIn = &SignIn{Interactive: time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)}
	t.Groups = []Group{
		{ID: Engineering, DisplayName: "Engineering", Members: []Member{
			{ID: Alice, Type: "user", DisplayName: "Alice Example"},
			{ID: Bob, Type: "user", DisplayName: "Bob Example"},
			{ID: Platform, Type: "group", DisplayName: "Platform"},
		}},
		{ID: Platform, DisplayName: "Platform", Members: []Member{
			{ID: Carol, Type: "user", DisplayName: "Carol Guest"},
		}},
		{ID: Sales, DisplayName: "Sales", Types: []string{"DynamicMembership"},
			MembershipRule: `(user.department -eq "Sales")`, RuleState: "On",
			Members: []Member{{ID: Dave, Type: "user", DisplayName: "Dave Example"}}},
		{ID: Admins, DisplayName: "Admins", AssignableToRole: true, Members: []Member{
			{ID: Alice, Type: "user", DisplayName: "Alice Example"},
			{ID: Laptop, Type: "device", DisplayName: "LAPTOP-1"},
		}},
	}
	t.ServicePrincipals = []ServicePrincipal{
		{ID: Payroll, AppID: GUID("app-payroll"), DisplayName: "Payroll", Type: "Application",
			Enabled: Enabled(true), OwnerTenant: t.ID, AssignmentRequired: true,
			AppRoles: []AppRole{
				{ID: PayrollReader, DisplayName: "Reader", Value: "Payroll.Read", Enabled: true},
				{ID: PayrollAdmin, DisplayName: "Administrator", Value: "Payroll.Admin", Enabled: true},
			}},
		{ID: Automation, AppID: GUID("app-automation"), DisplayName: "Automation", Type: "Application",
			Enabled: Enabled(true), OwnerTenant: t.ID},
		{ID: VMIdentity, AppID: GUID("app-vm"), DisplayName: "vm-build-01", Type: "ManagedIdentity",
			Enabled: Enabled(true)},
		// An app made before registrations existed, with no roles of its own.
		{ID: LegacyApp, AppID: GUID("app-legacy"), DisplayName: "Old Intranet", Type: "Legacy",
			Enabled: Enabled(false)},
	}
	t.AppRoleAssignments = map[string][]AppRoleAssignment{
		Payroll: {
			{ID: "ara1", AppRoleID: PayrollAdmin, Principal: Alice, PrincipalType: "User", PrincipalName: "Alice Example"},
			{ID: "ara2", AppRoleID: PayrollReader, Principal: Engineering, PrincipalType: "Group", PrincipalName: "Engineering"},
			{ID: "ara3", AppRoleID: PayrollReader, Principal: Automation, PrincipalType: "ServicePrincipal", PrincipalName: "Automation"},
		},
		LegacyApp: {
			// The all-zeros role: assigned to the app without any role of its own.
			{ID: "ara4", AppRoleID: "00000000-0000-0000-0000-000000000000", Principal: Carol, PrincipalType: "User", PrincipalName: "Carol Guest"},
		},
	}
	t.RoleDefs = []RoleDef{
		{ID: GlobalAdmin, DisplayName: "Global Administrator", BuiltIn: true, Enabled: true},
		{ID: Helpdesk, DisplayName: "Helpdesk Administrator", BuiltIn: true, Enabled: true},
	}
	t.RoleAssignments = []RoleAssignment{
		{ID: "ra1", Principal: Alice, PrincipalType: "user", PrincipalName: "Alice Example", RoleDefID: GlobalAdmin, Scope: "/"},
		{ID: "ra2", Principal: Admins, PrincipalType: "group", PrincipalName: "Admins", RoleDefID: GlobalAdmin, Scope: "/"},
		{ID: "ra3", Principal: Bob, PrincipalType: "user", PrincipalName: "Bob Example", RoleDefID: Helpdesk,
			Scope: "/administrativeUnits/" + UnitA},
	}
	return t
}
