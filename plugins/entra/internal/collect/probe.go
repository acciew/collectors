package collect

import (
	"context"
	"errors"
	"fmt"

	"go.acciew.io/collector/plugins/entra/internal/graph"
)

// ActivityState is whether a tenant can answer about sign-in activity.
type ActivityState int

// Three answers, not two: a tenant that records nothing and a tenant whose
// answer we could not get both yield no activity, but only the first is fixed by
// changing something in the tenant. The second sends an operator to check a
// credential.
const (
	// ActivityAvailable: the tenant answers.
	ActivityAvailable ActivityState = iota
	// ActivityUnavailable: the tenant refused for want of a licence.
	ActivityUnavailable
	// ActivityUndetermined: the read that would have told us failed.
	ActivityUndetermined
)

// ActivityAnswer is what a probe found out about sign-in activity.
type ActivityAnswer struct {
	State ActivityState
	// Why not, or why we could not tell. Empty when it is available.
	Note string
}

// probeActivity asks for one user's signInActivity and says what came back.
//
// A refusal is called a missing licence only if it carries a code Graph is
// known to use for one. What a tenant without Entra ID P1 or P2 is answered is
// not verified, so any other failure is reported as not knowing, which is the
// safe direction: it never retires an account on a guess.
func probeActivity(ctx context.Context, g *graph.Client, do retryFunc) (ActivityAnswer, error) {
	err := do(ctx, func() error { return g.Read(ctx, graph.ActivityProbePath()) })
	if err == nil {
		return ActivityAnswer{State: ActivityAvailable}, nil
	}
	answer := activityFailed(err)
	// A request that could not be made for want of patience is not an answer
	// about the tenant. The caller is told, because a throttle that is deciding
	// "could not find out" for a whole collection is a short glitch costing all
	// of it.
	var halt *stopError
	if errors.As(err, &halt) {
		return answer, halt
	}
	return answer, nil
}

// activityFailed says what a failed probe means.
func activityFailed(err error) ActivityAnswer {
	var ge *graph.Error
	switch {
	case errors.As(err, &ge) && ge.LicenceRequired():
		return ActivityAnswer{State: ActivityUnavailable, Note: "sign-in activity needs Microsoft Entra ID P1 or P2, " +
			"which this tenant does not appear to have: Graph refused it (" + ge.Code + "). Last activity is " +
			"reported as unavailable for everyone, never as none"}
	case errors.As(err, &ge) && ge.Kind == graph.KindPermission:
		return ActivityAnswer{State: ActivityUndetermined, Note: "could not find out whether this tenant records " +
			"sign-in activity: the request was refused (" + ge.Code + "). Grant the application permission " +
			"AuditLog.Read.All (with User.Read.All) to find out; it is not known whether the tenant is licensed"}
	}
	return ActivityAnswer{State: ActivityUndetermined, Note: "could not find out whether this tenant records " +
		"sign-in activity: " + err.Error()}
}

// Probe is what a pre-flight check found out about the tenant.
type Probe struct {
	Tenant string
	// Name is the organisation's, or the tenant's ID when it cannot be read.
	Name      string
	Reachable bool
	// Err is set when Reachable is false: one sentence for each thing to fix.
	Err      error
	Activity ActivityAnswer
}

// read is one thing a collection will read, and the permission it needs.
type read struct {
	permission, what, path string
	// licensed marks a read a tenant may be refused for want of a licence,
	// which is a tenant without the feature and not a fault to fix.
	licensed bool
	// bounded asks for one item with $top. Only where Microsoft documents it:
	// Graph ignores a query parameter it does not support without a word, or
	// refuses the request, and a check that failed on its own question would
	// report a tenant unreachable for nothing.
	bounded bool
}

// requiredReads are the reads this collection will make.
func requiredReads(w Wanted) []read {
	reads := []read{
		{permission: "User.Read.All", what: "list the users", path: "/users", bounded: true},
		{permission: "Group.Read.All", what: "list the groups and their members", path: "/groups", bounded: true},
		{permission: "RoleManagement.Read.Directory", what: "list the directory roles",
			path: "/roleManagement/directory/roleDefinitions"},
		{permission: "RoleManagement.Read.Directory", what: "list the directory role assignments",
			path: "/roleManagement/directory/roleAssignments"},
	}
	if w.ServicePrincipals || w.AppRoles {
		reads = append(reads, read{permission: "Application.Read.All",
			what: "list the service principals and who is assigned their app roles",
			path: "/servicePrincipals", bounded: true})
	}
	if w.AdministrativeUnits {
		reads = append(reads, read{permission: "AdministrativeUnit.Read.All",
			what: "list the administrative units", path: "/directory/administrativeUnits"})
	}
	if w.OAuth2Grants {
		reads = append(reads, read{permission: "Directory.Read.All",
			what: "list the delegated permission grants", path: "/oauth2PermissionGrants"})
	}
	if w.PIM {
		reads = append(reads,
			read{permission: "RoleEligibilitySchedule.Read.Directory",
				what: "list the roles principals are eligible for",
				path: "/roleManagement/directory/roleEligibilityScheduleInstances", licensed: true},
			read{permission: "RoleAssignmentSchedule.Read.Directory",
				what: "list the time-bound role assignments",
				path: "/roleManagement/directory/roleAssignmentScheduleInstances", licensed: true})
	}
	return reads
}

// Probes checks the tenant this client is signed in to.
//
// A check asks whether a read is allowed and not what it returns: one page of
// each, and never the whole tenant. A scope the credential cannot fully read is
// a result, not an error, because the operator needs the list to fix it.
func (r Run) Probes(ctx context.Context) []Probe {
	g := r.Graph
	tenant := g.TenantID()
	if tenant == "" {
		tenant = r.Config.TenantID
	}
	p := Probe{Tenant: tenant, Name: tenant, Reachable: true}
	var org graph.Page[graph.Organization]
	if err := r.retrying(ctx, func() error {
		var err error
		org, err = graph.GetPage[graph.Organization](ctx, g, graph.OrganizationPath())
		return err
	}); err == nil && len(org.Items) > 0 && org.Items[0].DisplayName != "" {
		p.Name = org.Items[0].DisplayName
	}

	var problems []error
	groupsReadable := true
	for _, rd := range requiredReads(r.Config.Wants()) {
		path := rd.path
		if rd.bounded {
			path = graph.ProbePath(path)
		}
		err := r.retrying(ctx, func() error { return g.ReadPage(ctx, path) })
		if err != nil && (!rd.licensed || !licenceRefusal(err)) {
			problems = append(problems, probeFailure(err, rd))
			groupsReadable = groupsReadable && rd.path != "/groups"
		}
	}
	// Only worth asking when the groups can be listed at all.
	if groupsReadable {
		problems = append(problems, sampleMembership(ctx, g, r.retrying)...)
	}

	if len(problems) > 0 {
		p.Reachable, p.Err = false, errors.Join(problems...)
	}
	p.Activity, _ = probeActivity(ctx, g, r.retrying)
	return []Probe{p}
}

// retryFunc runs one request under some patience: the stream's, or the check's.
type retryFunc func(ctx context.Context, op func() error) error

func licenceRefusal(err error) bool {
	var ge *graph.Error
	return errors.As(err, &ge) && ge.LicenceRequired()
}

// probeFailure is one sentence for one read. Only a refusal is advice to grant
// something: anything else is not about a permission, and saying so sends
// somebody to change what was never the problem.
func probeFailure(err error, r read) error {
	var ge *graph.Error
	if errors.As(err, &ge) && ge.Kind == graph.KindPermission {
		return fmt.Errorf("grant the application permission %s (admin consent) to %s: %w", r.permission, r.what, err)
	}
	return fmt.Errorf("could not %s: %w", r.what, err)
}

const (
	sampledGroups  = 10
	sampledMembers = 25
)

// sampleMembership reads the members of a few groups, and of every group whose
// membership is hidden that the first page holds, to find the permissions that
// fail silently: a type of member that comes back as an id and nothing else,
// and the members of a hidden-membership group.
func sampleMembership(ctx context.Context, g *graph.Client, do retryFunc) []error {
	var page graph.Page[graph.Group]
	if err := do(ctx, func() error {
		var err error
		page, err = graph.GetPage[graph.Group](ctx, g, graph.GroupsPath(25))
		return err
	}); err != nil {
		return nil // already reported as a failed read of the groups
	}
	var problems []error
	checked := map[string]bool{}
	hidden := false
	for i, grp := range page.Items {
		isHidden := grp.Visibility == hiddenMembership
		if i >= sampledGroups && !isHidden {
			continue
		}
		var members graph.Page[graph.DirectoryObject]
		if err := do(ctx, func() error {
			var err error
			members, err = graph.GetPage[graph.DirectoryObject](ctx, g, graph.MembersPath(grp.ID, sampledMembers))
			return err
		}); err != nil {
			var ge *graph.Error
			if isHidden && !hidden && errors.As(err, &ge) && ge.Kind == graph.KindPermission {
				hidden = true
				problems = append(problems, fmt.Errorf("grant the application permission Member.Read.Hidden (admin "+
					"consent) to read the members of groups with hidden membership: %w", err))
			}
			continue
		}
		for _, m := range members.Items {
			perm := permissionToRead[m.Kind()]
			if !m.IDOnly() || perm == "" || checked[m.Kind()] {
				continue
			}
			// A read that could not be answered settles nothing, and the next
			// member of the type is asked.
			denied, answered, _ := confirmDenied(ctx, g, do, m)
			if !answered {
				continue
			}
			checked[m.Kind()] = true
			if denied {
				problems = append(problems, fmt.Errorf("grant the application permission %s (admin consent) to read %s "+
					"objects: group members of that type come back as an id and nothing else, which is how Graph "+
					"answers an object the application may not read", perm, m.Kind()))
			}
		}
	}
	return problems
}
