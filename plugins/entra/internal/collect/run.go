package collect

import (
	"context"
	"errors"
	"fmt"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Run collects one tenant.
type Run struct {
	Graph  *graph.Client
	Config Config
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Wait pauses between a throttled request and its retry; nil means a real
	// timer. A test sets it so a throttle does not cost real seconds.
	Wait func(context.Context, time.Duration) error
}

// phase is one part of the collection. The order is the order of the stream: the
// parts that write nodes (users, service principals, administrative units,
// groups) come first and read nothing inside a page; the parts that write edges
// come after, and an edge only names a node whose part has ended or failed. See
// owners.go.
type phase struct {
	name string
	// first is the request that begins its read, given the page size and
	// whether users are read with their sign-in activity.
	first func(pageSize int, activity bool) string
	on    func(Wanted) bool
	run   func(*state, context.Context) error
}

func always(Wanted) bool { return true }

var phases = []phase{
	{"users", graph.UsersPath, always, (*state).users},
	{"service_principals", func(size int, _ bool) string { return graph.ServicePrincipalsPath(size) },
		func(w Wanted) bool { return w.ServicePrincipals || w.AppRoles }, (*state).servicePrincipals},
	{"administrative_units", func(int, bool) string { return graph.AdministrativeUnitsPath() },
		func(w Wanted) bool { return w.AdministrativeUnits }, (*state).administrativeUnits},
	{"groups", func(size int, _ bool) string { return graph.GroupsPath(size) }, always, (*state).groups},
	{"group_members", func(size int, _ bool) string { return graph.GroupRefsPath(size) }, always, (*state).groupMemberships},
	{"app_role_assignments", func(size int, _ bool) string { return graph.AppRoleHoldersPath(size) },
		func(w Wanted) bool { return w.AppRoles }, (*state).appRoleAssignments},
	{"role_definitions", func(int, bool) string { return graph.RoleDefinitionsPath() }, always, (*state).roleDefinitions},
	{"role_assignments", func(int, bool) string { return graph.RoleAssignmentsPath() }, always, (*state).roleAssignments},
	{"pim_eligible", func(int, bool) string { return graph.EligibilityInstancesPath() },
		func(w Wanted) bool { return w.PIM }, (*state).pimEligible},
	{"pim_active", func(int, bool) string { return graph.AssignmentInstancesPath() },
		func(w Wanted) bool { return w.PIM }, (*state).pimActive},
	{"oauth2_grants", func(int, bool) string { return graph.OAuth2PermissionGrantsPath() },
		func(w Wanted) bool { return w.OAuth2Grants }, (*state).oauth2Grants},
}

// Collect streams the tenant, from the start, in one stream. It returns nil only
// when the stream carries the whole tenant: anything else is an *Incomplete,
// because a truncated population that reads as a full one is worse than a
// failure.
//
// Entra does not resume. A collection that is cut short is read again from the
// beginning, so the only checkpoint is the position before anything was sent,
// and a cursor the caller offers is set aside, said so, and the collection starts
// over. A budget is the caller's stopping point "at the next checkpoint", and
// there is none until the end.
func (r Run) Collect(ctx context.Context, req collector.CollectRequest, out collector.Stream) error {
	lim := &limited{Stream: out}
	st := r.newState(ctx, req, lim)
	st.lim = lim

	// First, before any record: a stream that sends records must offer a point to
	// resume from, and the only honest one is the start.
	if err := st.checkpoint(); err != nil {
		return err
	}
	if len(req.ResumeFrom) > 0 {
		if err := st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "cursor.rejected",
			"this collector does not resume: the cursor was set aside and the collection started from the beginning"); err != nil {
			return err
		}
	}
	if !st.requested(req.Scopes) {
		return st.unrequested(req.Scopes)
	}
	// A throttle that will not end, on any request, ends the stream.
	stopped := func(err error) error {
		var halt *stopError
		if errors.As(err, &halt) {
			st.stopErr = halt.err
			return st.stop(halt.cause)
		}
		return err
	}
	if err := st.announce(ctx); err != nil {
		return stopped(err)
	}
	// Asked before the users are read: whether the tenant answers about activity
	// is a fact about the scope, and the users are read under the answer.
	if err := st.announceActivity(ctx); err != nil {
		return stopped(err)
	}

	for _, p := range phases {
		if !p.on(st.wants) {
			continue
		}
		st.phase = p.name
		st.firstPage = p.first(st.pageSize, st.readsActivity())
		if err := st.out.Progress(p.name, nil); err != nil {
			return err
		}
		st.mark()
		err := p.run(st, ctx)

		var halt *stopError
		var ge *graph.Error
		switch {
		case err == nil:
			st.done[p.name] = true
		case errors.Is(err, errEventLimit), errors.Is(err, errByteLimit):
			return st.limitReached(p.name, err)
		case errors.As(err, &halt):
			st.stopErr = halt.err
			return st.stop(halt.cause)
		case !errors.As(err, &ge):
			return err // not Graph's doing: the stream, or this code
		case ge.Kind == graph.KindAuth:
			st.stopErr = fmt.Errorf("%s: %w", p.name, err)
			return st.stop(collector.SourceFailed)
		default:
			// One part failing does not abandon the others: an operator needs
			// the whole picture to fix one thing. The verdict at the end is
			// what stops the rest being read as everything.
			st.fail(p.name, err)
		}
		if err := st.reportSkipped(p.name); err != nil {
			return err
		}
		if err := st.reportLeftOut(p.name); err != nil {
			return err
		}
	}

	if len(st.problems) > 0 {
		return st.stop(collector.ScopeUnreachable)
	}
	if err := st.reportUnconfirmed(); err != nil {
		return err
	}
	return st.finish(collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED, nil)
}

// problem is one reason the tenant is not whole. The key keeps one of a kind.
type problem struct {
	Key  string
	Text string
	// Fault is the kind of failure, as the SDK numbers them, so a refused
	// permission is still one when it is reported at the end.
	Fault int
}

// maxProblemText is the longest a reason is kept: it goes into the verdict, and a
// tenant's own names can make a message as long as they like.
const maxProblemText = 600
