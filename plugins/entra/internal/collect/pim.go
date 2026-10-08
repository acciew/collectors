package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
)

// Privileged Identity Management adds two states to a directory role, and a
// reviewer asks about both: who can become a Global Administrator, and who is
// one for a limited time. Each is an entitlement of its own (see roles.go), so
// neither is mistaken for the role being held outright.

// pimEligible collects what principals are eligible for.
//
// Only the instances Entra states as direct: an instance whose memberType is
// Group or Inherited is the same eligibility seen through a group, and the
// group's own instance, expanded to its direct members, already says it.
func (st *state) pimEligible(ctx context.Context) error {
	defs, err := st.roleDefs(ctx)
	if err != nil {
		return err
	}
	err = walk(ctx, st, func(is []graph.ScheduleInstance) error {
		for _, in := range is {
			if !directInstance(in) {
				st.pim["not direct"]++
				continue
			}
			if err := st.emitGrant(ctx, defs, eligible, scheduled(in)); err != nil {
				return err
			}
		}
		return nil
	})
	return st.pimFailure(err, "RoleEligibilitySchedule.Read.Directory", "list the roles principals are eligible for")
}

// pimActive collects the role assignments that are made by an administrator
// and end.
//
// Neither of the other two kinds is new. A permanent assignment is among the
// role assignments already, and an activation lasts hours and derives from an
// eligibility that is collected.
func (st *state) pimActive(ctx context.Context) error {
	defs, err := st.roleDefs(ctx)
	if err != nil {
		return err
	}
	err = walk(ctx, st, func(is []graph.ScheduleInstance) error {
		for _, in := range is {
			switch {
			case !directInstance(in):
				st.pim["not direct"]++
			case in.AssignmentType == "Activated":
				st.pim["activated"]++
			case in.EndDateTime == nil || in.EndDateTime.IsZero():
				st.pim["permanent"]++
			default:
				if err := st.emitGrant(ctx, defs, active, scheduled(in)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err = st.pimFailure(err, "RoleAssignmentSchedule.Read.Directory", "list the time-bound role assignments"); err != nil {
		return err
	}
	return st.reportPIMSkipped()
}

// directInstance says the instance is the one Entra states for the principal:
// memberType Direct, or none given.
func directInstance(in graph.ScheduleInstance) bool {
	return in.MemberType == "" || strings.EqualFold(in.MemberType, "Direct")
}

func scheduled(in graph.ScheduleInstance) grant {
	return grant{
		id: in.ID, principalID: in.PrincipalID, principal: in.Principal,
		roleDefinitionID: in.RoleDefinitionID, scope: in.DirectoryScopeID,
	}
}

// pimFailure decides what a failed PIM read means. PIM is on by default and a
// tenant need not be licensed for it: a refusal with a code Graph is known to
// use for a missing licence is a tenant with nothing to collect here, and says
// so. Only when nothing of PIM was read: a licence does not come and go between
// pages, or between the two reads, so a refusal after one is a read that stopped,
// and what was collected of it is not the whole. Any other failure is not assumed to be a licence either.
// Skipping the eligible administrators because an answer was not recognised
// would be wrong in the direction an auditor asks about.
func (st *state) pimFailure(err error, permission, what string) error {
	if err == nil {
		return nil
	}
	var ge *graph.Error
	// Read from either PIM part: a licence does not come and go between pages, or
	// between the two reads, so a refusal after one has answered is the read
	// stopping.
	if pages := st.pagesRead["pim_eligible"] + st.pagesRead["pim_active"]; errors.As(err, &ge) && ge.LicenceRequired() && pages > 0 {
		return &partial{err: err, text: fmt.Sprintf("Graph refused with %s after %d page(s) of Privileged Identity Management "+
			"were read, which is not a tenant without the licence: what was collected of it is not the whole", ge.Code, pages)}
	}
	if errors.As(err, &ge) && ge.LicenceRequired() {
		return st.out.Diagnostic(collectorv1.Severity_SEVERITY_INFO, "entra.pim.unlicensed",
			"this tenant does not appear to be licensed for Privileged Identity Management, so no eligible or "+
				"time-bound role assignments were collected: Graph refused ("+ge.Code+")")
	}
	err = needs(err, permission, what)
	if errors.As(err, &ge) && ge.Kind == graph.KindPermission {
		err = fmt.Errorf("%w. If this tenant does not use PIM, set \"pim\" to false under \"collect\"", err)
	}
	return err
}

// reportPIMSkipped says what was left out of the PIM schedules, and why.
func (st *state) reportPIMSkipped() error {
	var parts []string
	for _, k := range []string{"activated", "permanent", "not direct"} {
		if n := st.pim[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return st.out.Diagnostic(collectorv1.Severity_SEVERITY_INFO, "entra.pim.skipped",
		"schedule instances that add nothing to what is collected were left out: "+strings.Join(parts, ", ")+
			". An activated instance lasts hours and derives from an eligibility; a permanent one is among the "+
			"role assignments; one that is not direct is the same grant seen through a group")
}
