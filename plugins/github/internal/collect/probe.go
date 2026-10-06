package collect

import (
	"context"
	"errors"
	"sort"

	"go.acciew.io/collector/plugins/github/internal/api"
)

// Probe is what a pre-flight check found out about one organization.
type Probe struct {
	Org       string
	Reachable bool
	// Set when Reachable is false.
	Err error
}

// Probes checks each organization the token can see, narrowed to wanted when
// wanted is non-empty.
//
// Reading the organization is the right probe rather than the cheapest one:
// it is the call that carries the base permission, so a token that can list
// an organization but not read it would pass a cheaper check and then produce
// a collection missing the single most far-reaching entitlement in it.
func Probes(ctx context.Context, src Source, orgs []string, wanted map[string]bool) []Probe {
	var probes []Probe
	for _, org := range orgs {
		if len(wanted) > 0 && !wanted[org] {
			continue
		}
		p := Probe{Org: org, Reachable: true}
		if _, err := src.Org(ctx, org); err != nil {
			p.Reachable, p.Err = false, err
		}
		probes = append(probes, p)
	}

	// An organization somebody named and the token cannot see is the most
	// useful thing this call can report. Sorted, because a map is not an
	// order and a list somebody reads should not shuffle between runs.
	var missing []string
	for name := range wanted {
		if !contains(orgs, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		probes = append(probes, Probe{
			Org: name,
			Err: errors.New("this token cannot see this organization, or it does not exist; " +
				"a token needs read:org and the organization may also require SSO authorisation"),
		})
	}
	return probes
}

// OrgNames lists the organizations a token can see.
func OrgNames(ctx context.Context, orgs []api.Org) []string {
	out := make([]string, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, o.Login)
	}
	sort.Strings(out)
	return out
}
