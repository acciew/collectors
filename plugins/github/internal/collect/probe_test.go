package collect_test

import (
	"context"
	"strings"
	"testing"

	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/plugins/github/internal/collect"
)

func probeFor(t *testing.T, probes []collect.Probe, org string) collect.Probe {
	t.Helper()
	for _, p := range probes {
		if p.Org == org {
			return p
		}
	}
	t.Fatalf("no probe for %q", org)
	return collect.Probe{}
}

func TestAReachableOrganizationProbesClean(t *testing.T) {
	got := probeFor(t, collect.Probes(context.Background(), org(), []string{"acme-org"}, nil), "acme-org")
	if !got.Reachable || got.Err != nil {
		t.Errorf("probe = %+v", got)
	}
}

// Reading the organization is the right probe rather than the cheapest one:
// it is the call that carries the base permission, so a token that can list
// an organization but not read it would pass a cheaper check and then produce
// a collection missing the most far-reaching entitlement in it.
func TestAnOrganizationThatCannotBeReadIsNotReachable(t *testing.T) {
	src := failing{
		fakeSource: org(), failFor: "acme-org",
		err: &api.Error{Kind: api.Permission, What: "reading organization acme-org"},
	}
	got := probeFor(t, collect.Probes(context.Background(), src, []string{"acme-org"}, nil), "acme-org")
	if got.Reachable {
		t.Error("an organization that could not be read was reported reachable")
	}
	if got.Err == nil {
		t.Error("an unreachable organization must say why")
	}
}

// The most useful thing this call can report is an organization somebody
// named and the token cannot see.
func TestAnOrganizationAskedForAndNotVisibleIsProbed(t *testing.T) {
	probes := collect.Probes(context.Background(), org(), []string{"acme-org"},
		map[string]bool{"acme-org": true, "ghost": true})
	got := probeFor(t, probes, "ghost")
	if got.Reachable || got.Err == nil {
		t.Error("an invisible organization was reported as fine")
	}
	// SSO is the commonest reason a token that looks right cannot see an
	// organization, and it is not obvious.
	if !strings.Contains(got.Err.Error(), "SSO") {
		t.Errorf("the error does not mention the usual cause: %v", got.Err)
	}
}

func TestAnOrganizationNobodyAskedForIsNotProbed(t *testing.T) {
	probes := collect.Probes(context.Background(), org(), []string{"acme-org", "other"},
		map[string]bool{"acme-org": true})
	if len(probes) != 1 || probes[0].Org != "acme-org" {
		t.Errorf("probes = %v, want only acme-org", probes)
	}
}

// A list somebody reads should not shuffle between runs.
func TestProbesComeBackInAStableOrder(t *testing.T) {
	wanted := map[string]bool{}
	for _, n := range []string{"delta", "alpha", "charlie", "bravo", "echo"} {
		wanted[n] = true
	}
	var first []string
	for range 20 {
		var got []string
		for _, p := range collect.Probes(context.Background(), org(), nil, wanted) {
			got = append(got, p.Org)
		}
		if first == nil {
			first = got
			continue
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("order is not stable: %v then %v", first, got)
			}
		}
	}
	if first[0] != "alpha" {
		t.Errorf("order = %v, want alphabetical", first)
	}
}

func TestOrgNamesAreSorted(t *testing.T) {
	got := collect.OrgNames(context.Background(), []api.Org{
		{Login: "zulu"}, {Login: "alpha"}, {Login: "mike"},
	})
	if got[0] != "alpha" || got[2] != "zulu" {
		t.Errorf("OrgNames = %v", got)
	}
}
