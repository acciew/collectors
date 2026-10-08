package collect_test

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// chainOf collects in streams of at most n records until the collection ends,
// and returns every stream. between runs after each stream that stopped, with
// the cursor it handed back.
func chainOf(t *testing.T, w *world, flags string, n uint64, between func(cursor []byte)) ([]*capture, *collector.Incomplete) {
	t.Helper()
	var outs []*capture
	var cursor []byte
	for i := 0; i < 1500; i++ {
		out, err := w.run(flags, collector.CollectRequest{MaxRecords: n, ResumeFrom: cursor})
		outs = append(outs, out)
		if err == nil {
			return outs, nil
		}
		inc := incomplete(t, err)
		if inc.Cause != collector.BudgetExhausted {
			return outs, inc
		}
		cursor = inc.ResumeFrom
		if between != nil {
			between(cursor)
		}
	}
	t.Fatal("the chain never ended")
	return nil, nil
}

// recordsOf is what a set of streams said, as a set: a node by its key and
// content, an edge by its ends, path and kind, an activity by subject and signal.
func recordsOf(outs []*capture) map[string]bool {
	set := map[string]bool{}
	for _, o := range outs {
		for _, e := range o.events {
			switch {
			case e.GetNode() != nil:
				n := e.GetNode()
				set[fmt.Sprintf("node %v %s %v %s", n.GetKey().GetType(), n.GetKey().GetId(), n.GetProvenance(), n.GetName())] = true
			case e.GetEdge() != nil:
				ed := e.GetEdge()
				var via []string
				for _, v := range ed.GetPath().GetVia() {
					via = append(via, v.GetId())
				}
				set[fmt.Sprintf("edge %v %s>%s via %v %v %s", ed.GetType(), ed.GetFrom().GetId(), ed.GetTo().GetId(),
					via, ed.GetFidelity(), ed.GetSourceType())] = true
			case e.GetActivity() != nil:
				a := e.GetActivity()
				set["activity "+a.GetSubject().GetId()+" "+a.GetSignal()] = true
			}
		}
	}
	return set
}

func diffSets(want, got map[string]bool) (missing, extra []string) {
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

func activityCount(outs []*capture) map[string]int {
	n := map[string]int{}
	for _, o := range outs {
		for _, e := range o.events {
			if a := e.GetActivity(); a != nil {
				n[a.GetSubject().GetId()+" "+a.GetSignal()]++
			}
		}
	}
	return n
}

// With the applications off every one the collection names is written as
// referenced, and what it says of its sign-ins is said once in the chain.
func TestAReferencedApplicationSaysItsActivityOnceInAChain(t *testing.T) {
	w := newWorld(t, withGrants())
	w.srv.PageSize = 1
	outs, _ := chainOf(t, w, `{"oauth2_grants":true,"service_principals":false}`, 1, nil)
	outs[0].assertContract(outs[1:]...)
	if n := activityCount(outs)[automation+" "+"service_principal_sign_in"]; n != 1 {
		t.Errorf("the application said %d times that its sign-ins were not collected, want once", n)
	}
}

// An application that is a member of a group and that the applications part
// did not write is written as referenced, with what is known of its sign-ins,
// even when the applications are collected.
func TestAnApplicationTheApplicationsPartDidNotWriteIsReferencedWithItsActivity(t *testing.T) {
	late := fakegraph.GUID("sp-late")
	d := directory()
	d.Groups[0].Members = append(d.Groups[0].Members, fakegraph.Member{ID: late, Type: "servicePrincipal", DisplayName: "Late App"})
	out := newWorld(t, d).mustRun("")

	n := out.node("", "NODE_TYPE_IDENTITY", late)
	if n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Fatalf("node = %v, want it written as referenced", n)
	}
	if out.activities(late)["service_principal_sign_in"] == nil {
		t.Error("the referenced application does not say that its sign-ins are not collected")
	}
	if memberOf(out, late, engineering) == 0 {
		t.Error("its place in the group was not stated")
	}
	out.assertContract()
}

// An application returned as a group member is written by the applications part
// or left out with the edge naming it; never named and unwritten.
func TestAnApplicationInAGroupWhoseApplicationsPartFailedIsLeftOutAndCounted(t *testing.T) {
	d := directory()
	d.Groups[0].Members = append(d.Groups[0].Members, fakegraph.Member{ID: automation, Type: "servicePrincipal", DisplayName: "Automation"})
	w := newWorld(t, d)
	w.srv.Refuse("/v1.0/servicePrincipals", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	out, _ := w.run("", collector.CollectRequest{})
	out.assertContract()
	if out.diag("entra.edges.left-out") == nil {
		t.Error("the memberships left out were not counted")
	}
	if memberOf(out, automation, engineering) != 0 {
		t.Error("a membership naming an application nobody wrote was stated")
	}
}

// A role over a unit the units part did not return is written as referenced
// whichever stream names it.
func TestARoleOverAUnitThatWasNotReturnedIsReferencedInAChain(t *testing.T) {
	w := newWorld(t, withGrants())
	w.srv.PageSize = 1
	outs, _ := chainOf(t, w, `{"oauth2_grants":true,"administrative_units":true}`, 1, nil)
	outs[0].assertContract(outs[1:]...)
}

// A members read whose pages never end and never change says each member once
// and is stopped on the first page that says nothing new.
func TestAMembersReadThatRepeatsItsPageIsStoppedAtOnce(t *testing.T) {
	w := newWorld(t, directory())
	var calls atomic.Int64
	path := "/v1.0/groups/" + engineering + "/members"
	w.srv.Intercept(path, func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != path {
			return false
		}
		n := calls.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(rw, `{"value":[{"@odata.type":"#microsoft.graph.user","id":%q,"displayName":"A"}],"@odata.nextLink":%q}`,
			alice, w.srv.URL+path+fmt.Sprintf("?$skiptoken=t%d", n))
		return true
	})
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Fatalf("cause = %v, want the part failed", inc.Cause)
	}
	if got := calls.Load(); got > 3 {
		t.Errorf("%d pages read of a group that says the same page, want it stopped at the second", got)
	}
	if n := len(out.edges(collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF, alice, engineering)); n > 2 {
		t.Errorf("%d identical memberships sent", n)
	}
	if !strings.Contains(inc.Err.Error(), "same") {
		t.Errorf("err = %v, want it to say why", inc.Err)
	}
}

// A part that only names the nodes of a part that failed is not run: every edge
// it would write names a node nobody wrote, and its reads would be spent for it.
func TestThePartsThatOnlyNameAnotherPartsNodesAreNotRunWhenItFailed(t *testing.T) {
	for _, c := range []struct{ refuse, part, owner string }{
		{"/v1.0/groups", "group_members", "groups"},
		{"/v1.0/servicePrincipals", "app_role_assignments", "service_principals"},
	} {
		w := newWorld(t, directory())
		w.srv.Refuse(c.refuse, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
		out, err := w.run("", collector.CollectRequest{})
		inc := incomplete(t, err)
		if !partFailed(inc.Err, c.owner) || partFailed(inc.Err, c.part) {
			t.Errorf("%s: err = %v, want %s failed and %s passed over, not failed", c.owner, inc.Err, c.owner, c.part)
		}
		for _, p := range w.srv.Paths() {
			if strings.Contains(p, "/members") && c.owner == "groups" {
				t.Errorf("%s: asked for %s", c.owner, p)
			}
			if strings.Contains(p, "appRoleAssignedTo") && c.owner == "service_principals" {
				t.Errorf("%s: asked for %s", c.owner, p)
			}
		}
		skipped := false
		for _, d := range out.diags {
			if d.GetCode() == "entra.edges.left-out" && strings.Contains(d.GetMessage(), c.part+" part was not run") {
				skipped = true
			}
		}
		if !skipped {
			t.Errorf("%s: the part left out was not said", c.part)
		}
		out.assertContract()
	}
}

// An application made after the applications part ran, with roles of its own
// that a user holds, is named by the part that reads who holds them, with the
// roles it lists.
func TestAnApplicationMadeAfterTheApplicationsPartRanIsWrittenWithItsRolesWhereItsAssignmentsAreRead(t *testing.T) {
	late := fakegraph.GUID("sp-late")
	role := fakegraph.GUID("late-reader")
	w := newWorld(t, directory())
	var once atomic.Bool
	w.srv.Intercept("/v1.0/groups", func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1.0/groups" && once.CompareAndSwap(false, true) {
			ten := w.srv.Tenant
			ten.ServicePrincipals = append(ten.ServicePrincipals, fakegraph.ServicePrincipal{
				ID: late, AppID: fakegraph.GUID("app-late"), DisplayName: "Late", Type: "Application", Enabled: fakegraph.Enabled(true),
				AppRoles: []fakegraph.AppRole{{ID: role, DisplayName: "Reader", Value: "Late.Read", Enabled: true}},
			})
			ten.AppRoleAssignments[late] = []fakegraph.AppRoleAssignment{
				{ID: "late1", AppRoleID: role, Principal: alice, PrincipalType: "User", PrincipalName: "Alice Example"},
			}
		}
		return false
	})
	out := w.mustRun("")

	key := "app-role:" + late + ":" + role
	if out.node("", "NODE_TYPE_ENTITLEMENT", key) == nil {
		t.Error("the role the new application lists was never written")
	}
	if n := out.node("", "NODE_TYPE_RESOURCE", late); n == nil || n.GetProvenance() != collectorv1.Provenance_PROVENANCE_REFERENCED {
		t.Errorf("application = %v, want it named as referenced", n)
	}
	if len(out.edges(collectorv1.EdgeType_EDGE_TYPE_HOLDS, alice, key)) != 1 {
		t.Error("the user's assignment was not stated")
	}
	out.assertContract()
}
