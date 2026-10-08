package collect_test

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Entra does not resume. A collection is one stream that reads the tenant from
// the start, in memory; the only checkpoint it offers is the position before
// anything was sent, and a cursor it is handed is set aside, said so, and the
// collection starts over.

func largestCheckpoint(c *capture) int {
	biggest := 0
	for _, cp := range c.checkpoints {
		biggest = max(biggest, len(cp))
	}
	return biggest
}

// bigTenant is thirty thousand objects: users, groups with members, roles held.
func bigTenant() *fakegraph.Tenant {
	d := directory()
	for i := 0; i < 22_000; i++ {
		d.Users = append(d.Users, fakegraph.User{ID: fakegraph.GUID(fmt.Sprintf("bulk-user-%d", i)),
			DisplayName: fmt.Sprintf("User %d", i), UPN: fmt.Sprintf("u%d@example.onmicrosoft.com", i), UserType: "Member",
			Enabled: fakegraph.Enabled(true)})
	}
	for i := 0; i < 6_000; i++ {
		d.Groups = append(d.Groups, fakegraph.Group{ID: fakegraph.GUID(fmt.Sprintf("bulk-group-%d", i)),
			DisplayName: fmt.Sprintf("Group %d", i), Members: []fakegraph.Member{
				{ID: fakegraph.GUID(fmt.Sprintf("bulk-user-%d", i)), Type: "user", DisplayName: "U"},
				{ID: fakegraph.GUID(fmt.Sprintf("bulk-user-%d", i+6_000)), Type: "user", DisplayName: "U"},
			}})
	}
	for i := 0; i < 2_000; i++ {
		id := fakegraph.GUID(fmt.Sprintf("bulk-role-%d", i))
		d.RoleDefs = append(d.RoleDefs, fakegraph.RoleDef{ID: id, DisplayName: fmt.Sprintf("Role %d", i), Enabled: true})
		d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{
			ID: fmt.Sprintf("bulk-ra-%d", i), Principal: fakegraph.GUID(fmt.Sprintf("bulk-user-%d", i+12_000)),
			PrincipalType: "user", PrincipalName: "U", RoleDefID: id, Scope: "/"})
	}
	return d
}

// A tenant of thirty thousand objects is one stream with one checkpoint that is
// a few bytes: nothing the collector remembers travels through the service.
func TestAThirtyThousandObjectTenantIsOneStreamWithATinyCheckpoint(t *testing.T) {
	w := newWorld(t, bigTenant())
	w.srv.PageSize = 999
	out, err := w.run(noApplications, collector.CollectRequest{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(out.checkpoints) != 1 {
		t.Errorf("%d checkpoints, want the one before anything was sent", len(out.checkpoints))
	}
	if n := largestCheckpoint(out); n >= 1024 {
		t.Errorf("a checkpoint carries %d bytes, want under a kibibyte", n)
	}
	first := -1
	for i, e := range out.events {
		if e.GetCheckpoint() != nil {
			first = i
			break
		}
	}
	if first != 0 {
		t.Errorf("the checkpoint is event %d, want the first: nothing before it has to be kept", first)
	}
	if got := out.count(func(e *collectorv1.CollectResponse) bool { return e.GetNode() != nil }); got < 30_000 {
		t.Errorf("%d nodes, want the whole tenant", got)
	}
	out.assertContract()
}

// A cursor, whatever it is, is set aside: the collection starts over, says so
// under the contract's code, and is whole.
func TestACursorIsSetAsideAndTheCollectionStartsOverAndSaysSo(t *testing.T) {
	whole := recordsOf([]*capture{newWorld(t, directory()).mustRun("")})
	for name, token := range map[string]string{
		"one this build offered":         `{"v":1}`,
		"one an earlier build wrote":     `{"done":["users"],"activity":"available"}`,
		"one that is not JSON":           `not a cursor`,
		"one that holds a link":          `{"phase":"users","next":"https://example.invalid/v1.0/users?$skiptoken=x"}`,
		"one that holds a ledger":        `{"done":["users"],"wrote":{"users":"YWJjZGVm"}}`,
		"one far larger than is offered": strings.Repeat("x", 100_000),
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, directory())
			before := len(w.srv.Requests())
			out, err := w.run("", collector.CollectRequest{ResumeFrom: []byte(token)})
			if err != nil {
				t.Fatalf("Collect: %v, want the whole collection", err)
			}
			d := out.diag("cursor.rejected")
			if d == nil || d.GetSeverity() != collectorv1.Severity_SEVERITY_WARNING {
				t.Errorf("diagnostic = %v, want a warning under cursor.rejected", d)
			}
			if missing, extra := diffSets(whole, recordsOf([]*capture{out})); len(missing)+len(extra) > 0 {
				t.Errorf("the collection that started over is not the whole one.\nmissing: %v\nextra: %v", missing, extra)
			}
			for _, r := range w.srv.Requests()[before:] {
				if strings.Contains(r.Query.Get("$skiptoken"), "x") && r.Path == "/v1.0/users" {
					t.Errorf("a link out of the cursor was followed: %s", r.Path)
				}
			}
			out.assertContract()
		})
	}
}

// Without a cursor nothing is said about one.
func TestNothingIsSaidAboutACursorWhenNoneWasGiven(t *testing.T) {
	if newWorld(t, directory()).mustRun("").diag("cursor.rejected") != nil {
		t.Error("a collection with no cursor says it rejected one")
	}
}

// The tenant is one scope, sent once, and a clean collection says it was
// collected: the service takes that to mean whole.
func TestACleanCollectionSendsTheScopeOnceAndSaysItWasCollected(t *testing.T) {
	out := newWorld(t, directory()).mustRun("")
	n := out.count(func(e *collectorv1.CollectResponse) bool {
		return e.GetNode().GetKey().GetType() == collectorv1.NodeType_NODE_TYPE_SCOPE
	})
	if n != 1 {
		t.Errorf("%d scope nodes, want one", n)
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("scope outcomes = %+v, want the tenant collected", out.scopes)
	}
	// And a cursor does not make it less whole: it was read from the start.
	again, err := newWorld(t, directory()).run("", collector.CollectRequest{ResumeFrom: []byte(`{"v":1}`)})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if again.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Errorf("a collection that started over says %v", again.scopes[0].Status)
	}
}

// Entra has no point in the middle of a collection at which it could stop and
// go on, so a budget, which the contract applies at the next checkpoint, is
// reached only at the end.
func TestABudgetIsReachedOnlyAtTheEnd(t *testing.T) {
	w := newWorld(t, directory())
	out, err := w.run("", collector.CollectRequest{MaxRecords: 1, MaxDuration: time.Nanosecond})
	if err != nil {
		t.Fatalf("Collect: %v, want the whole collection: a stream that stopped would be restarted from the beginning, to stop again", err)
	}
	if out.node("", "NODE_TYPE_IDENTITY", alice) == nil {
		t.Error("the collection was cut short")
	}
	out.assertContract()
}

// A source that stays unwell fails the part it was reading, and the others are
// still collected: there is no later stream to go back to it in.
func TestAnOutageThatOutlastsItsRetriesFailsThePartAndTheRestIsStillRead(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Outage("/v1.0/roleManagement/directory/roleDefinitions", 1000, 0)
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable {
		t.Fatalf("cause = %v: %v, want the part failed", inc.Cause, inc.Err)
	}
	if len(inc.ResumeFrom) != 0 {
		t.Errorf("a cursor of %d bytes offered; there is nothing to resume", len(inc.ResumeFrom))
	}
	if out.node("", "NODE_TYPE_IDENTITY", alice) == nil || out.node("", "NODE_TYPE_GROUPING", engineering) == nil {
		t.Error("the parts before the one that failed were not read")
	}
	// The four parts that read the roles fail the same way, and each waits out
	// the retries of one request and no more.
	const readers = 4
	if got := len(w.waited); got != readers*collect.OutageRetries {
		t.Errorf("waited %d times, want %d: %d retries for each of %d parts", got, readers*collect.OutageRetries, collect.OutageRetries, readers)
	}
	asked := 0
	for _, p := range w.srv.Paths() {
		if strings.HasPrefix(p, "/v1.0/roleManagement/directory/roleDefinitions") {
			asked++
		}
	}
	if asked != readers*(collect.OutageRetries+1) {
		t.Errorf("%d requests for the roles, want %d", asked, readers*(collect.OutageRetries+1))
	}
	if !partFailed(inc.Err, "role_definitions") {
		t.Errorf("err = %v, want it to name the part", inc.Err)
	}
}

// A throttle that will not end stops the collection, and says how long to wait.
func TestAThrottleThatWillNotEndEndsTheStreamRateLimitedWithNoCursor(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/groups", 1000, 3600)
	_, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited || len(inc.ResumeFrom) != 0 {
		t.Errorf("cause %v with a %d-byte cursor, want RATE_LIMITED and none", inc.Cause, len(inc.ResumeFrom))
	}
}

// A refusal stays a refusal: the part fails at once.
func TestARefusalFailsThePartAtOnceAndOffersNothingToResume(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Refuse("/v1.0/groups", http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")
	_, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || len(inc.ResumeFrom) != 0 {
		t.Errorf("cause %v with a %d-byte cursor", inc.Cause, len(inc.ResumeFrom))
	}
}

// The probe cannot be answered for want of patience: what the tenant says about
// sign-in activity is "could not find out", and the collection goes on.
func TestAnActivityProbeThatOutlastsItsRetriesDecidesUndeterminedAndTheCollectionGoesOn(t *testing.T) {
	w := newWorld(t, signedIn())
	w.srv.Intercept("/v1.0/users", func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("$top") != "1" || !strings.Contains(r.URL.Query().Get("$select"), "signInActivity") {
			return false
		}
		rw.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	out, err := w.run("", collector.CollectRequest{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if s := out.scopes[0]; s.ActivityAvailable || !s.ActivityUndetermined {
		t.Errorf("scope = %+v, want activity undetermined", s)
	}
	if out.node("", "NODE_TYPE_IDENTITY", alice) == nil {
		t.Error("the users were never read")
	}
}

// A part's own collection is held to the same ceiling as a read inside a page: a
// next link that is never the same twice and never ends fails the part, and the
// others are still collected.
func TestAPartWhoseLinksNeverEndFailsAtTheCeilingAndTheRestIsStillRead(t *testing.T) {
	defer collect.LowerLimits(5, -1, -1)()
	w := newWorld(t, directory())
	var calls atomic.Int64
	w.srv.Intercept("/v1.0/directory/administrativeUnits", func(rw http.ResponseWriter, r *http.Request) bool {
		n := calls.Add(1)
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(rw, `{"value":[{"id":%q,"displayName":"U"}],"@odata.nextLink":%q}`,
			fakegraph.GUID(fmt.Sprintf("endless-unit-%d", n)), w.srv.URL+"/v1.0/directory/administrativeUnits?$skiptoken=t"+fmt.Sprint(n))
		return true
	})
	out, err := w.run(`{"administrative_units":true,"service_principals":false,"app_roles":false}`, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "administrative_units") {
		t.Fatalf("cause %v: %v, want the units part failed", inc.Cause, inc.Err)
	}
	if got := calls.Load(); got != 5 {
		t.Errorf("%d pages read, want it stopped at the ceiling of 5", got)
	}
	if out.node("", "NODE_TYPE_GROUPING", engineering) == nil {
		t.Error("the parts after the units were not read")
	}
}

// What a part counted before a throttle stopped the stream is still said.
func TestWhatAPartLeftOutBeforeAThrottleStoppedTheStreamIsStillSaid(t *testing.T) {
	d := directory()
	d.Groups = append(d.Groups, fakegraph.Group{ID: fakegraph.GUID("last-group"), DisplayName: "Last"})
	w := newWorld(t, d)
	w.srv.Throttle("/v1.0/groups/"+fakegraph.GUID("last-group")+"/members", 1000, 1)
	out, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.RateLimited {
		t.Fatalf("cause = %v, want rate limited", inc.Cause)
	}
	said := false
	for _, dg := range out.diags {
		if dg.GetCode() == "entra.skipped" && strings.Contains(dg.GetMessage(), "1 device") {
			said = true
		}
	}
	if !said {
		t.Error("the device member of Admins, counted before the stream stopped, was never said to be left out")
	}
}

// An outage that names a wait too long to sit through is not waited for.
func TestAnOutageWhoseRetryAfterIsTooLongFailsTheReadAtOnce(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Outage("/v1.0/groups", 1000, 3600)
	_, err := w.run(noApplications, collector.CollectRequest{})
	inc := incomplete(t, err)
	if inc.Cause != collector.ScopeUnreachable || !partFailed(inc.Err, "groups") {
		t.Fatalf("cause %v: %v, want the groups part failed", inc.Cause, inc.Err)
	}
	if len(w.waited) != 0 {
		t.Errorf("waited %v, want no wait: Graph asked for an hour", w.waited)
	}
}

// duplicates lists every node, edge and activity a stream sent more than once.
// The service refuses a record that two streams send, so a stream that sends one
// twice is a stream that gives it nothing to stitch to.
func duplicates(c *capture) []string {
	seen := map[string]int{}
	for _, e := range c.events {
		var id string
		switch {
		case e.GetNode() != nil:
			id = "node " + keyText(e.GetNode().GetKey())
		case e.GetEdge() != nil:
			ed := e.GetEdge()
			var via []string
			for _, k := range ed.GetPath().GetVia() {
				via = append(via, keyText(k))
			}
			id = fmt.Sprintf("edge %v %s>%s [%s]", ed.GetType(), keyText(ed.GetFrom()), keyText(ed.GetTo()), strings.Join(via, " "))
		case e.GetActivity() != nil:
			id = "activity " + keyText(e.GetActivity().GetSubject()) + " " + e.GetActivity().GetSignal()
		default:
			continue
		}
		seen[id]++
	}
	var out []string
	for id, n := range seen {
		if n > 1 {
			out = append(out, fmt.Sprintf("%dx %s", n, id))
		}
	}
	sort.Strings(out)
	return out
}

func keyText(k *collectorv1.Key) string {
	return fmt.Sprintf("%s/%d/%s", k.GetScope(), k.GetType(), k.GetId())
}

// Whatever the tenant and however Graph pages it, the one stream passes the
// host's check, sends nothing twice, and says the tenant was collected.
func TestEveryTenantIsOneCleanStream(t *testing.T) {
	withSPMember := func() *fakegraph.Tenant {
		d := withGrants()
		d.Groups[0].Members = append(d.Groups[0].Members,
			fakegraph.Member{ID: automation, Type: "servicePrincipal", DisplayName: "Automation"},
			fakegraph.Member{ID: fakegraph.GUID("sp-new"), Type: "servicePrincipal", DisplayName: "New App"})
		return d
	}
	tenants := []struct {
		name  string
		build func() *fakegraph.Tenant
		flags []string
	}{
		{"the sample", directory, []string{"", noApplications, `{"service_principals":false}`, `{"app_roles":false}`, `{"pim":false}`}},
		{"with PIM", privileged, []string{"", `{"service_principals":false}`}},
		{"with grants and units", withGrants, []string{
			"", `{"oauth2_grants":true,"administrative_units":true}`,
			`{"oauth2_grants":true,"service_principals":false}`,
			`{"oauth2_grants":true,"service_principals":false,"app_roles":false}`,
		}},
		{"with applications as members", withSPMember, []string{"", `{"service_principals":false}`, `{"oauth2_grants":true,"administrative_units":true}`}},
		{"with sign-in activity", signedIn, []string{""}},
	}
	for _, tn := range tenants {
		for _, flags := range tn.flags {
			for _, size := range []int{0, 1, 2, 3} {
				name := fmt.Sprintf("%s %s page=%d", tn.name, flags, size)
				w := newWorld(t, tn.build())
				if size > 0 {
					w.srv.PageSize = size
				}
				out, err := w.run(flags, collector.CollectRequest{})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				out.assertContract()
				if t.Failed() {
					t.Fatalf("%s: the stream breaks the stream check", name)
				}
				if dup := duplicates(out); len(dup) > 0 {
					t.Fatalf("%s: the stream sends %d records twice, e.g. %s", name, len(dup), dup[0])
				}
				if len(out.scopes) != 1 || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
					t.Fatalf("%s: scopes = %+v", name, out.scopes)
				}
			}
		}
	}
}
