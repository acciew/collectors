package collect_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/sdk/go/collector"
)

// A 503 is the service being briefly unwell, and one transient answer must not
// fail a whole part and everything it would have carried.
func TestAnOutageThatNamesHowLongToWaitIsWaitedOut(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Outage("/v1.0/groups", 1, 4)
	out := w.mustRun("")

	if len(w.waited) != 1 || w.waited[0] != 4*time.Second {
		t.Errorf("waited %v, want the 4 seconds Graph asked for", w.waited)
	}
	if out.node("", "NODE_TYPE_GROUPING", engineering) == nil || out.scopes[0].Status != collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED {
		t.Error("a transient 503 cost the groups")
	}
	// It is not a rate limit, and is not reported as one.
	if len(out.progress) != 0 {
		t.Errorf("progress = %+v: a wait for an outage is not a rate limit", out.progress)
	}
}

func TestAnOutageThatNamesNothingIsWaitedOutWithABackoff(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Outage("/v1.0/groups", 2, 0)
	w.mustRun("")

	if len(w.waited) != 2 || w.waited[1] <= w.waited[0] {
		t.Errorf("waited %v, want two waits, the second longer", w.waited)
	}
}

// A 429 that names no delay is waited out for a stated default, not for none.
func TestAThrottleThatNamesNoDelayIsWaitedOutForTheDefault(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/groups", 1, -1)
	w.mustRun("")

	if len(w.waited) != 1 || w.waited[0] != collect.DefaultThrottleWait {
		t.Errorf("waited %v, want the default %v", w.waited, collect.DefaultThrottleWait)
	}
}

// The reads outside a part's own pages are throttled as often as any, and a
// README that says a 429 is honoured cannot mean only some of them.
func TestEverySingleReadWaitsOutAThrottleToo(t *testing.T) {
	for _, c := range []struct {
		name, path, flags string
		check             func(t *testing.T, out *capture)
	}{
		{"the organization", "/v1.0/organization", "", func(t *testing.T, out *capture) {
			if out.diag("entra.organization.unreadable") != nil {
				t.Error("a throttle on the organization cost its name")
			}
		}},
		{"the activity probe", "/v1.0/users", "", func(t *testing.T, out *capture) {
			if !out.scopes[0].ActivityAvailable {
				t.Errorf("a throttle on the activity probe made activity %+v", out.scopes[0])
			}
		}},
		{"a name lookup", "/v1.0/servicePrincipals/" + fakegraph.GUID("sp-graph"), `{"oauth2_grants":true}`, func(t *testing.T, out *capture) {
			e := out.node("", "NODE_TYPE_ENTITLEMENT", "oauth2-grant:g1")
			if e == nil || !strings.Contains(e.GetName(), "Microsoft Graph") {
				t.Errorf("grant = %v, want the API named after the throttle", e)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, withGrants())
			w.srv.Throttle(c.path, 1, 2)
			out := w.mustRun(c.flags)

			if len(w.waited) < 1 || w.waited[0] != 2*time.Second {
				t.Errorf("waited %v, want the 2 seconds Graph asked for", w.waited)
			}
			c.check(t, out)
		})
	}
}

func TestTheCheckWaitsOutAThrottleToo(t *testing.T) {
	w := newWorld(t, directory())
	w.srv.Throttle("/v1.0/users", 2, 1)
	p := w.probe("")

	if !p.Reachable || p.Activity.State != collect.ActivityAvailable {
		t.Errorf("probe = %+v, want it to wait the throttle out", p)
	}
	if len(w.waited) != 2 {
		t.Errorf("waited %v", w.waited)
	}
}

// Confirming that a type of member is unreadable is one read per type, so a
// throttle on it must not decide the type is fine for the rest of the stream.
func TestAThrottleOnTheConfirmingReadDoesNotMarkATypeReadable(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true // alice, in Engineering
	w := newWorld(t, d)
	w.srv.Throttle("/v1.0/users/"+alice, 1, 1)
	w.srv.Refuse("/v1.0/users/"+alice, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "User.Read.All") {
		t.Errorf("err = %v, want the throttle waited out and the refusal found", err)
	}
}

// And a read that could not be answered at all is tried again on the next
// member of that type, not taken for an answer.
func TestAConfirmingReadThatCannotBeAnsweredIsTriedAgainOnAnotherMember(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true // alice
	d.Groups[0].Members[1].IDOnly = true // bob
	w := newWorld(t, d)
	w.srv.Outage("/v1.0/users/"+alice, 100, 0)
	w.srv.Refuse("/v1.0/users/"+bob, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges.")

	_, err := w.run("", collector.CollectRequest{})
	if err == nil || !strings.Contains(err.Error(), "User.Read.All") {
		t.Errorf("err = %v, want bob's refusal to settle what alice's outage could not", err)
	}
}

func TestAConfirmingReadThatNeverAnswersIsSaidAndNotTakenForReadable(t *testing.T) {
	d := directory()
	d.Groups[0].Members[0].IDOnly = true
	w := newWorld(t, d)
	w.srv.Outage("/v1.0/users/"+alice, 100, 0)
	out := w.mustRun("")

	if diag := out.diag("entra.members.unconfirmed"); diag == nil || !strings.Contains(diag.GetMessage(), "user") {
		t.Errorf("diagnostic = %v, want it to say whether users can be read could not be found out", diag)
	}
}

// Each type of member is confirmed once, however many come back id-only.
func TestEachTypeOfIDOnlyMemberIsConfirmedOnce(t *testing.T) {
	d := directory()
	for i := range d.Groups[0].Members[:2] {
		d.Groups[0].Members[i].IDOnly = true
	}
	d.Groups[3].Members[0].IDOnly = true // alice again, in Admins
	w := newWorld(t, d)
	w.mustRun("")

	n := 0
	for _, r := range w.srv.Requests() {
		if strings.HasPrefix(r.Path, "/v1.0/users/") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d reads of single users to confirm the type, want 1", n)
	}
}

// A next-page link that repeats would loop for ever, kept alive by heartbeats.
func TestAPageLinkThatRepeatsEndsTheReadInsteadOfLoopingForEver(t *testing.T) {
	w := newWorld(t, directory())
	link := w.srv.URL + "/v1.0/users?$skiptoken=1"
	w.srv.Respond("/v1.0/users", http.StatusOK, "application/json", `{"value":[],"@odata.nextLink":"`+link+`"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out := &capture{t: t}
	err := w.runner("").Collect(ctx, collector.CollectRequest{}, out)

	if ctx.Err() != nil {
		t.Fatal("the collection looped until it was cancelled")
	}
	if err == nil || !strings.Contains(err.Error(), "same page link") {
		t.Errorf("err = %v, want the repeated link named", err)
	}
}
