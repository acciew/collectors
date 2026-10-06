package collect_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// A collection that did not cover everything it was asked for must say so.
// A truncated population presented as a whole one is the worst thing this
// product can produce, and every case below used to produce one.

// failingSource fails for one named realm and behaves normally otherwise.
type failingSource struct {
	*fakeSource
	failFor string
	err     error
}

func (f failingSource) Users(ctx context.Context, realm string) ([]admin.User, error) {
	if realm == f.failFor {
		return nil, f.err
	}
	return f.fakeSource.Users(ctx, realm)
}

func (c *capture) scopeStatus() map[string]collectorv1.ScopeStatus {
	out := map[string]collectorv1.ScopeStatus{}
	for _, r := range c.scopes {
		out[r.Scope.GetId()] = r.Status
	}
	return out
}

// runAll drives the collection and then checks the stream it produced is one
// the SDK would actually send.
func runAll(t *testing.T, src collect.Source, realms []admin.Realm,
	req collector.CollectRequest, out *capture) error {
	t.Helper()
	err := collect.All(context.Background(), src, realms, req, out)
	out.checkStreamIsSendable()
	return err
}

func realmList(names ...string) []admin.Realm {
	out := make([]admin.Realm, 0, len(names))
	for _, n := range names {
		out = append(out, admin.Realm{Realm: n, Enabled: live()})
	}
	return out
}

// One realm failing used to return nil, which the SDK reads as "complete".
// The completion then contradicted its own scope outcomes, the SDK refused to
// send it, and the host reported a transport failure — losing the verdict and
// every good realm's data along with it.
func TestARealmThatFailsMakesTheWholeCollectionIncomplete(t *testing.T) {
	boom := errors.New("keycloak said no")
	src := failingSource{fakeSource: realm(), failFor: "broken", err: boom}
	out := &capture{t: t}

	err := runAll(t, src, realmList("probe", "broken"),
		collector.CollectRequest{}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want an incomplete verdict", err)
	}
	if inc.Cause != collector.ScopeUnreachable {
		t.Errorf("cause = %v, want scope unreachable", inc.Cause)
	}
	status := out.scopeStatus()
	if status["probe"] != collector.Collected {
		t.Errorf("the good realm = %v, want collected", status["probe"])
	}
	if status["broken"] != collector.Partial {
		t.Errorf("the failed realm = %v, want partial", status["broken"])
	}
}

// A realm named in the config that the credentials cannot see produced no
// scope outcome at all and a COMPLETE verdict: the operator asked for two
// realms, got one, and was told the population was whole.
func TestARealmAskedForAndNotVisibleIsReported(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("probe"),
		collector.CollectRequest{Scopes: []string{"probe", "ghost"}}, out)

	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want an incomplete verdict", err)
	}
	if got := out.scopeStatus()["ghost"]; got != collector.Unreachable {
		t.Errorf("the invisible realm = %v, want unreachable", got)
	}
}

func TestCollectingEverythingThatWasAskedForIsComplete(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, realm(), realmList("probe"),
		collector.CollectRequest{}, out); err != nil {
		t.Fatalf("All: %v", err)
	}
	if got := out.scopeStatus()["probe"]; got != collector.Collected {
		t.Errorf("status = %v, want collected", got)
	}
}

// Narrowing by request is not a partial population: the caller asked for less
// and got exactly that.
func TestARealmExcludedByRequestDoesNotMakeThePopulationPartial(t *testing.T) {
	out := &capture{t: t}
	if err := runAll(t, realm(), realmList("probe", "other"),
		collector.CollectRequest{Scopes: []string{"probe"}}, out); err != nil {
		t.Fatalf("All: %v", err)
	}
	if got := out.scopeStatus()["other"]; got != collector.Skipped {
		t.Errorf("status = %v, want skipped", got)
	}
}

// A checkpoint that cannot be resumed from is worse than none: the host
// records a cursor, hands it back, and gets a full re-collection with every
// record duplicated.
func TestResumingSkipsWhatTheCursorAlreadyCovered(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("a", "probe", "z"),
		collector.CollectRequest{ResumeFrom: cursorFor("a", "probe")}, out)

	// A resumed stream is never a whole population on its own.
	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want incomplete", err)
	}
	if inc.Cause != collector.PartialStream {
		t.Errorf("cause = %v, want partial stream", inc.Cause)
	}
	status := out.scopeStatus()
	if _, ok := status["a"]; ok {
		t.Errorf("a realm the cursor already covered was collected again: %v", status)
	}
	if status["z"] != collector.Collected {
		t.Errorf("the realm the cursor had not covered = %v, want collected", status["z"])
	}
}

// A cursor that cannot be read at all is refused: silently starting from the
// beginning would duplicate everything the caller already holds.
func TestAnUnreadableCursorIsRefusedRatherThanIgnored(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("probe"),
		collector.CollectRequest{ResumeFrom: []byte("not json at all")}, out)
	if err == nil {
		t.Fatal("want an error for a cursor that cannot be read")
	}
	if len(out.scopeStatus()) != 0 {
		t.Error("something was collected against an unreadable cursor")
	}
}

// A cursor naming a realm that has since been deleted is not a reason to
// re-collect everything: the realm is gone, and there is nothing to skip.
func TestACursorNamingARealmThatIsGoneIsStillUsable(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("probe"),
		collector.CollectRequest{ResumeFrom: cursorFor("deleted-realm")}, out)
	if _, ok := collector.AsIncomplete(err); !ok {
		t.Fatalf("err = %v, want incomplete: a resumed stream is part of a population", err)
	}
	if got := out.scopeStatus()["probe"]; got != collector.Collected {
		t.Errorf("probe = %v, want collected", got)
	}
}

func cursorFor(realms ...string) []byte {
	raw, err := json.Marshal(struct {
		Collected []string `json:"collected"`
	}{Collected: realms})
	if err != nil {
		panic(err)
	}
	return raw
}

// A budget is a promise to stop, and stopping without saying so leaves a
// partial population looking whole.
func TestExhaustingTheBudgetEndsIncompleteWithSomethingToResumeFrom(t *testing.T) {
	out := &capture{t: t}
	err := runAll(t, realm(), realmList("probe", "second"),
		collector.CollectRequest{MaxRecords: 1}, out)
	_ = err

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("err = %v, want an incomplete verdict", err)
	}
	if inc.Cause != collector.BudgetExhausted {
		t.Errorf("cause = %v, want budget exhausted", inc.Cause)
	}
	if len(inc.ResumeFrom) == 0 {
		t.Error("a budget stop has to say where to resume from")
	}
}

// The whole-collection shape of the doubt refusal. Realm() returning an error
// is only half the promise: the scope has to be reported partial, the realm
// must not enter the cursor as done, and what was collected must still be in
// the stream. A collection that refused and then said "collected" would be
// the failure this guards, one layer up.
func TestARealmTheTokenCannotSeeAllOfIsPartialNotCollected(t *testing.T) {
	src := realm()
	src.grant = map[string]bool{"view-users": true, "query-clients": true, "view-realm": true}

	out := &capture{t: t, tolerateInvalid: true}
	err := collect.All(context.Background(), src,
		[]admin.Realm{{Realm: "probe", Enabled: live()}},
		collector.CollectRequest{}, out)

	var incomplete *collector.Incomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("want an incomplete collection, got %v", err)
	}
	if incomplete.Cause != collector.ScopeUnreachable {
		t.Errorf("Cause = %v, want scope unreachable", incomplete.Cause)
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collector.Partial {
		t.Fatalf("scope results = %+v, want one partial", out.scopes)
	}
	if out.scopes[0].Err == nil || !strings.Contains(out.scopes[0].Err.Error(), "view-clients") {
		t.Errorf("the scope does not say which role would fix it: %v", out.scopes[0].Err)
	}
	// Not in the cursor: a resume that skipped it would collect the rest and
	// call the population whole with this realm still missing.
	if len(out.checkpoints) == 0 {
		t.Fatal("no checkpoint, so the records emitted cannot be completed")
	}
	if got := string(out.checkpoints[len(out.checkpoints)-1]); strings.Contains(got, "probe") {
		t.Errorf("cursor %s records the realm as done", got)
	}
	if len(out.events) == 0 {
		t.Error("nothing was emitted, so the operator sees a failure and no evidence")
	}
}

// Keycloak answers /admin/realms with the realm's name and nothing else when
// the token cannot read the realm itself — measured on 26.4.7, one key rather
// than a hundred and one. Read as a struct, the missing enabled field is
// false, and a live realm recorded as disabled turns every grant in it into
// one a reviewer skips. That is the product's promise inverted, so it is
// refused rather than guessed.
func TestARealmThatDidNotSayWhetherItIsEnabledIsNotAssumedDisabled(t *testing.T) {
	src := realm()

	out := &capture{t: t, tolerateInvalid: true}
	_, err := collect.Realm(context.Background(), src,
		admin.Realm{Realm: "probe"}, now, out)
	if err == nil {
		t.Fatal("a realm whose own record could not be read was collected anyway; " +
			"its grants are then reported against a realm reported disabled")
	}
	if !strings.Contains(err.Error(), "view-realm") {
		t.Errorf("the error does not name the role that would fix it: %v", err)
	}
}

// Partial says some of it is in the stream. A realm refused before anything
// was read has nothing there, and a reader told "partial" goes looking for
// the part that arrived.
func TestARealmRefusedBeforeAnythingWasReadIsUnreachableNotPartial(t *testing.T) {
	src := realm()

	out := &capture{t: t, tolerateInvalid: true}
	err := collect.All(context.Background(), src,
		[]admin.Realm{{Realm: "probe"}}, collector.CollectRequest{}, out)
	if err == nil {
		t.Fatal("a realm whose own record could not be read was collected anyway")
	}
	if len(out.scopes) != 1 {
		t.Fatalf("scope results = %+v, want one", out.scopes)
	}
	if out.scopes[0].Status != collector.Unreachable {
		t.Errorf("status = %v, want unreachable: nothing was emitted for it", out.scopes[0].Status)
	}
}

// And a realm that emitted records before it failed is partial, because some
// of it is in the stream and saying otherwise throws that away.
func TestARealmThatFailedPartWayThroughIsPartial(t *testing.T) {
	src := realm()
	src.grant = map[string]bool{"view-users": true, "query-clients": true, "view-realm": true}

	out := &capture{t: t, tolerateInvalid: true}
	if err := collect.All(context.Background(), src,
		[]admin.Realm{{Realm: "probe", Enabled: live()}},
		collector.CollectRequest{}, out); err == nil {
		t.Fatal("a realm the token cannot see all of was collected without complaint")
	}
	if len(out.scopes) != 1 || out.scopes[0].Status != collector.Partial {
		t.Fatalf("scope results = %+v, want one partial", out.scopes)
	}
}

// A cursor this build cannot read is not the source's doing, and reporting it
// as a source error sends an operator to look at something that did nothing
// wrong. The contract has a code for exactly this.
func TestAnUnreadableCursorIsNotASourceError(t *testing.T) {
	out := &capture{t: t}
	err := collect.All(context.Background(), realm(),
		[]admin.Realm{{Realm: "probe", Enabled: live()}},
		collector.CollectRequest{ResumeFrom: []byte("this is not a cursor")}, out)

	inc, ok := collector.AsIncomplete(err)
	if !ok {
		t.Fatalf("want an incomplete collection, got %v", err)
	}
	var faulty interface{ Fault() collector.Fault }
	if !errors.As(inc.Err, &faulty) {
		t.Fatalf("the refusal does not classify itself, so it reaches the wire as a source "+
			"error: %v", inc.Err)
	}
	if got := faulty.Fault(); got != collector.FaultInvalidCursor {
		t.Errorf("Fault = %v, want FaultInvalidCursor", got)
	}
	// And the cause, which is what the host reads. PartialStream would say a
	// continuation arrived; nothing was collected at all.
	if inc.Cause != collector.InvalidCursor {
		t.Errorf("Cause = %v, want InvalidCursor", inc.Cause)
	}
}

// Three different answers about activity, and the scope has to carry the
// right one. "This realm records nothing" sends an operator to turn event
// storage on; "the read that would have told us was refused" sends them to
// check a credential. Reporting the second as the first sends them to switch
// on something that may already be on.
func TestAScopeSaysWhichActivityAnswerItHas(t *testing.T) {
	denied := &admin.Error{Kind: admin.KindPermission, Status: 403, Message: "no view-events"}
	partialToken := map[string]bool{"query-users": true, "view-clients": true, "view-realm": true}
	for _, c := range []struct {
		name         string
		setup        func(*fakeSource)
		available    bool
		undetermined bool
	}{
		{"events recorded", func(f *fakeSource) { f.eventsConfig = eventsOn(0) }, true, false},
		{"event storage off", func(f *fakeSource) {
			f.eventsConfig = admin.EventsConfig{EventsEnabled: false}
		}, false, false},
		{"event configuration refused", func(f *fakeSource) { f.eventsErr = denied }, false, true},
		{"event log refused", func(f *fakeSource) {
			f.eventsConfig = eventsOn(0)
			f.eventLogErr = denied
		}, false, true},
		// The realm fails after its events were read: the scope is partial,
		// but whether it records activity was found out and stays found out.
		{"events recorded, population untrusted", func(f *fakeSource) {
			f.eventsConfig = eventsOn(0)
			f.grant = partialToken
		}, true, false},
		{"event storage off, population untrusted", func(f *fakeSource) {
			f.eventsConfig = admin.EventsConfig{EventsEnabled: false}
			f.grant = partialToken
		}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := realm()
			c.setup(src)

			out := &capture{t: t}
			// A failed realm ends the collection incomplete; the scope result
			// is still reported, and that is what this is about.
			err := collect.All(context.Background(), src,
				[]admin.Realm{{Realm: "probe", Enabled: live()}}, collector.CollectRequest{}, out)
			var inc *collector.Incomplete
			if err != nil && !errors.As(err, &inc) {
				t.Fatalf("All: %v", err)
			}
			if len(out.scopes) != 1 {
				t.Fatalf("scope results = %+v, want one", out.scopes)
			}
			got := out.scopes[0]
			if got.ActivityAvailable != c.available || got.ActivityUndetermined != c.undetermined {
				t.Errorf("available=%v undetermined=%v, want available=%v undetermined=%v",
					got.ActivityAvailable, got.ActivityUndetermined, c.available, c.undetermined)
			}
		})
	}
}

// A realm nobody got as far as asking about has no activity answer. The zero
// value would say it records nothing, which sends an operator to switch
// event storage on in a realm they could not even see.
func TestARealmNotReadHasNoActivityAnswer(t *testing.T) {
	for _, c := range []struct {
		name   string
		realms []admin.Realm
		want   []string
	}{
		{"unreadable", []admin.Realm{{Realm: "probe"}}, nil},
		{"named but invisible", nil, []string{"probe"}},
		{"not asked for", []admin.Realm{{Realm: "probe", Enabled: live()}, {Realm: "other", Enabled: live()}},
			[]string{"other"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := realm()
			src.eventsConfig = eventsOn(0)
			out := &capture{t: t}
			err := collect.All(context.Background(), src, c.realms,
				collector.CollectRequest{Scopes: c.want}, out)
			var inc *collector.Incomplete
			if err != nil && !errors.As(err, &inc) {
				t.Fatalf("All: %v", err)
			}
			var probe *collector.ScopeResult
			for i := range out.scopes {
				if out.scopes[i].Scope.GetId() == "probe" {
					probe = &out.scopes[i]
				}
			}
			if probe == nil {
				t.Fatalf("no result for the probe realm in %+v", out.scopes)
			}
			if probe.ActivityAvailable || !probe.ActivityUndetermined {
				t.Errorf("%v: available=%v undetermined=%v, want undetermined",
					probe.Status, probe.ActivityAvailable, probe.ActivityUndetermined)
			}
		})
	}
}
