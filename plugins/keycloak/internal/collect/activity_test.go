package collect_test

import (
	"context"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func (c *capture) activities() map[string]*collectorv1.Activity {
	out := map[string]*collectorv1.Activity{}
	for _, e := range c.events {
		if a := e.GetActivity(); a != nil {
			out[a.GetSubject().GetId()] = a
		}
	}
	return out
}

func (c *capture) diagnostics() []string { return c.diagCodes }

func collectWithEvents(t *testing.T, cfg admin.EventsConfig, events []admin.Event) (*capture, bool) {
	t.Helper()
	src := realm()
	src.eventsConfig = cfg
	src.events = events

	out := &capture{t: t}
	available, err := collect.Realm(context.Background(), src, admin.Realm{Realm: "probe", Enabled: live()}, now, out)
	if err != nil {
		t.Fatalf("Realm: %v", err)
	}
	return out, available == collect.ActivityAvailableForScope
}

func eventsOn(expiration int64, types ...string) admin.EventsConfig {
	if len(types) == 0 {
		types = []string{"LOGIN", "CLIENT_LOGIN"}
	}
	return admin.EventsConfig{EventsEnabled: true, EventsExpiration: expiration, EnabledEventTypes: types}
}

// The failure this whole file exists to prevent. A realm that records nothing
// must not report anyone as never used: "we cannot see" and "nobody logged
// in" are different claims and only one of them retires an account.
func TestARealmWithEventStorageOffAnswersForNobody(t *testing.T) {
	out, available := collectWithEvents(t, admin.EventsConfig{EventsEnabled: false}, nil)

	if available {
		t.Error("a realm with storage off cannot answer about activity")
	}
	if got := out.activities(); len(got) != 0 {
		t.Errorf("emitted %d activity records for a realm that records nothing", len(got))
	}
	// Said once, at the scope, rather than once per user: a realm of ten
	// thousand people would otherwise produce ten thousand identical records
	// that all mean the same thing.
	var warned bool
	for _, code := range out.diagnostics() {
		if code == "keycloak.events.disabled" {
			warned = true
		}
	}
	if !warned {
		t.Error("an operator should be told why there is no activity, and that turning it on cannot fill in the past")
	}
}

// The finding that would otherwise have shipped: a service account
// authenticating by client credentials produces CLIENT_LOGIN, not LOGIN.
func TestAServiceAccountIsAnsweredForByClientLogin(t *testing.T) {
	out, _ := collectWithEvents(t, eventsOn(0), []admin.Event{
		{Type: "CLIENT_LOGIN", UserID: "u-svc", Time: now.Add(-2 * time.Hour).UnixMilli()},
		{Type: "LOGIN", UserID: "u-alice", Time: now.Add(-time.Hour).UnixMilli()},
	})

	acts := out.activities()
	svc, ok := acts["u-svc"]
	if !ok {
		t.Fatal("the service account got no activity record")
	}
	if svc.GetSignal() != collect.SignalClientLogin {
		t.Errorf("signal = %q, want the client-login signal", svc.GetSignal())
	}
	if svc.GetSeen() == nil {
		t.Fatalf("the service account should be seen, got %T", svc.GetResult())
	}
	if !svc.GetSeen().GetLastSeen().AsTime().Equal(now.Add(-2 * time.Hour)) {
		t.Errorf("last seen = %v", svc.GetSeen().GetLastSeen().AsTime())
	}
	// And a person is answered for by LOGIN, from the same read.
	if alice := acts["u-alice"]; alice.GetSignal() != collect.SignalLogin || alice.GetSeen() == nil {
		t.Errorf("alice = %+v", alice)
	}
}

// Every principal gets an answer. Silence about one person is what a reviewer
// reads as "never used".
func TestEveryPrincipalIsAccountedFor(t *testing.T) {
	out, available := collectWithEvents(t, eventsOn(0), []admin.Event{
		{Type: "LOGIN", UserID: "u-alice", Time: now.Add(-time.Hour).UnixMilli()},
	})
	if !available {
		t.Fatal("the realm should be able to answer")
	}

	acts := out.activities()
	for _, id := range []string{"u-alice", "u-mallory", "u-svc"} {
		if _, ok := acts[id]; !ok {
			t.Errorf("%s has no activity record at all", id)
		}
	}
	// Mallory has no events, which is a claim about the window rather than
	// about all time.
	if acts["u-mallory"].GetNotSeen() == nil {
		t.Errorf("mallory = %T, want a not-seen result", acts["u-mallory"].GetResult())
	}
}

// Storage on, but the type that would answer for these principals is not
// among the recorded ones. That is unanswerable rather than "never".
func TestATypeThatIsNotRecordedIsUnanswerableRatherThanNever(t *testing.T) {
	out, available := collectWithEvents(t, eventsOn(0, "LOGIN"), []admin.Event{
		{Type: "LOGIN", UserID: "u-alice", Time: now.Add(-time.Hour).UnixMilli()},
	})
	if !available {
		t.Fatal("the realm still answers for people")
	}

	svc := out.activities()["u-svc"]
	if svc.GetUnavailable() == nil {
		t.Fatalf("the service account = %T, want unavailable: CLIENT_LOGIN is not recorded", svc.GetResult())
	}
	if out.activities()["u-alice"].GetSeen() == nil {
		t.Error("a person is still answerable from LOGIN")
	}
}

func TestStorageOnButNoLoginTypesRecordedAnswersForNobody(t *testing.T) {
	out, available := collectWithEvents(t, eventsOn(0, "LOGOUT", "REFRESH_TOKEN"), nil)

	if available {
		t.Error("a realm recording neither login type cannot answer about activity")
	}
	if got := out.activities(); len(got) != 0 {
		t.Errorf("emitted %d records anyway", len(got))
	}
}

// The most recent event per principal is the answer, whatever order the log
// arrives in.
func TestTheMostRecentEventWins(t *testing.T) {
	out, _ := collectWithEvents(t, eventsOn(0), []admin.Event{
		{Type: "LOGIN", UserID: "u-alice", Time: now.Add(-72 * time.Hour).UnixMilli()},
		{Type: "LOGIN", UserID: "u-alice", Time: now.Add(-time.Hour).UnixMilli()},
		{Type: "LOGIN", UserID: "u-alice", Time: now.Add(-48 * time.Hour).UnixMilli()},
	})

	seen := out.activities()["u-alice"].GetSeen()
	if !seen.GetLastSeen().AsTime().Equal(now.Add(-time.Hour)) {
		t.Errorf("last seen = %v, want the most recent", seen.GetLastSeen().AsTime())
	}
}

// A realm that cannot answer about activity is not the same as a realm that
// could not be reached, and the two must not be collapsed either way.
//
// A missing role will not change on a retry, so the population stands and the
// activity answer is withheld. A 503 will change on a retry, and swallowing
// it would turn a blip into a permanent "nothing is known" with no resume
// point — the reviewer looking at the next run cannot tell it happened.
func TestActivityDegradesOnAPermissionAndFailsTheRealmOnABlip(t *testing.T) {
	for _, c := range []struct {
		name     string
		err      error
		degrades bool
	}{
		{"a missing role", &admin.Error{
			Kind: admin.KindPermission, Status: 403, Message: "no view-events"}, true},
		{"an unwell Keycloak", &admin.Error{
			Kind: admin.KindUnavailable, Retryable: true, Status: 503, Message: "unwell"}, false},
		{"a rate limit", &admin.Error{
			Kind: admin.KindRateLimited, Retryable: true, Status: 429, Message: "slow down"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Both reads, because they fail the same way for the same
			// reasons and only one of them was covered.
			for _, at := range []string{"the configuration", "the log"} {
				t.Run(at, func(t *testing.T) {
					src := realm()
					if at == "the configuration" {
						src.eventsErr = c.err
					} else {
						src.eventsConfig = eventsOn(0)
						src.eventLogErr = c.err
					}
					runActivityCase(t, src, c.degrades)
				})
			}
		})
	}
}

func runActivityCase(t *testing.T, src *fakeSource, degrades bool) {
	t.Helper()

	out := &capture{t: t}
	available, err := collect.Realm(context.Background(), src,
		admin.Realm{Realm: "probe", Enabled: live()}, now, out)
	switch {
	case degrades && err != nil:
		t.Fatalf("the population was readable and the realm failed anyway: %v", err)
	case !degrades && err == nil:
		t.Fatal("a failure worth retrying was answered around, so nothing is left to retry")
	}
	// Neither a refusal nor a failure is an answer about whether the realm
	// records anything: the scope has to say it could not find out.
	if available != collect.ActivityUndetermined {
		t.Errorf("answer = %v, want undetermined when the event log could not be read", available)
	}
	if !degrades {
		return
	}
	var warned bool
	for _, code := range out.diagnostics() {
		if code == "keycloak.events.unreadable" {
			warned = true
		}
	}
	if !warned {
		t.Error("an operator should be told why there is no activity for anyone here")
	}
}
