package collect_test

import (
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
)

// The coverage window is the only part of a NotSeen record a reviewer can
// check. Get it wrong and "not seen" becomes either a lie or a tautology.

func activityFor(t *testing.T, out *capture, userID string) *collectorv1.Activity {
	t.Helper()
	for _, e := range out.events {
		if a := e.GetActivity(); a != nil && a.GetSubject().GetId() == userID {
			return a
		}
	}
	t.Fatalf("no activity record for %q", userID)
	return nil
}

func loginEvent(userID string, at time.Time) admin.Event {
	return admin.Event{Type: "LOGIN", UserID: userID, Time: at.UnixMilli()}
}

// A quiet realm answers across the period it can prove it was recording, and
// no further. The oldest event held is that proof; configured retention is
// not, because storage may have been switched on yesterday.
func TestTheWindowStartsAtTheOldestEventActuallyHeld(t *testing.T) {
	oldest := now.Add(-72 * time.Hour)
	out, available := collectWithEvents(t, eventsOn(30*24*3600), []admin.Event{
		loginEvent("u-alice", now.Add(-time.Hour)),
		loginEvent("someone-else", oldest),
	})
	if !available {
		t.Fatal("a realm with storage on can answer")
	}

	a := activityFor(t, out, "u-mallory")
	since := a.GetCoverage().GetSince().AsTime()
	if since.Sub(oldest).Abs() > time.Second {
		t.Errorf("coverage starts %v, want the oldest event held %v", since, oldest)
	}
	if a.GetNotSeen() == nil {
		t.Errorf("result = %v, want not-seen across the provable window", a.GetResult())
	}
}

// Storage on and nothing in the log: there is no window to answer across, so
// there is no answer. A point window called NotSeen is a claim about nothing
// that reads like a claim about someone.
func TestAnEmptyLogCannotBeAnswered(t *testing.T) {
	for _, expiration := range []int64{0, 30 * 24 * 3600} {
		out, _ := collectWithEvents(t, eventsOn(expiration), nil)
		a := activityFor(t, out, "u-alice")
		if a.GetUnavailable() == nil {
			t.Errorf("expiration %d: result = %v, want unavailable", expiration, a.GetResult())
		}
	}
}

// The two signals are read from one log. A service account authenticating
// every few seconds must not narrow the window every person is judged by.
func TestABusyServiceAccountDoesNotNarrowThePeopleWindow(t *testing.T) {
	oldLogin := now.Add(-30 * 24 * time.Hour)
	out, _ := collectWithEvents(t, eventsOn(0), []admin.Event{
		loginEvent("u-alice", oldLogin),
		{Type: "CLIENT_LOGIN", UserID: "u-svc", Time: now.Add(-time.Minute).UnixMilli()},
	})

	person := activityFor(t, out, "u-mallory")
	since := person.GetCoverage().GetSince().AsTime()
	if since.Sub(oldLogin).Abs() > time.Second {
		t.Errorf("a person's window starts %v, want the oldest LOGIN %v", since, oldLogin)
	}
}

// One read of the newest events. A full page means there is older history we
// did not look at, so every window is narrower than the realm can see. Silent
// truncation makes a bounded answer misleading.
func TestAFullPageOfEventsIsReportedAsTruncated(t *testing.T) {
	var many []admin.Event
	for i := range 5000 {
		many = append(many, loginEvent("u-alice", now.Add(-time.Duration(i)*time.Second)))
	}
	out, _ := collectWithEvents(t, eventsOn(30*24*3600), many)

	var found bool
	for _, code := range out.diagnostics() {
		if code == "keycloak.events.truncated" {
			found = true
		}
	}
	if !found {
		t.Errorf("a full page was not reported as truncated: %v", out.diagnostics())
	}
}

// Keycloak's expiry is a scheduled task, so lowering eventsExpiration leaves
// older events in the log until it runs. Clamping the window forward past an
// event we are actually holding makes the sighting fall outside its own
// coverage — which the contract rejects, failing the whole realm. An ordinary
// retention setting made a realm uncollectable.
func TestASightingIsNeverOutsideItsOwnWindow(t *testing.T) {
	old := now.Add(-72 * time.Hour)
	out, _ := collectWithEvents(t, eventsOn(3600), []admin.Event{loginEvent("u-alice", old)})

	a := activityFor(t, out, "u-alice")
	seen := a.GetSeen()
	if seen == nil {
		t.Fatalf("result = %v, want a sighting", a.GetResult())
	}
	at := seen.GetLastSeen().AsTime()
	since := a.GetCoverage().GetSince().AsTime()
	until := a.GetCoverage().GetUntil().AsTime()
	if at.Before(since) || at.After(until) {
		t.Errorf("the sighting %v is outside its window %v..%v", at, since, until)
	}
	// And the record has to be one the contract accepts, or the realm fails.
	if vs := collectorv1.ValidateActivity(a); len(vs) > 0 {
		t.Errorf("the record is invalid: %s", vs[0])
	}
}
