package collect_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/collect"
	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
)

// signedIn is a tenant whose users have all three kinds of answer: one who has
// signed in every way, one who has only tried, one with nothing recorded.
func signedIn() *fakegraph.Tenant {
	d := directory()
	d.Users[0].SignIn = &fakegraph.SignIn{ // alice
		Interactive:    time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC),
		NonInteractive: time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC),
		Successful:     time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC),
	}
	// bob: nothing at all
	d.Users[2].SignIn = &fakegraph.SignIn{ // carol has tried and never got in
		Interactive: time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC),
	}
	d.Users[3].SignIn = &fakegraph.SignIn{} // dave: Graph returned the property, every value null
	return d
}

func TestEachUserHasOneRecordPerSignalAndEachSaysHowStaleItMayBe(t *testing.T) {
	out := newWorld(t, signedIn()).mustRun("")

	got := out.activities(alice)
	for signal, last := range map[string]time.Time{
		"interactive_sign_in_attempt":     time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC),
		"non_interactive_sign_in_attempt": time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC),
		"successful_sign_in":              time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC),
	} {
		a := got[signal]
		if a == nil || a.GetSeen() == nil {
			t.Errorf("%s: %v, want a sighting", signal, a)
			continue
		}
		if !a.GetSeen().GetLastSeen().AsTime().Equal(last) || a.GetSeen().GetConfidence() != collectorv1.Confidence_CONFIDENCE_EXACT {
			t.Errorf("%s: seen %v (%v), want %v exactly", signal, a.GetSeen().GetLastSeen().AsTime(), a.GetSeen().GetConfidence(), last)
		}
		// Entra documents up to a day before a value is current.
		if a.GetSourceLag().AsDuration() != 24*time.Hour {
			t.Errorf("%s: lag %v, want the 24 hours Entra documents", signal, a.GetSourceLag().AsDuration())
		}
		if !a.GetCoverage().GetUntil().AsTime().Equal(now) {
			t.Errorf("%s: window ends %v, want when it was read", signal, a.GetCoverage().GetUntil().AsTime())
		}
	}
	if len(got) != 3 {
		t.Errorf("%d records for alice, want one per signal (3): %v", len(got), got)
	}
	out.assertContract()
}

// Entra answers a sign-in it has no record of with a blank. That is a user who
// never signed in, or one whose last attempt was before the signal began, and
// the two cannot be told apart. Reported as not seen it would retire an account
// on a gap in Entra's memory.
func TestABlankSignInIsUnavailableAndNeverNotSeen(t *testing.T) {
	out := newWorld(t, signedIn()).mustRun("")

	// Bob has no signInActivity at all, dave has one with nothing in it, and
	// carol has never succeeded.
	for _, c := range []struct{ who, signal string }{
		{bob, "interactive_sign_in_attempt"}, {bob, "non_interactive_sign_in_attempt"}, {bob, "successful_sign_in"},
		{dave, "interactive_sign_in_attempt"}, {dave, "successful_sign_in"},
		{carol, "non_interactive_sign_in_attempt"}, {carol, "successful_sign_in"},
	} {
		a := out.activities(c.who)[c.signal]
		if a == nil || a.GetUnavailable().GetCode() != "entra.no-sign-in-recorded" {
			t.Errorf("%s / %s = %v, want unavailable with entra.no-sign-in-recorded", c.who[:4], c.signal, a)
		}
	}
	// What carol did record is a sighting, an attempt and not a success.
	if a := out.activities(carol)["interactive_sign_in_attempt"]; a == nil || a.GetSeen() == nil {
		t.Errorf("carol's interactive attempt = %v", a)
	}
	notSeen := out.count(func(e *collectorv1.CollectResponse) bool { return e.GetActivity().GetNotSeen() != nil })
	if notSeen != 0 {
		t.Errorf("%d activity records say not seen; a blank is two facts in one value and no window can say which", notSeen)
	}
	out.assertContract()
}

func TestTheSuccessfulSignInSaysItWasNeverBackfilled(t *testing.T) {
	out := newWorld(t, signedIn()).mustRun("")

	reason := out.activities(bob)["successful_sign_in"].GetUnavailable().GetReason()
	if !strings.Contains(reason, "1 December 2023") {
		t.Errorf("reason = %q; it must say the signal began on 1 December 2023", reason)
	}
	if reason := out.activities(bob)["interactive_sign_in_attempt"].GetUnavailable().GetReason(); !strings.Contains(reason, "April 2020") {
		t.Errorf("reason = %q; it must say interactive records begin in April 2020", reason)
	}
}

// The window is how far back Entra can be proved to see: no earlier than the
// signal began, and no earlier than the tenant existed.
func TestTheWindowStartsAtTheLaterOfTheSignalAndTheTenant(t *testing.T) {
	d := signedIn() // created 9 March 2021
	out := newWorld(t, d).mustRun("")

	got := out.activities(alice)
	if since := got["interactive_sign_in_attempt"].GetCoverage().GetSince().AsTime(); !since.Equal(d.Created) {
		t.Errorf("interactive since %v, want the tenant's creation (%v): it is later than April 2020", since, d.Created)
	}
	if since := got["successful_sign_in"].GetCoverage().GetSince().AsTime(); !since.Equal(time.Date(2023, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("successful since %v, want 1 December 2023: it is later than the tenant", since)
	}

	old := signedIn()
	old.Created = time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	got = newWorld(t, old).mustRun("").activities(alice)
	// The documentation says April and May 2020, and a month is not a day, so
	// the window starts at the end of it: later is the direction that cannot
	// claim a period nothing was recorded.
	if since := got["interactive_sign_in_attempt"].GetCoverage().GetSince().AsTime(); since.Before(time.Date(2020, 4, 30, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("interactive since %v, want no earlier than the end of April 2020", since)
	}
	if since := got["non_interactive_sign_in_attempt"].GetCoverage().GetSince().AsTime(); since.Before(time.Date(2020, 5, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("non-interactive since %v, want no earlier than the end of May 2020", since)
	}
}

// A sighting outside its own window is a contract violation, and one record
// would fail the whole collection. The sighting is evidence the source could
// see that far back, so the window follows it.
func TestASightingOutsideTheWindowWidensTheWindowAndDoesNotFailTheTenant(t *testing.T) {
	d := signedIn()
	early := time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC)
	skewed := now.Add(5 * time.Second)
	d.Users[0].SignIn = &fakegraph.SignIn{Interactive: early, NonInteractive: skewed, Successful: skewed}
	out := newWorld(t, d).mustRun("")

	a := out.activities(alice)["interactive_sign_in_attempt"]
	if !a.GetCoverage().GetSince().AsTime().Equal(early) {
		t.Errorf("window starts %v, want it to reach back to the sighting", a.GetCoverage().GetSince().AsTime())
	}
	b := out.activities(alice)["non_interactive_sign_in_attempt"]
	if b.GetCoverage().GetUntil().AsTime().Before(skewed) {
		t.Errorf("window ends %v, before a sighting %v", b.GetCoverage().GetUntil().AsTime(), skewed)
	}
	out.assertContract()
}

func TestActivityIsReportedOncePerScopeAsAvailable(t *testing.T) {
	out := newWorld(t, signedIn()).mustRun("")

	if len(out.scopes) != 1 || !out.scopes[0].ActivityAvailable || out.scopes[0].ActivityUndetermined {
		t.Errorf("scopes = %+v, want activity available", out.scopes)
	}
}

func TestSignInActivityIsAskedForOnlyWhenTheTenantAnswersAndInPagesOfAtMost500(t *testing.T) {
	w := newWorld(t, signedIn())
	w.mustRun("")

	var asked int
	for _, p := range w.srv.Paths() {
		if !strings.Contains(p, "signInActivity") || !strings.HasPrefix(p, "/v1.0/users") {
			continue
		}
		asked++
		q, _ := url.ParseQuery(p[strings.Index(p, "?")+1:])
		if top, _ := strconv.Atoi(q.Get("$top")); top > 500 {
			t.Errorf("signInActivity asked for in pages of %d: %s", top, p)
		}
	}
	if asked < 2 {
		t.Errorf("%d requests carried signInActivity, want the probe and the users", asked)
	}
}

func TestATenantThatCannotAnswerAboutActivityIsReadWithoutAskingAgainAndSaysWhy(t *testing.T) {
	for _, c := range []struct {
		name         string
		refusal      fakegraph.Refusal
		code         string
		undetermined bool
	}{
		{"for want of a licence", fakegraph.Refusal{Status: http.StatusForbidden, Code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", Message: "Neither tenant is B2C or tenant doesn't have premium license"}, "entra.activity.unavailable", false},
		{"for want of anything we recognise", fakegraph.Refusal{Status: http.StatusForbidden, Code: "Authorization_RequestDenied", Message: "Insufficient privileges."}, "entra.activity.undetermined", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := signedIn()
			d.ActivityRefusal = &c.refusal
			w := newWorld(t, d)
			out := w.mustRun("")

			if out.diag(c.code) == nil {
				t.Errorf("no %s diagnostic: %v", c.code, out.diags)
			}
			if n := out.count(func(e *collectorv1.CollectResponse) bool { return e.GetActivity() != nil }); n != 0 {
				t.Errorf("%d activity records from a tenant that cannot answer; silence is the one thing a reviewer reads as never", n)
			}
			if s := out.scopes[0]; s.ActivityAvailable || s.ActivityUndetermined != c.undetermined {
				t.Errorf("scope = %+v", s)
			}
			// The users were still collected, and without asking for what would be refused.
			if out.node("", "NODE_TYPE_IDENTITY", alice) == nil {
				t.Error("a tenant without the licence lost its users")
			}
			probes := 0
			for _, p := range w.srv.Paths() {
				if strings.Contains(p, "signInActivity") {
					probes++
				}
			}
			if probes != 1 {
				t.Errorf("%d requests carried signInActivity, want only the probe", probes)
			}
			out.assertContract()
		})
	}
}

// An application holding a role is named and not read, and not reading it is
// said, not left as silence.
func TestAnApplicationNamedByARoleHasNoSignInActivityAndSaysSo(t *testing.T) {
	d := signedIn()
	sp := fakegraph.GUID("sp")
	d.RoleAssignments = append(d.RoleAssignments, fakegraph.RoleAssignment{
		ID: "ra9", Principal: sp, PrincipalType: "servicePrincipal", PrincipalName: "Some App",
		RoleDefID: helpdesk, Scope: "/",
	})
	out := newWorld(t, d).mustRun(`{"service_principals":false}`)

	a := out.activities(sp)["service_principal_sign_in"]
	if a == nil || a.GetUnavailable().GetCode() != "entra.sp-sign-in-not-collected" {
		t.Errorf("activity = %v, want unavailable with entra.sp-sign-in-not-collected", a)
	}
	out.assertContract()
}

func TestTheSignalsTheCollectorDeclaresAreTheOnesItEmits(t *testing.T) {
	want := map[string]bool{
		collect.SignalInteractive: true, collect.SignalNonInteractive: true,
		collect.SignalSuccessful: true, collect.SignalServicePrincipal: true,
	}
	out := newWorld(t, signedIn()).mustRun("")
	for _, e := range out.events {
		if a := e.GetActivity(); a != nil && !want[a.GetSignal()] {
			t.Errorf("emitted signal %q, which is not one of the declared names", a.GetSignal())
		}
	}
}
