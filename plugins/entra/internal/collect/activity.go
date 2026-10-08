package collect

import (
	"context"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Last activity, and the ways it can mislead.
//
// A user's signInActivity holds three timestamps, and they are three different
// facts. lastSignInDateTime and lastNonInteractiveSignInDateTime count failed
// attempts as well as successes, so neither says the person got in;
// lastSuccessfulSignInDateTime does, and Entra began recording it on 1
// December 2023 without backfilling it.
//
// A value is blank for a user who never signed in that way and for one whose
// last attempt was before the signal began, and the two cannot be told apart.
// That is the same trap as AWS's "no information": read as "never", it retires
// a live account. So a blank is reported as unanswerable, never as not seen,
// and not seen is never emitted at all.
const (
	// SignalInteractive is the last interactive sign-in attempt, failed or not.
	SignalInteractive = "interactive_sign_in_attempt"
	// SignalNonInteractive is the last non-interactive attempt, failed or not.
	SignalNonInteractive = "non_interactive_sign_in_attempt"
	// SignalSuccessful is the last sign-in that succeeded.
	SignalSuccessful = "successful_sign_in"
	// SignalServicePrincipal is an application's sign-in. It is always
	// unavailable: a service principal's sign-ins are a separate surface that
	// this collector does not read.
	SignalServicePrincipal = "service_principal_sign_in"
)

// Codes of the unavailable answers.
const (
	codeNoSignIn = "entra.no-sign-in-recorded"
	codeSPSignIn = "entra.sp-sign-in-not-collected"
)

// sourceLag is how stale Entra says a value may be: up to 24 hours to update.
const sourceLag = 24 * time.Hour

// signal is one of the three timestamps of signInActivity.
type signal struct {
	name string
	// since is when Entra began recording it. Microsoft gives April and May
	// 2020 as months, and a month is not a day, so these are the ends of those
	// months: later is the direction that cannot claim a period in which
	// nothing was recorded.
	since  time.Time
	value  func(*graph.SignInActivity) *time.Time
	began  string
	notice string
}

var signals = []signal{
	{
		name:  SignalInteractive,
		since: time.Date(2020, 4, 30, 0, 0, 0, 0, time.UTC),
		value: func(a *graph.SignInActivity) *time.Time { return a.LastSignIn },
		began: "April 2020",
		notice: "an interactive sign-in attempt, which includes failed ones, so it does not say the " +
			"person got in",
	},
	{
		name:  SignalNonInteractive,
		since: time.Date(2020, 5, 31, 0, 0, 0, 0, time.UTC),
		value: func(a *graph.SignInActivity) *time.Time { return a.LastNonInteractiveSignIn },
		began: "May 2020",
		notice: "a non-interactive sign-in attempt, made by a client on the person's behalf, which " +
			"includes failed ones",
	},
	{
		name:   SignalSuccessful,
		since:  time.Date(2023, 12, 1, 0, 0, 0, 0, time.UTC),
		value:  func(a *graph.SignInActivity) *time.Time { return a.LastSuccessfulSignIn },
		began:  "1 December 2023, and it was not backfilled",
		notice: "a successful sign-in",
	},
}

// blank says Entra holds no value: absent, null, or the zero time.
func blank(t *time.Time) bool { return t == nil || t.IsZero() || t.Year() <= 1 }

// emitActivity writes one record per signal for a user.
func (st *state) emitActivity(u graph.User) error {
	subject := collector.IdentityKey(st.tenant, u.ID)
	for _, sig := range signals {
		var last *time.Time
		if u.SignInActivity != nil {
			last = sig.value(u.SignInActivity)
		}
		if blank(last) {
			if err := st.out.Activity(collector.Unavailable(subject, sig.name, st.observed, codeNoSignIn,
				"Entra holds no value for "+sig.notice+". That means the user has never signed in this way, "+
					"or last did before Entra began recording it ("+sig.began+"); the two cannot be told apart")); err != nil {
				return err
			}
			continue
		}
		seen := last.UTC()
		since := laterOf(sig.since, st.created)
		until := st.observed
		// The sighting is evidence of how far the source can see. A window
		// that excludes it is a wrong window, and the contract refuses it.
		if seen.Before(since) {
			since = seen
		}
		if seen.After(until) {
			until = seen
		}
		if err := st.out.Activity(collector.Seen(subject, sig.name, st.observed, collector.Window(since, until),
			sourceLag, seen, collector.Exact)); err != nil {
			return err
		}
	}
	return nil
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// emitUnreadSPActivity says an application has no sign-in activity collected.
func (st *state) emitUnreadSPActivity(subject *collectorv1.Key) error {
	if st.activity.State != ActivityAvailable {
		return nil
	}
	return st.out.Activity(collector.Unavailable(subject, SignalServicePrincipal, st.observed, codeSPSignIn,
		"an application's sign-ins are a separate surface that this collector does not read, so nothing "+
			"is known about when it last signed in"))
}

// announceActivity decides whether users are read with their sign-in activity,
// and says why not when they are not.
//
// It is decided once, before any user is read: users are read with the activity
// the tenant answers, or without it. A probe the tenant cannot answer for an
// outage decides "could not find out" and the collection goes on; one that
// cannot be answered for want of patience, a throttle that will not end, decides
// nothing and stops the stream.
func (st *state) announceActivity(ctx context.Context) error {
	answer, err := probeActivity(ctx, st.Graph, st.retrying)
	if err != nil {
		st.activity = ActivityAnswer{State: ActivityUndetermined, Note: answer.Note}
		return err
	}
	st.activity = answer
	switch st.activity.State {
	case ActivityUnavailable:
		return st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.activity.unavailable", st.activity.Note)
	case ActivityUndetermined:
		return st.out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "entra.activity.undetermined", st.activity.Note)
	}
	return nil
}
