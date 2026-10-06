package collect

import (
	"context"
	"errors"
	"fmt"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/sdk/go/collector"
)

// Last-activity, and the several ways it can mislead.
//
// Keycloak stores no last-login field. Activity comes from the realm event
// log, and three things about that log shape everything here.
//
// It is off by default, so most realms answer nothing at all — which is not
// the same as answering "nobody logged in", and must not be reported as one.
//
// It only reaches back as far as the realm's retention allows, so a claim of
// "never" is only ever a claim about a window, and the window has to travel
// with it.
//
// And LOGIN is not the whole story: a service account authenticating by
// client credentials produces CLIENT_LOGIN, so a collector that asks only for
// LOGIN reports every service account as never used. In a real tenant that is
// a large fraction of the principals, and it is exactly the population a
// dormant-account review would then retire.
const (
	// SignalLogin is an interactive login by a person.
	SignalLogin = "login_event"
	// SignalClientLogin is a service account obtaining a token.
	SignalClientLogin = "client_login_event"
)

// keycloakLogin and keycloakClientLogin are the event types behind those
// signals.
const (
	keycloakLogin       = "LOGIN"
	keycloakClientLogin = "CLIENT_LOGIN"
)

// eventPageSize bounds one read of the event log. The log can be very large,
// and the collector wants the most recent entry per principal rather than the
// whole history.
const eventPageSize = 5000

// activityFor emits one record per principal in a realm.
//
// Every principal gets one, or the scope says it cannot answer for any of
// them. Silence about a particular person is the one thing a reviewer reads
// as "never used", so it is not an option.
func activityFor(ctx context.Context, src Source, realm string, now time.Time,
	people []principal, out collector.Stream) (ActivityAvailable, error) {
	// Not being allowed to read the event configuration says nothing about
	// whether the identities were collected. The population is whole either
	// way; only the activity answer is withheld, which is what the Unavailable
	// arm of the signal is for. Failing the realm here would report an
	// incomplete scope for a complete one — the opposite mistake, but a
	// mistake, and it is the one that made `check` and `collect` disagree.
	cfg, err := src.EventsConfig(ctx, realm)
	if err != nil && !denied(err) {
		// A timeout, a 503, a wrong path: none is an answer about activity,
		// they are the absence of one. Degrading here would turn a blip into
		// a permanent "nothing is known" in a scheduled run, with nothing to
		// resume — and the check says the same about the same error, which
		// is the point.
		return ActivityUnavailable, err
	}
	if err != nil {
		return ActivityUndetermined, out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"keycloak.events.unreadable",
			"could not read the event configuration for realm "+realm+
				", so no last-activity is available for anyone in it and whether this realm "+
				"records activity at all is unknown: "+err.Error())
	}
	if !cfg.EventsEnabled {
		// Nothing to say about anyone here, and saying it once at the scope
		// spares a realm of ten thousand users ten thousand identical
		// records that all mean "we cannot see".
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"keycloak.events.disabled",
			"event storage is off for realm "+realm+", so no last-activity is available for anyone in it; "+
				"turning it on records from that moment and cannot fill in the past",
		); err != nil {
			return ActivityUnavailable, err
		}
		return ActivityUnavailable, nil
	}

	wanted := enabledAmong(cfg.EnabledEventTypes, keycloakLogin, keycloakClientLogin)
	if len(wanted) == 0 {
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"keycloak.events.no_login_types",
			"event storage is on for realm "+realm+" but neither LOGIN nor CLIENT_LOGIN is enabled, "+
				"so no last-activity is available",
		); err != nil {
			return ActivityUnavailable, err
		}
		return ActivityUnavailable, nil
	}

	events, err := src.Events(ctx, realm, wanted, eventPageSize)
	if err != nil && !denied(err) {
		return ActivityUnavailable, err
	}
	if err != nil {
		// Same reasoning as the configuration read above: the population
		// stands, the activity answer does not.
		return ActivityUndetermined, out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"keycloak.events.unreadable",
			"event storage is on for realm "+realm+" but the log could not be read, so no "+
				"last-activity is available for anyone in it: "+err.Error())
	}

	latest := map[string]time.Time{}
	// Per event type, because the two signals are read from one log: twenty
	// service accounts authenticating every few seconds would otherwise
	// narrow every person's window to the span of their traffic.
	oldest := map[string]time.Time{}
	for _, e := range events {
		at := time.UnixMilli(e.Time).UTC()
		if o, ok := oldest[e.Type]; !ok || at.Before(o) {
			oldest[e.Type] = at
		}
		key := e.UserID + "\x00" + e.Type
		if seen, ok := latest[key]; !ok || at.After(seen) {
			latest[key] = at
		}
	}

	// One read of the newest events. Filling the page means there is more
	// history we did not look at, so every window below starts later than
	// the realm can actually see and every NotSeen is narrower than it
	// looks. Saying so is the difference between a bounded answer and a
	// misleading one.
	if len(events) >= eventPageSize {
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"keycloak.events.truncated",
			fmt.Sprintf("realm %s returned the maximum %d events, so activity is answered only "+
				"across the period they span; older history was not read", realm, eventPageSize),
		); err != nil {
			return ActivityUnavailable, err
		}
	}

	for _, p := range people {
		signal, eventType := SignalLogin, keycloakLogin
		if p.service {
			signal, eventType = SignalClientLogin, keycloakClientLogin
		}
		// A principal whose event type is not being recorded cannot be
		// answered for, even though the realm records something else.
		if !contains(wanted, eventType) {
			if err := out.Activity(collector.Unavailable(
				collector.IdentityKey(realm, p.id), signal, now,
				"keycloak.events.type_disabled",
				"realm "+realm+" does not record "+eventType,
			)); err != nil {
				return ActivityAvailableForScope, err
			}
			continue
		}

		subject := collector.IdentityKey(realm, p.id)
		window := coverage(now, oldest[eventType])
		if window == nil {
			// Nothing of this type has ever been recorded, so there is no
			// window to answer across. "We cannot see" is not "nobody
			// logged in", and only one of those retires an account.
			if err := out.Activity(collector.Unavailable(
				subject, signal, now, "keycloak.events.no_history",
				"realm "+realm+" holds no "+eventType+" events at all, so how far back the log "+
					"reaches cannot be established",
			)); err != nil {
				return ActivityAvailableForScope, err
			}
			continue
		}
		if at, ok := latest[p.id+"\x00"+eventType]; ok {
			// The event log records the event itself, so the timestamp is
			// exact and there is no lag between the thing happening and
			// Keycloak knowing it.
			if err := out.Activity(collector.Seen(subject, signal, now, window, 0,
				at, collector.Exact)); err != nil {
				return ActivityAvailableForScope, err
			}
			continue
		}
		if err := out.Activity(collector.NotSeen(subject, signal, now, window, 0,
			collector.Exact)); err != nil {
			return ActivityAvailableForScope, err
		}
	}
	return ActivityAvailableForScope, nil
}

// coverage works out how far back this realm can be proved to see, and
// returns nil when nothing establishes a lower bound at all.
//
// eventsExpiration is an upper bound on retention, not a statement that the
// realm was recording that long ago: storage may have been switched on
// yesterday, a moment Keycloak does not expose. So the window starts at the
// oldest event actually held, which is the only lower bound we can prove.
// That under-claims coverage on a quiet realm — a year of silence looks like
// a week of it — and under-claiming is the safe direction. Over-claiming
// would mark people NotSeen across a period nothing was being recorded.
//
// With no events of this signal at all there is no lower bound to be had,
// and a window with no lower bound is the one claim in an activity record a
// reviewer cannot check. The caller answers Unavailable instead.
func coverage(now, oldestObserved time.Time) *collectorv1.CoverageWindow {
	if oldestObserved.IsZero() || oldestObserved.After(now) {
		return nil
	}
	// The oldest event actually held, and nothing later. Keycloak's expiry is
	// a scheduled task, so lowering eventsExpiration leaves older events in
	// the log until it runs; clamping the window forward to the configured
	// retention would put a sighting we are holding outside the window the
	// record says we can see. The contract rejects that, and the whole realm
	// fails over an ordinary retention setting. The realm demonstrably can
	// see back to this event, because it just handed it to us.
	return collector.Window(oldestObserved, now)
}

func enabledAmong(enabled []string, wanted ...string) []string {
	var out []string
	for _, w := range wanted {
		if contains(enabled, w) {
			out = append(out, w)
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// principal is a collected identity and whether it is a service account,
// which decides which event type answers for it.
type principal struct {
	id      string
	service bool
}

// denied says the source refused this read because of a missing permission,
// as opposed to failing for any of the other reasons a call can fail.
//
// It is the whole of the rule above, and of the same rule in the check. A
// missing role is a fact about the realm that will not change on a retry, and
// a reviewer is better served by a complete population with activity marked
// unavailable. Everything else may change on a retry, and answering around it
// loses the signal with nothing left to resume.
//
// The distinction is also what separates advice an operator can act on from
// advice that sends them to change something that was never the problem.
func denied(err error) bool {
	var ae *admin.Error
	return errors.As(err, &ae) && ae.Kind == admin.KindPermission
}
