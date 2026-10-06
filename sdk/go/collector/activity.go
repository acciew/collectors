package collector

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// Activity constructors.
//
// There is no constructor that takes a bare timestamp, because there is no
// honest activity record that is one. A reviewer deciding whether an account
// is dormant needs to know how far back the source can see and how stale the
// reading is; without both, "no logins" and "we cannot see that far back" are
// the same picture, and only one of them means the account is unused.

// Window is how far back the source can see. Both bounds are required.
//
// Getting `since` right matters more than it looks. For Keycloak it is the
// later of the oldest event you can actually observe and now minus the realm's
// event expiration — not simply now minus the expiration, because a realm
// where event storage was switched on last week has nothing from last month,
// and claiming a month-long window would report those users as inactive inside
// it.
func Window(since, until time.Time) *collectorv1.CoverageWindow {
	return &collectorv1.CoverageWindow{
		Since: timestamppb.New(since),
		Until: timestamppb.New(until),
	}
}

// Seen records that the source reports activity, and when.
func Seen(subject *collectorv1.Key, signal string, observedAt time.Time,
	coverage *collectorv1.CoverageWindow, sourceLag time.Duration,
	lastSeen time.Time, confidence collectorv1.Confidence) *collectorv1.Activity {
	a := activity(subject, signal, observedAt, coverage, sourceLag)
	a.Result = &collectorv1.Activity_Seen{Seen: &collectorv1.Seen{
		LastSeen:   timestamppb.New(lastSeen),
		Confidence: confidence,
	}}
	return a
}

// NotSeen records that the source reports no activity within the window.
//
// This is a claim about the window, not about all time, which is why the
// window is not optional. The confidence matters too: an aggregated "not
// accessed" is a weaker statement than an empty log.
func NotSeen(subject *collectorv1.Key, signal string, observedAt time.Time,
	coverage *collectorv1.CoverageWindow, sourceLag time.Duration,
	confidence collectorv1.Confidence) *collectorv1.Activity {
	a := activity(subject, signal, observedAt, coverage, sourceLag)
	a.Result = &collectorv1.Activity_NotSeen{NotSeen: &collectorv1.NotSeen{Confidence: confidence}}
	return a
}

// Unavailable records that the source cannot answer for this subject at all.
//
// Use it rather than NotSeen whenever the absence of data is about us and not
// about the principal — a Keycloak realm with event storage off, an Access
// Advisor job that failed for one role. Reporting either of those as "never
// used" retires live accounts. It takes no window because there is no window
// to describe.
func Unavailable(subject *collectorv1.Key, signal string, observedAt time.Time,
	code, reason string) *collectorv1.Activity {
	return &collectorv1.Activity{
		Subject:    subject,
		Signal:     signal,
		ObservedAt: timestamppb.New(observedAt),
		Result: &collectorv1.Activity_Unavailable{Unavailable: &collectorv1.Unavailable{
			Code: code, Reason: reason,
		}},
	}
}

func activity(subject *collectorv1.Key, signal string, observedAt time.Time,
	coverage *collectorv1.CoverageWindow, sourceLag time.Duration) *collectorv1.Activity {
	return &collectorv1.Activity{
		Subject:    subject,
		Signal:     signal,
		ObservedAt: timestamppb.New(observedAt),
		Coverage:   coverage,
		SourceLag:  durationpb.New(sourceLag),
	}
}
