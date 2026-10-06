package collect

import (
	"fmt"
	"time"

	"go.acciew.io/collector/plugins/awsiam/internal/iam"
	"go.acciew.io/collector/sdk/go/collector"
)

// The three signals AWS offers, and the sentinel that makes them dangerous.
//
// A user has two independent credentials — a console password and up to two
// access keys — and they are different facts. Observed on a real account: one
// user last signed in to the console long ago with no active key, another
// used a key recently. Merging them into one "last used" loses which
// credential a reviewer would take away.
//
// A role has one, and it arrives with the data the collection already
// fetches.
//
// The sentinel is the whole problem. AWS answers `no_information` for a
// password that has never been used *or* was last used before it began
// recording, which are different facts and only one of them would justify
// retiring an account. It answers `N/A` for an access key in the same
// position. Read as "never", either one reports the account root — the most
// privileged principal there is — as dormant.
const (
	SignalConsolePassword = "console_password"
	SignalAccessKey       = "access_key"
	SignalRoleLastUsed    = "role_last_used"
)

// Tracking is when AWS began recording each signal. Reported as the lower
// bound of the coverage window, because "not used in the covered period" is
// only a claim if the period is stated — and before these dates AWS has
// nothing to say about anybody.
//
// The dates are AWS's own, from its documentation of each field.
var (
	passwordTrackingBegan = time.Date(2014, 10, 20, 0, 0, 0, 0, time.UTC)
	// Access keys are six months later than passwords, and claiming the
	// earlier date would assert half a year of coverage that never existed —
	// on a signal that can produce a definite negative.
	accessKeyTrackingBegan = time.Date(2015, 4, 22, 0, 0, 0, 0, time.UTC)
	// Roles are per region, and AWS switched tracking on at different times.
	// This is a floor, taken late on purpose because a window that starts too
	// early is a claim about a period nobody was recording. The trailing 400
	// days below is what bounds a window today.
	roleTrackingBegan = time.Date(2020, 4, 27, 0, 0, 0, 0, time.UTC)
)

// roleReportedFor is how far back AWS reports a role's last use: the trailing
// 400 days. A role last assumed longer ago than that looks the same as one
// never assumed, so a window reaching further back would claim a period in
// which "not seen" could be wrong.
const roleReportedFor = 400 * 24 * time.Hour

// roleWindowStart is where a role's coverage window begins: the later of when
// AWS began recording and the trailing 400 days.
func roleWindowStart(readAt time.Time) time.Time {
	if start := readAt.Add(-roleReportedFor); start.After(roleTrackingBegan) {
		return start
	}
	return roleTrackingBegan
}

// userActivity emits what is known about one user's credentials.
func userActivity(scope string, u iam.User, c iam.Credentials, report iam.CredentialReport,
	now time.Time, out collector.Stream) error {
	subject := collector.IdentityKey(scope, u.ID)
	// How stale the answer may be. AWS caches the report and tells us when it
	// made this one, so the lag is a fact rather than a guess.
	lag := now.Sub(report.GeneratedAt)
	if lag < 0 {
		lag = 0
	}
	passwordWindow := collector.Window(passwordTrackingBegan, report.GeneratedAt)
	keyWindow := collector.Window(accessKeyTrackingBegan, report.GeneratedAt)

	switch {
	case !c.PasswordEnabled:
		// No console password at all. Not "never signed in": there is
		// nothing that could have been used.
		if err := out.Activity(collector.Unavailable(subject, SignalConsolePassword, now,
			"aws.password.none", "this user has no console password, so there is nothing "+
				"to have used")); err != nil {
			return err
		}
	case c.PasswordUnknown:
		// AWS's own "no_information", which means never used *or* used
		// before it started recording. Reported as what it is.
		if err := out.Activity(collector.Unavailable(subject, SignalConsolePassword, now,
			"aws.password.no_information",
			fmt.Sprintf("AWS reports no information for this password, which means either that "+
				"it has never been used or that it was last used before AWS began recording on %s",
				passwordTrackingBegan.Format("2 January 2006")))); err != nil {
			return err
		}
	case !c.PasswordLastUsed.IsZero():
		if err := out.Activity(collector.Seen(subject, SignalConsolePassword, now,
			passwordWindow, lag, c.PasswordLastUsed, collector.Exact)); err != nil {
			return err
		}
	default:
		if err := out.Activity(collector.NotSeen(subject, SignalConsolePassword, now,
			passwordWindow, lag, collector.Exact)); err != nil {
			return err
		}
	}

	// Each key is its own answer. A user with a stale key and a fresh one is
	// not "active"; they have one credential worth taking away.
	for _, k := range c.Keys {
		if !k.Active {
			continue
		}
		signal := fmt.Sprintf("%s_%d", SignalAccessKey, k.Number)
		switch {
		case k.Unknown:
			if err := out.Activity(collector.Unavailable(subject, signal, now,
				"aws.access_key.not_used_since_recording_began",
				"AWS has no record of this key being used, which means either that it never "+
					"has been or that it was last used before AWS began recording")); err != nil {
				return err
			}
		case !k.LastUsed.IsZero():
			if err := out.Activity(collector.Seen(subject, signal, now, keyWindow, lag,
				k.LastUsed, collector.Exact)); err != nil {
				return err
			}
		default:
			if err := out.Activity(collector.NotSeen(subject, signal, now, keyWindow, lag,
				collector.Exact)); err != nil {
				return err
			}
		}
	}
	return nil
}

// roleActivity emits what AWS says about a role's use.
//
// Roles are the largest identity class in a real account by a long way —
// observed to outnumber users by a wide margin — so this is the signal that decides
// whether an AWS review is worth anything.
func roleActivity(scope string, r iam.Role, readAt, now time.Time, out collector.Stream) error {
	subject := collector.IdentityKey(scope, r.ID)
	// The window ends when the record was read, not now: the account takes
	// minutes to paginate, and claiming to see up to this instant would
	// cover a period after we stopped looking.
	window := collector.Window(roleWindowStart(readAt), readAt)
	lag := now.Sub(readAt)
	if lag < 0 {
		lag = 0
	}

	if r.LastUsed.IsZero() {
		// The field arrives empty for a role AWS has no record of. Not
		// "never assumed": tracking began at a date, and a role last used
		// before it looks identical to one never used at all.
		return out.Activity(collector.Unavailable(subject, SignalRoleLastUsed, now,
			"aws.role.not_used_since_recording_began",
			"AWS has no record of this role being assumed, which means either that it never "+
				"has been or that it was last assumed more than 400 days ago, the furthest back "+
				"AWS reports"))
	}
	// The value AWS returns is the region's, and it is near real time.
	return out.Activity(collector.Seen(subject, SignalRoleLastUsed, now, window, lag,
		r.LastUsed, collector.Exact))
}
