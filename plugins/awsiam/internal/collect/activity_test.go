package collect_test

import (
	"testing"
	"time"

	"strings"

	"go.acciew.io/collector/plugins/awsiam/internal/iam"
)

// AWS answers "no_information" for a password that has never been used *or*
// was last used before it began recording in 2014. Two different facts in one
// value, and only one of them would justify retiring an account. Observed on
// a real account: the value the account root came back with.
func TestNoInformationIsNotReportedAsNeverUsed(t *testing.T) {
	out := collectAccount(t, account())

	a := out.activityFor("root", "console_password")
	if a == nil {
		t.Fatal("nothing was said about the root account's password")
	}
	if a.GetNotSeen() != nil {
		t.Error("AWS's \"no information\" was reported as a definite negative; " +
			"the account root would read as dormant")
	}
	if a.GetUnavailable() == nil {
		t.Fatalf("result = %v, want unavailable", a.GetResult())
	}
	// And it has to say which of the two it might be, or the reader will
	// assume the wrong one.
	if !strings.Contains(a.GetUnavailable().GetReason(), "never been used") ||
		!strings.Contains(a.GetUnavailable().GetReason(), "began recording") {
		t.Errorf("the reason does not say what the sentinel means: %q",
			a.GetUnavailable().GetReason())
	}
}

// A role AWS has no record of is not a role nobody has assumed. Tracking
// began on a date, and a role last used before it looks identical to one
// never used at all. Observed on a real account: many roles on a page.
func TestARoleWithNoRecordIsNotReportedAsNeverAssumed(t *testing.T) {
	out := collectAccount(t, account())

	a := out.activityFor("AROAEXAMPLE2", "role_last_used")
	if a == nil {
		t.Fatal("nothing was said about the role")
	}
	if a.GetNotSeen() != nil {
		t.Error("a role with no record was reported as never assumed")
	}
	if a.GetUnavailable() == nil {
		t.Errorf("result = %v, want unavailable", a.GetResult())
	}
}

// A role AWS does have a record of is a real sighting, with a window that
// starts when AWS began recording rather than at the beginning of time.
func TestARoleThatWasAssumedIsReportedWithABoundedWindow(t *testing.T) {
	out := collectAccount(t, account())

	a := out.activityFor("AROAEXAMPLE1", "role_last_used")
	if a.GetSeen() == nil {
		t.Fatalf("result = %v, want a sighting", a.GetResult())
	}
	// The window never starts before AWS recorded anything, because starting
	// earlier claims coverage of a period nobody was recording in.
	since := a.GetCoverage().GetSince().AsTime()
	if since.Before(time.Date(2019, 7, 8, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("the window starts %v, before AWS recorded anything", since)
	}
	at := a.GetSeen().GetLastSeen().AsTime()
	if at.Before(since) || at.After(a.GetCoverage().GetUntil().AsTime()) {
		t.Errorf("the sighting %v is outside its own window", at)
	}
}

// AWS reports a role's last use only for the trailing 400 days. A window that
// reaches back further claims a period in which a role that was assumed would
// still look unused, and "not seen" inside it would be false.
func TestARoleWindowNeverReachesBackFurtherThanAWSReports(t *testing.T) {
	out := collectAccount(t, account())

	a := out.activityFor("AROAEXAMPLE1", "role_last_used")
	since := a.GetCoverage().GetSince().AsTime()
	until := a.GetCoverage().GetUntil().AsTime()
	if limit := until.Add(-400 * 24 * time.Hour); since.Before(limit) {
		t.Errorf("the window starts %v, more than 400 days before it ends (%v)", since, until)
	}
}

// A user's console password and their access keys are different facts. One
// user was observed last signing in long ago with no active key, and
// another using a key recently; merging them loses which credential a
// reviewer would take away.
func TestAPasswordAndAnAccessKeyAreSeparateAnswers(t *testing.T) {
	out := collectAccount(t, account())

	password := out.activityFor("AIDAEXAMPLE1", "console_password")
	key := out.activityFor("AIDAEXAMPLE1", "access_key_1")
	if password == nil || key == nil {
		t.Fatal("a user's two credentials were not answered for separately")
	}
	if password.GetSeen() == nil || key.GetSeen() == nil {
		t.Fatalf("password %v, key %v", password.GetResult(), key.GetResult())
	}
	if password.GetSeen().GetLastSeen().AsTime().Equal(key.GetSeen().GetLastSeen().AsTime()) {
		t.Error("the two credentials were given one answer")
	}
}

// A key AWS has no record of is not an unused key, for the same reason.
func TestAKeyWithNoRecordIsNotReportedAsUnused(t *testing.T) {
	a := collectAccount(t, account()).activityFor("AIDAEXAMPLE1", "access_key_2")
	if a == nil {
		t.Fatal("the second key was not answered for")
	}
	if a.GetUnavailable() == nil {
		t.Errorf("result = %v, want unavailable", a.GetResult())
	}
}

// A user with no console password has nothing that could have been used.
// "Never signed in" would be a claim about a credential that does not exist.
func TestAUserWithNoPasswordIsNotReportedAsNeverSigningIn(t *testing.T) {
	src := account()
	src.report.Rows[0].PasswordEnabled = false
	src.report.Rows[0].PasswordLastUsed = time.Time{}

	a := collectAccount(t, src).activityFor("AIDAEXAMPLE1", "console_password")
	if a.GetNotSeen() != nil {
		t.Error("a user with no console password was reported as never having used one")
	}
	if a.GetUnavailable() == nil {
		t.Errorf("result = %v, want unavailable", a.GetResult())
	}
}

// The report is cached by AWS, and it says when it was made. That is how
// stale every answer in it may be, and it is a fact rather than a guess.
func TestTheReportsOwnStalenessTravelsWithEveryAnswer(t *testing.T) {
	out := collectAccount(t, account())
	a := out.activityFor("AIDAEXAMPLE1", "console_password")
	lag := a.GetSourceLag().AsDuration()
	if lag != 30*time.Minute {
		t.Errorf("source lag = %v, want the age of the credential report", lag)
	}
}

// An inactive key is not a credential anybody can use, and answering about it
// would put a row in front of a reviewer that has nothing to decide.
func TestAnInactiveKeyIsNotAnsweredFor(t *testing.T) {
	src := account()
	src.report.Rows[0].Keys = []iam.AccessKey{{Number: 1, Active: false}}
	if a := collectAccount(t, src).activityFor("AIDAEXAMPLE1", "access_key_1"); a != nil {
		t.Errorf("an inactive key was answered for: %v", a.GetResult())
	}
}

// Access keys and passwords have different start dates: AWS began recording
// key use six months after password use. Claiming the earlier date on a key
// asserts half a year of coverage that never existed, on a signal that can
// produce a definite negative.
func TestEachSignalsWindowStartsWhenAWSStartedRecordingThatSignal(t *testing.T) {
	out := collectAccount(t, account())

	password := out.activityFor("AIDAEXAMPLE1", "console_password")
	key := out.activityFor("AIDAEXAMPLE1", "access_key_1")
	if password == nil || key == nil {
		t.Fatal("both signals should be answered for")
	}
	pSince := password.GetCoverage().GetSince().AsTime()
	kSince := key.GetCoverage().GetSince().AsTime()
	if !kSince.After(pSince) {
		t.Errorf("access keys start %v and passwords %v; AWS began recording key use "+
			"later, and claiming otherwise covers a period that was never recorded",
			kSince, pSince)
	}
}

// The account takes minutes to paginate. A window ending "now" covers a
// period after the reading stopped.
func TestARoleWindowEndsWhenTheAccountWasReadNotNow(t *testing.T) {
	src := account()
	readAt := now.Add(-4 * time.Minute)
	src.snap.ReadAt = readAt

	a := collectAccount(t, src).activityFor("AROAEXAMPLE1", "role_last_used")
	if got := a.GetCoverage().GetUntil().AsTime(); !got.Equal(readAt) {
		t.Errorf("the window ends %v, want when the account was read (%v)", got, readAt)
	}
	if lag := a.GetSourceLag().AsDuration(); lag != 4*time.Minute {
		t.Errorf("source lag = %v, want how long ago the account was read", lag)
	}
}
