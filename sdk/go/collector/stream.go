package collector

import (
	"errors"
	"fmt"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
)

// Stream is where a collector puts what it finds.
//
// Every method validates before sending, so a malformed record comes back to
// you as an error at the call site rather than as a collection the host
// rejects with a field path you then have to trace. The error is the contract
// telling you now instead of later.
type Stream interface {
	// Node emits a vertex.
	Node(*collectorv1.Node) error
	// Edge emits a relationship.
	Edge(*collectorv1.Edge) error
	// Activity emits a last-seen signal.
	Activity(*collectorv1.Activity) error

	// Checkpoint offers a point the host can resume from. Emit at least one,
	// and emit it only when it is true that everything before it has been
	// sent: a cursor that skips records is worse than no cursor.
	Checkpoint(cursor []byte) error

	// Progress reports liveness and pacing: which phase you are in, or that
	// you are waiting on a rate limit.
	//
	// Nothing sends one for you. The contract asks a collector to emit some
	// event at least as often as CollectRequest.Heartbeat so a caller can
	// tell "slow" from "stuck"; a collector that goes quiet for an hour
	// between pages has to say so itself.
	Progress(phase string, rateLimit *RateLimit) error

	// ScopeDone records what happened to one scope. Call it once for every
	// scope you discovered, whether or not you collected it: the host uses
	// these to decide whether the population may be presented as whole, and a
	// scope you never mention is one it cannot account for.
	ScopeDone(ScopeResult) error

	// Diagnostic records something evidence-grade that is not a record and
	// not a failure: "event storage is on but LOGIN is not in
	// enabledEventTypes". It travels with the snapshot rather than to stderr,
	// because a reviewer may need to know it.
	Diagnostic(severity collectorv1.Severity, code, message string) error
}

// ScopeResult is what happened to one isolation boundary.
type ScopeResult struct {
	// A scope key, from Scope().
	Scope *collectorv1.Key
	// One of Collected, Skipped, Partial or Unreachable.
	Status collectorv1.ScopeStatus
	// Required for Partial and Unreachable. Say what an operator has to fix.
	Err error
	// Whether activity data exists for this scope at all.
	ActivityAvailable bool
	// ActivityUndetermined says the collection could not find out whether
	// this scope answers about activity — the read that would have told us
	// failed, typically on a permission or because the scope failed before we
	// asked. Distinct from ActivityAvailable being false, which is the source
	// saying it records nothing: this is nobody having asked successfully,
	// and it sends an operator to check a credential rather than to switch
	// something on.
	ActivityUndetermined bool
}

// Scope outcomes. Skipped means excluded by request: the caller asked for
// less and got exactly that, so it does not make the population partial.
const (
	Collected   = collectorv1.ScopeStatus_SCOPE_STATUS_COLLECTED
	Partial     = collectorv1.ScopeStatus_SCOPE_STATUS_PARTIAL
	Unreachable = collectorv1.ScopeStatus_SCOPE_STATUS_UNREACHABLE
	Skipped     = collectorv1.ScopeStatus_SCOPE_STATUS_SKIPPED
)

// RateLimit is what the source says about its own limits. Every field is
// optional: GitHub publishes headers, AWS throttles reactively and tells you
// nothing until it does, and Keycloak has no limit at all.
type RateLimit struct {
	Remaining  *int64
	Limit      *int64
	ResetsAt   time.Time
	RetryAfter time.Duration
}

// Incomplete tells the host that the population is not whole.
//
// Return it from Collect rather than nil whenever a scope was not fully
// collected, for any reason. The host turns it into an error for the caller,
// which is the whole point: a truncated population that looks complete is
// worse than a failure, because the error is invisible exactly when it does
// damage.
type Incomplete struct {
	// Why. Use the constants below.
	Cause collectorv1.IncompleteCause
	// A cursor the caller can resume from, if you have one. Omit it only when
	// the sole recovery is a fresh collection.
	ResumeFrom []byte
	// The underlying failure, if there was one.
	Err error
}

// Reasons a collection can end incomplete.
const (
	RateLimited      = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_RATE_LIMITED
	BudgetExhausted  = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_BUDGET_EXHAUSTED
	ScopeUnreachable = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_SCOPE_UNREACHABLE
	SourceFailed     = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_SOURCE_ERROR
	// PartialStream says this stream resumed from a cursor and is therefore
	// only part of the population, whatever it managed to collect.
	PartialStream = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_PARTIAL_STREAM
	// InvalidConfig says the configuration could not be used, so the source
	// was never reached. Reporting that as SourceFailed sends an operator to
	// look at something that did nothing wrong.
	InvalidConfig = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_INVALID_CONFIG
	// InvalidCursor says a resume cursor could not be used and this collector
	// refused rather than starting over, so nothing was collected. Saying
	// PartialStream instead would report a continuation that never arrived.
	InvalidCursor = collectorv1.IncompleteCause_INCOMPLETE_CAUSE_INVALID_CURSOR
)

func (e *Incomplete) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("collection incomplete (%v): %v", e.Cause, e.Err)
	}
	return fmt.Sprintf("collection incomplete (%v)", e.Cause)
}

func (e *Incomplete) Unwrap() error { return e.Err }

// AsIncomplete reports whether an error says the population is not whole.
func AsIncomplete(err error) (*Incomplete, bool) {
	var inc *Incomplete
	ok := errors.As(err, &inc)
	return inc, ok
}
