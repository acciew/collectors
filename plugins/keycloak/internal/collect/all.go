package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/sdk/go/collector"
)

// All collects every realm the caller asked for.
//
// It lives here rather than in main so that the completeness rules — the ones
// a mistake in is most expensive — can be tested without a Keycloak.
//
// The rule the whole function serves: it returns nil only when this stream
// carries every realm that was asked for, collected whole. Anything else is
// an *Incomplete, because a truncated population that reads as a full one is
// worse than a failure.
func All(ctx context.Context, src Source, realms []admin.Realm,
	req collector.CollectRequest, out collector.Stream) error {
	// Ordered so that a run is reproducible and a reader of the stream sees
	// realms in the same order every time.
	sorted := append([]admin.Realm(nil), realms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Realm < sorted[j].Realm })

	wanted := map[string]bool{}
	for _, s := range req.Scopes {
		wanted[s] = true
	}

	resumed := len(req.ResumeFrom) > 0
	done, err := readCursor(req.ResumeFrom)
	if err != nil {
		// Nothing was collected and the population is not here.
		// Not PartialStream: nothing was collected, and saying a
		// continuation arrived when none did is the same overstatement in
		// the other direction.
		return &collector.Incomplete{Cause: collector.InvalidCursor,
			Err: collector.BadCursor(err)}
	}

	run := &collection{out: out, done: done, resumed: resumed}
	deadline := time.Time{}
	if req.MaxDuration > 0 {
		deadline = time.Now().Add(req.MaxDuration)
	}

	for _, r := range sorted {
		// A realm the cursor says is already collected is not looked at
		// again, and gets no scope outcome: this stream did not read it, and
		// claiming otherwise would let a continuation read as a whole
		// collection. The cursor names realms rather than marking a
		// position, so a realm that failed is retried and a realm that
		// appeared since is collected.
		if done[r.Realm] {
			continue
		}
		if len(wanted) > 0 && !wanted[r.Realm] {
			// Excluded by request, which does not make the population
			// partial: the caller asked for less and got exactly that.
			// Undetermined: nobody asked. The zero value says "records nothing".
			if err := out.ScopeDone(collector.ScopeResult{
				Scope: collector.Scope(r.Realm, r.Realm), Status: collector.Skipped,
				ActivityUndetermined: true,
			}); err != nil {
				return err
			}
			continue
		}

		// Checked before each realm rather than mid-realm, because a
		// half-collected realm cannot be resumed from a realm-granular
		// cursor. A realm is the unit this collector can stop at honestly.
		if run.overBudget(req.MaxRecords, deadline) {
			return run.stop(collector.BudgetExhausted)
		}
		if err := run.realm(ctx, src, r); err != nil {
			return err
		}
	}

	// A realm the operator named and the credentials cannot see produced no
	// outcome at all, so the collection reported itself whole while missing
	// exactly the thing that was asked for.
	var missing []string
	for name := range wanted {
		if !done[name] && !ContainsRealm(sorted, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		err := fmt.Errorf("realm %s: the service account cannot see this realm, or it does not exist", name)
		run.failed = append(run.failed, err)
		if reportErr := out.ScopeDone(collector.ScopeResult{
			Scope: collector.Scope(name, name), Status: collector.Unreachable, Err: err,
			ActivityUndetermined: true,
		}); reportErr != nil {
			return reportErr
		}
	}

	switch {
	case len(run.failed) > 0:
		return run.stop(collector.ScopeUnreachable)
	case resumed:
		// Everything left was collected, and this stream is still only the
		// remainder. The host has to combine it with the stream that
		// produced the cursor before anyone calls it a population.
		return run.stop(collector.PartialStream)
	case run.collected == 0:
		return run.stop(collector.ScopeUnreachable)
	}
	return nil
}

// collection is the state one call to All accumulates.
type collection struct {
	out     collector.Stream
	done    map[string]bool
	resumed bool

	records   uint64
	collected int
	failed    []error
}

func (c *collection) realm(ctx context.Context, src Source, r admin.Realm) error {
	counted := &counting{Stream: c.out}
	available, err := Realm(ctx, src, r, time.Now().UTC(), counted)
	c.records += counted.n

	result := collector.ScopeResult{
		Scope: collector.Scope(r.Realm, r.Realm), Status: collector.Collected,
		// Reported per realm because it is a property of the realm: one with
		// event storage off answers nothing for anyone in it, and saying so
		// once beats one identical record per user.
		ActivityAvailable:    available == ActivityAvailableForScope,
		ActivityUndetermined: available == ActivityUndetermined,
	}
	if err != nil {
		// One unreachable realm does not abandon the others: an operator
		// needs the whole picture to fix one thing. The verdict at the end
		// is what stops the rest being read as everything.
		c.failed = append(c.failed, fmt.Errorf("realm %s: %w", r.Realm, err))
		// Partial says some of it is in the stream. A realm refused before
		// anything was read has nothing there, and calling that partial
		// invites a reader to look for the part that arrived.
		status := collector.Partial
		if counted.n == 0 {
			status = collector.Unreachable
		}
		// Realm says undetermined unless it got as far as finding out, so a
		// failed realm is never reported as one that records nothing.
		result.Status, result.Err = status, err
	} else {
		c.done[r.Realm] = true
		c.collected++
	}
	if err := c.out.ScopeDone(result); err != nil {
		return err
	}
	// Checkpointed whether or not the realm succeeded. A realm emits records
	// before it can fail, and a stream carrying records with no checkpoint is
	// one the SDK refuses to complete — losing the verdict and the data
	// together, which for a single-realm Keycloak is every failure.
	return c.out.Checkpoint(c.cursor())
}

// stop ends the collection, naming the cause and handing back a cursor that
// covers everything collected so far.
//
// Failures are carried whatever the cause: a budget that trips after a realm
// failed used to report the budget and drop the failure, so the one thing an
// operator had to fix never reached them.
func (c *collection) stop(cause collectorv1.IncompleteCause) *collector.Incomplete {
	inc := &collector.Incomplete{Cause: cause, ResumeFrom: c.cursor()}
	switch {
	case len(c.failed) > 0:
		inc.Err = errors.Join(c.failed...)
	case cause == collector.ScopeUnreachable && c.collected == 0:
		inc.Err = errors.New("no realm was collected")
	case cause == collector.PartialStream && c.resumed:
		inc.Err = errors.New("this stream continues an earlier one and carries only part of the population")
	}
	return inc
}

func (c *collection) overBudget(limit uint64, deadline time.Time) bool {
	if limit > 0 && c.records >= limit {
		return true
	}
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

// cursor names the realms collected so far.
//
// A set rather than a position. A high-water mark cannot express "beta failed
// and gamma succeeded": the next run would skip beta as already covered and
// never look at it again, while reporting itself complete.
func (c *collection) cursor() []byte {
	names := make([]string, 0, len(c.done))
	for name := range c.done {
		names = append(names, name)
	}
	sort.Strings(names)
	// Marshal cannot fail for a []string.
	raw, _ := json.Marshal(cursor{Collected: names})
	return raw
}

type cursor struct {
	Collected []string `json:"collected"`
}

// readCursor reads what an earlier stream said it had collected. Names in it
// that no longer exist are ignored: a realm that has been deleted is not
// something to collect, and refusing the whole cursor over one would force a
// full re-collection for no gain.
func readCursor(raw []byte) (map[string]bool, error) {
	done := map[string]bool{}
	if len(raw) == 0 {
		return done, nil
	}
	var c cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("the resume cursor could not be read (%w); collect again without it", err)
	}
	for _, name := range c.Collected {
		done[name] = true
	}
	return done, nil
}

// counting counts the records that went past, so a budget can be honoured
// without every emitter having to know about it.
type counting struct {
	collector.Stream
	n uint64
}

func (c *counting) Node(n *collectorv1.Node) error { c.n++; return c.Stream.Node(n) }
func (c *counting) Edge(e *collectorv1.Edge) error { c.n++; return c.Stream.Edge(e) }
func (c *counting) Activity(a *collectorv1.Activity) error {
	c.n++
	return c.Stream.Activity(a)
}

// ContainsRealm reports whether a realm of that name is in the list. Exported
// because both the collection loop and the pre-flight probe need it, and two
// copies of a membership test is two places to get it wrong.
func ContainsRealm(realms []admin.Realm, name string) bool {
	for _, r := range realms {
		if r.Realm == name {
			return true
		}
	}
	return false
}
