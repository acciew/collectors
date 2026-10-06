package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/sdk/go/collector"
)

// All collects every organization the caller asked for.
//
// It returns nil only when this stream carries every organization that was
// asked for, collected whole. Anything else is an *Incomplete, because a
// truncated population that reads as a full one is worse than a failure — and
// with GitHub that is not a rare case: a large organization does not fit
// inside one rate-limit window, so stopping early is an ordinary outcome
// rather than an error.
func All(ctx context.Context, src Source, orgs []string,
	req collector.CollectRequest, out collector.Stream) error {
	return AllWith(ctx, src, orgs, Config{}, req, out)
}

// AllWith collects every organization under a configuration.
func AllWith(ctx context.Context, src Source, orgs []string, cfg Config,
	req collector.CollectRequest, out collector.Stream) error {
	sorted := append([]string(nil), orgs...)
	sort.Strings(sorted)

	wanted := map[string]bool{}
	for _, s := range req.Scopes {
		wanted[s] = true
	}

	resumed := len(req.ResumeFrom) > 0
	done, err := readCursor(req.ResumeFrom)
	if err != nil {
		// Not PartialStream: nothing was collected, and saying a
		// continuation arrived when none did is the same overstatement in
		// the other direction.
		return &collector.Incomplete{Cause: collector.InvalidCursor,
			Err: collector.BadCursor(err)}
	}

	run := &collection{out: out, done: done, resumed: resumed, cfg: cfg}
	deadline := time.Time{}
	if req.MaxDuration > 0 {
		deadline = time.Now().Add(req.MaxDuration)
	}

	for _, org := range sorted {
		// An organization the cursor says is collected is not read again and
		// gets no scope outcome: this stream did not look at it, and saying
		// otherwise would let a continuation read as a whole collection.
		if done[org] {
			continue
		}
		if len(wanted) > 0 && !wanted[org] {
			if err := out.ScopeDone(collector.ScopeResult{
				Scope: collector.Scope(org, org), Status: collector.Skipped,
			}); err != nil {
				return err
			}
			continue
		}
		if run.overBudget(req.MaxRecords, deadline) {
			// A budget stop after an organization was throttled still has to
			// say that waiting would help: the operator's next move differs.
			return run.stop(run.budgetCause())
		}
		if err := run.org(ctx, src, org); err != nil {
			return err
		}
	}

	var missing []string
	for name := range wanted {
		if !done[name] && !contains(sorted, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		err := fmt.Errorf("organization %s: this token cannot see it, or it does not exist", name)
		run.failed = append(run.failed, err)
		if reportErr := out.ScopeDone(collector.ScopeResult{
			Scope: collector.Scope(name, name), Status: collector.Unreachable, Err: err,
		}); reportErr != nil {
			return reportErr
		}
	}

	switch {
	case len(run.failed) > 0:
		return run.stop(run.cause())
	case resumed:
		return run.stop(collector.PartialStream)
	case run.collected == 0:
		return run.stop(collector.ScopeUnreachable)
	}
	return nil
}

type collection struct {
	out     collector.Stream
	done    map[string]bool
	resumed bool
	cfg     Config

	records   uint64
	collected int
	failed    []error
	// limited records that at least one organization stopped on quota rather
	// than on a mistake, which is a different thing to tell an operator.
	limited bool
}

func (c *collection) org(ctx context.Context, src Source, org string) error {
	counted := &counting{Stream: c.out}
	err := OrganizationWith(ctx, src, org, c.cfg, counted)
	c.records += counted.n

	result := collector.ScopeResult{
		Scope: collector.Scope(org, org), Status: collector.Collected,
	}
	if err != nil {
		// One organization stopping does not abandon the others: an operator
		// needs the whole picture to fix one thing, and with rate limits the
		// commonest outcome is that some organizations finished and one did
		// not.
		var e *api.Error
		if errors.As(err, &e) && e.Kind == api.RateLimited {
			c.limited = true
		}
		c.failed = append(c.failed, fmt.Errorf("organization %s: %w", org, err))
		result = collector.ScopeResult{
			Scope: collector.Scope(org, org), Status: collector.Partial, Err: err,
		}
	} else {
		c.done[org] = true
		c.collected++
	}
	if err := c.out.ScopeDone(result); err != nil {
		return err
	}
	// Checkpointed whether or not the organization finished. Records are
	// emitted before a failure can happen, and a stream carrying records with
	// no checkpoint is one the SDK refuses to complete — losing the verdict
	// and the data together.
	return c.out.Checkpoint(c.cursor())
}

// cause distinguishes running out of quota from running into a mistake. Both
// end the collection incomplete; only one of them is fixed by waiting.
func (c *collection) cause() collectorv1.IncompleteCause {
	if c.limited {
		return collector.RateLimited
	}
	return collector.ScopeUnreachable
}

// budgetCause names why a budget stop happened when something was already
// wrong. Running out of quota is the more useful thing to tell an operator,
// because it is the one waiting fixes.
func (c *collection) budgetCause() collectorv1.IncompleteCause {
	if c.limited {
		return collector.RateLimited
	}
	return collector.BudgetExhausted
}

func (c *collection) stop(cause collectorv1.IncompleteCause) *collector.Incomplete {
	inc := &collector.Incomplete{Cause: cause, ResumeFrom: c.cursor()}
	switch {
	case len(c.failed) > 0:
		inc.Err = errors.Join(c.failed...)
	case cause == collector.ScopeUnreachable && c.collected == 0:
		inc.Err = errors.New("no organization was collected")
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

// cursor names the organizations collected so far.
//
// A set rather than a position, for the same reason the Keycloak collector
// uses one: a high-water mark cannot express "the second one failed and the
// third succeeded", so the failed one would sit behind the mark for ever
// while the next run reported itself complete.
func (c *collection) cursor() []byte {
	names := make([]string, 0, len(c.done))
	for name := range c.done {
		names = append(names, name)
	}
	sort.Strings(names)
	raw, _ := json.Marshal(cursor{Collected: names})
	return raw
}

type cursor struct {
	Collected []string `json:"collected"`
}

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

func contains(all []string, name string) bool {
	for _, s := range all {
		if s == name {
			return true
		}
	}
	return false
}
