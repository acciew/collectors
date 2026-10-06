package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/sdk/go/collector"
)

// All collects the account these credentials reach.
//
// One account per collection, because that is what one set of credentials
// reaches: reading a second means assuming a role into it, which is a
// different configuration and therefore a different collection. Organizations
// — where a management account can reach many — is deliberately out of Phase
// 1, and the plugin says so rather than half-supporting it.
//
// The shape is still the one the other collectors use, cursor and all, so
// that adding accounts later changes what is in the set rather than how the
// loop works.
func All(ctx context.Context, src Source, now time.Time,
	req collector.CollectRequest, out collector.Stream) error {
	snap, err := src.Snapshot(ctx)
	if err != nil {
		// Nothing was read, so there is nothing to present as a population.
		// Being throttled is named as itself, because it is the one cause
		// waiting fixes.
		return &collector.Incomplete{Cause: causeOf(err), Err: err}
	}
	account := snap.Account.ID

	resumed := len(req.ResumeFrom) > 0
	done, err := readCursor(req.ResumeFrom)
	if err != nil {
		// Not PartialStream: nothing was collected, and saying a
		// continuation arrived when none did is the same overstatement in
		// the other direction.
		return &collector.Incomplete{Cause: collector.InvalidCursor,
			Err: collector.BadCursor(err)}
	}
	if done[account] {
		// Everything the cursor covers is already collected, so this stream
		// carries nothing. Saying so beats an empty snapshot that reads as a
		// complete collection of nobody.
		return &collector.Incomplete{
			Cause:      collector.PartialStream,
			ResumeFrom: req.ResumeFrom,
			Err: fmt.Errorf("account %s was already collected by the stream that produced "+
				"this cursor; there is nothing left to do", account),
		}
	}
	// Every account the caller named has to be accounted for. One never
	// mentioned is one the host cannot reason about, so it would be free to
	// present a collection of one account as a collection of the two that
	// were asked for.
	var unreachable []string
	for _, want := range req.Scopes {
		if want != account {
			unreachable = append(unreachable, want)
		}
	}
	for _, want := range unreachable {
		err := fmt.Errorf("these credentials are in account %s and cannot reach %s; "+
			"reading another account means assuming a role into it, which is a "+
			"different configuration", account, want)
		// Undetermined, not the zero value's "records nothing": nobody read it.
		if reportErr := out.ScopeDone(collector.ScopeResult{
			Scope: collector.Scope(want, want), Status: collector.Unreachable, Err: err,
			ActivityUndetermined: true,
		}); reportErr != nil {
			return reportErr
		}
	}
	if len(req.Scopes) > 0 && !contains(req.Scopes, account) {
		if err := out.ScopeDone(collector.ScopeResult{
			Scope: collector.Scope(account, account), Status: collector.Skipped,
			ActivityUndetermined: true,
		}); err != nil {
			return err
		}
		return &collector.Incomplete{
			Cause: collector.ScopeUnreachable,
			Err: fmt.Errorf("these credentials reach account %s, and the request asked for %v",
				account, req.Scopes),
		}
	}

	// The snapshot is already read. Reading it again would double the most
	// expensive call in the collection.
	collectErr := AccountFrom(ctx, src, snap, now, out)
	result := collector.ScopeResult{
		Scope: collector.Scope(account, account), Status: collector.Collected,
		// Roles carry their own last-used and the credential report covers
		// the users, so this account can answer — for the population AWS
		// records anything about.
		ActivityAvailable: true,
	}
	if collectErr != nil {
		result = collector.ScopeResult{
			Scope: collector.Scope(account, account), Status: collector.Partial, Err: collectErr,
			// The account still answers about activity — roles carry their
			// own last-used and the credential report covers the users — and
			// the zero value here would say it records nothing at all.
			ActivityAvailable: true,
		}
	}
	if err := out.ScopeDone(result); err != nil {
		return err
	}
	// Checkpointed whether or not it finished. Records are emitted before a
	// failure can happen, and a stream carrying records with no checkpoint is
	// one the SDK refuses to complete — losing the verdict and the data
	// together.
	if collectErr == nil {
		done[account] = true
	}
	if err := out.Checkpoint(cursorOf(done)); err != nil {
		return err
	}

	switch {
	case len(unreachable) > 0:
		return &collector.Incomplete{
			Cause: collector.ScopeUnreachable, ResumeFrom: cursorOf(done),
			Err: fmt.Errorf("%d account(s) that were asked for cannot be reached from here: %v",
				len(unreachable), unreachable),
		}
	case collectErr != nil:
		return &collector.Incomplete{
			Cause: causeOf(collectErr), ResumeFrom: cursorOf(done), Err: collectErr,
		}
	case resumed:
		return &collector.Incomplete{
			Cause: collector.PartialStream, ResumeFrom: cursorOf(done),
			Err: errors.New("this stream continues an earlier one and carries only part of the population"),
		}
	}
	return nil
}

// causeOf distinguishes being throttled from running into a mistake. IAM
// throttles, and only one of the two is fixed by waiting.
func causeOf(err error) collectorv1.IncompleteCause {
	if isThrottling(err) {
		return collector.RateLimited
	}
	return collector.SourceFailed
}

func cursorOf(done map[string]bool) []byte {
	names := make([]string, 0, len(done))
	for name := range done {
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

func contains(all []string, name string) bool {
	for _, s := range all {
		if s == name {
			return true
		}
	}
	return false
}
