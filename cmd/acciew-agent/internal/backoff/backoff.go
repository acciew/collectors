// Package backoff is how long to wait before asking again after a failure: exponential, jittered,
// capped. An agent that cannot reach the service must not hammer it, and agents that lost the
// network together must not return together.
package backoff

import (
	"context"
	"math/rand/v2"
	"time"
)

// Policy is the shortest and the longest wait.
type Policy struct{ Min, Max time.Duration }

// Defaults are for talking to the service: a second at first, two minutes at most.
var Defaults = Policy{Min: time.Second, Max: 2 * time.Minute}

// Delay is the wait after the attempt-th failure in a row (from 0): between half of the
// doubling delay and all of it.
func (p Policy) Delay(attempt int) time.Duration {
	minimum, maximum := p.Min, p.Max
	if minimum <= 0 {
		minimum = Defaults.Min
	}
	if maximum <= 0 {
		maximum = max(Defaults.Max, minimum)
	}
	if maximum < minimum {
		maximum = minimum
	}
	d := minimum
	for range min(attempt, 30) {
		if d >= maximum/2 {
			d = maximum
			break
		}
		d *= 2
	}
	d = min(d, maximum)
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter, not a secret
}

// Sleep waits d, or until ctx ends, and says which.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
