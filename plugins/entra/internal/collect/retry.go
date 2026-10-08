package collect

import (
	"context"
	"errors"
	"time"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

// Throttling and outages. Graph asks a caller to slow down with a 429 and a
// Retry-After, and may do so under its published limits; it may also be briefly
// unwell and answer 503 or 504, naming a delay or not. A short wait is honoured
// and reported. A throttle that is longer, or keeps coming, ends the stream
// RATE_LIMITED: the caller can come back later, and a collector that sits on a
// connection for an hour helps nobody. An outage that outlasts its retries is
// the read failing, and the part with it: there is no later stream to go back to
// it in, and the parts after it are still worth reading.
const (
	// ThrottleRetries is how many times one request is retried after a 429.
	ThrottleRetries = 4
	// OutageRetries is how many times one request is retried after a 5xx or a
	// failure to reach Graph.
	OutageRetries = 2
	// DefaultThrottleWait is how long a 429 that names no delay is waited out.
	DefaultThrottleWait = 5 * time.Second

	// maxThrottleWait is the longest single wait honoured; a longer
	// Retry-After ends the stream or fails the read at once.
	maxThrottleWait = 60 * time.Second
	// outageBackoff is the first wait after an outage that names none; each
	// retry waits one more of it.
	outageBackoff = 2 * time.Second
)

// retrier runs one request, waiting out a throttle or an outage.
type retrier struct {
	wait func(context.Context, time.Duration) error
	// waiting is told of each wait, and whether it is for a throttle; nil means
	// nobody is listening.
	waiting func(d time.Duration, throttled bool) error
}

// do runs op until it succeeds, fails in a way waiting cannot help, or runs out
// of patience. An exhausted throttle is a *stopError: the stream should end. An
// exhausted outage is the outage itself, an error of the read.
func (rt retrier) do(ctx context.Context, op func() error) error {
	for attempt := 0; ; attempt++ {
		err := op()
		var ge *graph.Error
		if err == nil || !errors.As(err, &ge) {
			return err
		}
		var d time.Duration
		throttled := false
		switch ge.Kind {
		case graph.KindRateLimited:
			throttled = true
			d = ge.RetryAfter
			if d <= 0 {
				d = DefaultThrottleWait
			}
			if d > maxThrottleWait || attempt >= ThrottleRetries {
				return &stopError{cause: collector.RateLimited, err: err}
			}
		case graph.KindUnavailable:
			d = ge.RetryAfter
			if d <= 0 {
				d = outageBackoff * time.Duration(attempt+1)
			}
			if attempt >= OutageRetries || d > maxThrottleWait {
				return err
			}
		default:
			return err
		}
		if rt.waiting != nil {
			if e := rt.waiting(d, throttled); e != nil {
				return e
			}
		}
		if e := rt.wait(ctx, d); e != nil {
			return e
		}
	}
}

// retrying runs a request under this stream's patience, which is reported as
// Progress.
func (st *state) retrying(ctx context.Context, op func() error) error {
	return retrier{
		wait: st.Wait,
		waiting: func(d time.Duration, throttled bool) error {
			var rl *collector.RateLimit
			if throttled {
				rl = &collector.RateLimit{RetryAfter: d}
			}
			err := st.out.Progress(st.phase, rl)
			st.mark()
			return err
		},
	}.do(ctx, op)
}

// retrying runs a request for the check, which has no stream to report to.
func (r Run) retrying(ctx context.Context, op func() error) error {
	wait := r.Wait
	if wait == nil {
		wait = pause
	}
	return retrier{wait: wait}.do(ctx, op)
}

// stopError ends a stream with a cause. It is not a failure of a part, and
// nothing after it is read.
type stopError struct {
	cause collectorv1.IncompleteCause
	err   error
}

func (e *stopError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return "the stream stopped"
}

func (e *stopError) Unwrap() error { return e.err }
