// Package loop is the agent's life once it is running: ask the service for work, do one job at a
// time, and never ask faster than the service can bear, whatever goes wrong.
package loop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"go.acciew.io/collector/cmd/acciew-agent/internal/backoff"
	"go.acciew.io/collector/cmd/acciew-agent/internal/client"
	"go.acciew.io/collector/cmd/acciew-agent/internal/job"
	"go.acciew.io/collector/cmd/acciew-agent/internal/session"
	"go.acciew.io/collector/cmd/acciew-agent/internal/spool"
)

// Agent is a running agent.
type Agent struct {
	Client  *client.Client
	Session *session.Session
	Runner  *job.Runner
	// Backoff paces retries after a failure; the zero value is backoff.Defaults.
	Backoff backoff.Policy
	// MinPoll is the least time between two requests for work that came back without any: a
	// service that answers at once, over and over, is not hammered. Zero is a second.
	MinPoll time.Duration
	// SpoolDir is cleaned of what a crash left, once, at the start.
	SpoolDir string
	// Out is where a person is told things that matter to them; Log is for the record.
	Out io.Writer
	Log *slog.Logger
}

// maxWait is the longest a Retry-After is believed: the service says an hour at most.
const maxWait = time.Hour

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (a *Agent) policy() backoff.Policy {
	if a.Backoff == (backoff.Policy{}) {
		return backoff.Defaults
	}
	return a.Backoff
}

func (a *Agent) minPoll() time.Duration {
	if a.MinPoll > 0 {
		return a.MinPoll
	}
	return time.Second
}

// ErrRevoked is an agent the service has deleted.
var ErrRevoked = errors.New("this agent was revoked by an administrator and the service accepts nothing more from it: enrol it again with a new token")

// Run asks for work until ctx ends (nil) or the service says this agent is revoked (ErrRevoked).
func (a *Agent) Run(ctx context.Context) error {
	if a.SpoolDir != "" {
		if err := spool.Clean(a.SpoolDir); err != nil {
			a.log().Warn("could not clean the spool directory", "error", err)
		}
	}
	var (
		failures  int
		announced bool
	)
	for ctx.Err() == nil {
		began := time.Now()
		// Asked for first, apart from the call that needs it, so that an agent that is not
		// confirmed, or was revoked, is told so before it asks for work.
		if _, err := a.Session.Token(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			wait, fatal := a.tokenFailed(err, failures, &announced)
			if fatal != nil {
				return fatal
			}
			failures++
			if backoff.Sleep(ctx, wait) != nil {
				break
			}
			continue
		}
		if announced {
			announced = false
			a.say("This agent is confirmed. Asking for work.\n")
		}

		var offered *client.Job
		err := a.Session.Do(ctx, func(tok string) (err error) {
			offered, err = a.Client.Jobs(ctx, tok)
			return err
		})
		switch {
		case ctx.Err() != nil:
		case err != nil:
			wait := a.policy().Delay(failures)
			var api *client.APIError
			if errors.As(err, &api) && api.Status == http.StatusTooManyRequests {
				wait = min(max(api.RetryAfter, a.minPoll()), maxWait)
				a.log().Info("the service says this agent has had its jobs; waiting", "wait", wait)
			} else {
				a.log().Warn("asking for work failed", "error", err, "retry_in", wait)
			}
			failures++
			if backoff.Sleep(ctx, wait) != nil {
				return nil
			}
		case offered == nil:
			failures = 0
			// The service holds a poll for most of a minute; one that comes back at once is paced.
			if left := a.minPoll() - time.Since(began); left > 0 {
				if backoff.Sleep(ctx, left) != nil {
					return nil
				}
			}
		default:
			failures = 0
			a.log().Info("taking a job", "collector", offered.Collector, "run", offered.Run, "stream", offered.Stream)
			a.Runner.Run(ctx, offered)
		}
	}
	return nil
}

func (a *Agent) say(format string, args ...any) {
	if a.Out != nil {
		_, _ = fmt.Fprintf(a.Out, format, args...)
	}
}

// tokenFailed decides what a refused token request means: how long to wait, or that it is the end.
func (a *Agent) tokenFailed(err error, failures int, announced *bool) (wait time.Duration, fatal error) {
	wait = a.policy().Delay(failures)
	var api *client.APIError
	if !errors.As(err, &api) {
		a.log().Warn("could not reach the service for a token", "error", err, "retry_in", wait)
		return wait, nil
	}
	switch {
	case api.Status == http.StatusForbidden && api.State == "revoked":
		return 0, ErrRevoked
	case api.Status == http.StatusForbidden && api.State == "pending":
		if !*announced {
			*announced = true
			a.say("This agent is waiting for an administrator to confirm its fingerprint, %s.\nIt asks again until then, and is offered no work before.\n", a.Session.Fingerprint())
		}
		return wait, nil
	case api.Status == http.StatusUnauthorized:
		if off, ok := a.Client.ClockOffset(); ok && (off > 45*time.Second || off < -45*time.Second) {
			dir := "ahead of"
			if off < 0 {
				dir, off = "behind", -off
			}
			a.log().Warn("the service refused the agent's assertion, and its clock is "+off.Round(time.Second).String()+" "+dir+
				" this host's: an assertion is refused when the clocks differ by more than a minute; check this host's time", "retry_in", wait)
			return wait, nil
		}
		a.log().Warn("the service refused the agent's assertion: is the agent still registered, and is this host's clock right?", "retry_in", wait)
		return wait, nil
	}
	a.log().Warn("the service refused a token request", "error", err, "retry_in", wait)
	return wait, nil
}
