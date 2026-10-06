package api

import (
	"fmt"
	"time"
)

// Kind is what went wrong, in terms an operator can act on.
//
// The distinction that earns its keep is between waiting and doing something:
// a rate limit clears on its own and a missing permission never does, and
// telling somebody to wait for the second wastes their afternoon.
type Kind int

const (
	// Unavailable is a transport failure or a 5xx: the source is there and
	// did not answer.
	Unavailable Kind = iota
	// Auth means the credential is wrong or expired.
	Auth
	// Permission means the credential is valid and does not carry the access
	// this call needs.
	Permission
	// RateLimited means the source asked us to slow down.
	RateLimited
	// NotFound means the thing is not there — or the token cannot see it,
	// which GitHub answers identically and on purpose.
	NotFound
	// Source is anything else the API refused.
	Source
)

func (k Kind) String() string {
	switch k {
	case Unavailable:
		return "unavailable"
	case Auth:
		return "authentication"
	case Permission:
		return "permission"
	case RateLimited:
		return "rate limited"
	case NotFound:
		return "not found"
	case Source:
		return "source error"
	}
	return fmt.Sprintf("unrecognised(%d)", int(k))
}

// Error is a failed call. It never carries the credential: an error ends up in
// logs, tickets and screen shares.
type Error struct {
	Kind Kind
	// What was being asked for, in plain words.
	What string
	// Status is the HTTP status, zero for a transport failure.
	Status int
	// Message is what the API said, if anything.
	Message string
	// RetryAfter is how long the source asked us to wait. Only meaningful
	// when Kind is RateLimited.
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	out := fmt.Sprintf("github: %s: %s", e.What, e.Kind)
	if e.Status != 0 {
		out += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Message != "" {
		out += ": " + e.Message
	}
	if e.Kind == NotFound {
		// GitHub answers 404 for a thing that is not there and for a thing
		// this token may not see, deliberately, so as not to confirm the
		// existence of private resources. Reporting only the first sends an
		// operator to create something that already exists.
		out += " — this may also mean the credential cannot see it"
	}
	if e.RetryAfter > 0 {
		out += fmt.Sprintf("; retry after %s", e.RetryAfter)
	}
	if e.Err != nil {
		out += ": " + e.Err.Error()
	}
	return out
}

func (e *Error) Unwrap() error { return e.Err }

// Retryable reports whether waiting would help.
func (e *Error) Retryable() bool {
	return e.Kind == RateLimited || e.Kind == Unavailable
}
