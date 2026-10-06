package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.acciew.io/collector/sdk/go/collector"
)

// Kind classifies a failure by what an operator should do about it.
//
// The distinction that matters is between "your credentials are wrong",
// "your credentials are right but lack a role", and "try again later". They
// look similar in a stack trace and call for completely different actions.
type Kind int

const (
	// KindSource is anything the source rejected that is not covered below.
	KindSource Kind = iota
	// KindAuth means the credentials were rejected outright.
	KindAuth
	// KindPermission means the credentials were accepted and lack a role.
	// For Keycloak that is usually a missing realm-management role.
	KindPermission
	// KindRateLimited means back off and retry.
	KindRateLimited
	// KindUnavailable means Keycloak could not be reached or is unwell.
	KindUnavailable
)

func (k Kind) String() string {
	switch k {
	case KindAuth:
		return "authentication failed"
	case KindPermission:
		return "permission denied"
	case KindRateLimited:
		return "rate limited"
	case KindUnavailable:
		return "source unavailable"
	}
	return "source error"
}

// Error is a failure talking to Keycloak.
type Error struct {
	Kind    Kind
	Status  int
	Message string
	// Retryable says whether trying again unchanged could succeed. It exists
	// so a collector can decide between waiting and giving up without parsing
	// a message.
	Retryable bool
	// RetryAfter is what the source asked for, when it asked.
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	msg := e.Message
	if e.Status != 0 {
		msg = fmt.Sprintf("%s (HTTP %d)", msg, e.Status)
	}
	if e.Err != nil {
		return fmt.Sprintf("%v: %s: %v", e.Kind, msg, e.Err)
	}
	return fmt.Sprintf("%v: %s", e.Kind, msg)
}

func (e *Error) Unwrap() error { return e.Err }

func errorFor(resp *http.Response, what string) *Error {
	e := &Error{Status: resp.StatusCode, Message: what}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		e.Kind = KindAuth
		e.Message = what + ": Keycloak rejected the client credentials"
	case http.StatusForbidden:
		// Only when the refusal looks like Keycloak's. A proxy, a WAF or a
		// login page in front of it also answers 403, and calling that a
		// missing role sends an operator to grant something they already
		// hold. This does not identify Keycloak — a gateway that speaks JSON
		// still passes — it only rules out the ones that do not.
		if !isJSON(resp) {
			e.Kind = KindSource
			e.Message = what + ": refused by something that is not Keycloak — the response was " +
				resp.Header.Get("Content-Type") + " rather than JSON, so a proxy or gateway " +
				"is answering for it"
			break
		}
		e.Kind = KindPermission
		e.Message = what + ": the service account lacks a realm-management role for this"
	case http.StatusTooManyRequests:
		e.Kind, e.Retryable = KindRateLimited, true
		if after := resp.Header.Get("Retry-After"); after != "" {
			if secs, err := strconv.Atoi(after); err == nil {
				e.RetryAfter = time.Duration(secs) * time.Second
			}
		}
	default:
		if resp.StatusCode >= 500 {
			e.Kind, e.Retryable = KindUnavailable, true
		} else {
			e.Kind = KindSource
		}
	}
	return e
}

// CanRetry and Denied answer the SDK's optional interfaces, so that "wait"
// and "grant something" reach the person deciding what to do next rather than
// arriving as one undifferentiated source error.
func (e *Error) CanRetry() (bool, time.Duration) { return e.Retryable, e.RetryAfter }

// Fault classifies this failure for the SDK, which has no view of Kind.
func (e *Error) Fault() collector.Fault {
	switch e.Kind {
	case KindAuth:
		return collector.FaultAuth
	case KindPermission:
		return collector.FaultPermission
	case KindRateLimited:
		return collector.FaultRateLimited
	case KindUnavailable:
		return collector.FaultUnavailable
	}
	return collector.FaultSource
}

// isJSON says whether a refusal was written in the admin API's language.
//
// Measured on 26.4.7: every endpoint this collector reads answers a genuine
// permission failure with application/json and a JSON body, so this never
// turns a real missing role into "something else refused it". That holds
// because every admin request this client makes sends Accept:
// application/json — asked for HTML, Keycloak answers a 403 in HTML too. The
// token request does not send it and does not need to: a refusal there is a
// rejected credential, which is a different Kind. Pinned by
// TestEveryRealRefusalIsRecognisedAsOne against a container rather than
// trusting the measurement.
//
// An empty content type counts as Keycloak's, which is the one unmeasured
// case: no 26.4.7 refusal arrives without a body, so it is there for a
// version that might, and a header-less proxy would pass through it.
func isJSON(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return ct == "" || strings.Contains(ct, "json")
}
