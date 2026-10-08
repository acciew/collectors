package graph

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.acciew.io/collector/sdk/go/collector"
)

// Kind classifies a failure by what an operator should do about it: fix the
// credential, grant a permission, or wait.
type Kind int

// The kinds of failure.
const (
	// KindSource is anything not covered below.
	KindSource Kind = iota
	// KindAuth means the credential was rejected outright.
	KindAuth
	// KindPermission means the credential was accepted and lacks a right.
	KindPermission
	// KindRateLimited means the caller was asked to slow down.
	KindRateLimited
	// KindUnavailable means Graph could not be reached or is unwell.
	KindUnavailable
	// KindBadRequest means Graph refused the request itself.
	KindBadRequest
	// KindNotFound means the thing asked for is not there.
	KindNotFound
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
	case KindBadRequest:
		return "request refused"
	case KindNotFound:
		return "not found"
	}
	return "source error"
}

// Error is a failure talking to Microsoft Graph or to the token service.
type Error struct {
	Kind   Kind
	Status int
	// Code is the service's own code: Graph's error.code, or the token
	// service's AADSTS number. It is the most useful single word in a report.
	Code    string
	Message string
	// RetryAfter is what the service asked for, when it asked.
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	msg := e.Message
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.Status != 0 {
		msg = fmt.Sprintf("%s (HTTP %d)", msg, e.Status)
	}
	if e.Err != nil {
		return fmt.Sprintf("%v: %s: %v", e.Kind, msg, e.Err)
	}
	return fmt.Sprintf("%v: %s", e.Kind, msg)
}

func (e *Error) Unwrap() error { return e.Err }

// CanRetry answers the SDK's optional interface: a throttle or an outage may
// pass, a refusal will not.
func (e *Error) CanRetry() (bool, time.Duration) {
	return e.Kind == KindRateLimited || e.Kind == KindUnavailable, e.RetryAfter
}

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
	case KindBadRequest, KindNotFound, KindSource:
	}
	return collector.FaultSource
}

// retryAfter reads Retry-After, which is either a number of seconds or an
// HTTP date.
func retryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

// kindFor maps a status onto a Kind.
func kindFor(status int) Kind {
	switch {
	case status == http.StatusUnauthorized:
		return KindAuth
	case status == http.StatusForbidden:
		return KindPermission
	case status == http.StatusTooManyRequests:
		return KindRateLimited
	case status == http.StatusNotFound:
		return KindNotFound
	case status == http.StatusBadRequest:
		return KindBadRequest
	case status >= 500:
		return KindUnavailable
	}
	return KindSource
}

// firstLine keeps the sentence of a message and drops the trace lines the
// token service appends after it.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// licenceCodes are the codes Graph is known to refuse a tenant without the
// licence for a feature. The list is short on purpose and it is not verified
// against a tenant that lacks the licence: a refusal of any other shape is
// reported as one nobody recognised, never as a missing licence.
var licenceCodes = []string{
	"Authentication_RequestFromNonPremiumTenantOrB2CTenant",
	"AadPremiumLicenseRequired",
}

// LicenceRequired says Graph refused the request because the tenant lacks a
// licence for the feature, as opposed to the application lacking a permission
// or anything else going wrong.
func (e *Error) LicenceRequired() bool {
	if e.Kind != KindPermission && e.Kind != KindBadRequest {
		return false
	}
	for _, c := range licenceCodes {
		if strings.EqualFold(e.Code, c) {
			return true
		}
	}
	return false
}
