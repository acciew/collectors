package fakegraph

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rule makes the fake misbehave for the paths it matches, the way a real
// service does: it refuses, or it asks the caller to slow down.
type rule struct {
	prefix string
	// times bounds how often the rule fires; zero means every time.
	times int

	mu     sync.Mutex
	fired  int
	status int
	code   string
	msg    string
	// retryAfter is served as the Retry-After header when set.
	retryAfter string
	// raw, when set, is served as the body instead of Graph's error shape.
	raw         string
	contentType string
	// handler, when set, answers instead, and says whether it did.
	handler func(http.ResponseWriter, *http.Request) bool
}

// apply writes the rule's response and says whether it fired.
func (rl *rule) apply(w http.ResponseWriter, r *http.Request) bool {
	if rl.handler != nil {
		return rl.handler(w, r)
	}
	rl.mu.Lock()
	if rl.times > 0 && rl.fired >= rl.times {
		rl.mu.Unlock()
		return false
	}
	rl.fired++
	rl.mu.Unlock()
	if rl.retryAfter != "" {
		w.Header().Set("Retry-After", rl.retryAfter)
	}
	if rl.contentType != "" {
		w.Header().Set("Content-Type", rl.contentType)
		w.WriteHeader(rl.status)
		_, _ = w.Write([]byte(rl.raw))
		return true
	}
	writeError(w, rl.status, rl.code, rl.msg)
	return true
}

// match returns every rule for a path, in the order they were added; the first
// that has not run out answers.
func (s *Server) match(path string) []*rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*rule
	for _, rl := range s.rules {
		if strings.HasPrefix(path, rl.prefix) {
			out = append(out, rl)
		}
	}
	return out
}

func (s *Server) addRule(rl *rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rl)
}

// Refuse answers requests under a path prefix with an error, as Graph does
// for a missing permission or licence: a status and Graph's own error code.
func (s *Server) Refuse(prefix string, status int, code, message string) {
	s.addRule(&rule{prefix: prefix, status: status, code: code, msg: message})
}

// Throttle answers the next n requests under a prefix with 429 and a
// Retry-After header, then lets requests through. A negative number of seconds
// leaves the header out.
func (s *Server) Throttle(prefix string, n int, retryAfterSeconds int) {
	rl := &rule{
		prefix: prefix, times: n, status: http.StatusTooManyRequests,
		code: "TooManyRequests", msg: "Please retry again later.",
	}
	// A negative number leaves the header out, as a 429 may.
	if retryAfterSeconds >= 0 {
		rl.retryAfter = strconv.Itoa(retryAfterSeconds)
	}
	s.addRule(rl)
}

// Respond answers requests under a prefix with a body of the test's choosing,
// for the replies that are not Graph's: a proxy's HTML refusal, a page that is
// not JSON at all.
func (s *Server) Respond(prefix string, status int, contentType, body string) {
	s.addRule(&rule{prefix: prefix, status: status, contentType: contentType, raw: body})
}

// Outage answers the next n requests under a prefix with 503, naming how long
// to wait when retryAfterSeconds is positive, then lets requests through.
func (s *Server) Outage(prefix string, n int, retryAfterSeconds int) {
	rl := &rule{
		prefix: prefix, times: n, status: http.StatusServiceUnavailable,
		code: "serviceNotAvailable", msg: "The service is unavailable.",
	}
	if retryAfterSeconds > 0 {
		rl.retryAfter = strconv.Itoa(retryAfterSeconds)
	}
	s.addRule(rl)
}

// ThrottleUntil is Throttle with Retry-After given as an HTTP date, which the
// header allows.
func (s *Server) ThrottleUntil(prefix string, n int, at time.Time) {
	s.addRule(&rule{
		prefix: prefix, times: n, status: http.StatusTooManyRequests,
		code: "TooManyRequests", msg: "Please retry again later.",
		retryAfter: at.UTC().Format(http.TimeFormat),
	})
}

// Intercept lets a test answer requests under a prefix itself: the handler
// returns true for the ones it answered and false to let the fake have them.
// It is for a shape of reply no rule above makes, such as pages whose links go
// round in a circle.
func (s *Server) Intercept(prefix string, handler func(http.ResponseWriter, *http.Request) bool) {
	s.addRule(&rule{prefix: prefix, handler: handler})
}
