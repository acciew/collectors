// Package client speaks /agent/v1 (docs/agent-protocol.md) and nothing else: one method per
// address, and an error that says what the service said. It decides nothing about what to do next.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is one service as an agent reaches it.
type Client struct {
	// Base is the service's address without a trailing slash: the audience of an assertion is
	// this and a path, compared exactly.
	Base string
	HTTP *http.Client
	// Timeouts bound one call; a long poll and a chunk get their own. Zero is the default.
	Timeouts Timeouts

	userAgent string

	mu     sync.Mutex
	offset time.Duration // the service's clock less ours, from the last answer's Date
	known  bool
}

// Timeouts bound a call. The service holds a poll for 30 to 60 seconds.
type Timeouts struct{ Call, Poll, Chunk time.Duration }

func (t Timeouts) call() time.Duration { return orDefault(t.Call, 30*time.Second) }
func (t Timeouts) poll() time.Duration { return orDefault(t.Poll, 2*time.Minute) }
func (t Timeouts) chunk() time.Duration {
	// The service gives a chunk ten minutes to arrive, so a slow uplink is not cut off.
	return orDefault(t.Chunk, 10*time.Minute)
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// New checks the address. An agent sends an assertion and a token to it, so it is https; the
// machine itself may be plain, for trying the agent against a service on the same host.
func New(base, version string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("%q is not the address of a service: use https://host", base)
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return nil, fmt.Errorf("%q is plain http: the agent sends its credentials to the service, so it needs https", base)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("%q has more than a service's address in it", base)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck // the default transport is one; proxies come from the environment
	return &Client{
		Base:      strings.TrimRight(base, "/"),
		userAgent: "acciew-agent/" + version,
		HTTP: &http.Client{
			Transport: transport,
			// A redirect would carry an assertion or a token to an address nobody configured.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// APIError is the service refusing: its status, and what it said as a problem document.
type APIError struct {
	Status int
	// Code is the machine word of a 409 (out_of_order, chunk_conflict, lease_lost, stream_closed).
	Code string
	// State is pending or revoked, on a 403 from the token address.
	State  string
	Detail string
	// Next is the chunk number wanted, with an out_of_order.
	Next    int
	HasNext bool
	// RetryAfter is what a 429 asked for.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("the service answered %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.State != "" {
		s += " (" + e.State + ")"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Is lets errors.Is match an APIError by its code, as the caller's own sentinel.
func (e *APIError) Is(target error) bool {
	t, ok := target.(*APIError)
	return ok && t.Status == e.Status && t.Code == e.Code
}

// Transient says whether asking again may help: the network failed, the service had a bad
// moment, was asked too often, or saw the bytes damaged on the way. A refusal that is
// about the request or the lease is final.
func Transient(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var e *APIError
	if errors.As(err, &e) {
		switch {
		case e.Status >= 500, e.Status == http.StatusTooManyRequests, e.Status == http.StatusRequestTimeout, e.Status == http.StatusUnprocessableEntity:
			return true
		}
		return false
	}
	return true
}

// do makes one request and decodes a 2xx JSON answer into out (when out is not nil). A status
// in ok is a success with whatever it carries.
func (c *Client) do(ctx context.Context, timeout time.Duration, method, path, token string, header http.Header, body []byte, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil && header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, unwrapURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	c.noteClock(resp)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("%s %s: reading the answer: %w", method, path, unwrapURL(err))
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, problem(resp, raw)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: the answer is not what this address sends: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// unwrapURL drops the *url.Error wrapper, which repeats the address the caller already named.
func unwrapURL(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}

func problem(resp *http.Response, raw []byte) error {
	e := &APIError{Status: resp.StatusCode}
	var doc struct {
		Code   string `json:"code"`
		State  string `json:"state"`
		Detail string `json:"detail"`
		Next   *int   `json:"next"`
	}
	if json.Unmarshal(raw, &doc) == nil {
		e.Code, e.State, e.Detail = doc.Code, doc.State, doc.Detail
		if doc.Next != nil {
			e.Next, e.HasNext = *doc.Next, true
		}
	}
	if len(e.Detail) > 300 {
		e.Detail = e.Detail[:300]
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		} else if at, err := http.ParseTime(v); err == nil {
			e.RetryAfter = max(0, time.Until(at))
		}
	}
	return e
}

func (c *Client) noteClock(resp *http.Response) {
	if at, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		c.mu.Lock()
		c.offset, c.known = time.Until(at), true
		c.mu.Unlock()
	}
}

// ClockOffset is the service's clock less this one's, as of its last answer, to the second.
// An assertion is refused when the clocks are more than a minute apart.
func (c *Client) ClockOffset() (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset, c.known
}

func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// EnrollRequest is POST /agent/v1/enroll.
type EnrollRequest struct {
	Token     string            `json:"token"`
	Name      string            `json:"name"`
	Versions  map[string]string `json:"versions"`
	PublicKey string            `json:"public_key"`
}

// Enrolled is the answer: the agent's id, the fingerprint the service computed, and pending.
type Enrolled struct {
	AgentID     string `json:"agent_id"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
}

// Enroll registers a public key with an enrolment token.
func (c *Client) Enroll(ctx context.Context, in EnrollRequest) (Enrolled, error) {
	var out Enrolled
	_, err := c.do(ctx, c.Timeouts.call(), http.MethodPost, "/agent/v1/enroll", "", nil, marshal(in), &out)
	return out, err
}

// AccessToken is what an assertion is traded for.
type AccessToken struct {
	Token     string
	ExpiresAt time.Time
	ExpiresIn time.Duration
}

// Token trades an assertion for an access token. A 403 is an APIError whose State is pending or revoked.
func (c *Client) Token(ctx context.Context, assertion string) (AccessToken, error) {
	var out struct {
		AccessToken string    `json:"access_token"`
		ExpiresAt   time.Time `json:"expires_at"`
		ExpiresIn   int       `json:"expires_in"`
	}
	if _, err := c.do(ctx, c.Timeouts.call(), http.MethodPost, "/agent/v1/token", "", nil, marshal(map[string]string{"assertion": assertion}), &out); err != nil {
		return AccessToken{}, err
	}
	if out.AccessToken == "" {
		return AccessToken{}, errors.New("the service answered a token request without a token")
	}
	return AccessToken{Token: out.AccessToken, ExpiresAt: out.ExpiresAt, ExpiresIn: time.Duration(out.ExpiresIn) * time.Second}, nil
}

// Rotated is the answer to a rotation: the new key's fingerprint as the service computed it.
type Rotated struct {
	AgentID     string `json:"agent_id"`
	Fingerprint string `json:"fingerprint"`
}

// Rotate registers a new key. The assertion is signed by the old key, and the signature is the new key's.
func (c *Client) Rotate(ctx context.Context, assertion, newKeySignature string) (Rotated, error) {
	var out Rotated
	_, err := c.do(ctx, c.Timeouts.call(), http.MethodPost, "/agent/v1/rotate", "", nil,
		marshal(map[string]string{"assertion": assertion, "new_key_signature": newKeySignature}), &out)
	return out, err
}

// Hello says who a token is for.
func (c *Client) Hello(ctx context.Context, token string) (map[string]any, error) {
	var out map[string]any
	_, err := c.do(ctx, c.Timeouts.call(), http.MethodGet, "/agent/v1/hello", token, nil, nil, &out)
	return out, err
}

// Job is what the service asks an agent to do.
type Job struct {
	Run       string          `json:"run"`
	Stream    string          `json:"stream"`
	Attempt   int             `json:"attempt"`
	SourceID  string          `json:"source_id"`
	Collector string          `json:"collector"`
	Config    json.RawMessage `json:"config"`
	Scopes    []string        `json:"scopes"`
	// Budget is null today. ResumeCursor is null for a fresh start, and otherwise {"token": "<base64>"}:
	// where the collector resumes from, the last checkpoint the earlier attempt's stream carried.
	Budget       json.RawMessage `json:"budget"`
	ResumeCursor json.RawMessage `json:"resume_cursor"`
	// ResumeEvents is how many events the earlier streams of the run contribute to the collection. The
	// service's limit on events is for the whole collection, so this stream may send that much less.
	ResumeEvents     int       `json:"resume_events"`
	LeaseUntil       time.Time `json:"lease_until"`
	LeaseSeconds     int       `json:"lease_seconds"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	ChunkBytes       int       `json:"chunk_bytes"`
}

// NoBudget says the job puts no limit on the collection. The protocol says nothing yet of
// what a budget looks like, so a job that carries one is not run.
func (j *Job) NoBudget() bool { return isNull(j.Budget) }

// Resume is the cursor to resume from, or nil for a fresh start.
func (j *Job) Resume() ([]byte, error) {
	if isNull(j.ResumeCursor) {
		return nil, nil
	}
	var doc struct {
		Token *string `json:"token"`
	}
	dec := json.NewDecoder(bytes.NewReader(j.ResumeCursor))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Token == nil {
		return nil, errors.New(`the resume cursor is not {"token": "<base64>"}`)
	}
	token, err := base64.StdEncoding.DecodeString(*doc.Token)
	if err != nil {
		return nil, fmt.Errorf("the resume cursor's token is not standard base64: %w", err)
	}
	if len(token) == 0 {
		return nil, errors.New("the resume cursor's token is empty")
	}
	return token, nil
}

func isNull(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// Jobs asks for work: a job, or nil when the poll ended with none.
func (c *Client) Jobs(ctx context.Context, token string) (*Job, error) {
	var job Job
	status, err := c.do(ctx, c.Timeouts.poll(), http.MethodGet, "/agent/v1/jobs", token, nil, nil, &job)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	if job.Stream == "" || job.Collector == "" {
		return nil, errors.New("the service offered a job without a stream or a collector")
	}
	return &job, nil
}

// Heartbeat holds the job for another lease.
func (c *Client) Heartbeat(ctx context.Context, token, stream string) error {
	_, err := c.do(ctx, c.Timeouts.call(), http.MethodPost, "/agent/v1/streams/"+url.PathEscape(stream)+"/heartbeat", token, nil, nil, nil)
	return err
}

// ChunkResult is the service's answer to a chunk it took.
type ChunkResult struct {
	// Duplicate says the service already had this chunk: an answer was lost and it was sent again.
	Duplicate bool
	// EndedEarly says this was the last chunk and carried no completion: the stream ended before
	// the collector finished, and the service offers the job again, resumed.
	EndedEarly bool
}

// Collector is what the agent says of the collector file it ran, on every chunk it sends. The
// service has only its word for it. A value that is empty, or that cannot go in a header as it is,
// is left out: the chunk is worth more than the label.
type Collector struct {
	// SHA256 is the hex SHA-256 of the file, read just before the agent started it.
	SHA256 string
	// Version is what the collector called itself when it started.
	Version string
}

var (
	collectorSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	collectorVersion = regexp.MustCompile(`^[0-9A-Za-z._+~-]{1,64}$`)
)

// PutChunk sends chunk n of a stream with its digest, and what the agent says of the collector.
func (c *Client) PutChunk(ctx context.Context, token, stream string, n int, body []byte, final bool, col Collector) (ChunkResult, error) {
	sum := sha256.Sum256(body)
	header := http.Header{"Content-Type": {"application/octet-stream"}, "X-Acciew-Sha256": {hex.EncodeToString(sum[:])}}
	if final {
		header.Set("X-Acciew-Final", "true")
	}
	if collectorSHA256.MatchString(col.SHA256) {
		header.Set("X-Acciew-Collector-Sha256", col.SHA256)
	}
	if collectorVersion.MatchString(col.Version) {
		header.Set("X-Acciew-Collector-Version", col.Version)
	}
	var out struct {
		Status     string `json:"status"`
		EndedEarly bool   `json:"ended_early"`
	}
	path := "/agent/v1/streams/" + url.PathEscape(stream) + "/chunks/" + strconv.Itoa(n)
	if _, err := c.do(ctx, c.Timeouts.chunk(), http.MethodPut, path, token, header, body, &out); err != nil {
		return ChunkResult{}, err
	}
	return ChunkResult{Duplicate: out.Status == "duplicate", EndedEarly: out.EndedEarly}, nil
}

// Abort says the job cannot be done, and why.
func (c *Client) Abort(ctx context.Context, token, stream, reason string) error {
	_, err := c.do(ctx, c.Timeouts.call(), http.MethodPost, "/agent/v1/streams/"+url.PathEscape(stream)+"/abort", token, nil,
		marshal(map[string]string{"reason": reason}), nil)
	return err
}
