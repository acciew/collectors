// Package fakeservice is the Acciew service's /agent/v1 as far as an agent can tell: the
// same addresses, the same answers, the same rules for an assertion, a token, a lease and a
// chunk, with nothing behind them but memory. It exists so that the agent is tested whole,
// over HTTP, against something that refuses what the service refuses.
//
// It also keeps, byte for byte, everything it was sent, so that a test can search it.
package fakeservice

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// MaxChunkBytes is the most a chunk may be as sent.
const MaxChunkBytes = 8 << 20

// Service is the fake. The zero value is not usable: use New.
type Service struct {
	Server *httptest.Server
	Tenant string

	// Hold is how long a poll for work waits before 204 (default 100ms, in place of 30 to 60 s).
	Hold time.Duration
	// LeaseSeconds and HeartbeatSeconds are what a job says (default 300 and 100).
	LeaseSeconds, HeartbeatSeconds int
	// TokenLife is how long an access token lasts (default an hour).
	TokenLife time.Duration
	// RotateDelay holds a rotation request before the service looks at it: the time in which a
	// second rotation can begin.
	RotateDelay time.Duration
	// AgentID, when set, is the id enrol answers in place of a made one: a service that gives an id no agent can use.
	AgentID string
	// ChunkBytes is the chunk_bytes a job says (default 8 MiB).
	ChunkBytes int
	// Fingerprint, when set, is what enrol and rotate answer in place of the true one: a
	// service, or something between, that swapped the key.
	Fingerprint string

	mu         sync.Mutex
	enrolments map[string]bool
	agents     map[string]*Agent
	tokens     map[string]*token
	jtis       map[string]time.Time
	queue      []*Run
	runs       map[string]*Run // by stream id
	requests   []Request
	faults     []*fault
	hits       map[string]int
	conflicts  int
}

// Agent is an enrolled agent as the service knows it.
type Agent struct {
	ID       string
	Name     string
	Key      ed25519.PublicKey
	State    string // pending, confirmed, revoked
	Versions map[string]string
}

type token struct {
	agent   string
	expires time.Time
}

// Request is one request as it arrived, whole.
type Request struct {
	Method, Path string
	Raw          []byte // the request as it was on the wire: line, headers and body
}

// New starts a fake service and stops it with the test.
func New(t testing.TB) *Service {
	t.Helper()
	s := &Service{
		Tenant: "0a1b2c3d-0000-4000-8000-000000000001", Hold: 100 * time.Millisecond,
		LeaseSeconds: 300, HeartbeatSeconds: 100, TokenLife: time.Hour,
		enrolments: map[string]bool{}, agents: map[string]*Agent{}, tokens: map[string]*token{},
		jtis: map[string]time.Time{}, runs: map[string]*Run{}, hits: map[string]int{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Server.Close)
	return s
}

// URL is the service's public address.
func (s *Service) URL() string { return s.Server.URL }

// AddEnrolment makes an enrolment token good, once.
func (s *Service) AddEnrolment(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrolments[tok] = true
}

// Agent returns an enrolled agent, or nil.
func (s *Service) Agent(id string) *Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.agents[id]; a != nil {
		c := *a
		return &c
	}
	return nil
}

// Agents lists the ids of the enrolled agents.
func (s *Service) Agents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}

// Confirm is an administrator confirming a fingerprint.
func (s *Service) Confirm(id string) { s.setState(id, "confirmed") }

// Revoke is an administrator deleting an agent: its tokens stop at once.
func (s *Service) Revoke(id string) { s.setState(id, "revoked") }

func (s *Service) setState(id, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.agents[id]; a != nil {
		a.State = state
	}
}

// ForgetTokens makes every access token it has given stop working, as an expiry would.
func (s *Service) ForgetTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = map[string]*token{}
}

// Requests returns everything received so far.
func (s *Service) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Hits counts requests by "METHOD /path-shape" (a stream's id and a chunk's number are elided).
func (s *Service) Hits(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[key]
}

// Everything is every byte the service was sent: each request whole, and each chunk body
// again inflated, so that a search cannot be fooled by compression.
func (s *Service) Everything() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []byte
	for _, r := range s.requests {
		all = append(all, r.Raw...)
		all = append(all, '\n')
	}
	for _, r := range s.runs {
		r.mu.Lock()
		chunks := append([][]byte(nil), r.chunks...)
		for _, h := range r.history {
			chunks = append(chunks, h.chunks...)
		}
		for _, c := range chunks {
			if raw, err := inflate(c); err == nil {
				all = append(all, raw...)
			}
		}
		r.mu.Unlock()
	}
	return all
}

func (s *Service) now() time.Time { return time.Now() }

func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	dump, _ := httputil.DumpRequest(r, true)
	shape := r.Method + " " + pathShape(r.URL.Path)
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.RequestURI(), Raw: dump})
	s.hits[shape]++
	f := s.matchFault(r)
	s.mu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	if f != nil && f.apply(w, r, s) {
		return
	}
	switch {
	case r.URL.Path == "/agent/v1/enroll" && r.Method == http.MethodPost:
		s.enroll(w, r)
	case r.URL.Path == "/agent/v1/token" && r.Method == http.MethodPost:
		s.token(w, r)
	case r.URL.Path == "/agent/v1/rotate" && r.Method == http.MethodPost:
		s.rotate(w, r)
	case r.URL.Path == "/agent/v1/hello" && r.Method == http.MethodGet:
		s.hello(w, r)
	case r.URL.Path == "/agent/v1/jobs" && r.Method == http.MethodGet:
		s.jobs(w, r)
	case strings.HasPrefix(r.URL.Path, "/agent/v1/streams/"):
		s.stream(w, r)
	default:
		problem(w, http.StatusNotFound, "", nil)
	}
}

func pathShape(p string) string {
	rest, ok := strings.CutPrefix(p, "/agent/v1/streams/")
	if !ok {
		return p
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 3 {
		return "/agent/v1/streams/{stream}/chunks/{n}"
	}
	if len(parts) == 2 {
		return "/agent/v1/streams/{stream}/" + parts[1]
	}
	return p
}

func problem(w http.ResponseWriter, status int, detail string, extra map[string]any) {
	body := map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status}
	if detail != "" {
		body["detail"] = detail
	}
	for k, v := range extra {
		body[k] = v
	}
	reply(w, status, body, "application/problem+json")
}

func reply(w http.ResponseWriter, status int, v any, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(into); err != nil {
		problem(w, http.StatusBadRequest, "the request is not a JSON document of the shape this address reads", nil)
		return false
	}
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

func uuid() string {
	h := randomHex(16)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

// enroll turns an enrolment token and a public key into a pending agent.
func (s *Service) enroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token     string            `json:"token"`
		Name      string            `json:"name"`
		Versions  map[string]string `json:"versions"`
		PublicKey string            `json:"public_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	key, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		problem(w, http.StatusUnprocessableEntity, "public_key is an Ed25519 public key of 32 bytes, in standard base64", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enrolments[in.Token] {
		problem(w, http.StatusUnauthorized, "the enrolment token is not valid, was already used, or has expired", nil)
		return
	}
	for _, a := range s.agents {
		if string(a.Key) == string(key) {
			problem(w, http.StatusConflict, "that key is already enrolled: make a new one", nil)
			return
		}
	}
	delete(s.enrolments, in.Token)
	a := &Agent{ID: s.Tenant + "." + uuid(), Name: in.Name, Key: key, State: "pending", Versions: in.Versions}
	s.agents[a.ID] = a
	answered := a.ID
	if s.AgentID != "" {
		answered = s.AgentID
	}
	reply(w, http.StatusCreated, map[string]any{"agent_id": answered, "fingerprint": s.fingerprintOf(key), "state": a.State}, "application/json")
}

func (s *Service) fingerprintOf(key []byte) string {
	if s.Fingerprint != "" {
		return s.Fingerprint
	}
	return fingerprint(key)
}

func (s *Service) notOffered(w http.ResponseWriter, state string) {
	problem(w, http.StatusForbidden, "this agent is "+state, map[string]any{"state": state})
}

// open reads and verifies an assertion for an endpoint. Whatever is wrong is one 401.
func (s *Service) open(w http.ResponseWriter, r *http.Request, endpoint string) (*Assertion, *Agent, string, bool) {
	var in struct {
		Assertion       string `json:"assertion"`
		NewKeySignature string `json:"new_key_signature"`
	}
	if !readJSON(w, r, &in) {
		return nil, nil, "", false
	}
	a, err := ParseAssertion(in.Assertion, s.Server.URL+endpoint, s.now())
	if err != nil {
		problem(w, http.StatusUnauthorized, "the assertion is not valid", nil)
		return nil, nil, "", false
	}
	s.mu.Lock()
	agent := s.agents[a.ID]
	var key ed25519.PublicKey
	if agent != nil {
		key = agent.Key
	}
	s.mu.Unlock()
	if agent == nil || !a.Verify(key) {
		problem(w, http.StatusUnauthorized, "the assertion is not valid", nil)
		return nil, nil, "", false
	}
	return a, agent, in.NewKeySignature, true
}

// useJTI remembers an assertion until its end, and says whether it had been seen.
func (s *Service) useJTI(a *Assertion) bool {
	now := s.now()
	for k, until := range s.jtis {
		if now.After(until) {
			delete(s.jtis, k)
		}
	}
	if _, seen := s.jtis[a.ID+"/"+a.Claims.Jti]; seen {
		return false
	}
	s.jtis[a.ID+"/"+a.Claims.Jti] = a.Expires().Add(4 * time.Minute)
	return true
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	a, agent, _, proved := s.open(w, r, "/agent/v1/token")
	if !proved {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent.State != "confirmed" {
		s.notOffered(w, agent.State)
		return
	}
	if !s.useJTI(a) {
		problem(w, http.StatusUnauthorized, "the assertion is not valid", nil)
		return
	}
	tok := "acc_agt_" + randomHex(24)
	expires := s.now().Add(s.TokenLife)
	s.tokens[tok] = &token{agent: agent.ID, expires: expires}
	reply(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer",
		"expires_at": expires.UTC().Format(time.RFC3339), "expires_in": int(s.TokenLife.Seconds())}, "application/json")
}

// rotate changes an agent's key; the access tokens the old key got stop working at once.
func (s *Service) rotate(w http.ResponseWriter, r *http.Request) {
	time.Sleep(s.RotateDelay)
	a, agent, sigText, proved := s.open(w, r, "/agent/v1/rotate")
	if !proved {
		return
	}
	newKey, err := base64.StdEncoding.DecodeString(a.Claims.NewKey)
	sig, serr := base64.RawURLEncoding.DecodeString(sigText)
	if err != nil || serr != nil || len(newKey) != ed25519.PublicKeySize || !ed25519.Verify(newKey, []byte(a.Signed), sig) {
		problem(w, http.StatusUnauthorized, "the assertion is not valid", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent.State != "confirmed" {
		s.notOffered(w, agent.State)
		return
	}
	if !s.useJTI(a) {
		problem(w, http.StatusUnauthorized, "the assertion is not valid", nil)
		return
	}
	for _, other := range s.agents {
		if string(other.Key) == string(newKey) {
			problem(w, http.StatusConflict, "that key is already enrolled: make a new one", nil)
			return
		}
	}
	agent.Key = newKey
	for t, info := range s.tokens {
		if info.agent == agent.ID {
			delete(s.tokens, t)
		}
	}
	reply(w, http.StatusOK, map[string]any{"agent_id": agent.ID, "fingerprint": s.fingerprintOf(newKey)}, "application/json")
}

// authenticate finds the agent an access token is for.
func (s *Service) authenticate(w http.ResponseWriter, r *http.Request) *Agent {
	tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	info := s.tokens[tok]
	if !found || info == nil || !s.now().Before(info.expires) {
		problem(w, http.StatusUnauthorized, "", nil)
		return nil
	}
	agent := s.agents[info.agent]
	if agent == nil || agent.State != "confirmed" {
		problem(w, http.StatusUnauthorized, "", nil)
		return nil
	}
	return agent
}

func (s *Service) hello(w http.ResponseWriter, r *http.Request) {
	if a := s.authenticate(w, r); a != nil {
		reply(w, http.StatusOK, map[string]any{"agent_id": a.ID, "name": a.Name, "state": "confirmed"}, "application/json")
	}
}

// fault is a scripted misbehaviour.
type fault struct {
	match  func(*http.Request) bool
	times  int // how many matching requests it applies to; <0 is all
	status int
	header http.Header
	// store handles the request normally and then drops the connection without an answer,
	// as a network that lost the response would.
	dropAfter bool
	// drop closes the connection without handling the request: it never arrived.
	drop bool
	// body, when set, is the whole answer, sent in place of handling the request.
	body string
}

func (f *fault) apply(w http.ResponseWriter, r *http.Request, s *Service) bool {
	if f.dropAfter || f.drop {
		if f.dropAfter {
			s.route(httptest.NewRecorder(), r)
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			return false
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return true
	}
	for k, v := range f.header {
		w.Header()[k] = v
	}
	if f.body != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
		return true
	}
	problem(w, f.status, "scripted", nil)
	return true
}

// route runs the handlers without the fault hook.
func (s *Service) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/agent/v1/jobs":
		s.jobs(w, r)
	case strings.HasPrefix(r.URL.Path, "/agent/v1/streams/"):
		s.stream(w, r)
	case r.URL.Path == "/agent/v1/token":
		s.token(w, r)
	case r.URL.Path == "/agent/v1/rotate":
		s.rotate(w, r)
	case r.URL.Path == "/agent/v1/enroll":
		s.enroll(w, r)
	default:
		s.hello(w, r)
	}
}

func (s *Service) matchFault(r *http.Request) *fault {
	for _, f := range s.faults {
		if f.times != 0 && f.match(r) {
			if f.times > 0 {
				f.times--
			}
			return f
		}
	}
	return nil
}

// Fail answers the next times requests that match with a problem of that status (and these
// headers), whatever they were. times < 0 is every one.
func (s *Service) Fail(match func(*http.Request) bool, times, status int, header http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &fault{match: match, times: times, status: status, header: header})
}

// Reply answers the next times requests that match with this status and this body, as it is.
func (s *Service) Reply(match func(*http.Request) bool, times, status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &fault{match: match, times: times, status: status, body: body})
}

// DropAnswers lets the next times requests that match be handled and then loses the answer.
func (s *Service) DropAnswers(match func(*http.Request) bool, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &fault{match: match, times: times, dropAfter: true})
}

// DropRequests closes the connection on the next times requests that match, unhandled.
func (s *Service) DropRequests(match func(*http.Request) bool, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, &fault{match: match, times: times, drop: true})
}

// Chunk matches the PUT of chunk n of any stream.
func Chunk(n int) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/chunks/"+strconv.Itoa(n))
	}
}

// Path matches a method and the end of a path.
func Path(method, suffix string) func(*http.Request) bool {
	return func(r *http.Request) bool { return r.Method == method && strings.HasSuffix(r.URL.Path, suffix) }
}

func (s *Service) String() string { return fmt.Sprintf("fakeservice(%s)", s.Server.URL) }
