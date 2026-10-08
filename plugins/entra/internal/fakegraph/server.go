// Package fakegraph is a Microsoft Graph standing in for the real one, for
// tests: an httptest server that issues tokens, checks them, pages its
// collections with @odata.nextLink and honours $select the way Graph does.
//
// Everything in it is synthetic: identifiers are made up and the domain is
// example.onmicrosoft.com. It models the behaviour the collector relies on,
// each piece taken from Microsoft's documentation; where the documentation is
// silent the fake does not guess, so a behaviour that is not verified is not
// one a test can quietly depend on.
package fakegraph

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Server is a running fake Graph and token service.
type Server struct {
	*httptest.Server
	Tenant *Tenant

	// OnRequest, when set, is called with every request before it is answered,
	// from the server's goroutines. A test uses it to move a clock when a
	// particular read happens.
	OnRequest func(Request)

	// PageSize is how many items a collection returns before a nextLink. It
	// overrides $top when smaller, so a test sees paging without large data.
	PageSize int

	mu       sync.Mutex
	secret   string
	cert     *x509.Certificate
	clientID string
	log      []Request
	rules    []*rule
	// generation is bumped to expire every token issued so far.
	generation int
}

// Request is one request the fake received.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Auth   string
}

// New starts a fake for a tenant. The caller closes nothing: the server is
// closed when the test ends.
func New(t testing.TB, tenant *Tenant) *Server {
	t.Helper()
	s := &Server{Tenant: tenant, PageSize: 3}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// AcceptSecret makes the token endpoint accept this client and secret.
func (s *Server) AcceptSecret(clientID, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientID, s.secret, s.cert = clientID, secret, nil
}

// AcceptCertificate makes the token endpoint accept a client assertion signed
// by the key of this certificate, and nothing else.
func (s *Server) AcceptCertificate(clientID string, cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientID, s.cert, s.secret = clientID, cert, ""
}

// Requests returns what the fake has received, oldest first.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

// Paths returns the path and query of every Graph request, for assertions
// about what the collector did and did not ask for.
func (s *Server) Paths() []string {
	var out []string
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, "/v1.0/") {
			out = append(out, r.Path+"?"+r.Query.Encode())
		}
	}
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	req := Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Auth: r.Header.Get("Authorization")}
	s.mu.Lock()
	s.log = append(s.log, req)
	hook := s.OnRequest
	s.mu.Unlock()
	if hook != nil {
		hook(req)
	}

	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		s.token(w, r)
		return
	}
	if !s.authorised(req.Auth) {
		writeError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty or not valid.")
		return
	}
	for _, rl := range s.match(r.URL.Path) {
		if rl.apply(w, r) {
			return
		}
	}
	s.graph(w, r)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	clientID, secret, cert := s.clientID, s.secret, s.cert
	s.mu.Unlock()

	refuse := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_client",
			"error_description": code + ": the credentials were refused.\r\nTrace ID: 0\r\nCorrelation ID: 0",
		})
	}
	form := r.PostForm
	switch {
	case form.Get("grant_type") != "client_credentials":
		refuse("AADSTS70003")
		return
	case form.Get("client_id") != clientID:
		refuse("AADSTS700016")
		return
	case form.Get("scope") != s.URL+"/.default":
		refuse("AADSTS70011")
		return
	case cert != nil:
		if form.Get("client_secret") != "" || !validAssertion(form, cert, clientID, s.URL+r.URL.Path) {
			refuse("AADSTS700027")
			return
		}
	case form.Get("client_secret") != secret || secret == "":
		refuse("AADSTS7000215")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token_type": "Bearer", "expires_in": 3599,
		"access_token": s.currentToken(),
	})
}

// fakeToken is shaped like Graph's access tokens: three parts, the middle one
// carrying claims. The signature is not one; nothing here verifies it.
func fakeToken(tenant string, generation int) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]any{"tid": tenant, "gen": generation})
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

func (s *Server) currentToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fakeToken(s.Tenant.ID, s.generation)
}

// ExpireTokens makes every token issued so far be refused with 401, as Graph
// refuses one that has run out.
func (s *Server) ExpireTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation++
}

func (s *Server) authorised(header string) bool {
	token, ok := strings.CutPrefix(header, "Bearer ")
	return ok && token == s.currentToken()
}

// validAssertion checks a client assertion the way the token service does: a
// PS256 signature by the registered certificate's key, the certificate's
// thumbprint in the header, and the claims that bind it to this client and
// this endpoint.
func validAssertion(form url.Values, cert *x509.Certificate, clientID, audience string) bool {
	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return false
	}
	parts := strings.Split(form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		return false
	}
	dec := base64.RawURLEncoding
	var header struct {
		Alg, Typ string
		X5t      string `json:"x5t#S256"`
	}
	var claims struct {
		Aud, Iss, Sub, Jti string
		Nbf, Exp           int64
	}
	for i, into := range []any{&header, &claims} {
		raw, err := dec.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, into) != nil {
			return false
		}
	}
	sum := sha256.Sum256(cert.Raw)
	if header.Alg != "PS256" || header.X5t != dec.EncodeToString(sum[:]) {
		return false
	}
	now := time.Now().Unix()
	if claims.Aud != audience || claims.Iss != clientID || claims.Sub != clientID ||
		claims.Jti == "" || claims.Exp <= now || claims.Nbf > now+60 {
		return false
	}
	sig, err := dec.DecodeString(parts[2])
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if err != nil || !ok {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// page serves one page of a collection: the items from $skiptoken on, at most
// PageSize (or $top, if smaller), with a nextLink that carries the rest.
func (s *Server) page(w http.ResponseWriter, r *http.Request, items []map[string]any) {
	size := s.PageSize
	if top, err := strconv.Atoi(r.URL.Query().Get("$top")); err == nil && top > 0 && top < size {
		size = top
	}
	start := 0
	if tok := r.URL.Query().Get("$skiptoken"); tok != "" {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 0 || n > len(items) {
			writeError(w, http.StatusBadRequest, "Request_BadRequest", "Invalid skip token.")
			return
		}
		start = n
	}
	end := min(start+size, len(items))
	out := map[string]any{"value": items[start:end]}
	if out["value"] == nil || start == end {
		out["value"] = []map[string]any{}
	}
	if end < len(items) {
		q := r.URL.Query()
		q.Set("$skiptoken", strconv.Itoa(end))
		out["@odata.nextLink"] = s.URL + r.URL.Path + "?" + q.Encode()
	}
	writeJSON(w, out)
}

// selected keeps the properties a request asked for with $select, plus id and
// the type annotation, which Graph always returns. Without $select a resource
// comes back with its default properties.
func selected(r *http.Request, all map[string]any, defaults ...string) map[string]any {
	want := defaults
	if sel := r.URL.Query().Get("$select"); sel != "" {
		want = strings.Split(sel, ",")
	}
	out := map[string]any{}
	for _, k := range []string{"id", "@odata.type"} {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	for _, k := range want {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out
}

func guid(label string) string {
	sum := sha256.Sum256([]byte(label))
	h := fmt.Sprintf("%x", sum[:16])
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:32]
}

// GUID is a stable, made-up identifier for a label, shaped like the real ones.
func GUID(label string) string { return guid(label) }
