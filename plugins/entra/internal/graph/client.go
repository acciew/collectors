package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config is what the client needs to reach a tenant.
type Config struct {
	// TenantID is a tenant GUID or a verified domain name.
	TenantID string
	ClientID string
	// Exactly one of ClientSecret and Certificate.
	ClientSecret string
	Certificate  *Certificate
	Endpoints    Endpoints
	// HTTP is the client to use. Nil means one with a timeout.
	HTTP *http.Client
	// Now is the clock; nil means time.Now. A test sets it to make the
	// assertion's lifetime and the token's expiry deterministic.
	Now func() time.Time
}

// Client reads Microsoft Graph as an application.
type Client struct {
	cfg  Config
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
	tenant  string
}

// apiRoot is the version of Graph the collector reads. v1.0 only: a beta
// endpoint can change under a collector with no notice.
const apiRoot = "/v1.0"

// maxBody bounds one response. Graph pages are far smaller; the bound is for a
// service that answers with something else entirely.
const maxBody = 64 << 20

// Dial authenticates and returns a client.
//
// Authentication happens here rather than on the first read so that a wrong
// secret fails where an operator is looking, and not in the middle of a
// collection.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if (cfg.ClientSecret == "") == (cfg.Certificate == nil) {
		return nil, errors.New("exactly one of a client secret and a certificate is required")
	}
	c := &Client{cfg: cfg, now: cfg.Now}
	if cfg.HTTP != nil {
		copied := *cfg.HTTP
		c.http = &copied
	} else {
		c.http = &http.Client{Timeout: 60 * time.Second}
	}
	// A redirect is never followed. The token request carries the client
	// secret in its body, and a 307 would send that body to wherever the
	// redirect pointed; a page request carries a token that reads the whole
	// directory. Neither service redirects, so a redirect is a failure.
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if c.now == nil {
		c.now = time.Now
	}
	c.cfg.Endpoints.Graph = strings.TrimSuffix(cfg.Endpoints.Graph, "/")
	c.cfg.Endpoints.Login = strings.TrimSuffix(cfg.Endpoints.Login, "/")
	if _, err := c.bearer(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// TenantID is the tenant GUID the token was issued for, which is the tenant
// the collection describes however the configuration named it.
func (c *Client) TenantID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tenant
}

// bearer returns a valid access token, fetching one only when needed.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	return c.login(ctx)
}

func (c *Client) forget(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

func (c *Client) login(ctx context.Context) (string, error) {
	endpoint := c.cfg.Endpoints.Login + "/" + url.PathEscape(c.cfg.TenantID) + "/oauth2/v2.0/token"
	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {c.cfg.ClientID},
		"scope":      {c.cfg.Endpoints.Graph + "/.default"},
	}
	if c.cfg.Certificate != nil {
		assertion, err := c.cfg.Certificate.assertion(c.cfg.ClientID, endpoint, c.now())
		if err != nil {
			return "", fmt.Errorf("signing the client assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	} else {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", &Error{Kind: KindUnavailable, Message: "could not reach the token service", Err: urlError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	if resp.StatusCode != http.StatusOK {
		e := &Error{Kind: kindFor(resp.StatusCode), Status: resp.StatusCode, Message: "authenticating"}
		// A rejected credential is a 400 or a 401 depending on the failure,
		// and both mean the same thing to an operator.
		if resp.StatusCode == http.StatusBadRequest {
			e.Kind = KindAuth
		}
		var tokenErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &tokenErr) == nil && tokenErr.Description != "" {
			e.Message = "authenticating: " + firstLine(tokenErr.Description)
		}
		if e.Kind == KindRateLimited {
			e.RetryAfter = retryAfter(resp.Header, c.now())
		}
		return "", e
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", &Error{Kind: KindSource, Message: "the token response was not a token", Err: err}
	}
	c.token = out.AccessToken
	// Renew early: a token that expires mid-collection is a failure that looks
	// like a permissions problem.
	lifetime := time.Duration(out.ExpiresIn) * time.Second
	c.expires = c.now().Add(lifetime - lifetime/5)
	c.tenant = tenantClaim(out.AccessToken)
	return c.token, nil
}

// tenantClaim reads the tid claim of an access token. No signature check, on
// purpose: this is not an authorisation decision, it is reading back which
// tenant the service says the token is for.
func tenantClaim(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		TID string `json:"tid"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.TID
}

// urlError drops the URL from a transport error: it can carry a query, and
// nothing the caller needs is in it.
func urlError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Page is one page of a collection and the link to the next, empty on the
// last.
type Page[T any] struct {
	Items []T
	Next  string
}

// GetPage reads one page. A target is either a path below v1.0, such as
// "/users?$top=5", or a nextLink Graph itself returned.
//
// A nextLink is followed only if it names the Graph host this client was
// configured for. It comes from the service; following one to another host would
// hand that host a token that reads the whole directory.
//
// A body with no value is not an empty page. A 200 that says nothing about its
// collection would otherwise read as a tenant with nobody in it.
func GetPage[T any](ctx context.Context, c *Client, target string) (Page[T], error) {
	var raw json.RawMessage
	if err := c.get(ctx, target, &raw); err != nil {
		return Page[T]{}, err
	}
	page, err := DecodePage[T](raw)
	if err != nil {
		return Page[T]{}, &Error{Kind: KindSource, Message: pathOf(target) + " did not return a page", Err: err}
	}
	return page, nil
}

// Get reads one object.
func Get[T any](ctx context.Context, c *Client, target string) (T, error) {
	var out T
	err := c.get(ctx, target, &out)
	return out, err
}

// Read makes a request and discards the answer, for a check that asks whether
// a read is allowed and not what it returns.
func (c *Client) Read(ctx context.Context, target string) error {
	var discard json.RawMessage
	return c.get(ctx, target, &discard)
}

// ReadPage makes a request for a collection and discards the page, for a check
// that asks whether a read is allowed and not what it returns. The answer must
// still be a page: a body with no value is not a collection that can be read.
func (c *Client) ReadPage(ctx context.Context, target string) error {
	var raw json.RawMessage
	if err := c.get(ctx, target, &raw); err != nil {
		return err
	}
	if _, err := DecodePage[json.RawMessage](raw); err != nil {
		return &Error{Kind: KindSource, Message: pathOf(target) + " did not return a page", Err: err}
	}
	return nil
}

// Valid says whether a target is one this client would follow: a path below
// v1.0, or a link on the configured Graph host.
func (c *Client) Valid(target string) bool {
	_, err := c.resolve(target)
	return err == nil
}

// Absolute is a target as the URL it is read from, or empty if this client
// would not follow it. Two spellings of one page are one page.
func (c *Client) Absolute(target string) string {
	u, err := c.resolve(target)
	if err != nil {
		return ""
	}
	return u
}

// DecodePage reads a page out of a body, and refuses one that has no value to
// read.
func DecodePage[T any](raw json.RawMessage) (Page[T], error) {
	var env struct {
		Value *[]T   `json:"value"`
		Next  string `json:"@odata.nextLink"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return Page[T]{}, err
	}
	if env.Value == nil {
		return Page[T]{}, errors.New("the body has no value")
	}
	return Page[T]{Items: *env.Value, Next: env.Next}, nil
}

func (c *Client) resolve(target string) (string, error) {
	switch {
	case strings.HasPrefix(target, c.cfg.Endpoints.Graph+apiRoot+"/"):
		return target, nil
	case strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//"):
		return c.cfg.Endpoints.Graph + apiRoot + target, nil
	}
	return "", &Error{Kind: KindSource, Message: "refusing to follow a link that is not on the configured Graph host"}
}

// get fetches one target into out, renewing the token once if Graph says it
// has expired.
func (c *Client) get(ctx context.Context, target string, out any) error {
	u, err := c.resolve(target)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		token, err := c.bearer(ctx)
		if err != nil {
			return err
		}
		status, err := c.do(ctx, u, token, out)
		if status == http.StatusUnauthorized && attempt == 0 {
			c.forget(token)
			continue
		}
		return err
	}
}

// do makes one request and reports the status it got.
func (c *Client) do(ctx context.Context, u, token string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, &Error{Kind: KindUnavailable, Message: "could not reach " + pathOf(u), Err: urlError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, c.failure(resp, u, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, &Error{Kind: KindSource, Message: pathOf(u) + " did not return the JSON expected", Err: err}
	}
	return resp.StatusCode, nil
}

func (c *Client) failure(resp *http.Response, u string, body []byte) *Error {
	e := &Error{Kind: kindFor(resp.StatusCode), Status: resp.StatusCode, Message: pathOf(u)}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	graphBody := json.Unmarshal(body, &env) == nil
	if graphBody {
		e.Code = env.Error.Code
		if env.Error.Message != "" {
			e.Message += ": " + firstLine(env.Error.Message)
		}
	}
	switch {
	case e.Kind == KindNotFound && (!graphBody || env.Error.Code == ""):
		// Only Graph's own not-found says a thing is gone: an error body with a
		// code that is one of its not-found codes. A proxy or gateway answers 404
		// for paths it does not know, and reading that as a deleted group or a
		// principal that is gone would drop what was never read and call the
		// collection whole.
		e.Kind = KindSource
		e.Message += ": not found by something that is not Microsoft Graph; a proxy or gateway is answering for it"
	case e.Kind == KindNotFound && !notFoundCode(env.Error.Code):
		// Graph-shaped, but it says something else: a refusal's code on a 404 is
		// not a thing that is gone.
		e.Kind = KindSource
		e.Message += ": answered 404 with " + env.Error.Code + ", which is not a not-found code"
	case e.Kind == KindPermission && !graphBody:
		// Only a refusal that looks like Graph's says anything about a grant.
		// A proxy or gateway in front of it also answers 403, and telling an
		// operator to grant a permission they hold sends them the wrong way.
		e.Kind = KindSource
		e.Message += ": refused by something that is not Microsoft Graph; a proxy or gateway is answering for it"
	}
	// A throttle names how long to wait, and so may an outage.
	if e.Kind == KindRateLimited || e.Kind == KindUnavailable {
		e.RetryAfter = retryAfter(resp.Header, c.now())
	}
	return e
}

// notFoundCodes are the codes Graph answers a 404 with when a thing is not
// there: Entra's, and the Outlook and OneDrive ones that other Graph services
// share. Compared without regard to case. A code that only contains one is not
// one.
var notFoundCodes = map[string]bool{
	"request_resourcenotfound": true,
	"resourcenotfound":         true,
	"erroritemnotfound":        true,
	"itemnotfound":             true,
}

func notFoundCode(code string) bool { return notFoundCodes[strings.ToLower(code)] }

// pathOf is the path of a URL, without its query: errors and logs name what
// was read and not what was filtered for.
func pathOf(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "a Graph URL"
	}
	return strings.TrimPrefix(parsed.Path, apiRoot)
}
