// Package admin is a small client for the Keycloak Admin REST API.
//
// It covers what the collector needs and nothing else. A general-purpose
// Keycloak library would be a larger dependency tree and a larger CVE surface
// for the sake of endpoints we never call, and the endpoints we do call are
// the ones documented and verified in docs/design/three-source-mapping.md.
//
// Read-only by design: there is no method here that writes to Keycloak, and
// there should never be one. Write-back is a different risk class.
package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is what the collector needs to reach a Keycloak.
type Config struct {
	// BaseURL of the Keycloak, without a trailing slash: https://kc.example.com
	BaseURL string
	// AuthRealm is the realm the service account authenticates against, which
	// is not necessarily a realm being collected.
	AuthRealm string
	// ClientID and ClientSecret are a confidential client with the roles
	// needed to read the realms in scope.
	ClientID     string
	ClientSecret string
	// PageSize for paged endpoints. Zero means 100.
	PageSize int
	// HTTP is the client to use. Nil means a sensible default.
	HTTP *http.Client
}

// Client reads a Keycloak.
type Client struct {
	base      string
	authRealm string
	authURL   string
	id        string
	secret    string
	pageSize  int
	http      *http.Client
	// onePage stops paged reads after the first page. Set only on the client
	// a pre-flight check uses; see OnePage.
	onePage bool

	auth *authState
}

// authState is the token, shared by every client that came from one Dial.
// Held behind a pointer so OnePage can hand back a different client without
// a second login or a copied mutex.
type authState struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

// Dial authenticates and returns a client.
//
// Authentication happens here rather than lazily so that a wrong secret fails
// where an operator is looking, instead of in the middle of a collection.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}
	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	c := &Client{
		base:      strings.TrimSuffix(cfg.BaseURL, "/"),
		authRealm: cfg.AuthRealm,
		id:        cfg.ClientID,
		secret:    cfg.ClientSecret,
		pageSize:  pageSize,
		http:      httpClient,
		auth:      &authState{},
	}
	c.authURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		c.base, url.PathEscape(cfg.AuthRealm))
	if _, err := c.bearer(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// bearer returns a valid access token, fetching one only when needed. A token
// per request would multiply the load on every customer's token endpoint for
// no benefit.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.auth.mu.Lock()
	defer c.auth.mu.Unlock()
	if c.auth.token != "" && time.Now().Before(c.auth.expires) {
		return c.auth.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.id},
		"client_secret": {c.secret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", &Error{Kind: KindUnavailable, Retryable: true, Err: err,
			Message: "could not reach the Keycloak token endpoint"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", errorFor(resp, "authenticating")
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", &Error{Kind: KindSource, Err: err, Message: "the token response was not JSON"}
	}
	c.auth.token = body.AccessToken
	// Renew early. A token that expires mid-collection is a failure that
	// looks like a permissions problem.
	lifetime := time.Duration(body.ExpiresIn) * time.Second
	c.auth.expires = time.Now().Add(lifetime - lifetime/5)
	return c.auth.token, nil
}

// get fetches one admin path into out.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	token, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	u := c.base + "/admin" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Kind: KindUnavailable, Retryable: true, Err: err,
			Message: "could not reach " + path}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return errorFor(resp, path)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return &Error{Kind: KindSource, Err: err, Message: path + " did not return JSON"}
	}
	return nil
}

// OnePage returns a client whose paged reads stop after the first page.
//
// For a pre-flight check, which asks whether a read is allowed rather than
// what it returns: checking a realm of a hundred thousand users should not
// download a hundred thousand users to learn one thing about a token.
//
// A distinct client rather than a flag on a call or a value on a context,
// because a bounded read reaching a collection would produce one page of a
// realm reported as the whole of it. This way it cannot travel: the
// collection holds a client that has no such setting, and no context it is
// handed can give it one. Both clients share one token, so this costs no
// second login.
func (c *Client) OnePage() *Client {
	bounded := *c
	bounded.onePage = true
	return &bounded
}

// paged walks a first/max endpoint to its end.
//
// Stopping at the first page is the mistake that matters here: it produces a
// population that looks complete and is not, which is exactly what the
// contract's completeness rules exist to prevent one level up.
func paged[T any](ctx context.Context, c *Client, path string, extra url.Values) ([]T, error) {
	var out []T
	for first := 0; ; first += c.pageSize {
		query := url.Values{
			"first": {strconv.Itoa(first)},
			"max":   {strconv.Itoa(c.pageSize)},
		}
		for k, vs := range extra {
			query[k] = vs
		}
		var page []T
		if err := c.get(ctx, path, query, &page); err != nil {
			return out, err
		}
		out = append(out, page...)
		if len(page) < c.pageSize || c.onePage {
			return out, nil
		}
	}
}

// ManagementClient names the client whose roles govern reads of one realm.
//
// Every realm but master has a realm-management client governing itself.
// Master has none: it holds a <realm>-realm client for every realm including
// its own, which is how master administers the others and itself — verified
// against 26.4.7, where master's clients are master-realm and one -realm
// client per other realm. Telling an operator to look in a client that does
// not exist is telling them the roles are not there.
func (c *Client) ManagementClient(realm string) string {
	if realm == c.authRealm && realm != masterRealm {
		return "realm-management"
	}
	return realm + "-realm"
}

// masterRealm is the one realm that can administer another, and the one
// without a realm-management client of its own.
const masterRealm = "master"

// GrantedRoles reports which of that client's roles this token carries, and
// whether it could tell at all.
//
// The second return is the point. A client with full scope off carries none
// of them in the token while holding all of them in Keycloak, so an absent
// claim means "no answer", never "no roles". Read as a positive it would
// refuse working credentials.
func (c *Client) GrantedRoles(realm string) (map[string]bool, bool) {
	c.auth.mu.Lock()
	token := c.auth.token
	c.auth.mu.Unlock()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	// No signature check on purpose. This is not an authorisation decision —
	// Keycloak makes those — it is reading back what Keycloak said it granted
	// us, to tell an operator which role to add.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims struct {
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	// A token with no resource_access at all says nothing: lightweight
	// access tokens and a missing roles scope both look like this, and the
	// grant could be anything. A token that carries resource_access without
	// an entry for this realm's management client is a different thing
	// entirely — it is Keycloak stating that none of those roles are held,
	// which is exactly the first state a service account is in.
	if claims.ResourceAccess == nil {
		return nil, false
	}
	access := claims.ResourceAccess[c.ManagementClient(realm)]
	roles := make(map[string]bool, len(access.Roles))
	for _, r := range access.Roles {
		roles[r] = true
	}
	return roles, true
}
