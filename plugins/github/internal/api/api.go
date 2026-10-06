// Package api reads the GitHub REST API.
//
// Hand-rolled rather than built on a client library, for the same reason the
// Keycloak collector is: this reads eleven endpoints, it never writes, and a
// narrow surface is one whose failure modes can be stated. The library would
// bring a dependency tree larger than the plugin.
//
// Two things here are structurally unlike the Keycloak client and are the
// reason this package exists at all. Paging is a Link header rather than a
// marker, and running out of quota is an ordinary outcome rather than a
// failure — a large organization cannot be collected inside one rate-limit
// window, which makes resumption a correctness requirement.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is what the client needs to talk to GitHub.
type Config struct {
	// BaseURL of the API. Empty means github.com; an Enterprise Server
	// installation is https://ghe.example.com/api/v3.
	BaseURL string
	// Token is the credential. Never logged, never put in an error.
	Token string
	// PageSize for paged endpoints. Zero means 100, GitHub's maximum.
	PageSize int
	HTTP     *http.Client
}

// Client reads a GitHub. It never writes.
type Client struct {
	base     string
	token    string
	pageSize int
	http     *http.Client
}

// Dial prepares a client. It contacts nothing: reachability is a question for
// TestConnection, which reports it as a result rather than as an error.
func Dial(cfg Config) (*Client, error) {
	base := strings.TrimSuffix(cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("github: the base URL is not usable: %w", err)
	}
	if cfg.Token == "" {
		return nil, errors.New("github: a token is required")
	}
	size := cfg.PageSize
	if size <= 0 {
		size = 100
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: base, token: cfg.Token, pageSize: size, http: client}, nil
}

// maxPages bounds a single paged walk. A source that keeps handing back a
// next link — a proxy rewriting headers, a bug at the far end — would
// otherwise be walked for ever, and a collection that never finishes is
// indistinguishable from one that hung.
const maxPages = 10_000

func (c *Client) get(ctx context.Context, path, what string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return &Error{Kind: Source, What: what, Err: err}
	}
	c.sign(req)

	resp, err := c.http.Do(req)
	if err != nil {
		// The URL can carry an organization name but never the credential,
		// which is in a header.
		return &Error{Kind: Unavailable, What: what, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return errorFor(resp, what)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return &Error{Kind: Source, What: what, Err: fmt.Errorf("unreadable response: %w", err)}
		}
	}
	return nil
}

func (c *Client) sign(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	// Pinned, so that a change to GitHub's default cannot change what this
	// collector reads without somebody choosing it.
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// paged walks a list endpoint to the end, following the Link header.
func paged[T any](ctx context.Context, c *Client, path, what string) ([]T, error) {
	next := c.base + withPageSize(path, c.pageSize)
	seen := map[string]bool{}

	var all []T
	for pages := 0; next != ""; pages++ {
		if pages >= maxPages {
			return nil, &Error{Kind: Source, What: what,
				Err: fmt.Errorf("stopped after %d pages; the source keeps offering another", maxPages)}
		}
		if seen[next] {
			return nil, &Error{Kind: Source, What: what,
				Err: errors.New("the source's next link points at a page already read")}
		}
		seen[next] = true

		page, link, err := c.page(ctx, next, what)
		if err != nil {
			return nil, err
		}
		var batch []T
		if err := json.Unmarshal(page, &batch); err != nil {
			return nil, &Error{Kind: Source, What: what,
				Err: fmt.Errorf("unreadable response: %w", err)}
		}
		all = append(all, batch...)
		next = nextLink(link)
	}
	return all, nil
}

func (c *Client) page(ctx context.Context, target, what string) (body []byte, link string, err error) {
	// The next link comes from the response, and the request that follows it
	// carries the credential. A rewritten header — a proxy, a compromised
	// Enterprise host — would otherwise send the token wherever it points.
	if err := c.sameHost(target); err != nil {
		return nil, "", &Error{Kind: Source, What: what, Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", &Error{Kind: Source, What: what, Err: err}
	}
	c.sign(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", &Error{Kind: Unavailable, What: what, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return nil, "", errorFor(resp, what)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", &Error{Kind: Unavailable, What: what, Err: err}
	}
	return body, resp.Header.Get("Link"), nil
}

func withPageSize(path string, size int) string {
	if strings.Contains(path, "?") {
		return path + "&per_page=" + strconv.Itoa(size)
	}
	return path + "?per_page=" + strconv.Itoa(size)
}

// sameHost refuses to follow a link off the host this client was configured
// for. Anything the client signs goes to that host and no other.
func (c *Client) sameHost(target string) error {
	base, err := url.Parse(c.base)
	if err != nil {
		return err
	}
	next, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("the source offered a next page at an unreadable address")
	}
	if next.Host != base.Host || next.Scheme != base.Scheme {
		return fmt.Errorf("the source offered a next page at %s://%s, which is not %s; "+
			"the credential is not sent there", next.Scheme, next.Host, base.Host)
	}
	return nil
}

// linkNext matches the one relation that matters in a Link header.
var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

func nextLink(header string) string {
	if m := linkNext.FindStringSubmatch(header); m != nil {
		return m[1]
	}
	return ""
}

// errorFor turns a refusal into something an operator can act on.
//
// The subtle one is 403. GitHub uses it both for "you are going too fast" and
// for "your token does not carry this", and only the first is worth waiting
// out. The headers say which.
func errorFor(resp *http.Response, what string) *Error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var payload struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &payload)

	e := &Error{Status: resp.StatusCode, What: what, Message: payload.Message}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		e.Kind = Auth
	case http.StatusForbidden, http.StatusTooManyRequests:
		if wait, limited := rateLimited(resp, payload.Message); limited {
			e.Kind, e.RetryAfter = RateLimited, wait
		} else {
			e.Kind = Permission
		}
	case http.StatusNotFound:
		e.Kind = NotFound
	default:
		if resp.StatusCode >= 500 {
			e.Kind = Unavailable
		} else {
			e.Kind = Source
		}
	}
	return e
}

// rateLimited reports whether a refusal is a limit rather than a permission,
// and how long the source asked us to wait.
//
// There are two separate mechanisms. The primary limit spends a quota and
// says when it refills; the secondary limit is a burst rule that answers with
// Retry-After, and it is the one a fast collector actually trips.
func rateLimited(resp *http.Response, message string) (time.Duration, bool) {
	// Checked first, and for a reason. GitHub sends Remaining: 0 on every
	// response once the window is spent, so during the tail of a large
	// collection a genuine permission refusal would otherwise read as "wait
	// an hour" — and the operator would wait, and it would still fail.
	if saysPermission(message) {
		return 0, false
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second, true
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		wait := time.Minute
		if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
			if unix, err := strconv.ParseInt(v, 10, 64); err == nil {
				if d := time.Until(time.Unix(unix, 0)); d > 0 {
					wait = d
				}
			}
		}
		return wait, true
	}
	// No headers to go on. GitHub words both limits distinctively, and a
	// permission refusal never mentions a rate.
	if strings.Contains(strings.ToLower(message), "rate limit") {
		return time.Minute, true
	}
	return 0, false
}

// saysPermission reports whether GitHub's own words describe a refusal that
// waiting will not fix.
func saysPermission(message string) bool {
	m := strings.ToLower(message)
	for _, phrase := range []string{
		"must be an owner", "not accessible by integration", "resource not accessible",
		"forbidden", "requires authentication", "must have admin", "insufficient",
		"saml enforcement", "not authorized",
	} {
		if strings.Contains(m, phrase) {
			return true
		}
	}
	return false
}
