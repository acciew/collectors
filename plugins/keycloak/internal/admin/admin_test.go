package admin_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.acciew.io/collector/sdk/go/collector"

	"go.acciew.io/collector/plugins/keycloak/internal/admin"
)

// fakeKeycloak answers the shapes a real Keycloak answers. It exists to pin
// the requests this client makes — the paths, the paging, the token handling —
// precisely and in milliseconds. Whether Keycloak actually behaves this way is
// a separate question, answered by the container tests next to this file.
type fakeKeycloak struct {
	*httptest.Server
	tokens   atomic.Int64
	requests []string
}

// newFakeWithToken mints a real-shaped access token carrying the given
// claims, for the reads that look at what the token says rather than at what
// an endpoint answers.
func newFakeWithToken(t *testing.T, claims map[string]any) *fakeKeycloak {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jwt := "e30." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
	return newFakeToken(t, nil, jwt)
}

func newFake(t *testing.T, routes map[string]any) *fakeKeycloak {
	return newFakeToken(t, routes, "")
}

func newFakeToken(t *testing.T, routes map[string]any, token string) *fakeKeycloak {
	t.Helper()
	f := &fakeKeycloak{}
	mux := http.NewServeMux()

	// Any realm, not only master: a collector authenticating against the
	// realm it reads is an ordinary arrangement.
	mux.HandleFunc("/realms/{realm}/protocol/openid-connect/token",
		func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("token request was not a form: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q, want client_credentials", got)
			}
			n := f.tokens.Add(1)
			issued := token
			if issued == "" {
				issued = "token-" + string(rune('0'+n))
			}
			writeJSON(w, map[string]any{"access_token": issued, "expires_in": 60})
		})

	for path, body := range routes {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			f.requests = append(f.requests, r.URL.RequestURI())
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer token-") {
				t.Errorf("request to %s carried %q, want a bearer token", r.URL.Path, got)
			}
			if fn, ok := body.(func(*http.Request) any); ok {
				writeJSON(w, fn(r))
				return
			}
			writeJSON(w, body)
		})
	}
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func dial(t *testing.T, f *fakeKeycloak) *admin.Client {
	t.Helper()
	return dialAs(t, f, "master")
}

func dialAs(t *testing.T, f *fakeKeycloak, authRealm string) *admin.Client {
	t.Helper()
	c, err := admin.Dial(context.Background(), admin.Config{
		BaseURL: f.URL, AuthRealm: authRealm, ClientID: "acciew", ClientSecret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return c
}

func TestItAuthenticatesOnceAndReusesTheToken(t *testing.T) {
	f := newFake(t, map[string]any{
		"/admin/realms": []map[string]any{{"realm": "alpha", "id": "alpha"}},
	})
	c := dial(t, f)

	for range 3 {
		if _, err := c.Realms(context.Background()); err != nil {
			t.Fatalf("Realms: %v", err)
		}
	}
	// A token per request would triple the load on the token endpoint of
	// every customer's Keycloak, for nothing.
	if got := f.tokens.Load(); got != 1 {
		t.Errorf("fetched %d tokens for 3 requests, want 1", got)
	}
}

func TestItPagesUntilAShortPage(t *testing.T) {
	// 250 users at the default page size of 100: three requests, the last
	// short. A collector that stops at the first page silently under-reports
	// the population, which is the worst thing this product can do.
	f := newFake(t, map[string]any{
		"/admin/realms/alpha/users": func(r *http.Request) any {
			first := intParam(r.URL.Query(), "first")
			pageSize := intParam(r.URL.Query(), "max")
			var out []map[string]any
			for i := first; i < smaller(first+pageSize, 250); i++ {
				out = append(out, map[string]any{
					"id": "u" + itoa(i), "username": "user" + itoa(i), "enabled": true,
				})
			}
			return out
		},
	})
	users, err := dial(t, f).Users(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(users) != 250 {
		t.Fatalf("got %d users, want 250", len(users))
	}
	if len(f.requests) != 3 {
		t.Errorf("made %d requests, want 3 pages: %v", len(f.requests), f.requests)
	}
	if users[0].Username != "user0" || users[249].Username != "user249" {
		t.Errorf("first %q last %q", users[0].Username, users[249].Username)
	}
}

func TestItAsksForTheEndpointsTheMappingDocumentVerified(t *testing.T) {
	f := newFake(t, map[string]any{
		"/admin/realms/alpha/groups":                    []map[string]any{{"id": "g1", "name": "G", "subGroupCount": 1}},
		"/admin/realms/alpha/groups/g1/children":        []map[string]any{{"id": "g2", "name": "S"}},
		"/admin/realms/alpha/groups/g1/members":         []map[string]any{},
		"/admin/realms/alpha/groups/g2/members":         []map[string]any{{"id": "u1", "username": "alice"}},
		"/admin/realms/alpha/clients":                   []map[string]any{{"id": "c1", "clientId": "account"}},
		"/admin/realms/alpha/clients/c1/roles":          []map[string]any{{"id": "r9", "name": "view-profile"}},
		"/admin/realms/alpha/roles":                     []map[string]any{{"id": "r1", "name": "admin", "composite": true}},
		"/admin/realms/alpha/roles-by-id/r1/composites": []map[string]any{{"id": "r2", "name": "read"}},
	})
	c := dial(t, f)
	ctx := context.Background()

	groups, err := c.TopLevelGroups(ctx, "alpha")
	if err != nil || len(groups) != 1 || groups[0].SubGroupCount != 1 {
		t.Fatalf("TopLevelGroups = %+v, %v", groups, err)
	}
	// The tree is not inline: subGroups comes back empty and the children
	// need their own request. Verified against 26.4.7.
	children, err := c.Subgroups(ctx, "alpha", "g1")
	if err != nil || len(children) != 1 || children[0].Name != "S" {
		t.Fatalf("Subgroups = %+v, %v", children, err)
	}
	// Membership is direct only. The parent has none even though its child
	// does, and a collector that treats this as membership under-reports
	// every parent group.
	parentMembers, err := c.GroupMembers(ctx, "alpha", "g1")
	if err != nil || len(parentMembers) != 0 {
		t.Fatalf("parent members = %+v, %v", parentMembers, err)
	}
	childMembers, err := c.GroupMembers(ctx, "alpha", "g2")
	if err != nil || len(childMembers) != 1 {
		t.Fatalf("child members = %+v, %v", childMembers, err)
	}

	clients, err := c.Clients(ctx, "alpha")
	if err != nil || len(clients) != 1 || clients[0].ClientID != "account" {
		t.Fatalf("Clients = %+v, %v", clients, err)
	}
	clientRoles, err := c.ClientRoles(ctx, "alpha", "c1")
	if err != nil || len(clientRoles) != 1 {
		t.Fatalf("ClientRoles = %+v, %v", clientRoles, err)
	}
	realmRoles, err := c.RealmRoles(ctx, "alpha")
	if err != nil || len(realmRoles) != 1 || !realmRoles[0].Composite {
		t.Fatalf("RealmRoles = %+v, %v", realmRoles, err)
	}
	composites, err := c.RoleComposites(ctx, "alpha", "r1")
	if err != nil || len(composites) != 1 || composites[0].Name != "read" {
		t.Fatalf("RoleComposites = %+v, %v", composites, err)
	}
}

func TestErrorsSayWhichOnesAreWorthRetrying(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantKind  admin.Kind
		wantRetry bool
	}{
		{"credentials rejected", http.StatusUnauthorized, admin.KindAuth, false},
		{"credentials lack a role", http.StatusForbidden, admin.KindPermission, false},
		{"keycloak is rate limiting", http.StatusTooManyRequests, admin.KindRateLimited, true},
		{"keycloak is unwell", http.StatusServiceUnavailable, admin.KindUnavailable, true},
		{"something else", http.StatusTeapot, admin.KindSource, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/realms/master/protocol/openid-connect/token",
				func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, map[string]any{"access_token": "token-1", "expires_in": 60})
				})
			mux.HandleFunc("/admin/realms", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			c, err := admin.Dial(context.Background(), admin.Config{
				BaseURL: srv.URL, AuthRealm: "master", ClientID: "a", ClientSecret: "b",
			})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			_, err = c.Realms(context.Background())

			var apiErr *admin.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("want an *admin.Error, got %v", err)
			}
			if apiErr.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", apiErr.Kind, tt.wantKind)
			}
			if apiErr.Retryable != tt.wantRetry {
				t.Errorf("Retryable = %v, want %v", apiErr.Retryable, tt.wantRetry)
			}
		})
	}
}

func TestBadCredentialsFailAtDialRatherThanLater(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := admin.Dial(context.Background(), admin.Config{
		BaseURL: srv.URL, AuthRealm: "master", ClientID: "a", ClientSecret: "wrong",
	})
	var apiErr *admin.Error
	if !errors.As(err, &apiErr) || apiErr.Kind != admin.KindAuth {
		t.Fatalf("want an auth error at Dial, got %v", err)
	}
}

func intParam(v url.Values, name string) int {
	n := 0
	for _, c := range v.Get(name) {
		n = n*10 + int(c-'0')
	}
	return n
}

func smaller(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The bounded client a pre-flight check uses. It reads one page and stops,
// and the client it came from is unaffected — a check must not be able to
// turn a collection into one page of a realm.
func TestOnePageStopsAfterOnePageAndDoesNotAffectItsParent(t *testing.T) {
	users := func(r *http.Request) any {
		first := intParam(r.URL.Query(), "first")
		pageSize := intParam(r.URL.Query(), "max")
		var out []map[string]any
		for i := first; i < smaller(first+pageSize, 250); i++ {
			out = append(out, map[string]any{
				"id": "u" + itoa(i), "username": "user" + itoa(i), "enabled": true,
			})
		}
		return out
	}

	f := newFake(t, map[string]any{"/admin/realms/alpha/users": users})
	full := dial(t, f)
	bounded := full.OnePage()

	got, err := bounded.Users(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(got) != 100 {
		t.Errorf("the bounded client read %d users, want one page of 100", len(got))
	}

	// The same token, so no second login, and the parent still walks.
	before := len(f.requests)
	all, err := full.Users(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(all) != 250 {
		t.Fatalf("the client OnePage was called on read %d users, want all 250", len(all))
	}
	if len(f.requests)-before != 3 {
		t.Errorf("the unbounded read made %d requests, want 3", len(f.requests)-before)
	}
}

// Which client holds the roles for a realm, which is what an operator is told
// to go and look in. Measured against 26.4.7: master's clients are
// master-realm plus one <realm>-realm per other realm, and it has no
// realm-management; every other realm has realm-management and no -realm
// clients at all.
func TestWhichClientHoldsTheRolesForARealm(t *testing.T) {
	for _, c := range []struct{ auth, realm, want string }{
		{"acme", "acme", "realm-management"},
		{"master", "acme", "acme-realm"},
		// The case that named a client which does not exist: master
		// administers itself through master-realm like any other realm.
		{"master", "master", "master-realm"},
		{"acme", "master", "master-realm"},
	} {
		f := newFake(t, nil)
		client := dialAs(t, f, c.auth)
		if got := client.ManagementClient(c.realm); got != c.want {
			t.Errorf("auth %s, realm %s: got %s, want %s", c.auth, c.realm, got, c.want)
		}
	}
}

// A token that carries resource_access without an entry for the realm's
// management client is Keycloak saying those roles are not held — which is
// the first state a service account is in. Reading it as "no answer" tells
// an operator to go and fix a scope that was never broken.
func TestATokenWithoutTheseRolesIsAnAnswerNotASilence(t *testing.T) {
	for _, c := range []struct {
		name   string
		claims map[string]any
		known  bool
		holds  bool
	}{
		{"no resource_access at all", map[string]any{}, false, false},
		// An empty object is Keycloak saying "no client roles at all",
		// which is an answer. Only the key being absent is silence.
		{"an empty resource_access", map[string]any{
			"resource_access": map[string]any{}}, true, false},
		{"resource_access without realm-management", map[string]any{
			"resource_access": map[string]any{
				"account": map[string]any{"roles": []string{"view-profile"}},
			}}, true, false},
		{"realm-management with the role", map[string]any{
			"resource_access": map[string]any{
				"realm-management": map[string]any{"roles": []string{"view-users"}},
			}}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeWithToken(t, c.claims)
			roles, known := dialAs(t, f, "alpha").GrantedRoles("alpha")
			if known != c.known {
				t.Fatalf("known = %v, want %v", known, c.known)
			}
			if roles["view-users"] != c.holds {
				t.Errorf("view-users = %v, want %v", roles["view-users"], c.holds)
			}
		})
	}
}

// A 403 is only evidence about a grant when Keycloak is the one sending it.
// A proxy, a WAF or a login page in front of it answers 403 too, and calling
// that a missing role sends an operator to grant something they already hold.
func TestOnlyKeycloaksOwnRefusalIsAPermission(t *testing.T) {
	for _, c := range []struct {
		name        string
		contentType string
		want        admin.Kind
	}{
		{"Keycloak", "application/json", admin.KindPermission},
		{"Keycloak with no body", "", admin.KindPermission},
		{"a gateway", "text/html; charset=utf-8", admin.KindSource},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/token") {
					writeJSON(w, map[string]any{"access_token": "token-1", "expires_in": 60})
					return
				}
				if c.contentType != "" {
					w.Header().Set("Content-Type", c.contentType)
				}
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(srv.Close)

			client, err := admin.Dial(context.Background(), admin.Config{
				BaseURL: srv.URL, AuthRealm: "alpha", ClientID: "acciew", ClientSecret: "s",
			})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			_, err = client.Users(context.Background(), "alpha")
			var ae *admin.Error
			if !errors.As(err, &ae) {
				t.Fatalf("want an admin.Error, got %v", err)
			}
			if ae.Kind != c.want {
				t.Errorf("Kind = %v, want %v (%v)", ae.Kind, c.want, ae)
			}
		})
	}
}

// The mapping the SDK reads to tell an operator to wait rather than to grant.
func TestEachKindReachesTheSDKAsItself(t *testing.T) {
	for _, c := range []struct {
		kind admin.Kind
		want collector.Fault
	}{
		{admin.KindSource, collector.FaultSource},
		{admin.KindAuth, collector.FaultAuth},
		{admin.KindPermission, collector.FaultPermission},
		{admin.KindRateLimited, collector.FaultRateLimited},
		{admin.KindUnavailable, collector.FaultUnavailable},
	} {
		e := &admin.Error{Kind: c.kind, Retryable: true, RetryAfter: 5 * time.Second}
		if got := e.Fault(); got != c.want {
			t.Errorf("Kind %v -> Fault %v, want %v", c.kind, got, c.want)
		}
		if can, after := e.CanRetry(); !can || after != 5*time.Second {
			t.Errorf("CanRetry() = %v, %v", can, after)
		}
	}
}
