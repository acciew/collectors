package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.acciew.io/collector/plugins/entra/internal/fakegraph"
	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

const (
	testClient = "00000000-0000-4000-8000-0000000000c1"
	testSecret = "synthetic-secret-value"
)

func secretClient(t *testing.T, srv *fakegraph.Server) *graph.Client {
	t.Helper()
	srv.AcceptSecret(testClient, testSecret)
	c, err := graph.Dial(context.Background(), graph.Config{
		TenantID: srv.Tenant.ID, ClientID: testClient, ClientSecret: testSecret,
		Endpoints: graph.Endpoints{Login: srv.URL, Graph: srv.URL},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return c
}

func tenantWithUsers(n int) *fakegraph.Tenant {
	t := fakegraph.NewTenant()
	for i := range n {
		id := fakegraph.GUID("user" + string(rune('a'+i)))
		t.Users = append(t.Users, fakegraph.User{ID: id, DisplayName: "User " + id[:4], UPN: id[:4] + "@example.onmicrosoft.com"})
	}
	return t
}

func TestAClientSecretBuysAToken(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	c := secretClient(t, srv)

	page, err := graph.GetPage[graph.User](context.Background(), c, "/users")
	if err != nil {
		t.Fatalf("GetPage: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("got %d users", len(page.Items))
	}
	if c.TenantID() != srv.Tenant.ID {
		t.Errorf("TenantID = %q, want the tid the token carries (%q)", c.TenantID(), srv.Tenant.ID)
	}
}

// A rotated secret is the commonest way for a scheduled run to break, and the
// answer has to say it is the credential and not echo it.
func TestARejectedSecretIsAnAuthenticationFailureThatDoesNotEchoIt(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.AcceptSecret(testClient, testSecret)

	_, err := graph.Dial(context.Background(), graph.Config{
		TenantID: srv.Tenant.ID, ClientID: testClient, ClientSecret: "the-wrong-secret",
		Endpoints: graph.Endpoints{Login: srv.URL, Graph: srv.URL},
	})
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindAuth {
		t.Fatalf("err = %v, want an authentication failure", err)
	}
	if strings.Contains(err.Error(), "the-wrong-secret") {
		t.Errorf("the error repeats the secret: %v", err)
	}
	if !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Errorf("the error drops the service's own code, the one thing that says what is wrong: %v", err)
	}
	if strings.Contains(err.Error(), "Trace ID") {
		t.Errorf("the error carries the service's trace lines, not one sentence: %v", err)
	}
}

func TestAPagedReadFollowsTheNextLinkItWasGiven(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(7))
	srv.PageSize = 3
	c := secretClient(t, srv)

	var got []string
	for target := "/users"; target != ""; {
		page, err := graph.GetPage[graph.User](context.Background(), c, target)
		if err != nil {
			t.Fatalf("GetPage(%s): %v", target, err)
		}
		for _, u := range page.Items {
			got = append(got, u.ID)
		}
		target = page.Next
	}
	if len(got) != 7 {
		t.Errorf("read %d users over the pages, want 7", len(got))
	}
}

// A nextLink comes from the service, and a cursor comes from outside this
// process. Either could name another host, and following it would hand that
// host a bearer token that reads the whole directory.
func TestANextLinkToAnotherHostIsNeverFollowed(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(other.Close)

	srv := fakegraph.New(t, tenantWithUsers(2))
	c := secretClient(t, srv)

	for _, target := range []string{
		other.URL + "/v1.0/users",
		"http://" + strings.TrimPrefix(srv.URL, "http://") + ".evil.example/v1.0/users",
		"//evil.example/v1.0/users",
	} {
		if _, err := graph.GetPage[graph.User](context.Background(), c, target); err == nil {
			t.Errorf("%s: followed", target)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("another host received %d requests, carrying the token", hits.Load())
	}
}

func TestAMissingPermissionIsAPermissionFailureWithGraphsOwnCode(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Refuse("/v1.0/users", http.StatusForbidden, "Authorization_RequestDenied",
		"Insufficient privileges to complete the operation.")
	c := secretClient(t, srv)

	_, err := graph.GetPage[graph.User](context.Background(), c, "/users")
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindPermission || ge.Code != "Authorization_RequestDenied" {
		t.Fatalf("err = %#v, want a permission failure carrying Graph's code", err)
	}
}

func TestThrottlingNamesHowLongToWait(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Throttle("/v1.0/users", 1, 7)
	c := secretClient(t, srv)

	_, err := graph.GetPage[graph.User](context.Background(), c, "/users")
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindRateLimited {
		t.Fatalf("err = %v, want a rate limit", err)
	}
	if can, after := ge.CanRetry(); !can || after.Seconds() != 7 {
		t.Errorf("CanRetry = %v, %v; want true and the 7 seconds Graph asked for", can, after)
	}
}

func tokenRequests(srv *fakegraph.Server) int {
	n := 0
	for _, r := range srv.Requests() {
		if strings.HasSuffix(r.Path, "/oauth2/v2.0/token") {
			n++
		}
	}
	return n
}

// A token per request would multiply the load on the tenant's token service
// for no benefit; a token that has run out must not fail the collection.
func TestOneTokenServesManyReadsAndAnExpiredOneIsReplacedOnce(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	c := secretClient(t, srv)
	ctx := context.Background()

	for range 3 {
		if _, err := graph.GetPage[graph.User](ctx, c, "/users"); err != nil {
			t.Fatal(err)
		}
	}
	if n := tokenRequests(srv); n != 1 {
		t.Errorf("%d token requests for 3 reads, want 1", n)
	}

	srv.ExpireTokens()
	if _, err := graph.GetPage[graph.User](ctx, c, "/users"); err != nil {
		t.Fatalf("a read after the token expired: %v", err)
	}
	if n := tokenRequests(srv); n != 2 {
		t.Errorf("%d token requests after an expiry, want 2", n)
	}
}

func TestEachFailureIsClassifiedByWhatAnOperatorShouldDoAboutIt(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		kind   graph.Kind
		retry  bool
	}{
		{"a request Graph refuses", http.StatusBadRequest, graph.KindBadRequest, false},
		{"a thing that is not there", http.StatusNotFound, graph.KindNotFound, false},
		{"an unwell Graph", http.StatusServiceUnavailable, graph.KindUnavailable, true},
		{"a bad gateway", http.StatusBadGateway, graph.KindUnavailable, true},
		{"anything else", http.StatusTeapot, graph.KindSource, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := fakegraph.New(t, tenantWithUsers(1))
			code := "SomeCode"
			if c.status == http.StatusNotFound {
				code = "Request_ResourceNotFound" // Graph's, so that it is not taken for something else answering
			}
			srv.Refuse("/v1.0/users", c.status, code, "Some message.\r\nRequest-id: 1")
			_, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")

			var ge *graph.Error
			if !errors.As(err, &ge) || ge.Kind != c.kind {
				t.Fatalf("err = %v, want kind %v", err, c.kind)
			}
			if can, _ := ge.CanRetry(); can != c.retry {
				t.Errorf("CanRetry = %v, want %v", can, c.retry)
			}
			if strings.Contains(err.Error(), "Request-id") {
				t.Errorf("the error carries more than the first line of Graph's message: %v", err)
			}
			if c.kind.String() == "" {
				t.Error("a kind with no name")
			}
		})
	}
}

// A proxy or gateway in front of Graph also answers 403. Calling that a
// missing permission sends an operator to grant something they already hold.
func TestARefusalThatIsNotGraphsIsNotAPermissionProblem(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Respond("/v1.0/users", http.StatusForbidden, "text/html", "<html>Access denied by policy</html>")

	_, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindSource || !strings.Contains(err.Error(), "proxy or gateway") {
		t.Fatalf("err = %v, want a source error that says something else is answering", err)
	}
}

// The same for a 404. Only Graph's own not-found, an error body with a code,
// says that a thing is gone; a proxy or a gateway answers 404 for paths it does
// not know, and "gone" read from that is a read that was never made.
func TestANotFoundThatIsNotGraphsIsNotAThingThatIsGone(t *testing.T) {
	for name, c := range map[string]struct {
		status       int
		contentType  string
		body         string
		wantNotFound bool
	}{
		"an HTML page":                     {http.StatusNotFound, "text/html", "<html>no such route</html>", false},
		"an empty body":                    {http.StatusNotFound, "application/json", "", false},
		"JSON that is not an error":        {http.StatusNotFound, "application/json", `{"message":"not found"}`, false},
		"an error without a code":          {http.StatusNotFound, "application/json", `{"error":{"message":"gone"}}`, false},
		"an error that is a string":        {http.StatusNotFound, "application/json", `{"error":"not found"}`, false},
		"Graph's own":                      {http.StatusNotFound, "application/json", `{"error":{"code":"Request_ResourceNotFound","message":"gone"}}`, true},
		"Graph's, another code":            {http.StatusNotFound, "application/json", `{"error":{"code":"ResourceNotFound","message":"gone"}}`, true},
		"Graph's, an Outlook code":         {http.StatusNotFound, "application/json", `{"error":{"code":"ErrorItemNotFound","message":"gone"}}`, true},
		"Graph's, a OneDrive code":         {http.StatusNotFound, "application/json", `{"error":{"code":"itemNotFound","message":"gone"}}`, true},
		"a not-found code in another case": {http.StatusNotFound, "application/json", `{"error":{"code":"request_resourcenotfound","message":"gone"}}`, true},
		"a refusal code on a 404":          {http.StatusNotFound, "application/json", `{"error":{"code":"Authorization_RequestDenied","message":"no"}}`, false},
		"an outage code on a 404":          {http.StatusNotFound, "application/json", `{"error":{"code":"serviceNotAvailable","message":"down"}}`, false},
		"a code that merely contains one":  {http.StatusNotFound, "application/json", `{"error":{"code":"NotFoundButActuallyDenied","message":"no"}}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			srv := fakegraph.New(t, tenantWithUsers(1))
			srv.Respond("/v1.0/users", c.status, c.contentType, c.body)

			_, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")
			var ge *graph.Error
			if !errors.As(err, &ge) {
				t.Fatalf("err = %v, want a Graph error", err)
			}
			if got := ge.Kind == graph.KindNotFound; got != c.wantNotFound {
				t.Errorf("kind = %v, not found: %v, want %v", ge.Kind, got, c.wantNotFound)
			}
			if !c.wantNotFound && ge.Kind != graph.KindSource {
				t.Errorf("kind = %v, want a source error", ge.Kind)
			}
			if !c.wantNotFound && !strings.Contains(err.Error(), "not Microsoft Graph") && !strings.Contains(err.Error(), "not a not-found code") {
				t.Errorf("err = %v, want it to say why the 404 is not taken for a thing that is gone", err)
			}
		})
	}
}

func TestAnAnswerThatIsNotTheJSONExpectedIsASourceError(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Respond("/v1.0/users", http.StatusOK, "text/html", "<html>sign in</html>")

	_, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindSource {
		t.Fatalf("err = %v, want a source error", err)
	}
}

func TestAnUnreachableTokenServiceIsUnavailableNotARejectedCredential(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	url := srv.URL
	srv.Close()

	_, err := graph.Dial(context.Background(), graph.Config{
		TenantID: srv.Tenant.ID, ClientID: testClient, ClientSecret: testSecret,
		Endpoints: graph.Endpoints{Login: url, Graph: url},
	})
	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindUnavailable {
		t.Fatalf("err = %v, want unavailable", err)
	}
	if can, _ := ge.CanRetry(); !can {
		t.Error("an unreachable service is worth retrying")
	}
	if strings.Contains(err.Error(), url) && strings.Contains(err.Error(), "?") {
		t.Errorf("the error carries a URL with a query: %v", err)
	}
}

func TestRetryAfterMayBeADateAsWellAsASecondsCount(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.ThrottleUntil("/v1.0/users", 1, time.Now().Add(90*time.Second))

	_, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")
	var ge *graph.Error
	if !errors.As(err, &ge) {
		t.Fatalf("err = %v", err)
	}
	if _, after := ge.CanRetry(); after < 60*time.Second || after > 91*time.Second {
		t.Errorf("RetryAfter = %v, want about the 90 seconds the date names", after)
	}
}

func TestEachKindMapsToWhatTheSDKReportsToTheHost(t *testing.T) {
	for kind, want := range map[graph.Kind]collector.Fault{
		graph.KindAuth:        collector.FaultAuth,
		graph.KindPermission:  collector.FaultPermission,
		graph.KindRateLimited: collector.FaultRateLimited,
		graph.KindUnavailable: collector.FaultUnavailable,
		graph.KindSource:      collector.FaultSource,
		graph.KindBadRequest:  collector.FaultSource,
		graph.KindNotFound:    collector.FaultSource,
	} {
		if got := (&graph.Error{Kind: kind}).Fault(); got != want {
			t.Errorf("%v reports %v, want %v", kind, got, want)
		}
	}
	inner := errors.New("inner")
	if !errors.Is(&graph.Error{Err: inner}, inner) {
		t.Error("Error does not unwrap")
	}
}

// A token is read for the tenant it names, not trusted for anything else.
func TestATokenWithoutATenantClaimLeavesTheTenantUnnamed(t *testing.T) {
	odd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"opaque","expires_in":3600}`))
	}))
	t.Cleanup(odd.Close)

	c, err := graph.Dial(context.Background(), graph.Config{
		TenantID: "example.onmicrosoft.com", ClientID: testClient, ClientSecret: testSecret,
		Endpoints: graph.Endpoints{Login: odd.URL, Graph: odd.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.TenantID() != "" {
		t.Errorf("TenantID = %q from a token that names none", c.TenantID())
	}
}

func TestADirectoryObjectKnowsAMissingNameFromANullOne(t *testing.T) {
	for _, c := range []struct {
		name, json string
		idOnly     bool
	}{
		{"a name", `{"@odata.type":"#microsoft.graph.user","id":"u1","displayName":"Ann"}`, false},
		// Graph's answer for an object the caller may not read.
		{"a null name", `{"@odata.type":"#microsoft.graph.user","id":"u1","displayName":null}`, true},
		// What a query parameter Graph ignored silently looks like.
		{"no name at all", `{"@odata.type":"#microsoft.graph.user","id":"u1"}`, false},
		{"nothing identifying it", `{"displayName":null}`, false},
	} {
		var o graph.DirectoryObject
		if err := json.Unmarshal([]byte(c.json), &o); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if o.IDOnly() != c.idOnly {
			t.Errorf("%s: IDOnly = %v, want %v", c.name, o.IDOnly(), c.idOnly)
		}
	}
	var o graph.DirectoryObject
	if err := json.Unmarshal([]byte(`{"id":7}`), &o); err == nil {
		t.Error("an id that is not a string was accepted")
	}
	if err := json.Unmarshal([]byte(`[]`), &o); err == nil {
		t.Error("an array was accepted as an object")
	}
	if got := (graph.DirectoryObject{Type: "#microsoft.graph.servicePrincipal"}).Kind(); got != "servicePrincipal" {
		t.Errorf("Kind = %q", got)
	}
}

func TestAskingForSignInActivityCapsThePageSize(t *testing.T) {
	plain := graph.UsersPath(999, false)
	with := graph.UsersPath(999, true)
	if !strings.Contains(plain, "%24top=999") || strings.Contains(plain, "signInActivity") {
		t.Errorf("plain = %s", plain)
	}
	if !strings.Contains(with, "%24top=500") || !strings.Contains(with, "signInActivity") {
		t.Errorf("with activity = %s; Graph caps the page at 500 when signInActivity is selected", with)
	}
	if got := graph.UsersPath(0, false); !strings.Contains(got, "%24top=999") {
		t.Errorf("no page size should mean the largest: %s", got)
	}
	if got := graph.UsersPath(50, true); !strings.Contains(got, "%24top=50") {
		t.Errorf("a smaller page size should be kept: %s", got)
	}
}

// A redirect is never followed. The token request carries the client secret in
// its body, and a 307 would send that body wherever the redirect named.
func TestARedirectIsNeverFollowedSoNothingIsSentWhereItPoints(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(elsewhere.Close)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	_, err := graph.Dial(context.Background(), graph.Config{
		TenantID: "example.onmicrosoft.com", ClientID: testClient, ClientSecret: testSecret,
		Endpoints: graph.Endpoints{Login: redirecting.URL, Graph: redirecting.URL},
	})
	if err == nil {
		t.Fatal("a redirect was taken for a token")
	}
	if hits.Load() != 0 {
		t.Errorf("the redirect was followed: %d requests, carrying the secret, reached another host", hits.Load())
	}

	srv := fakegraph.New(t, tenantWithUsers(1))
	c := secretClient(t, srv)
	srv.Respond("/v1.0/users", http.StatusTemporaryRedirect, "text/plain", "")
	if _, err := graph.GetPage[graph.User](context.Background(), c, "/users"); err == nil {
		t.Error("a redirect was taken for a page")
	}
}

// An answer that is not a page is not an empty page. A 200 with no value would
// otherwise read as a collection of nothing, and a tenant of users as none.
func TestAnAnswerWithoutAValueIsAnErrorAndNotAnEmptyPage(t *testing.T) {
	for _, body := range []string{`{}`, `{"value":null}`, `{"value":"x"}`, `[]`, `{"error":"no"}`} {
		srv := fakegraph.New(t, tenantWithUsers(1))
		srv.Respond("/v1.0/users", http.StatusOK, "application/json", body)
		page, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")

		var ge *graph.Error
		if !errors.As(err, &ge) || ge.Kind != graph.KindSource {
			t.Errorf("%s: err = %v (page %+v), want a source error", body, err, page)
		}
	}

	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Respond("/v1.0/users", http.StatusOK, "application/json", `{"value":[]}`)
	page, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")
	if err != nil || len(page.Items) != 0 || page.Next != "" {
		t.Errorf(`{"value":[]} = %+v, %v; a page of nothing is a page`, page, err)
	}

	if _, err := graph.DecodePage[graph.User]([]byte(`{}`)); err == nil {
		t.Error("DecodePage read a body with no value as an empty page")
	}
}

func TestACheckThatReadsAPageNeedsOneToo(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Respond("/v1.0/users", http.StatusOK, "application/json", `{}`)
	if err := secretClient(t, srv).ReadPage(context.Background(), "/users"); err == nil {
		t.Error("a check took a body with no value for a readable collection")
	}
}

// A 503 or 504 may say how long to wait, as a 429 does, and a caller that
// wants to wait has to be told.
func TestAnOutageThatNamesHowLongToWaitSaysSo(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.Outage("/v1.0/users", 1, 9)
	_, err := graph.GetPage[graph.User](context.Background(), secretClient(t, srv), "/users")

	var ge *graph.Error
	if !errors.As(err, &ge) || ge.Kind != graph.KindUnavailable {
		t.Fatalf("err = %v, want unavailable", err)
	}
	if can, after := ge.CanRetry(); !can || after != 9*time.Second {
		t.Errorf("CanRetry = %v, %v; want true and the 9 seconds Graph asked for", can, after)
	}
}

// The token is renewed before it runs out, because one that expires part-way
// through a collection fails as though a permission were missing.
func TestATokenIsRenewedBeforeItRunsOut(t *testing.T) {
	srv := fakegraph.New(t, tenantWithUsers(1))
	srv.AcceptSecret(testClient, testSecret)
	clock := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	c, err := graph.Dial(context.Background(), graph.Config{
		TenantID: srv.Tenant.ID, ClientID: testClient, ClientSecret: testSecret,
		Endpoints: graph.Endpoints{Login: srv.URL, Graph: srv.URL},
		Now:       func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		if _, err := graph.GetPage[graph.User](context.Background(), c, "/users"); err != nil {
			t.Fatal(err)
		}
	}

	// The fake issues tokens for 3599 seconds.
	clock = clock.Add(2500 * time.Second) // 70%: well inside
	read()
	if n := tokenRequests(srv); n != 1 {
		t.Fatalf("%d token requests at 70%% of the lifetime, want the one", n)
	}
	clock = clock.Add(500 * time.Second) // 84%: past four fifths, not yet expired
	read()
	if n := tokenRequests(srv); n != 2 {
		t.Errorf("%d token requests at 84%% of the lifetime, want a renewal before it ran out", n)
	}
}

func TestTwoSpellingsOfOnePageAreOnePage(t *testing.T) {
	c := secretClient(t, fakegraph.New(t, tenantWithUsers(1)))
	rel := c.Absolute("/users?$top=5")
	if rel == "" || c.Absolute(rel) != rel {
		t.Errorf("Absolute(relative) = %q, Absolute(absolute) = %q", rel, c.Absolute(rel))
	}
	if c.Absolute("https://elsewhere.example/v1.0/users") != "" {
		t.Error("a link to another host has an absolute form")
	}
}
