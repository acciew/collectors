package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.acciew.io/collector/plugins/github/internal/api"
)

// fixture serves a recorded response. The files in testdata have the shape of
// responses GitHub returns, with every name, id and count invented; what they
// pin is that shape, which is the part a hand-written fake gets wrong.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func dial(t *testing.T, h http.HandlerFunc) *api.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := api.Dial(api.Config{BaseURL: srv.URL, Token: "t0ken"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheOrganizationCarriesItsBasePermission(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme-org" {
			t.Errorf("asked for %s", r.URL.Path)
		}
		_, _ = w.Write(fixture(t, "org.json"))
	})

	org, err := c.Org(context.Background(), "acme-org")
	if err != nil {
		t.Fatalf("Org: %v", err)
	}
	// The single most important field in this collector: it is the reason a
	// repository with no collaborators can still be writable by everyone.
	base, stated := org.BasePermission()
	if !stated || base != "write" {
		t.Errorf("base permission = %q (stated %v), want write", base, stated)
	}
	if org.Login != "acme-org" {
		t.Errorf("login = %q", org.Login)
	}
}

// GitHub pages with a Link header, not a marker or an offset. A client that
// stops at the first page silently collects a fraction of a large org and
// reports it as everything.
func TestPagingFollowsTheLinkHeaderToTheEnd(t *testing.T) {
	var calls atomic.Int32
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		page := calls.Add(1)
		if page < 3 {
			w.Header().Set("Link",
				fmt.Sprintf(`<%s?page=%d>; rel="next", <x?page=3>; rel="last"`,
					"http://"+r.Host+r.URL.Path, page+1))
		}
		_, _ = fmt.Fprintf(w, `[{"login":"user%d","id":%d}]`, page, page)
	})

	users, err := c.Members(context.Background(), "acme-org")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(users) != 3 {
		t.Errorf("got %d users from 3 pages: %+v", len(users), users)
	}
	if users[2].Login != "user3" {
		t.Errorf("the last page was not read: %+v", users)
	}
}

// A next link that points back at a page already read would spin for ever
// against a source that is misbehaving or a proxy that rewrites headers.
func TestPagingStopsIfTheSourceLoops(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+"http://"+r.Host+r.URL.Path+`?page=1>; rel="next"`)
		_, _ = fmt.Fprint(w, `[{"login":"same","id":1}]`)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Members(ctx, "acme-org"); err == nil {
		t.Fatal("want an error rather than an endless walk")
	}
}

// The primary rate limit is the reason a large organization cannot be
// collected in one pass. The client has to report it as what it is, so the
// collection can end incomplete and resumable rather than as a failure.
func TestARateLimitedResponseIsReportedAsSuch(t *testing.T) {
	reset := time.Now().Add(42 * time.Second).Unix()
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset))
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	})

	_, err := c.Members(context.Background(), "acme-org")
	var e *api.Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want a typed error", err)
	}
	if e.Kind != api.RateLimited {
		t.Errorf("kind = %v, want rate limited", e.Kind)
	}
	if e.RetryAfter <= 0 || e.RetryAfter > time.Minute {
		t.Errorf("retry after = %v, want roughly 42s from the reset header", e.RetryAfter)
	}
}

// A secondary rate limit is a different mechanism with a different header,
// and it is the one a fast collector actually trips.
func TestASecondaryRateLimitIsAlsoRecognised(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w,
			`{"message":"You have exceeded a secondary rate limit"}`)
	})

	_, err := c.Members(context.Background(), "acme-org")
	var e *api.Error
	if !errors.As(err, &e) || e.Kind != api.RateLimited {
		t.Fatalf("err = %v, want rate limited", err)
	}
	if e.RetryAfter != 30*time.Second {
		t.Errorf("retry after = %v, want 30s", e.RetryAfter)
	}
}

// A 403 that is not a rate limit is a permission problem, and telling an
// operator to wait for it would waste their afternoon.
func TestAForbiddenResponseThatIsNotARateLimitIsAPermissionProblem(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"Resource not accessible by integration"}`)
	})

	_, err := c.Members(context.Background(), "acme-org")
	var e *api.Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if e.Kind != api.Permission {
		t.Errorf("kind = %v, want a permission problem", e.Kind)
	}
	if e.Retryable() {
		t.Error("a permission problem does not clear on its own")
	}
}

// GitHub answers 404 both for things that are not there and for things the
// token may not see. Reporting "does not exist" for the second sends somebody
// to create a thing that already exists.
func TestANotFoundSaysItMayAlsoBeAPermissionProblem(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	_, err := c.Org(context.Background(), "acme-org")
	var e *api.Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(e.Error(), "credential cannot see it") {
		t.Errorf("a 404 should say it may also be the credential: %v", e)
	}
}

func TestAnUnauthorisedTokenIsNamedAsSuch(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"message":"Bad credentials"}`)
	})
	_, err := c.Org(context.Background(), "acme-org")
	var e *api.Error
	if !errors.As(err, &e) || e.Kind != api.Auth {
		t.Fatalf("err = %v, want an authentication problem", err)
	}
}

func TestTheTokenIsSentAndNeverLogged(t *testing.T) {
	var seen string
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"message":"Bad credentials"}`)
	})
	_, err := c.Org(context.Background(), "acme-org")
	if seen != "Bearer t0ken" {
		t.Errorf("Authorization = %q", seen)
	}
	// An error carrying the credential ends up in logs, tickets and screen
	// shares.
	if strings.Contains(err.Error(), "t0ken") {
		t.Errorf("the token is in the error text: %v", err)
	}
}

// The recorded shapes, replayed. Each of these is a fact about the real API
// rather than about a fixture somebody wrote to match the code.
func TestTheRecordedShapesParse(t *testing.T) {
	t.Run("a repository with no direct collaborators", func(t *testing.T) {
		var users []api.Collaborator
		if err := json.Unmarshal(fixture(t, "collaborators_direct.json"), &users); err != nil {
			t.Fatal(err)
		}
		if len(users) != 0 {
			t.Fatalf("the recorded response should be empty, got %d", len(users))
		}
	})

	t.Run("the same repository, all affiliations", func(t *testing.T) {
		var users []api.Collaborator
		if err := json.Unmarshal(fixture(t, "collaborators_all.json"), &users); err != nil {
			t.Fatal(err)
		}
		if len(users) != 4 {
			t.Fatalf("got %d collaborators, want the recorded 6", len(users))
		}
		// GitHub's own resolved answer, which the collector checks itself
		// against rather than deriving from.
		var admins, writers int
		for _, u := range users {
			switch u.RoleName {
			case "admin":
				admins++
			case "write":
				writers++
			}
			if u.Login == "" || u.ID == 0 {
				t.Errorf("a collaborator has no identity: %+v", u)
			}
		}
		if admins != 1 || writers != 3 {
			t.Errorf("got %d admins and %d writers, want 1 and 3", admins, writers)
		}
	})

	t.Run("repositories carry archived and private", func(t *testing.T) {
		var repos []api.Repo
		if err := json.Unmarshal(fixture(t, "repos.json"), &repos); err != nil {
			t.Fatal(err)
		}
		if len(repos) == 0 {
			t.Fatal("no repositories in the recording")
		}
		var archived int
		for _, r := range repos {
			if r.Name == "" {
				t.Errorf("a repository has no name: %+v", r)
			}
			if r.Archived {
				archived++
			}
		}
		if archived == 0 {
			t.Error("the recording was chosen to include an archived repository")
		}
	})

	t.Run("installations are wrapped in a count", func(t *testing.T) {
		var page api.InstallationPage
		if err := json.Unmarshal(fixture(t, "installations.json"), &page); err != nil {
			t.Fatal(err)
		}
		// Unlike every other list endpoint, this one is an object. A client
		// that assumes an array here decodes nothing and reports an org with
		// no applications in it.
		if page.TotalCount != 3 || len(page.Installations) == 0 {
			t.Errorf("total %d, installations %d", page.TotalCount, len(page.Installations))
		}
		if page.Installations[0].AppSlug == "" {
			t.Errorf("an installation has no application: %+v", page.Installations[0])
		}
	})

	t.Run("an organization with no teams", func(t *testing.T) {
		var teams []api.Team
		if err := json.Unmarshal(fixture(t, "teams.json"), &teams); err != nil {
			t.Fatal(err)
		}
		if len(teams) != 0 {
			t.Fatalf("got %d teams", len(teams))
		}
	})
}

// GitHub returns the base permission only to organization owners. A token
// that is merely a member gets a response with no such key — recorded from a
// real organization — and reading that as "the organization turned it off"
// drops the widest access there is while reporting the population as whole.
func TestAnOrganizationThatDidNotStateItsBasePermissionSaysSo(t *testing.T) {
	var org api.Org
	if err := json.Unmarshal(fixture(t, "org_not_owner.json"), &org); err != nil {
		t.Fatal(err)
	}
	if _, stated := org.BasePermission(); stated {
		t.Error("a response with no base permission was read as stating one")
	}
}

// An organization that has turned it off did state something, and the two
// must not be confused.
func TestAnOrganizationWithNoBasePermissionIsNotTheSameAsOneThatDidNotSay(t *testing.T) {
	var org api.Org
	if err := json.Unmarshal([]byte(`{"login":"acme","default_repository_permission":"none"}`),
		&org); err != nil {
		t.Fatal(err)
	}
	base, stated := org.BasePermission()
	if !stated || base != "none" {
		t.Errorf("base = %q, stated = %v; want an explicit none", base, stated)
	}
}

// The next link comes from the response and the request that follows it
// carries the credential. A rewritten header — a proxy, a compromised
// Enterprise host — would otherwise send the token wherever it points.
func TestANextLinkToAnotherHostIsNotFollowed(t *testing.T) {
	var elsewhere string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere = r.Header.Get("Authorization")
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer other.Close()

	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+other.URL+`/orgs/x/members>; rel="next"`)
		_, _ = fmt.Fprint(w, `[{"login":"alice","id":1}]`)
	})

	_, err := c.Members(context.Background(), "acme-org")
	if err == nil {
		t.Fatal("a link to another host was followed")
	}
	if elsewhere != "" {
		t.Errorf("the credential was sent to another host: %q", elsewhere)
	}
}

// GitHub sends Remaining: 0 on every response once the window is spent, so
// during the tail of a large collection a permission refusal would otherwise
// read as "wait an hour" — and the operator would wait, and it would still
// fail.
func TestAPermissionRefusalDuringAnExhaustedWindowIsStillAPermissionRefusal(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"You must be an owner of this organization."}`)
	})

	_, err := c.Members(context.Background(), "acme-org")
	var e *api.Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v", err)
	}
	if e.Kind != api.Permission {
		t.Errorf("kind = %v, want a permission problem; waiting will not fix it", e.Kind)
	}
	if e.Retryable() {
		t.Error("the operator was told to wait for something that will never clear")
	}
}

// Installed applications page like everything else, and in a real
// organization they outnumber the people. Reading only the first page loses
// the rest with no error at all.
func TestInstallationsArePagedToTheEnd(t *testing.T) {
	var page int
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		page++
		if page < 3 {
			w.Header().Set("Link",
				fmt.Sprintf(`<http://%s%s?page=%d>; rel="next"`, r.Host, r.URL.Path, page+1))
		}
		_, _ = fmt.Fprintf(w,
			`{"total_count":3,"installations":[{"id":%d,"app_slug":"app%d"}]}`, page, page)
	})

	got, err := c.Installations(context.Background(), "acme-org")
	if err != nil {
		t.Fatalf("Installations: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d installations from 3 pages: %+v", len(got), got)
	}
}

// GitHub says how many there are. If fewer arrive, a page was lost, and the
// applications in the organization would be under-reported silently.
func TestInstallationsThatDoNotAddUpAreRefused(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"total_count":18,"installations":[{"id":1,"app_slug":"one"}]}`)
	})
	_, err := c.Installations(context.Background(), "acme-org")
	if err == nil {
		t.Fatal("a truncated list was accepted")
	}
	if !strings.Contains(err.Error(), "18") {
		t.Errorf("the error does not say how many were expected: %v", err)
	}
}

// GraphQL answers 200 with a null team for one it cannot resolve — a secret
// team, a slug that has moved. Decoded into a value type that creates the key
// with no members, the caller sees a team that answered with nobody rather
// than a team that did not answer, skips the fallback, and loses every
// membership edge for it from a stream reporting itself complete.
func TestATeamGraphQLCannotResolveIsMissingRatherThanEmpty(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"data":{"organization":{"t0":null}}}`)
	})
	got, err := c.ImmediateTeamMembers(context.Background(), "acme-org", []string{"secret"})
	if err != nil {
		t.Fatalf("ImmediateTeamMembers: %v", err)
	}
	if _, present := got["secret"]; present {
		t.Error("a team GitHub could not resolve came back as a team with no members, " +
			"so the caller would skip the fallback and lose every membership edge for it")
	}
}
