package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.acciew.io/collector/plugins/github/internal/api"
)

// What each read asks for. These are thin wrappers, and the one thing that
// can be wrong about them is the URL — asking for direct collaborators where
// the collector meant everyone is a bug that reports no access on a
// repository the whole organization can write to.
func TestEachReadAsksForTheRightThing(t *testing.T) {
	var asked string
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RequestURI()
		switch {
		case strings.Contains(r.URL.Path, "/installations"):
			_, _ = w.Write([]byte(`{"total_count":0,"installations":[]}`))
		case r.URL.Path == "/orgs/acme-org":
			// The one read that answers with an object rather than a list.
			_, _ = w.Write([]byte(`{"login":"acme-org"}`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	})
	ctx := context.Background()

	for _, c2 := range []struct {
		name string
		call func() error
		want string
	}{
		{"organizations this token can see", func() error { _, err := c.Orgs(ctx); return err },
			"/user/orgs"},
		{"one organization", func() error { _, err := c.Org(ctx, "acme-org"); return err },
			"/orgs/acme-org"},
		{"members", func() error { _, err := c.Members(ctx, "acme-org"); return err },
			"/orgs/acme-org/members"},
		{"owners", func() error { _, err := c.Admins(ctx, "acme-org"); return err },
			"role=admin"},
		{"outside collaborators", func() error { _, err := c.OutsideCollaborators(ctx, "acme-org"); return err },
			"/orgs/acme-org/outside_collaborators"},
		{"teams", func() error { _, err := c.Teams(ctx, "acme-org"); return err },
			"/orgs/acme-org/teams"},
		{"team members", func() error { _, err := c.TeamMembers(ctx, "acme-org", "platform"); return err },
			"/orgs/acme-org/teams/platform/members"},
		{"team repositories", func() error { _, err := c.TeamRepos(ctx, "acme-org", "platform"); return err },
			"/orgs/acme-org/teams/platform/repos"},
		{"repositories", func() error { _, err := c.Repos(ctx, "acme-org"); return err },
			"/orgs/acme-org/repos"},
		{"everyone who can reach a repository", func() error {
			_, err := c.Collaborators(ctx, "acme-org", "infra")
			return err
		}, "affiliation=all"},
		{"who was granted a repository directly", func() error {
			_, err := c.DirectCollaborators(ctx, "acme-org", "infra")
			return err
		}, "affiliation=direct"},
		{"installations", func() error { _, err := c.Installations(ctx, "acme-org"); return err },
			"/orgs/acme-org/installations"},
	} {
		if err := c2.call(); err != nil {
			t.Errorf("%s: %v", c2.name, err)
			continue
		}
		if !strings.Contains(asked, c2.want) {
			t.Errorf("%s asked for %q, want it to contain %q", c2.name, asked, c2.want)
		}
	}
}

// A name with a slash or a space in it must not be able to reach a different
// endpoint than the one intended.
func TestNamesAreEscapedIntoThePath(t *testing.T) {
	var asked string
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`[]`))
	})
	if _, err := c.TeamMembers(context.Background(), "acme org", "a/b"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(asked, "a/b") {
		t.Errorf("a slash in a name reached the path unescaped: %s", asked)
	}
	if decoded, _ := url.PathUnescape(asked); !strings.Contains(decoded, "a/b") {
		t.Errorf("the name was lost rather than escaped: %s", asked)
	}
}

// Paging asks for the largest page GitHub allows, because the alternative is
// ten times the requests against a limit measured in requests.
func TestPagingAsksForTheLargestPage(t *testing.T) {
	var asked string
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	})
	if _, err := c.Members(context.Background(), "acme-org"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(asked, "per_page=100") {
		t.Errorf("query = %q", asked)
	}
}

// The immediate-membership query is the one thing REST cannot answer, and
// getting it wrong reintroduces the phantom-route bug it exists to prevent.
func TestImmediateTeamMembersAsksForImmediateMembership(t *testing.T) {
	var body string
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 4096)
		n, _ := r.Body.Read(raw)
		body = string(raw[:n])
		_, _ = w.Write([]byte(`{"data":{"organization":{
			"t0":{"members":{"pageInfo":{"hasNextPage":false},
			      "nodes":[{"login":"alice","databaseId":101}]}}}}}`))
	})

	got, err := c.ImmediateTeamMembers(context.Background(), "acme-org", []string{"platform"})
	if err != nil {
		t.Fatalf("ImmediateTeamMembers: %v", err)
	}
	if !strings.Contains(body, "membership:IMMEDIATE") {
		t.Errorf("the query did not ask for immediate membership: %s", body)
	}
	if len(got["platform"]) != 1 || got["platform"][0].Login != "alice" {
		t.Errorf("members = %+v", got)
	}
	if got["platform"][0].ID != 101 {
		t.Errorf("the numeric id, which the key is built from, was lost: %+v", got["platform"][0])
	}
}

// GraphQL answers 200 with an errors array. A partial membership list is
// worse than none: it silently drops somebody's access.
func TestAGraphQLErrorIsNotTreatedAsAnAnswer(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"organization":null},
			"errors":[{"message":"Could not resolve to an Organization"}]}`))
	})
	if _, err := c.ImmediateTeamMembers(context.Background(), "acme-org", []string{"platform"}); err == nil {
		t.Fatal("a GraphQL error was read as an empty membership list")
	}
}

// More than one page of immediate members would be a truncated list, which
// would silently drop access. Refused rather than half-answered.
func TestATeamTooLargeToAnswerInOnePageIsRefused(t *testing.T) {
	c := dial(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"organization":{
			"t0":{"members":{"pageInfo":{"hasNextPage":true},"nodes":[]}}}}}`))
	})
	_, err := c.ImmediateTeamMembers(context.Background(), "acme-org", []string{"platform"})
	if err == nil || !strings.Contains(err.Error(), "more than 100") {
		t.Errorf("err = %v, want a refusal naming the limit", err)
	}
}

func TestTheGraphQLEndpointSitsBesideTheRESTOne(t *testing.T) {
	for _, c := range []struct{ base, want string }{
		{"", "https://api.github.com/graphql"},
		{"https://ghe.example.com/api/v3", "https://ghe.example.com/api/graphql"},
	} {
		client, err := api.Dial(api.Config{BaseURL: c.base, Token: "t"})
		if err != nil {
			t.Fatal(err)
		}
		if got := api.GraphQLURLFor(client); got != c.want {
			t.Errorf("base %q -> %q, want %q", c.base, got, c.want)
		}
	}
}
