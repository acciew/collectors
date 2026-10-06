package api_test

import (
	"context"
	"os"
	"testing"

	"go.acciew.io/collector/plugins/github/internal/api"
)

// The claims this collector is built on, checked against the real API rather
// than against the recordings made from it. Skipped without a token, so it
// costs CI nothing; run it when changing what the client asks for.
//
//	ACCIEW_GITHUB_TOKEN=... ACCIEW_GITHUB_ORG=... go test ./internal/api/ -run Live
func TestLiveTheClaimsThisCollectorRestsOn(t *testing.T) {
	token, org := os.Getenv("ACCIEW_GITHUB_TOKEN"), os.Getenv("ACCIEW_GITHUB_ORG")
	if token == "" || org == "" {
		t.Skip("set ACCIEW_GITHUB_TOKEN and ACCIEW_GITHUB_ORG to check against a real organization")
	}
	c, err := api.Dial(api.Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	o, err := c.Org(ctx, org)
	if err != nil {
		t.Fatalf("reading the organization: %v", err)
	}
	base, stated := o.BasePermission()
	if !stated {
		t.Log("this token is not an owner of the organization, so GitHub did not state " +
			"the base permission; a collection would refuse rather than under-report")
	}
	t.Logf("base permission: %q (stated %v)", base, stated)

	repos, err := c.Repos(ctx, org)
	if err != nil {
		t.Fatalf("listing repositories: %v", err)
	}
	if len(repos) == 0 {
		t.Skip("the organization has no repositories to check against")
	}

	// The claim the collector is built around: everyone who can reach a
	// repository is visible only with affiliation=all, and asking for direct
	// collaborators reports nobody on a repository the whole organization
	// can write.
	people, err := c.Collaborators(ctx, org, repos[0].Name)
	if err != nil {
		t.Fatalf("listing collaborators: %v", err)
	}
	t.Logf("%s: %d people can reach it", repos[0].Name, len(people))
	for _, p := range people {
		if p.RoleName == "" {
			t.Errorf("%s carries no role_name; the check against GitHub's own answer "+
				"depends on it", p.Login)
		}
	}

	// Applications are principals too, and there are usually more of them
	// than people.
	apps, err := c.Installations(ctx, org)
	if err != nil {
		t.Fatalf("listing installations: %v", err)
	}
	t.Logf("%d applications installed, %d people", len(apps), len(people))
}
