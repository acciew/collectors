package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// The reads. Each one names what it is asking for, so a refusal says which
// call an operator has to fix rather than which URL failed.

// Orgs lists the organizations the credential can see. Discovering scopes is
// itself a collection step: the caller cannot be asked to list them up front
// and cannot assume one it names is reachable.
func (c *Client) Orgs(ctx context.Context) ([]Org, error) {
	return paged[Org](ctx, c, "/user/orgs", "listing the organizations this token can see")
}

// Org reads one organization, which carries the base permission every member
// holds on every repository in it.
func (c *Client) Org(ctx context.Context, org string) (Org, error) {
	var out Org
	err := c.get(ctx, "/orgs/"+url.PathEscape(org), "reading organization "+org, &out)
	return out, err
}

// Members lists the people in an organization.
func (c *Client) Members(ctx context.Context, org string) ([]User, error) {
	return paged[User](ctx, c, "/orgs/"+url.PathEscape(org)+"/members",
		"listing the members of "+org)
}

// Admins lists the owners, who hold administrative access to everything in
// the organization by virtue of the role rather than by any grant.
func (c *Client) Admins(ctx context.Context, org string) ([]User, error) {
	return paged[User](ctx, c, "/orgs/"+url.PathEscape(org)+"/members?role=admin",
		"listing the owners of "+org)
}

// OutsideCollaborators lists principals who hold repository access without
// being members. They are not in the members list and are easy to miss.
func (c *Client) OutsideCollaborators(ctx context.Context, org string) ([]User, error) {
	return paged[User](ctx, c, "/orgs/"+url.PathEscape(org)+"/outside_collaborators",
		"listing the outside collaborators of "+org)
}

// Teams lists an organization's teams. A team both groups people and holds
// repository access, which is why it becomes two nodes rather than one.
func (c *Client) Teams(ctx context.Context, org string) ([]Team, error) {
	return paged[Team](ctx, c, "/orgs/"+url.PathEscape(org)+"/teams", "listing the teams of "+org)
}

// TeamMembers lists a team's members. Members of child teams are included by
// GitHub, so a collector that treats this as direct membership over-reports
// the parent — the opposite of Keycloak's groups, which report only direct
// members and under-report the parent.
func (c *Client) TeamMembers(ctx context.Context, org, slug string) ([]User, error) {
	return paged[User](ctx, c, teamPath(org, slug)+"/members",
		fmt.Sprintf("listing the members of team %s", slug))
}

// TeamRepos lists the repositories a team holds access to, with the level.
func (c *Client) TeamRepos(ctx context.Context, org, slug string) ([]TeamRepo, error) {
	return paged[TeamRepo](ctx, c, teamPath(org, slug)+"/repos",
		fmt.Sprintf("listing the repositories of team %s", slug))
}

// Repos lists an organization's repositories.
func (c *Client) Repos(ctx context.Context, org string) ([]Repo, error) {
	return paged[Repo](ctx, c, "/orgs/"+url.PathEscape(org)+"/repos",
		"listing the repositories of "+org)
}

// Collaborators lists everyone with access to a repository, at the level
// GitHub itself resolves for them.
//
// The affiliation is always "all" and deliberately so. Verified against a real
// organization: "direct" returned nothing for a repository several people can
// push to, because their access comes from the organization's base permission
// rather than from a grant on the repository. A collector that asks for
// direct collaborators reports no access on repositories everybody can write.
func (c *Client) Collaborators(ctx context.Context, owner, repo string) ([]Collaborator, error) {
	return paged[Collaborator](ctx, c,
		fmt.Sprintf("/repos/%s/%s/collaborators?affiliation=all",
			url.PathEscape(owner), url.PathEscape(repo)),
		fmt.Sprintf("listing who can reach %s/%s", owner, repo))
}

// DirectCollaborators lists only the people granted access on the repository
// itself, excluding everyone who reaches it through organization membership
// or a team.
//
// This is the one call that can state a direct grant. It cannot be inferred
// by subtracting the other routes: a direct grant at the same level as the
// base permission would subtract to nothing and disappear, while still being
// the grant that survives if the person leaves every team.
func (c *Client) DirectCollaborators(ctx context.Context, owner, repo string) ([]Collaborator, error) {
	return paged[Collaborator](ctx, c,
		fmt.Sprintf("/repos/%s/%s/collaborators?affiliation=direct",
			url.PathEscape(owner), url.PathEscape(repo)),
		fmt.Sprintf("listing who was granted %s/%s directly", owner, repo))
}

// Installations lists the applications installed in an organization. In most
// real organizations these outnumber the people.
// This one endpoint answers with an object rather than an array, and it pages
// like every other. Reading only the first page loses every application after
// it, silently — and in a real organization the applications outnumber the
// people. The count it returns is checked against what arrived, so a page
// lost to a rewritten header is reported rather than believed.
func (c *Client) Installations(ctx context.Context, org string) ([]Installation, error) {
	what := "listing the applications installed in " + org
	next := c.base + withPageSize("/orgs/"+url.PathEscape(org)+"/installations", c.pageSize)
	seen := map[string]bool{}

	var all []Installation
	total := -1
	for pages := 0; next != ""; pages++ {
		if pages >= maxPages || seen[next] {
			return nil, &Error{Kind: Source, What: what,
				Err: errors.New("the source keeps offering another page of installations")}
		}
		seen[next] = true

		body, link, err := c.page(ctx, next, what)
		if err != nil {
			return nil, err
		}
		var page InstallationPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, &Error{Kind: Source, What: what,
				Err: fmt.Errorf("unreadable response: %w", err)}
		}
		if total < 0 {
			total = page.TotalCount
		}
		all = append(all, page.Installations...)
		next = nextLink(link)
	}
	if total >= 0 && len(all) != total {
		return nil, &Error{Kind: Source, What: what,
			Err: fmt.Errorf("GitHub said there are %d installations and %d arrived; "+
				"a page was lost and the applications in this organization would be "+
				"under-reported", total, len(all))}
	}
	return all, nil
}

func teamPath(org, slug string) string {
	return "/orgs/" + url.PathEscape(org) + "/teams/" + url.PathEscape(slug)
}
