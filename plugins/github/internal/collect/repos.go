package collect

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/sdk/go/collector"
)

// The effective level on a repository is the strongest of four things:
// the organization's base permission, ownership of the organization, a team
// the person is in, and a grant made on the repository itself. Leave out the
// first and a collector reports nobody on a repository the whole organization
// can push to; leave out the second and every owner looks like a reader.
//
// Each of the four is a separate route and each gets its own edge. A model
// that collapsed them into one grant per person per repository would tell a
// reviewer that removing somebody from a team ends their access when three
// other routes leave it standing.

func emitRepositories(ctx context.Context, src Source, org string, teams []api.Team,
	out collector.Stream, g *orgGraph) error {
	repos, err := src.Repos(ctx, org)
	if err != nil {
		return err
	}
	g.repos = len(repos)
	// The team grants, gathered once rather than per repository, from the
	// same team list the groupings were emitted from.
	teamGrants, err := gatherTeamGrants(ctx, src, org, teams)
	if err != nil {
		return err
	}

	for _, repo := range repos {
		if err := emitRepository(ctx, src, org, repo, teamGrants[repoID(repo.ID)], out, g); err != nil {
			return err
		}
	}
	return nil
}

// teamGrant is one team's access to one repository.
type teamGrant struct {
	team  api.Team
	level string
}

func gatherTeamGrants(ctx context.Context, src Source, org string,
	teams []api.Team) (map[string][]teamGrant, error) {
	out := map[string][]teamGrant{}
	for _, t := range teams {
		repos, err := src.TeamRepos(ctx, org, t.Slug)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			level := r.RoleName
			if level == "" {
				level = levelFrom(permissions(r.Permissions))
			}
			if level == "" {
				continue
			}
			out[repoID(r.ID)] = append(out[repoID(r.ID)], teamGrant{team: t, level: level})
		}
	}
	return out, nil
}

func emitRepository(ctx context.Context, src Source, org string, repo api.Repo,
	teamGrants []teamGrant, out collector.Stream, g *orgGraph) error {
	resource := collector.ResourceKey(org, repoID(repo.ID))
	attrs := map[string]string{
		"organization": org,
		"private":      strconv.FormatBool(repo.Private),
		// An archived repository is read-only whatever anybody's level says.
		// A write grant on one is not the access it appears to be, and the
		// only place a reviewer can learn that is here.
		"archived": strconv.FormatBool(repo.Archived),
	}
	if err := out.Node(collector.WithContext(
		collector.Resource(resource, repo.Name, "repository"), attrs)); err != nil {
		return err
	}

	direct, err := src.DirectCollaborators(ctx, org, repo.Name)
	if err != nil {
		return err
	}
	// Every level derived for a principal, not the strongest one. A custom
	// role cannot be compared with a default role, so collapsing them picks
	// one arbitrarily and the check below then disagrees with GitHub about a
	// derivation that was right — on every affected person, on every sampled
	// repository, until nobody reads the warning any more.
	derived := map[string]map[string]bool{}
	add := func(id, level string) {
		if level == "" {
			return
		}
		if derived[id] == nil {
			derived[id] = map[string]bool{}
		}
		derived[id][level] = true
	}

	// Direct grants: stated by the source on this repository.
	for _, c := range direct {
		level := levelOf(c)
		if level == "" {
			continue
		}
		id, known := g.idOf(c.Login)
		if !known {
			// Granted on the repository but in neither the member nor the
			// outside-collaborator list. Recorded rather than dropped: they
			// hold the access either way.
			if err := emitUser(api.User{Login: c.Login, ID: c.ID, Type: c.Type},
				"repository_collaborator", out, g); err != nil {
				return err
			}
			id = idOf(api.User{ID: c.ID})
		}
		// The base role a custom role extends is in the booleans GitHub
		// sends alongside the name, not in the name itself.
		key, err := entitlementFor(org, repo, level, levelFrom(permissions(c.Permissions)), out, g)
		if err != nil {
			return err
		}
		if err := out.Edge(collector.HowGranted(
			collector.Holds(collector.IdentityKey(org, id), key, collector.Direct),
			"repository_collaborator")); err != nil {
			return err
		}
		add(id, level)
	}

	// Team grants: reached through a team the person is in, and through the
	// team's ancestors, because a child team inherits its parent's access.
	for _, tg := range teamGrants {
		key, err := entitlementFor(org, repo, tg.level, "", out, g)
		if err != nil {
			return err
		}
		if err := out.Edge(collector.HowGranted(
			collector.Holds(collector.GroupingKey(org, teamID(tg.team)), key, collector.Direct),
			"team_repository_grant")); err != nil {
			return err
		}
		for _, p := range g.people {
			// The chain from the team this person is actually in up to the
			// team that holds the grant. A child team inherits its parent's
			// repositories, and the reviewer's question is which membership
			// to end — so the route names every hop rather than jumping to
			// the team at the top.
			route := g.routeToTeam(p.id, teamID(tg.team))
			if route == nil {
				continue
			}
			hops := make([]*collectorv1.Key, 0, len(route))
			for _, hop := range route {
				hops = append(hops, collector.GroupingKey(org, hop))
			}
			how := "team_membership"
			if len(route) > 1 {
				how = "team_inheritance"
			}
			if err := out.Edge(collector.HowGranted(
				collector.Holds(collector.IdentityKey(org, p.id), key,
					collector.Effective, hops...), how)); err != nil {
				return err
			}
			add(p.id, tg.level)
		}
	}

	// Ownership: an organization owner administers every repository by
	// virtue of the role rather than by any grant on the repository. The
	// route is the ownership itself, which is what a reviewer would have to
	// take away, so it goes through the owners grouping rather than
	// appearing from nowhere.
	if len(g.owners()) > 0 {
		key, err := entitlementFor(org, repo, "admin", "", out, g)
		if err != nil {
			return err
		}
		owners := collector.GroupingKey(org, ownersGroupingID)
		if err := out.Edge(collector.HowGranted(
			collector.Holds(owners, key, collector.Direct),
			"organization_ownership")); err != nil {
			return err
		}
		for _, id := range g.owners() {
			if err := out.Edge(collector.HowGranted(
				collector.Holds(collector.IdentityKey(org, id), key,
					collector.Effective, owners),
				"organization_ownership")); err != nil {
				return err
			}
			add(id, "admin")
		}
	}

	// The base permission reaches every member on every repository, and it
	// is already recorded once for the organization. It is folded in here
	// only so that the comparison below is against the whole answer.
	base := g.basePermission
	if base != "" {
		for _, p := range g.people {
			if g.member[p.id] {
				add(p.id, base)
			}
		}
	}

	// The check costs a request per repository. On a large organization that
	// is the difference between one rate-limit window and two, and it checks
	// this collector rather than the collection — so how much of it to do is
	// the operator's call, sampled by default.
	if !g.shouldVerify() {
		return nil
	}
	return checkAgainstGitHub(ctx, src, org, repo, derived, out, g)
}

// checkAgainstGitHub compares what this collector worked out with what GitHub
// says it resolves to.
//
// GitHub gives the level and not the route, so it cannot replace the
// derivation: a reviewer acts on the route. But it is an independent answer
// to the same question, and a disagreement means one of the two is wrong. It
// is reported rather than silently reconciled, because quietly taking
// GitHub's number would hide a bug in the route we are showing people.
func checkAgainstGitHub(ctx context.Context, src Source, org string, repo api.Repo,
	derived map[string]map[string]bool, out collector.Stream, g *orgGraph) error {
	actual, err := src.Collaborators(ctx, org, repo.Name)
	if err != nil {
		return err
	}
	var disagreements []string
	seen := map[string]bool{}
	for _, c := range actual {
		id, known := g.idOf(c.Login)
		if !known {
			id = strconv.FormatInt(c.ID, 10)
		}
		seen[id] = true
		theirs := levelOf(c)
		// GitHub reports one resolved level; we derived a set of routes,
		// each with its own level. The two agree when what GitHub says is
		// among them.
		if derived[id][theirs] {
			continue
		}
		// A custom role in the set makes the comparison unanswerable rather
		// than wrong: GitHub's level and a custom role are not on one scale.
		if anyCustom(derived[id]) {
			continue
		}
		disagreements = append(disagreements,
			fmt.Sprintf("%s: we derived %s, GitHub says %s",
				c.Login, orNone(levels(derived[id])), orNone(theirs)))
	}
	// The other direction matters more: somebody we derived access for whom
	// GitHub does not list at all is access we invented.
	for id, held := range derived {
		if !seen[id] && len(held) > 0 {
			disagreements = append(disagreements,
				fmt.Sprintf("%s: we derived %s, GitHub does not list them",
					g.loginOf(id), levels(held)))
		}
	}
	if len(disagreements) == 0 {
		return nil
	}
	sort.Strings(disagreements)
	return out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING, "github.derivation.disagrees",
		fmt.Sprintf("on %s/%s this collector and GitHub's own answer disagree, so one of them "+
			"is wrong and the routes shown for this repository may be too: %v",
			org, repo.Name, disagreements))
}

// entitlementFor emits the entitlement for a level on a repository once, and
// returns its key.
//
// One node per repository and level actually held, rather than one per
// repository per rung: a level nobody holds is not an entitlement anybody has
// to review.
// baseRole is the default level a custom role's permissions actually confer,
// taken from the booleans GitHub sends alongside the name. Empty for a
// default level, which is its own base.
func entitlementFor(org string, repo api.Repo, level, baseRole string,
	out collector.Stream, g *orgGraph) (*collectorv1.Key, error) {
	// Composed from stable parts: the repository's numeric id and the level.
	// A synthetic entitlement has no source object behind it, and how it is
	// composed is this plugin's own compatibility surface.
	id := "repo:" + repoID(repo.ID) + ":" + level
	key := collector.EntitlementKey(org, id)
	if g.emitted[id] {
		return key, nil
	}
	ctx := levelContext(level, baseRole)
	ctx["organization"] = org
	ctx["repository"] = repo.Name
	if repo.Archived {
		ctx["repository_archived"] = "true"
	}
	if err := out.Node(collector.WithContext(
		collector.Entitlement(key, level+" on "+repo.Name, "repository_permission"), ctx)); err != nil {
		return nil, err
	}
	if err := out.Edge(collector.AppliesTo(key, collector.ResourceKey(org, repoID(repo.ID)))); err != nil {
		return nil, err
	}
	g.emitted[id] = true
	return key, nil
}

func levelOf(c api.Collaborator) string {
	if c.RoleName != "" {
		return c.RoleName
	}
	return levelFrom(permissions(c.Permissions))
}

// anyCustom reports whether any level in a set is a custom role, which makes
// a comparison with GitHub's single resolved level unanswerable rather than
// wrong: the two are not on one scale.
func anyCustom(held map[string]bool) bool {
	for level := range held {
		if _, ranked := rank(level); !ranked {
			return true
		}
	}
	return false
}

// levels renders a set for a person to read, strongest first.
func levels(held map[string]bool) string {
	out := make([]string, 0, len(held))
	for level := range held {
		out = append(out, level)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, iOK := rank(out[i])
		rj, jOK := rank(out[j])
		if iOK && jOK {
			return ri > rj
		}
		return out[i] < out[j]
	})
	return strings.Join(out, " and ")
}

func repoID(id int64) string { return strconv.FormatInt(id, 10) }

func orNone(level string) string {
	if level == "" {
		return "nothing"
	}
	return level
}
