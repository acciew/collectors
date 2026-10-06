// Package collect turns a GitHub organization into the access graph.
//
// The shape of this collector is decided by three facts about GitHub that do
// not hold for Keycloak, and each one is a place a naive collector reports
// something false.
//
// The organization has a base permission that every member holds on every
// repository, and it is invisible in the collaborator list you would reach
// for first. Verified against a real organization: a repository with no
// direct collaborators at all was writable by several people.
//
// Repository permissions are an ordered ladder rather than a set of roles,
// and custom repository roles sit on it without being comparable to it. See
// levels.go.
//
// GitHub will tell you its own answer for who holds what — a resolved level
// per person per repository — but not how they got it. That makes it a check
// on this collector's derivation rather than a substitute for it, because the
// route is the part a reviewer acts on.
package collect

import (
	"context"
	"fmt"
	"strconv"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/sdk/go/collector"
)

// Source is what a collection reads. The API client satisfies it; tests use a
// fake, which is what keeps the mapping testable without a network.
type Source interface {
	Org(ctx context.Context, org string) (api.Org, error)
	Members(ctx context.Context, org string) ([]api.User, error)
	Admins(ctx context.Context, org string) ([]api.User, error)
	OutsideCollaborators(ctx context.Context, org string) ([]api.User, error)
	Teams(ctx context.Context, org string) ([]api.Team, error)
	TeamMembers(ctx context.Context, org, slug string) ([]api.User, error)
	// ImmediateTeamMembers answers with each team's own members, excluding
	// the members of its child teams. The REST endpoint above cannot: it is
	// transitive, and a transitive answer emitted as membership turns an
	// inherited route into a stated one.
	ImmediateTeamMembers(ctx context.Context, org string, slugs []string) (map[string][]api.User, error)
	TeamRepos(ctx context.Context, org, slug string) ([]api.TeamRepo, error)
	Repos(ctx context.Context, org string) ([]api.Repo, error)
	Collaborators(ctx context.Context, owner, repo string) ([]api.Collaborator, error)
	DirectCollaborators(ctx context.Context, owner, repo string) ([]api.Collaborator, error)
	Installations(ctx context.Context, org string) ([]api.Installation, error)
}

// Organization collects one organization into the stream.
//
// Nodes go before the edges that reference them, and direct grants before
// derived ones, so a consumer reading the stream in order is never told about
// a key it has not seen and never shown a route whose hops have not been
// stated.
func Organization(ctx context.Context, src Source, orgName string, out collector.Stream) error {
	return OrganizationWith(ctx, src, orgName, Config{}, out)
}

// OrganizationWith collects one organization under a configuration.
func OrganizationWith(ctx context.Context, src Source, orgName string, cfg Config,
	out collector.Stream) error {
	org, err := src.Org(ctx, orgName)
	if err != nil {
		return err
	}
	g := newOrgGraph(orgName)
	g.cfg = cfg

	if err := emitScope(org, out); err != nil {
		return err
	}
	if err := emitPeople(ctx, src, orgName, out, g); err != nil {
		return err
	}
	// Read once and reused: the repository phase needs them too, and a
	// second listing is both a wasted request against a request-counted
	// limit and a window in which a team created between the two calls would
	// produce a grant from a grouping this collection never emitted.
	teams, err := src.Teams(ctx, orgName)
	if err != nil {
		return err
	}
	if err := emitTeams(ctx, src, orgName, teams, out, g); err != nil {
		return err
	}
	if err := emitBasePermission(org, out, g); err != nil {
		return err
	}
	if err := emitRepositories(ctx, src, orgName, teams, out, g); err != nil {
		return err
	}
	return reportVerification(orgName, out, g)
}

// reportVerification says how much of this organization was checked against
// GitHub's own answer.
//
// Agreement is silent and disagreement is per repository, so without this a
// reader cannot tell a repository that was checked and agreed from one that
// was never checked at all — and the sample is always the same repositories,
// because it is simply the first ones the listing returned.
func reportVerification(org string, out collector.Stream, g *orgGraph) error {
	switch {
	case g.cfg.Verify == VerifyOff:
		return out.Diagnostic(collectorv1.Severity_SEVERITY_INFO, "github.verify.off",
			"no repository in "+org+" was checked against GitHub's own resolved answer, so a "+
				"mistake in how this collector derives access would show up as wrong evidence "+
				"rather than as a warning")
	case g.verified < g.repos:
		return out.Diagnostic(collectorv1.Severity_SEVERITY_INFO, "github.verify.sampled",
			fmt.Sprintf("%d of %d repositories in %s were checked against GitHub's own "+
				"resolved answer, and they are the first %d the listing returned rather than a "+
				"spread: agreement on them says nothing about the other %d",
				g.verified, g.repos, org, g.verified, g.repos-g.verified))
	}
	return nil
}

// membersGroupingID is the synthetic grouping every member belongs to.
//
// GitHub states the base permission once, for the whole organization. A
// collector that expands it into a grant per member per repository emits
// relationships the source never stated, quadratically in the size of the
// organization. One grouping, one entitlement, one edge per member: the same
// fact, at the size the fact actually is.
const membersGroupingID = "org-members"

// ownersGroupingID is the grouping the organization's owners belong to.
//
// An owner administers every repository by virtue of the role, not by any
// grant on any repository. That access is derived, so the contract requires
// it to say through what — and rightly: "alice has admin on service" is not
// something a reviewer can act on, while "via being an owner of acme-org"
// tells them exactly what taking it away would mean. Making ownership a
// grouping also makes "who owns this organization" a question the graph can
// answer on its own.
const ownersGroupingID = "org-owners"

type orgGraph struct {
	org string
	// people is every principal collected, in the order they were seen.
	people []principal
	// member says whether a principal id is an organization member, which is
	// what makes the base permission apply to them.
	member map[string]bool
	// owner says whether a principal id is an organization owner, which
	// confers administrative access to every repository by virtue of the
	// role.
	owner map[string]bool
	// byLogin resolves a login to a principal id, because the collaborator
	// endpoints answer in logins and the graph is keyed by id.
	byLogin map[string]string
	// seen is which principals have been emitted, by id. Keyed on the id
	// rather than the login because a rename between two calls would
	// otherwise emit the same person twice, with duplicate grants behind
	// them.
	seen map[string]bool
	// teams maps a principal id to the teams they are immediately in.
	teams map[string][]api.Team
	// parent maps a team id to its parent's id, so an inherited grant can
	// state the chain it was inherited through.
	parent map[string]string
	// entitlements already emitted, so a level shared by many repositories
	// is stated once per repository and not once per grant.
	emitted map[string]bool
	// basePermission is the level every member holds everywhere, folded into
	// the per-repository comparison against GitHub's own answer.
	basePermission string
	// cfg decides how much of the collection is checked against GitHub.
	cfg Config
	// verified counts the repositories checked so far, against the sample,
	// and repos how many there were to check.
	verified int
	repos    int
}

// principal is somebody or something that holds access.
//
// id is GitHub's numeric database id as a decimal string, which is what the
// key is built from: a login is what people type and is not rename-stable,
// and a rename that read as a delete plus a create would sever a person's
// history permanently.
type principal struct {
	id    string
	login string
	// human is false for applications and bot accounts.
	human bool
}

// owners returns the owner logins in the order the principals were
// collected, so the stream is the same on every run.
func (g *orgGraph) owners() []string {
	var out []string
	for _, p := range g.people {
		if g.owner[p.id] {
			out = append(out, p.id)
		}
	}
	return out
}

// idOf resolves a login to the principal id the graph is keyed by. The
// collaborator endpoints answer in logins; an unknown one is somebody this
// collection has not seen, and inventing a key for them would be worse than
// saying so.
func (g *orgGraph) idOf(login string) (string, bool) {
	id, ok := g.byLogin[login]
	return id, ok
}

func newOrgGraph(org string) *orgGraph {
	return &orgGraph{
		org:     org,
		member:  map[string]bool{},
		owner:   map[string]bool{},
		byLogin: map[string]string{},
		seen:    map[string]bool{},
		teams:   map[string][]api.Team{},
		parent:  map[string]string{},
		emitted: map[string]bool{},
	}
}

func emitScope(org api.Org, out collector.Stream) error {
	scope := collector.Scope(org.Login, org.Login)
	attrs := map[string]string{}
	// Absent rather than empty when GitHub did not say. An empty string
	// reads as "there is none", which is a different fact.
	if base, stated := org.BasePermission(); stated {
		attrs["base_repository_permission"] = base
	}
	return out.Node(collector.WithContext(
		collector.ScopeNode(scope, org.Login, "organization"), attrs))
}

func emitPeople(ctx context.Context, src Source, org string,
	out collector.Stream, g *orgGraph) error {
	members, err := src.Members(ctx, org)
	if err != nil {
		return err
	}
	admins, err := src.Admins(ctx, org)
	if err != nil {
		return err
	}
	for _, a := range admins {
		g.owner[idOf(a)] = true
	}

	// The groupings the organization-wide access hangs from, emitted before
	// the identities that belong to them.
	grouping := collector.GroupingKey(org, membersGroupingID)
	if err := out.Node(collector.WithContext(
		collector.Grouping(grouping, "members of "+org, "organization_membership"),
		map[string]string{"organization": org, "synthetic": "true"},
	)); err != nil {
		return err
	}
	owners := collector.GroupingKey(org, ownersGroupingID)
	if err := out.Node(collector.WithContext(
		collector.Grouping(owners, "owners of "+org, "organization_ownership"),
		map[string]string{"organization": org, "synthetic": "true"},
	)); err != nil {
		return err
	}

	for _, m := range members {
		id := idOf(m)
		g.member[id] = true
		if err := emitUser(m, roleOf(g, id), out, g); err != nil {
			return err
		}
		if err := out.Edge(collector.MemberOf(
			collector.IdentityKey(org, id), grouping)); err != nil {
			return err
		}
		if g.owner[id] {
			if err := out.Edge(collector.MemberOf(
				collector.IdentityKey(org, id), owners)); err != nil {
				return err
			}
		}
	}

	// Outside collaborators hold repository access without being members, so
	// they are not in the list above and the base permission does not reach
	// them. A collector that stops at the members endpoint misses every one
	// of them while they still hold access.
	outside, err := src.OutsideCollaborators(ctx, org)
	if err != nil {
		return err
	}
	for _, o := range outside {
		if err := emitUser(o, "outside_collaborator", out, g); err != nil {
			return err
		}
	}

	// Applications are principals too, and in most real organizations they
	// outnumber the people.
	apps, err := src.Installations(ctx, org)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if err := emitInstallation(org, app, out, g); err != nil {
			return err
		}
	}
	return nil
}

func roleOf(g *orgGraph, id string) string {
	if g.owner[id] {
		return "organization_owner"
	}
	return "organization_member"
}

// idOf is the key a principal is recorded under: GitHub's numeric database
// id, as a decimal string.
//
// Not the login. R9 fixes a property rather than a format — the id must
// survive a rename — and a GitHub login can be changed by its owner. Keyed on
// the login, a rename would read as one person leaving and another arriving,
// and in an append-only history that difference is permanent.
func idOf(u api.User) string { return strconv.FormatInt(u.ID, 10) }

func emitUser(u api.User, sourceType string, out collector.Stream, g *orgGraph) error {
	kind := collector.Human
	// GitHub says so itself rather than leaving it to a name heuristic, and
	// a "[bot]" suffix on a login is a convention rather than a guarantee.
	if u.Type == "Bot" {
		kind = collector.ServiceKind
	}
	id := idOf(u)
	attrs := map[string]string{
		"organization": g.org,
		"github_type":  u.Type,
		// The login is what people search for and what every other endpoint
		// answers in, so it travels with the record even though it is not
		// the key.
		"login": u.Login,
	}
	if g.owner[id] {
		attrs["organization_role"] = "owner"
	}
	if err := out.Node(collector.WithContext(
		collector.Identity(collector.IdentityKey(g.org, id), u.Login, sourceType,
			kind, collector.Active), attrs)); err != nil {
		return err
	}
	g.people = append(g.people, principal{id: id, login: u.Login, human: kind == collector.Human})
	g.byLogin[u.Login] = id
	g.seen[id] = true
	return nil
}

// emitInstallation records an installed application.
//
// Its permissions are not repository levels and do not sit on the repository
// ladder: "contents: write" is a different axis from a collaborator's write.
// They are recorded as context rather than as entitlements, because inventing
// an entitlement per permission area would put two incomparable things in one
// list and invite a reviewer to compare them.
func emitInstallation(org string, app api.Installation, out collector.Stream, g *orgGraph) error {
	// An installation has a stable numeric id of its own; the slug is the
	// application's name and can change.
	id := "installation:" + strconv.FormatInt(app.ID, 10)
	attrs := map[string]string{
		"organization":         org,
		"github_type":          "Installation",
		"app_slug":             app.AppSlug,
		"app_id":               strconv.FormatInt(app.AppID, 10),
		"repository_selection": app.RepositorySelection,
	}
	for area, level := range app.Permissions {
		attrs["permission."+area] = level
	}
	if !app.CreatedAt.IsZero() {
		attrs["installed_at"] = app.CreatedAt.UTC().Format("2006-01-02")
	}
	if err := out.Node(collector.WithContext(
		collector.Identity(collector.IdentityKey(org, id), app.AppSlug, "app_installation",
			collector.ServiceKind, collector.Active), attrs)); err != nil {
		return err
	}
	g.people = append(g.people, principal{id: id, login: app.AppSlug})
	g.seen[id] = true
	return nil
}

func emitTeams(ctx context.Context, src Source, org string, teams []api.Team,
	out collector.Stream, g *orgGraph) error {
	// Nodes first, so a child's edge to its parent has both ends stated.
	for _, t := range teams {
		if err := out.Node(collector.WithContext(
			collector.Grouping(collector.GroupingKey(org, teamID(t)), t.Name, "team"),
			map[string]string{"organization": org, "slug": t.Slug},
		)); err != nil {
			return err
		}
	}
	// Immediate membership, so that an inherited route is not restated as a
	// direct one. GitHub's REST endpoint includes the members of child
	// teams; emitting that as membership would tell a reviewer to remove
	// somebody from a team they are not in, which is an action nobody can
	// take. The fallback is the transitive answer, and it says so.
	immediate, immediateErr := src.ImmediateTeamMembers(ctx, org, slugs(teams))
	if immediateErr != nil {
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
			"github.teams.membership-not-immediate",
			"could not read immediate team membership, so team membership is reported as "+
				"GitHub's REST endpoint answers it, which includes the members of child "+
				"teams: somebody in a child team will appear as a direct member of its "+
				"parent, and a route through the parent will look like one that can be "+
				"revoked there. The reason: "+immediateErr.Error()); err != nil {
			return err
		}
	}

	// Which teams this collection actually emitted. A secret team is hidden
	// from a token that is not in it, while a child it can see still names
	// it as a parent — and an edge to a node never emitted is a contract
	// violation that makes the host throw the whole collection away, with an
	// error naming an edge rather than the missing permission.
	known := map[string]bool{}
	for _, t := range teams {
		known[teamID(t)] = true
	}

	for _, t := range teams {
		if t.Parent != nil {
			parent := teamID(*t.Parent)
			if !known[parent] {
				// The hierarchy is real and this token cannot see all of it.
				// Said out loud, because a grant reached through the unseen
				// parent is access this collection will not show.
				if err := out.Diagnostic(collectorv1.Severity_SEVERITY_WARNING,
					"github.teams.parent-not-visible",
					fmt.Sprintf("team %s sits under a team this token cannot see (%s), so any "+
						"repository access it inherits from that team is not collected",
						t.Slug, t.Parent.Slug)); err != nil {
					return err
				}
			} else {
				g.parent[teamID(t)] = parent
				if err := out.Edge(collector.ChildOf(
					collector.GroupingKey(org, teamID(t)),
					collector.GroupingKey(org, parent))); err != nil {
					return err
				}
			}
		}
		members, ok := immediate[t.Slug]
		if !ok {
			var err error
			if members, err = src.TeamMembers(ctx, org, t.Slug); err != nil {
				return err
			}
		}
		for _, m := range members {
			id := idOf(m)
			if !g.seen[id] {
				// A team member this collection has not otherwise seen. It
				// happens: an outside collaborator can be on a team. Record
				// them rather than dropping the membership.
				if err := emitUser(m, "team_member", out, g); err != nil {
					return err
				}
			}
			g.teams[id] = append(g.teams[id], t)
			if err := out.Edge(collector.MemberOf(
				collector.IdentityKey(org, id),
				collector.GroupingKey(org, teamID(t)))); err != nil {
				return err
			}
		}
	}
	return nil
}

// baseEntitlementID is the one entitlement that stands for the organization's
// base permission.
func baseEntitlementID(level string) string { return "base:" + level }

func emitBasePermission(org api.Org, out collector.Stream, g *orgGraph) error {
	level, stated := org.BasePermission()
	if !stated {
		// GitHub returns this field only to organization owners. Without it
		// there is no way to know what every member holds on every
		// repository, and that is usually the widest access in the
		// organization — several people on many repositories, in the
		// organization this was verified against.
		//
		// So the collection cannot be presented as a population. Refusing
		// here makes the scope partial and the whole collection incomplete,
		// which is the loud failure this product exists to produce instead
		// of a quiet wrong answer.
		if err := out.Diagnostic(collectorv1.Severity_SEVERITY_ERROR,
			"github.base_permission.unreadable",
			"this token cannot read "+org.Login+"'s default repository permission, which "+
				"GitHub returns only to organization owners. That permission is what every "+
				"member holds on every repository, so without it this collection would "+
				"report no access for people who have it on everything."); err != nil {
			return err
		}
		return fmt.Errorf("organization %s: the default repository permission is not "+
			"readable with this token; it needs to be an organization owner", org.Login)
	}
	if level == "none" {
		// Stated, and stated to be nothing. There is genuinely no
		// organization-wide grant, which is a different fact from not being
		// able to see one.
		return nil
	}
	key := collector.EntitlementKey(org.Login, baseEntitlementID(level))
	ctx := levelContext(level, "")
	ctx["organization"] = org.Login
	ctx["scope_wide"] = "true"
	// Nobody chose to grant this to anybody: it is the organization's
	// default, and a reviewer reading the widest-held list needs to know
	// that before treating it as a finding.
	ctx["default_grant"] = "true"

	// Named for what it does rather than for what GitHub calls it. A
	// reviewer reading "base:write" has to already know what that reaches;
	// reading the sentence, they do not.
	name := level + " on every repository in " + org.Login
	if err := out.Node(collector.WithContext(
		collector.Entitlement(key, name, "organization_base_permission"), ctx)); err != nil {
		return err
	}
	// It applies to the whole organization, not to any one repository. That
	// is the fact GitHub states, and expanding it per repository would emit
	// relationships the source never made.
	if err := out.Edge(collector.AppliesTo(key, collector.Scope(org.Login, org.Login))); err != nil {
		return err
	}
	grouping := collector.GroupingKey(org.Login, membersGroupingID)
	if err := out.Edge(collector.HowGranted(
		collector.Holds(grouping, key, collector.Direct),
		"organization_base_permission")); err != nil {
		return err
	}
	// And one derived edge per member, so that asking what a person holds
	// answers with their most far-reaching access rather than omitting it.
	// One edge per member, not one per member per repository.
	for _, p := range g.people {
		if !g.member[p.id] {
			continue
		}
		if err := out.Edge(collector.HowGranted(
			collector.Holds(collector.IdentityKey(org.Login, p.id), key,
				collector.Effective, grouping),
			"organization_membership")); err != nil {
			return err
		}
	}
	g.emitted[baseEntitlementID(level)] = true
	g.basePermission = level
	return nil
}

// slugs is the team slugs, in the order they were listed.
func slugs(teams []api.Team) []string {
	out := make([]string, 0, len(teams))
	for _, t := range teams {
		out = append(out, t.Slug)
	}
	return out
}

// teamID is the key a team is recorded under: its numeric id, for the same
// reason a person's is. A team can be renamed and its slug changes with it.
func teamID(t api.Team) string { return strconv.FormatInt(t.ID, 10) }

// loginOf turns a principal id back into the login a person would recognise,
// for messages people read.
func (g *orgGraph) loginOf(id string) string {
	for _, p := range g.people {
		if p.id == id {
			return p.login
		}
	}
	return id
}

// routeToTeam is the chain of teams from one this principal is immediately in
// up to the team that holds a grant, or nil when no membership reaches it.
//
// A child team inherits its parent's repositories, so a person in the child
// reaches the parent's grant — but the membership that gives it to them is
// the child's. Naming the whole chain is what makes the grant actionable: the
// reviewer needs to know which membership to end, and it is the first hop.
//
// The shortest chain wins when several memberships reach the same team, and
// the walk is bounded because a cycle would otherwise be walked for ever.
func (g *orgGraph) routeToTeam(principalID, granting string) []string {
	var best []string
	for _, t := range g.teams[principalID] {
		chain := []string{teamID(t)}
		seen := map[string]bool{teamID(t): true}
		for at := teamID(t); ; {
			if at == granting {
				if best == nil || len(chain) < len(best) {
					best = chain
				}
				break
			}
			next, ok := g.parent[at]
			if !ok || seen[next] {
				break
			}
			seen[next] = true
			chain = append(chain, next)
			at = next
		}
	}
	return best
}

// shouldVerify reports whether this repository is one of the ones checked
// against GitHub's own answer, and counts it.
func (g *orgGraph) shouldVerify() bool {
	switch g.cfg.Verify {
	case VerifyOff:
		return false
	case VerifyAll:
	default:
		if g.verified >= g.cfg.sampleSize() {
			return false
		}
	}
	// Counted in every mode, so that what was checked can be reported
	// against what there was to check.
	g.verified++
	return true
}
