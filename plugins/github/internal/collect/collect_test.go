package collect_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/github/internal/api"
	"go.acciew.io/collector/plugins/github/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// fakeSource is an organization in memory, shaped like the real one the
// fixtures were recorded from: a base permission of write, members who hold
// nothing on any repository directly, an owner, an outside collaborator, an
// installed application, and a team that owns one repository.
type fakeSource struct {
	org          api.Org
	members      []api.User
	admins       []api.User
	outside      []api.User
	teams        []api.Team
	teamMems     map[string][]api.User
	immediate    map[string][]api.User
	immediateErr error
	teamRepos    map[string][]api.TeamRepo
	repos        []api.Repo
	collabs      map[string][]api.Collaborator
	direct       map[string][]api.Collaborator
	apps         []api.Installation
	// checked records which repositories were cross-checked against
	// GitHub's own answer.
	checked []string
	// teamCalls counts how many times the team list was asked for.
	teamCalls int
}

func (f *fakeSource) Org(context.Context, string) (api.Org, error) { return f.org, nil }
func (f *fakeSource) Members(context.Context, string) ([]api.User, error) {
	return f.members, nil
}
func (f *fakeSource) Admins(context.Context, string) ([]api.User, error) { return f.admins, nil }
func (f *fakeSource) OutsideCollaborators(context.Context, string) ([]api.User, error) {
	return f.outside, nil
}
func (f *fakeSource) Teams(context.Context, string) ([]api.Team, error) {
	f.teamCalls++
	return f.teams, nil
}
func (f *fakeSource) TeamMembers(_ context.Context, _, slug string) ([]api.User, error) {
	return f.teamMems[slug], nil
}

func (f *fakeSource) ImmediateTeamMembers(_ context.Context, _ string, slugs []string) (map[string][]api.User, error) {
	if f.immediateErr != nil {
		return nil, f.immediateErr
	}
	if f.immediate == nil {
		return nil, nil
	}
	out := map[string][]api.User{}
	for _, s := range slugs {
		out[s] = f.immediate[s]
	}
	return out, nil
}
func (f *fakeSource) TeamRepos(_ context.Context, _, slug string) ([]api.TeamRepo, error) {
	return f.teamRepos[slug], nil
}
func (f *fakeSource) Repos(context.Context, string) ([]api.Repo, error) { return f.repos, nil }
func (f *fakeSource) Collaborators(_ context.Context, _, repo string) ([]api.Collaborator, error) {
	f.checked = append(f.checked, repo)
	return f.collabs[repo], nil
}
func (f *fakeSource) DirectCollaborators(_ context.Context, _, repo string) ([]api.Collaborator, error) {
	return f.direct[repo], nil
}
func (f *fakeSource) Installations(context.Context, string) ([]api.Installation, error) {
	return f.apps, nil
}

// Distinct ids, because the key is the id and not the login: a login can be
// changed by its owner and a rename must not read as a delete plus a create.
var ids = map[string]int64{"alice": 101, "bob": 102, "carol": 103, "dana": 104, "eve": 105}

// base is how GitHub states a default repository permission: present when
// the token is an organization owner, absent otherwise.
func base(level string) *string { return &level }

func user(login string) api.User {
	return api.User{Login: login, ID: ids[login], Type: "User"}
}

// id is the key the graph records a login under.
func id(login string) string { return strconv.FormatInt(ids[login], 10) }

func org() *fakeSource {
	return &fakeSource{
		org: api.Org{Login: "acme-org", DefaultRepositoryPermission: base("write")},
		members: []api.User{
			user("alice"), user("bob"), user("carol"),
		},
		admins:  []api.User{user("alice")},
		outside: []api.User{user("dana")},
		teams: []api.Team{
			{Slug: "platform", Name: "Platform", ID: 11},
			{Slug: "infra", Name: "Infra", ID: 12, Parent: &api.Team{Slug: "platform", ID: 11}},
		},
		teamMems: map[string][]api.User{
			"platform": {user("bob")},
			"infra":    {user("carol")},
		},
		teamRepos: map[string][]api.TeamRepo{
			"platform": {{Name: "service", ID: 21, RoleName: "maintain"}},
		},
		repos: []api.Repo{
			{Name: "service", ID: 21},
			{Name: "retired", ID: 22, Archived: true},
		},
		// GitHub's own answer: everyone who can reach the repository, with
		// the four terms already combined.
		collabs: map[string][]api.Collaborator{
			"service": {
				{Login: "alice", ID: ids["alice"], RoleName: "admin"},
				{Login: "bob", ID: ids["bob"], RoleName: "maintain"},
				// carol is in Infra, which is a child of Platform, and a
				// child team inherits its parent's repositories — so she
				// reaches maintain too, through a team she is not in.
				{Login: "carol", ID: ids["carol"], RoleName: "maintain"},
				{Login: "dana", ID: ids["dana"], RoleName: "read"},
			},
			"retired": {
				{Login: "alice", ID: ids["alice"], RoleName: "admin"},
				{Login: "bob", ID: ids["bob"], RoleName: "write"},
				{Login: "carol", ID: ids["carol"], RoleName: "write"},
			},
		},
		// As a real organization answers: nobody is a direct collaborator on
		// a repository the whole organization can already write to.
		direct: map[string][]api.Collaborator{
			"service": {{Login: "dana", ID: ids["dana"], RoleName: "read"}},
		},
		apps: []api.Installation{{
			ID: 31, AppID: 2, AppSlug: "ci-bot", TargetType: "Organization",
			Permissions: map[string]string{"contents": "write"},
		}},
	}
}

// capture records what the collector emitted and validates every record on
// the way past, exactly as the host would.
type capture struct {
	t           *testing.T
	events      []*collectorv1.CollectResponse
	diags       []string
	scopes      []collector.ScopeResult
	checkpoints [][]byte
}

func (c *capture) Node(n *collectorv1.Node) error {
	if vs := collectorv1.ValidateNode(n); len(vs) > 0 {
		c.t.Errorf("invalid node %q: %s", n.GetName(), vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Node{Node: n}})
	return nil
}

func (c *capture) Edge(e *collectorv1.Edge) error {
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 {
		c.t.Errorf("invalid edge: %s", vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Edge{Edge: e}})
	return nil
}

func (c *capture) Activity(a *collectorv1.Activity) error {
	c.t.Errorf("this collector produces no activity, and emitted one for %v", a.GetSubject())
	return nil
}

func (c *capture) Checkpoint(cursor []byte) error {
	c.checkpoints = append(c.checkpoints, cursor)
	return nil
}
func (c *capture) Progress(string, *collector.RateLimit) error { return nil }
func (c *capture) ScopeDone(r collector.ScopeResult) error {
	c.scopes = append(c.scopes, r)
	return nil
}
func (c *capture) Diagnostic(_ collectorv1.Severity, code, message string) error {
	c.diags = append(c.diags, code+": "+message)
	return nil
}

func collectOrg(t *testing.T, src collect.Source) *capture {
	t.Helper()
	out := &capture{t: t}
	if err := collect.Organization(context.Background(), src, "acme-org", out); err != nil {
		t.Fatalf("Organization: %v", err)
	}
	return out
}

func (c *capture) nodes() map[string]*collectorv1.Node {
	out := map[string]*collectorv1.Node{}
	for _, e := range c.events {
		if n := e.GetNode(); n != nil {
			out[n.GetKey().GetId()] = n
		}
	}
	return out
}

// grants returns what a subject holds, keyed by entitlement id, with the
// route rendered as readable ids.
func (c *capture) grants(subject string) map[string][]string {
	out := map[string][]string{}
	for _, e := range c.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_HOLDS ||
			edge.GetFrom().GetId() != subject {
			continue
		}
		var route []string
		for _, hop := range edge.GetPath().GetVia() {
			route = append(route, hop.GetId())
		}
		out[edge.GetTo().GetId()] = route
	}
	return out
}

// The trap this whole collector is shaped around. Verified against a real
// organization: a repository with no direct collaborators was writable by several
// people, because the organization's base permission reaches every member.
// A collector that enumerates collaborators reports nobody on it.
func TestTheOrganizationBasePermissionIsCollected(t *testing.T) {
	out := collectOrg(t, org())

	nodes := out.nodes()
	base, ok := nodes["base:write"]
	if !ok {
		t.Fatalf("the base permission was not collected: %v", keysOf(nodes))
	}
	// Named for what it reaches. "base:write" means nothing to somebody who
	// does not already know GitHub.
	if !strings.Contains(base.GetName(), "every repository") {
		t.Errorf("the base permission is named %q, which does not say what it reaches",
			base.GetName())
	}
	for _, who := range []string{"alice", "bob", "carol"} {
		if _, held := out.grants(id(who))["base:write"]; !held {
			t.Errorf("%s is a member and does not hold the base permission", who)
		}
	}
	// And an outside collaborator is not a member, so it must not reach them.
	if _, held := out.grants(id("dana"))["base:write"]; held {
		t.Error("an outside collaborator was given the organization's base permission")
	}
}

// One fact stated once. Expanding the base permission into a grant per member
// per repository emits relationships GitHub never stated, and does it
// quadratically in the size of the organization.
func TestTheBasePermissionIsOneEntitlementNotOnePerRepository(t *testing.T) {
	src := org()
	for i := range 50 {
		src.repos = append(src.repos, api.Repo{Name: "repo" + string(rune('a'+i%26)) + string(rune('a'+i/26)), ID: int64(100 + i)})
	}
	out := collectOrg(t, src)

	var baseEntitlements, baseEdges int
	for _, n := range out.nodes() {
		if strings.HasPrefix(n.GetKey().GetId(), "base:") {
			baseEntitlements++
		}
	}
	for _, e := range out.events {
		if edge := e.GetEdge(); edge.GetTo().GetId() == "base:write" {
			baseEdges++
		}
	}
	if baseEntitlements != 1 {
		t.Errorf("%d base entitlements, want exactly one", baseEntitlements)
	}
	// One per member plus one from the grouping. Not one per member per
	// repository, which for 52 repositories would be 156.
	if baseEdges > 10 {
		t.Errorf("%d edges to the base permission across 52 repositories; "+
			"it should not grow with the number of repositories", baseEdges)
	}
}

// Every route is its own grant, because revoking one leaves the others
// standing. Bob reaches maintain on service through a team; he also holds the
// organization's base write. Telling a reviewer that removing him from the
// team ends his access would be wrong.
func TestEachRouteToAccessIsItsOwnGrant(t *testing.T) {
	out := collectOrg(t, org())

	bob := out.grants(id("bob"))
	if route, ok := bob["repo:21:maintain"]; !ok {
		t.Errorf("bob does not hold maintain on service: %v", bob)
	} else if len(route) != 1 || route[0] != "11" {
		t.Errorf("bob's route to maintain = %v, want the team", route)
	}
	if _, ok := bob["base:write"]; !ok {
		t.Error("bob's base permission is missing, so removing him from the team " +
			"would look like removing his access")
	}
}

// An owner administers every repository by virtue of the role. A collector
// that only reads collaborator lists reports the owner at whatever level the
// list happens to say.
func TestAnOrganizationOwnerHoldsAdminEverywhere(t *testing.T) {
	out := collectOrg(t, org())

	alice := out.grants(id("alice"))
	for _, repo := range []string{"21", "22"} {
		if _, ok := alice["repo:"+repo+":admin"]; !ok {
			t.Errorf("the owner does not hold admin on %s: %v", repo, alice)
		}
	}
	if node := out.nodes()[id("alice")]; node.GetContext()["organization_role"] != "owner" {
		t.Errorf("the owner is not marked as one: %v", node.GetContext())
	}
}

// An archived repository is read-only whatever a level says, and this is the
// only place a reviewer can find that out.
func TestAnArchivedRepositorySaysSo(t *testing.T) {
	nodes := collectOrg(t, org()).nodes()
	if got := nodes["22"].GetContext()["archived"]; got != "true" {
		t.Errorf("archived = %q on a repository that is", got)
	}
	if got := nodes["21"].GetContext()["archived"]; got != "false" {
		t.Errorf("archived = %q on a repository that is not", got)
	}
}

// Applications hold access and are not people. In the organization these
// fixtures came from they outnumbered the humans three to one.
func TestAnInstalledApplicationIsAPrincipal(t *testing.T) {
	nodes := collectOrg(t, org()).nodes()
	app, ok := nodes["installation:31"]
	if !ok {
		t.Fatalf("the installed application is not a principal: %v", keysOf(nodes))
	}
	if app.GetIdentity().GetKind() != collectorv1.IdentityKind_IDENTITY_KIND_SERVICE {
		t.Errorf("kind = %v, want a service", app.GetIdentity().GetKind())
	}
	// Its permissions are a different axis from a repository level, and are
	// recorded as context rather than as entitlements so that nobody is
	// invited to compare the two.
	if app.GetContext()["permission.contents"] != "write" {
		t.Errorf("the application's permissions were dropped: %v", app.GetContext())
	}
}

// A team both groups people and holds access, and a child team inherits its
// parent's repositories.
func TestATeamIsAGroupingThatAlsoHoldsAccess(t *testing.T) {
	out := collectOrg(t, org())
	nodes := out.nodes()
	if _, ok := nodes["11"]; !ok {
		t.Fatal("the team was not collected as a grouping")
	}
	// The team holds the grant in its own right, so a reviewer can ask what
	// the team has rather than only what its members have.
	if _, ok := out.grants("11")["repo:21:maintain"]; !ok {
		t.Errorf("the team does not hold its own grant: %v", out.grants("11"))
	}
	var childOf bool
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() == collectorv1.EdgeType_EDGE_TYPE_CHILD_OF &&
			edge.GetFrom().GetId() == "12" && edge.GetTo().GetId() == "11" {
			childOf = true
		}
	}
	if !childOf {
		t.Error("the team hierarchy was not recorded")
	}
}

func keysOf(m map[string]*collectorv1.Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The strongest test available: the whole collection through the same stream
// checker the host and the conformance suite use. Among other things it
// proves every hop of every derived grant is an edge this collector actually
// stated, which is what makes a resolution bug detectable at all.
func TestTheEmittedStreamSatisfiesTheContract(t *testing.T) {
	out := collectOrg(t, org())

	checker := collectorv1.NewStreamChecker()
	var violations []collectorv1.Violation
	for _, e := range out.events {
		violations = append(violations, checker.Event(e)...)
	}
	violations = append(violations, checker.Close()...)

	for _, v := range violations {
		// This fixture is the record half of a stream, without the
		// completion the plugin adds.
		if strings.Contains(v.Rule, "completion") || strings.Contains(v.Rule, "checkpoint") {
			continue
		}
		t.Errorf("%s", v)
	}
}

// GitHub resolves the same question independently. It gives the level and not
// the route, so it cannot replace the derivation — but a disagreement means
// one of the two is wrong, and quietly taking GitHub's number would hide a
// bug in the routes being shown to people.
func TestADisagreementWithGitHubsOwnAnswerIsReported(t *testing.T) {
	src := org()
	// GitHub says dana can reach a repository this collector has no route to.
	src.collabs["service"] = append(src.collabs["service"],
		api.Collaborator{Login: "eve", ID: ids["eve"], RoleName: "admin"})

	out := collectOrg(t, src)
	var found bool
	for _, d := range out.diags {
		if strings.Contains(d, "github.derivation.disagrees") && strings.Contains(d, "eve") {
			found = true
		}
	}
	if !found {
		t.Errorf("a disagreement went unreported: %v", out.diags)
	}
}

// The other direction is worse: access this collector derived that GitHub
// does not agree exists is access we invented.
func TestAccessWeInventedIsReported(t *testing.T) {
	src := org()
	// GitHub lists nobody on the archived repository, while the base
	// permission says every member reaches it.
	src.collabs["retired"] = nil

	out := collectOrg(t, src)
	var found bool
	for _, d := range out.diags {
		if strings.Contains(d, "GitHub does not list them") {
			found = true
		}
	}
	if !found {
		t.Errorf("access nobody else agrees exists went unreported: %v", out.diags)
	}
}

// Agreement is the ordinary case and must be silent, or the diagnostic
// becomes noise nobody reads.
func TestAgreementIsSilent(t *testing.T) {
	out := collectOrg(t, org())
	for _, d := range out.diags {
		if strings.Contains(d, "disagrees") {
			t.Errorf("a correct derivation produced a warning: %s", d)
		}
	}
}

// Two runs of one collection emit the same records in the same order, or
// every snapshot diff is churn rather than change.
func TestTheEmissionOrderIsTheSameEveryRun(t *testing.T) {
	var first []string
	for range 8 {
		var got []string
		for _, e := range collectOrg(t, org()).events {
			switch {
			case e.GetNode() != nil:
				got = append(got, "n:"+e.GetNode().GetKey().GetId())
			case e.GetEdge() != nil:
				got = append(got, "e:"+e.GetEdge().GetFrom().GetId()+">"+e.GetEdge().GetTo().GetId())
			}
		}
		if first == nil {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Fatalf("run lengths differ: %d then %d", len(first), len(got))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("record %d differs between runs: %s then %s", i, first[i], got[i])
			}
		}
	}
}

// GitHub's REST team-members endpoint includes the members of child teams.
// Emitted as membership, that turns an inherited route into a stated one:
// carol is in Infra, and "carol is a member of Platform" would tell a
// reviewer to remove her from a team she is not in. It is the phantom-route
// failure the Keycloak collector guards against, one layer up.
func TestAnInheritedTeamMemberIsNotReportedAsADirectMember(t *testing.T) {
	src := org()
	// As the REST endpoint answers: the parent lists its own members and
	// every descendant's.
	src.teamMems["platform"] = []api.User{user("bob"), user("carol")}
	src.teamMems["infra"] = []api.User{user("carol")}
	// And the immediate answer, which is what the collector must use.
	src.immediate = map[string][]api.User{
		"platform": {user("bob")},
		"infra":    {user("carol")},
	}

	out := collectOrg(t, src)
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_MEMBER_OF {
			continue
		}
		if edge.GetFrom().GetId() == id("carol") && edge.GetTo().GetId() == "11" {
			t.Error("carol was reported as a direct member of the parent team; " +
				"removing her from it is an action nobody can take")
		}
	}
	// She still reaches the parent's grant, through the team she is in.
	route, held := out.grants(id("carol"))["repo:21:maintain"]
	if !held {
		t.Fatalf("carol lost the access she inherits: %v", out.grants(id("carol")))
	}
	if len(route) == 0 || route[len(route)-1] != "11" {
		t.Errorf("carol's route = %v, want it to end at the team that holds the grant", route)
	}
	if route[0] != "12" {
		t.Errorf("carol's route = %v, want it to start at the team she is actually in", route)
	}
}

// When the immediate answer is not available the collector must not quietly
// pretend the transitive one is it.
func TestFallingBackToTransitiveMembershipIsSaidOutLoud(t *testing.T) {
	src := org()
	src.immediateErr = errors.New("graphql unavailable")
	out := collectOrg(t, src)

	var warned bool
	for _, d := range out.diags {
		if strings.Contains(d, "github.teams.membership-not-immediate") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the collector fell back without saying so: %v", out.diags)
	}
}

// Checking every repository against GitHub's own answer costs a request per
// repository, which on a large organization is the difference between one
// rate-limit window and two. It checks this collector rather than the
// collection, so how much of it to do is the operator's call.
func TestTheCrossCheckIsSampledByDefault(t *testing.T) {
	src := org()
	for i := range 60 {
		src.repos = append(src.repos, api.Repo{Name: fmt.Sprintf("r%02d", i), ID: int64(300 + i)})
	}

	for _, c := range []struct {
		mode string
		want int
	}{
		{"", 25},    // the default: a sample
		{"off", 0},  // nothing checked
		{"all", 62}, // every repository
		{"sample", 25},
	} {
		src.checked = nil
		out := &capture{t: t}
		cfg := collect.Config{Verify: c.mode}
		if err := collect.OrganizationWith(context.Background(), src, "acme-org", cfg, out); err != nil {
			t.Fatalf("%q: %v", c.mode, err)
		}
		if len(src.checked) != c.want {
			t.Errorf("verify=%q checked %d repositories, want %d", c.mode, len(src.checked), c.want)
		}
	}
}

// Every repository's grants are still collected whatever the verification
// setting: sampling reduces the checking, not the collection.
func TestSamplingDoesNotReduceWhatIsCollected(t *testing.T) {
	src := org()
	out := &capture{t: t}
	if err := collect.OrganizationWith(context.Background(), src, "acme-org",
		collect.Config{Verify: "off"}, out); err != nil {
		t.Fatal(err)
	}
	nodes := out.nodes()
	for _, repo := range []string{"21", "22"} {
		if _, ok := nodes[repo]; !ok {
			t.Errorf("repository %s was not collected with verification off", repo)
		}
	}
	if _, held := out.grants(id("bob"))["repo:21:maintain"]; !held {
		t.Error("a grant went missing with verification off")
	}
}

// GitHub returns the base permission only to organization owners. Read as
// "the organization turned it off", a member's token produces a collection
// where people who can write to every repository hold nothing at all —
// and the verdict says complete. The most far-reaching entitlement in the
// organization goes missing and nothing says so.
func TestAnUnreadableBasePermissionFailsTheOrganizationRatherThanReportingNothing(t *testing.T) {
	src := org()
	src.org.DefaultRepositoryPermission = nil // as a member's token sees it

	out := &capture{t: t}
	err := collect.Organization(context.Background(), src, "acme-org", out)
	if err == nil {
		t.Fatal("an organization whose base permission could not be read collected clean")
	}
	var loud bool
	for _, d := range out.diags {
		if strings.Contains(d, "github.base_permission.unreadable") {
			loud = true
		}
	}
	if !loud {
		t.Errorf("nothing told the operator why: %v", out.diags)
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Errorf("the error does not say what to fix: %v", err)
	}
}

// An organization that has genuinely turned it off did state something. That
// is a fact about the organization, not a gap, and it must not fail.
func TestAnOrganizationWithTheBasePermissionTurnedOffCollectsCleanly(t *testing.T) {
	src := org()
	src.org.DefaultRepositoryPermission = base("none")

	out := &capture{t: t}
	if err := collect.Organization(context.Background(), src, "acme-org", out); err != nil {
		t.Fatalf("an organization with no base permission failed: %v", err)
	}
	for id := range out.nodes() {
		if strings.HasPrefix(id, "base:") {
			t.Errorf("a base entitlement was invented for an organization that has none: %s", id)
		}
	}
	// Everything else still collected.
	if _, ok := out.nodes()["21"]; !ok {
		t.Error("the repositories were lost")
	}
}

// A secret team is hidden from a token that is not in it, while a child it
// can see still names it as a parent. An edge to a node never emitted is a
// contract violation, and the host throws the whole collection away with an
// error naming an edge rather than the missing permission.
func TestAParentTeamThisTokenCannotSeeDoesNotBreakTheStream(t *testing.T) {
	src := org()
	src.teams = []api.Team{
		{Slug: "infra", Name: "Infra", ID: 12, Parent: &api.Team{Slug: "secret", ID: 99}},
	}
	src.teamMems = map[string][]api.User{"infra": {user("carol")}}
	src.teamRepos = map[string][]api.TeamRepo{}

	out := collectOrg(t, src)

	checker := collectorv1.NewStreamChecker()
	var violations []collectorv1.Violation
	for _, e := range out.events {
		violations = append(violations, checker.Event(e)...)
	}
	violations = append(violations, checker.Close()...)
	for _, v := range violations {
		if strings.Contains(v.Rule, "completion") || strings.Contains(v.Rule, "checkpoint") {
			continue
		}
		t.Errorf("the stream is not one the host would accept: %s", v)
	}
	// And the gap is said out loud, because access inherited through the
	// unseen team is access this collection does not show.
	var warned bool
	for _, d := range out.diags {
		if strings.Contains(d, "github.teams.parent-not-visible") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the invisible parent went unmentioned: %v", out.diags)
	}
}

// An owner who also holds a custom role directly is not a disagreement. The
// collector derived admin-via-ownership correctly; collapsing the two levels
// into one made the check fire on a right answer, and a warning that fires on
// right answers is one nobody reads.
func TestACustomRoleDoesNotManufactureADisagreement(t *testing.T) {
	src := org()
	src.direct["service"] = append(src.direct["service"],
		api.Collaborator{Login: "alice", ID: ids["alice"], RoleName: "security-reviewer",
			Permissions: api.Permissions{Pull: true, Push: true}})
	// GitHub resolves alice to admin, because she owns the organization.
	// Everyone else is unchanged.
	src.collabs["service"][0] = api.Collaborator{
		Login: "alice", ID: ids["alice"], RoleName: "admin"}

	out := collectOrg(t, src)
	for _, d := range out.diags {
		if strings.Contains(d, "disagrees") {
			t.Errorf("a correct derivation was reported as a disagreement: %s", d)
		}
	}
	// Both routes are still there, because revoking one leaves the other.
	alice := out.grants(id("alice"))
	if _, ok := alice["repo:21:admin"]; !ok {
		t.Error("the ownership route was lost")
	}
	if _, ok := alice["repo:21:security-reviewer"]; !ok {
		t.Error("the custom role route was lost")
	}
}

// A custom role extends a base role, and the base role is in the booleans
// GitHub sends alongside the name — not in the name, which is the custom
// role's own.
func TestACustomRoleCarriesTheBaseRoleItExtends(t *testing.T) {
	src := org()
	src.direct["service"] = []api.Collaborator{
		{Login: "dana", ID: ids["dana"], RoleName: "security-reviewer",
			Permissions: api.Permissions{Pull: true, Triage: true, Push: true}},
	}
	nodes := collectOrg(t, src).nodes()
	n, ok := nodes["repo:21:security-reviewer"]
	if !ok {
		t.Fatalf("the custom role was not collected: %v", keysOf(nodes))
	}
	if got := n.GetContext()["base_role"]; got != "write" {
		t.Errorf("base_role = %q, want the level its permissions actually confer", got)
	}
	if _, ranked := n.GetContext()["rank"]; ranked {
		t.Errorf("a custom role was given a rank: %v", n.GetContext())
	}
}

// Agreement is silent and disagreement is per repository, so without a word
// about the sample a reader cannot tell "checked and agreed" from "never
// checked".
func TestTheSampleSaysWhatItDidNotCheck(t *testing.T) {
	src := org()
	for i := range 40 {
		src.repos = append(src.repos, api.Repo{Name: fmt.Sprintf("r%02d", i), ID: int64(400 + i)})
	}
	out := &capture{t: t}
	if err := collect.OrganizationWith(context.Background(), src, "acme-org",
		collect.Config{}, out); err != nil {
		t.Fatal(err)
	}
	var said bool
	for _, d := range out.diags {
		if strings.Contains(d, "github.verify.sampled") && strings.Contains(d, "of 42") {
			said = true
		}
	}
	if !said {
		t.Errorf("the sample was not described: %v", out.diags)
	}
}

// Turning the check off entirely is supported, and it is worth saying that a
// derivation bug would now show up as wrong evidence rather than a warning.
func TestTurningTheCheckOffIsSaidOutLoud(t *testing.T) {
	out := &capture{t: t}
	if err := collect.OrganizationWith(context.Background(), org(), "acme-org",
		collect.Config{Verify: "off"}, out); err != nil {
		t.Fatal(err)
	}
	var said bool
	for _, d := range out.diags {
		if strings.Contains(d, "github.verify.off") {
			said = true
		}
	}
	if !said {
		t.Errorf("nothing said the check was off: %v", out.diags)
	}
}

// Checking every repository needs no caveat.
func TestCheckingEverythingSaysNothing(t *testing.T) {
	out := &capture{t: t}
	if err := collect.OrganizationWith(context.Background(), org(), "acme-org",
		collect.Config{Verify: "all"}, out); err != nil {
		t.Fatal(err)
	}
	for _, d := range out.diags {
		if strings.Contains(d, "github.verify") {
			t.Errorf("a full check produced a caveat: %s", d)
		}
	}
}

// The teams are listed once. A second listing is a wasted request against a
// request-counted limit, and a window in which a team created between the two
// calls yields a grant from a grouping never emitted.
func TestTheTeamsAreListedOnce(t *testing.T) {
	src := org()
	collectOrg(t, src)
	if src.teamCalls != 1 {
		t.Errorf("the teams were listed %d times, want once", src.teamCalls)
	}
}
