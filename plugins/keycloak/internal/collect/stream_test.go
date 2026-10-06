package collect_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	collectorv1 "go.acciew.io/collector/api/collector/v1"
	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
	"go.acciew.io/collector/sdk/go/collector"
)

// fakeSource is a realm in memory, shaped like a real one: a person in a
// subgroup of a group that holds a role, a composite role, a client with a
// role and a service account, and a disabled user who still holds something.
type fakeSource struct {
	users        []admin.User
	groups       map[string][]admin.Group // parent id ("" for root) -> children
	members      map[string][]admin.User
	groupRole    map[string][]admin.Role
	userRole     map[string][]admin.Role
	realm        []admin.Role
	clients      []admin.ClientApp
	clientRls    map[string][]admin.Role
	comps        map[string][]admin.Role
	svcUsers     map[string]*admin.User
	eventsConfig admin.EventsConfig
	eventsErr    error
	eventLogErr  error
	events       []admin.Event
	// grant is what this source's token says it holds. Nil means the roles
	// that read a whole realm, which is what these tests are not about.
	grant map[string]bool
}

// The collection refuses to call a population whole when the token that read
// it cannot see all of it, and asks the token to settle that. A fake with no
// answer is treated as a token with no answer, so it has to have one.
func (f *fakeSource) GrantedRoles(string) (map[string]bool, bool) {
	if f.grant == nil {
		return map[string]bool{"view-users": true, "view-clients": true, "view-realm": true}, true
	}
	return f.grant, true
}

func (f *fakeSource) ManagementClient(string) string { return "realm-management" }

func (f *fakeSource) EventsConfig(context.Context, string) (admin.EventsConfig, error) {
	return f.eventsConfig, f.eventsErr
}

func (f *fakeSource) Events(_ context.Context, _ string, types []string, _ int) ([]admin.Event, error) {
	if f.eventLogErr != nil {
		return nil, f.eventLogErr
	}
	var out []admin.Event
	for _, e := range f.events {
		for _, t := range types {
			if e.Type == t {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (f *fakeSource) Users(context.Context, string) ([]admin.User, error) { return f.users, nil }
func (f *fakeSource) ServiceAccountUser(_ context.Context, _, clientUUID string) (*admin.User, error) {
	return f.svcUsers[clientUUID], nil
}
func (f *fakeSource) TopLevelGroups(context.Context, string) ([]admin.Group, error) {
	return f.groups[""], nil
}
func (f *fakeSource) Subgroups(_ context.Context, _, id string) ([]admin.Group, error) {
	return f.groups[id], nil
}
func (f *fakeSource) GroupMembers(_ context.Context, _, id string) ([]admin.User, error) {
	return f.members[id], nil
}
func (f *fakeSource) GroupRoleMappings(_ context.Context, _, id string) (admin.MappingsRepresentation, error) {
	return admin.MappingsRepresentation{RealmMappings: f.groupRole[id]}, nil
}
func (f *fakeSource) RealmRoles(context.Context, string) ([]admin.Role, error) { return f.realm, nil }
func (f *fakeSource) Clients(context.Context, string) ([]admin.ClientApp, error) {
	return f.clients, nil
}
func (f *fakeSource) ClientRoles(_ context.Context, _, id string) ([]admin.Role, error) {
	return f.clientRls[id], nil
}
func (f *fakeSource) RoleComposites(_ context.Context, _, id string) ([]admin.Role, error) {
	return f.comps[id], nil
}
func (f *fakeSource) UserRoleMappings(_ context.Context, _, id string) (admin.MappingsRepresentation, error) {
	return admin.MappingsRepresentation{RealmMappings: f.userRole[id]}, nil
}

func realm() *fakeSource {
	role := func(id, name string, composite bool) admin.Role {
		return admin.Role{ID: id, Name: name, Composite: composite}
	}
	return &fakeSource{
		users: []admin.User{
			{ID: "u-alice", Username: "alice", Enabled: true, Email: "alice@example.com"},
			{ID: "u-mallory", Username: "mallory", Enabled: false},
		},
		groups: map[string][]admin.Group{
			"":      {{ID: "g-eng", Name: "Engineering", Path: "/Engineering", SubGroupCount: 1}},
			"g-eng": {{ID: "g-plat", Name: "Platform", Path: "/Engineering/Platform"}},
		},
		members: map[string][]admin.User{
			"g-eng":  {},
			"g-plat": {{ID: "u-alice", Username: "alice", Enabled: true}},
		},
		groupRole: map[string][]admin.Role{"g-eng": {role("r-eng", "engineer", false)}},
		userRole: map[string][]admin.Role{
			"u-alice":   {role("r-admin", "admin", true)},
			"u-mallory": {role("r-read", "read", false)},
		},
		realm: []admin.Role{
			role("r-admin", "admin", true),
			role("r-read", "read", false),
			role("r-eng", "engineer", false),
			role("default-roles-probe", "default-roles-probe", true),
		},
		clients:   []admin.ClientApp{{ID: "c-app", ClientID: "app", ServiceAccountsEnabled: true}},
		clientRls: map[string][]admin.Role{"c-app": {{ID: "cr-write", Name: "app-writer", ClientRole: true}}},
		comps: map[string][]admin.Role{
			"r-admin":             {role("r-read", "read", false)},
			"default-roles-probe": {},
		},
		svcUsers: map[string]*admin.User{
			"c-app": {ID: "u-svc", Username: "service-account-app", Enabled: true,
				ServiceAccountClientID: "app"},
		},
	}
}

// capture records what the collector emitted, and validates every record on
// the way past exactly as the host would.
type capture struct {
	events []*collectorv1.CollectResponse
	t      *testing.T
	// tolerateInvalid is set by the failure tests, which stop the collection
	// part-way and are not asserting record validity.
	tolerateInvalid bool
	diagCodes       []string
	scopes          []collector.ScopeResult
	checkpoints     [][]byte
}

// checkStreamIsSendable applies the rule the SDK applies before it will send
// a completion: records with no checkpoint are a stream that cannot be
// resumed, and the SDK refuses it — the host then sees a truncated stream and
// loses the verdict and the data together.
//
// The test double has to enforce this or a whole class of failure is
// invisible in every test in this package, which is exactly what happened.
func (c *capture) checkStreamIsSendable() {
	c.t.Helper()
	records := 0
	for _, e := range c.events {
		if e.GetNode() != nil || e.GetEdge() != nil || e.GetActivity() != nil {
			records++
		}
	}
	if records > 0 && len(c.checkpoints) == 0 {
		c.t.Errorf("the collector emitted %d records and never checkpointed; "+
			"the SDK will refuse to send the completion and the host loses everything", records)
	}
}

func (c *capture) Node(n *collectorv1.Node) error {
	if vs := collectorv1.ValidateNode(n); len(vs) > 0 && !c.tolerateInvalid {
		c.t.Errorf("invalid node %q: %s", n.GetName(), vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Node{Node: n}})
	return nil
}

func (c *capture) Edge(e *collectorv1.Edge) error {
	if vs := collectorv1.ValidateEdge(e); len(vs) > 0 && !c.tolerateInvalid {
		c.t.Errorf("invalid edge: %s", vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Edge{Edge: e}})
	return nil
}

func (c *capture) Activity(a *collectorv1.Activity) error {
	if vs := collectorv1.ValidateActivity(a); len(vs) > 0 && !c.tolerateInvalid {
		c.t.Errorf("invalid activity for %s: %s", a.GetSubject().GetId(), vs[0])
	}
	c.events = append(c.events, &collectorv1.CollectResponse{
		Event: &collectorv1.CollectResponse_Activity{Activity: a}})
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
func (c *capture) Diagnostic(_ collectorv1.Severity, code, _ string) error {
	c.diagCodes = append(c.diagCodes, code)
	return nil
}

func collectRealm(t *testing.T) *capture {
	t.Helper()
	out := &capture{t: t}
	if _, err := collect.Realm(context.Background(), realm(),
		admin.Realm{Realm: "probe", Enabled: live(),
			DefaultRole: &admin.Role{ID: "default-roles-probe", Name: "default-roles-probe"}},
		now, out); err != nil {
		t.Fatalf("Realm: %v", err)
	}
	return out
}

// The strongest test available: run the whole collection through the same
// stream checker the host and the conformance suite use. It proves, among
// other things, that every hop of every derived grant is an edge this
// collector actually emitted and stated directly — which is the property that
// makes a resolution bug detectable at all.
func TestTheEmittedStreamSatisfiesTheContract(t *testing.T) {
	out := collectRealm(t)

	checker := collectorv1.NewStreamChecker()
	var violations []collectorv1.Violation
	for _, e := range out.events {
		violations = append(violations, checker.Event(e)...)
	}
	violations = append(violations, checker.Close()...)

	for _, v := range violations {
		// EndStream is not called: this fixture is the record half of a
		// stream, without the completion the plugin adds.
		if strings.Contains(v.Rule, "completion") || strings.Contains(v.Rule, "checkpoint") {
			continue
		}
		t.Errorf("%s", v)
	}
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

// routes returns the path of every derived grant from a subject to a target,
// as readable ids.
func (c *capture) routes(from, to string) []string {
	var out []string
	for _, e := range c.events {
		edge := e.GetEdge()
		if edge.GetType() != collectorv1.EdgeType_EDGE_TYPE_HOLDS ||
			edge.GetFidelity() != collectorv1.Fidelity_FIDELITY_EFFECTIVE ||
			edge.GetFrom().GetId() != from || edge.GetTo().GetId() != to {
			continue
		}
		var hops []string
		for _, k := range edge.GetPath().GetVia() {
			hops = append(hops, k.GetId())
		}
		out = append(out, strings.Join(hops, ">"))
	}
	return out
}

// The case a collector that trusts GET /groups/{id}/members gets wrong: alice
// is a member of Platform only, and the role is mapped on Engineering above
// it. The route has to name both, because removing her from Platform ends
// this and removing the role from Engineering ends it for everyone below.
func TestARoleOnAnAncestorGroupIsCollectedWithItsRoute(t *testing.T) {
	out := collectRealm(t)

	routes := out.routes("u-alice", "r-eng")
	if len(routes) != 1 || routes[0] != "g-plat>g-eng" {
		t.Errorf("routes for the inherited role = %v, want one through Platform then Engineering", routes)
	}
}

func TestACompositeRoleIsCollectedWithItsRoute(t *testing.T) {
	if routes := collectRealm(t).routes("u-alice", "r-read"); len(routes) != 1 || routes[0] != "r-admin" {
		t.Errorf("routes = %v, want one through the composite", routes)
	}
}

// GET /users does not return service accounts. A collector that stops there
// misses every non-human principal in the realm, and in a real tenant that is
// a large fraction of it.
func TestTheServiceAccountIsCollectedAsANonHumanIdentity(t *testing.T) {
	nodes := collectRealm(t).nodes()

	sa, ok := nodes["u-svc"]
	if !ok {
		t.Fatal("the client's service account was not collected")
	}
	if sa.GetIdentity().GetKind() != collectorv1.IdentityKind_IDENTITY_KIND_SERVICE {
		t.Errorf("kind = %v, want service", sa.GetIdentity().GetKind())
	}
	if sa.GetSourceType() != "service_account" {
		t.Errorf("source type = %q", sa.GetSourceType())
	}
	if sa.GetContext()["service_account_of"] != "app" {
		t.Errorf("context = %v, want it to name the client it belongs to", sa.GetContext())
	}
}

// A disabled principal that still holds grants is a review finding, not a
// non-event, so it is collected rather than skipped.
func TestADisabledUserIsCollectedWithTheirGrants(t *testing.T) {
	out := collectRealm(t)

	mallory, ok := out.nodes()["u-mallory"]
	if !ok {
		t.Fatal("the disabled user was skipped")
	}
	if mallory.GetIdentity().GetStatus() != collectorv1.IdentityStatus_IDENTITY_STATUS_DISABLED {
		t.Errorf("status = %v, want disabled", mallory.GetIdentity().GetStatus())
	}
	var holds bool
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() == collectorv1.EdgeType_EDGE_TYPE_HOLDS &&
			edge.GetFrom().GetId() == "u-mallory" {
			holds = true
		}
	}
	if !holds {
		t.Error("a disabled user's grants still matter; they are what a reviewer acts on")
	}
}

// Every user in every realm carries this one and nobody decided to grant it.
// Untagged, it is four entitlements of noise per person before the real ones
// start.
func TestTheRealmDefaultRoleIsTaggedAsOne(t *testing.T) {
	role, ok := collectRealm(t).nodes()["default-roles-probe"]
	if !ok {
		t.Fatal("the realm default role was not collected")
	}
	if role.GetContext()["default_grant"] != "true" {
		t.Errorf("context = %v, want it tagged so a UI can fold it away", role.GetContext())
	}
}

// A client role means nothing without its client: a reviewer looking at
// "app-writer" needs to know which application that is.
func TestAClientRoleIsScopedToItsClient(t *testing.T) {
	out := collectRealm(t)

	var scoped bool
	for _, e := range out.events {
		edge := e.GetEdge()
		if edge.GetType() == collectorv1.EdgeType_EDGE_TYPE_APPLIES_TO &&
			edge.GetFrom().GetId() == "cr-write" && edge.GetTo().GetId() == "c-app" {
			scoped = true
		}
	}
	if !scoped {
		t.Error("the client role is not scoped to its client")
	}
	role := out.nodes()["cr-write"]
	if role.GetContext()["client_id"] != "app" || role.GetContext()["role_type"] != "client" {
		t.Errorf("context = %v, want the source's own vocabulary", role.GetContext())
	}
}

// Nodes before the edges that reference them, so a consumer reading in order
// never meets a key it has not been told about.
func TestNodesArriveBeforeTheEdgesThatReferenceThem(t *testing.T) {
	known := map[string]bool{}
	for _, e := range collectRealm(t).events {
		if n := e.GetNode(); n != nil {
			known[n.GetKey().GetId()] = true
			continue
		}
		edge := e.GetEdge()
		if edge == nil {
			continue
		}
		for _, k := range append([]*collectorv1.Key{edge.GetFrom(), edge.GetTo()},
			edge.GetPath().GetVia()...) {
			if !known[k.GetId()] {
				t.Errorf("%v edge references %q before it was emitted", edge.GetType(), k.GetId())
			}
		}
	}
}

// failing wraps a source and makes one method fail, so each stage can be
// checked in turn.
type failing struct {
	*fakeSource
	at  string
	err error
}

func (f *failing) fail(name string) error {
	if f.at == name {
		return f.err
	}
	return nil
}

func (f *failing) Users(ctx context.Context, r string) ([]admin.User, error) {
	if err := f.fail("Users"); err != nil {
		return nil, err
	}
	return f.fakeSource.Users(ctx, r)
}
func (f *failing) Clients(ctx context.Context, r string) ([]admin.ClientApp, error) {
	if err := f.fail("Clients"); err != nil {
		return nil, err
	}
	return f.fakeSource.Clients(ctx, r)
}
func (f *failing) RealmRoles(ctx context.Context, r string) ([]admin.Role, error) {
	if err := f.fail("RealmRoles"); err != nil {
		return nil, err
	}
	return f.fakeSource.RealmRoles(ctx, r)
}
func (f *failing) TopLevelGroups(ctx context.Context, r string) ([]admin.Group, error) {
	if err := f.fail("TopLevelGroups"); err != nil {
		return nil, err
	}
	return f.fakeSource.TopLevelGroups(ctx, r)
}
func (f *failing) Subgroups(ctx context.Context, r, id string) ([]admin.Group, error) {
	if err := f.fail("Subgroups"); err != nil {
		return nil, err
	}
	return f.fakeSource.Subgroups(ctx, r, id)
}
func (f *failing) GroupMembers(ctx context.Context, r, id string) ([]admin.User, error) {
	if err := f.fail("GroupMembers"); err != nil {
		return nil, err
	}
	return f.fakeSource.GroupMembers(ctx, r, id)
}
func (f *failing) RoleComposites(ctx context.Context, r, id string) ([]admin.Role, error) {
	if err := f.fail("RoleComposites"); err != nil {
		return nil, err
	}
	return f.fakeSource.RoleComposites(ctx, r, id)
}
func (f *failing) UserRoleMappings(ctx context.Context, r, id string) (admin.MappingsRepresentation, error) {
	if err := f.fail("UserRoleMappings"); err != nil {
		return admin.MappingsRepresentation{}, err
	}
	return f.fakeSource.UserRoleMappings(ctx, r, id)
}
func (f *failing) GroupRoleMappings(ctx context.Context, r, id string) (admin.MappingsRepresentation, error) {
	if err := f.fail("GroupRoleMappings"); err != nil {
		return admin.MappingsRepresentation{}, err
	}
	return f.fakeSource.GroupRoleMappings(ctx, r, id)
}
func (f *failing) ServiceAccountUser(ctx context.Context, r, id string) (*admin.User, error) {
	if err := f.fail("ServiceAccountUser"); err != nil {
		return nil, err
	}
	return f.fakeSource.ServiceAccountUser(ctx, r, id)
}

// A source error must reach the caller. Swallowing one would produce a realm
// that looks fully collected and is missing whatever the failed call would
// have returned — and nothing downstream could tell.
func TestASourceFailureAtAnyStageStopsTheCollection(t *testing.T) {
	stages := []string{
		"Clients", "ClientRoles", "RealmRoles", "RoleComposites",
		"Users", "UserRoleMappings", "ServiceAccountUser",
		"TopLevelGroups", "Subgroups", "GroupMembers", "GroupRoleMappings",
	}
	boom := errors.New("keycloak said no")

	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			src := &failing{fakeSource: realm(), at: stage, err: boom}
			_, err := collect.Realm(context.Background(), src, admin.Realm{Realm: "probe", Enabled: live()}, now,
				&capture{t: t, tolerateInvalid: true})
			if !errors.Is(err, boom) {
				t.Errorf("a failure in %s produced %v; it must reach the caller", stage, err)
			}
		})
	}
}

func (f *failing) ClientRoles(ctx context.Context, r, id string) ([]admin.Role, error) {
	if err := f.fail("ClientRoles"); err != nil {
		return nil, err
	}
	return f.fakeSource.ClientRoles(ctx, r, id)
}

// A stream that refuses a record — a closed connection, a host that has given
// up — must stop the collection rather than carry on emitting into nothing.
func TestAStreamFailureStopsTheCollection(t *testing.T) {
	boom := errors.New("the host went away")
	_, err := collect.Realm(context.Background(), realm(), admin.Realm{Realm: "probe", Enabled: live()}, now, &refusing{err: boom})
	if !errors.Is(err, boom) {
		t.Errorf("got %v, want the stream's error", err)
	}
}

type refusing struct{ err error }

func (r *refusing) Node(*collectorv1.Node) error                          { return r.err }
func (r *refusing) Edge(*collectorv1.Edge) error                          { return r.err }
func (r *refusing) Activity(*collectorv1.Activity) error                  { return r.err }
func (r *refusing) Checkpoint([]byte) error                               { return r.err }
func (r *refusing) Progress(string, *collector.RateLimit) error           { return r.err }
func (r *refusing) ScopeDone(collector.ScopeResult) error                 { return r.err }
func (r *refusing) Diagnostic(collectorv1.Severity, string, string) error { return r.err }

// The promise the check makes has to hold at the surface a scheduled run
// actually uses. Nothing calls `acciew check` on a timer, so a rule enforced
// only there is a rule that protects the demo and not the product.
func TestACollectionRefusesToCallAPartialRealmWhole(t *testing.T) {
	for _, c := range []struct {
		name    string
		grant   map[string]bool
		refuses bool
	}{
		{"a token that reads all of it", map[string]bool{
			"view-users": true, "view-clients": true, "view-realm": true}, false},
		{"manage-* in place of view-*", map[string]bool{
			"manage-users": true, "manage-clients": true, "view-realm": true}, false},
		{"query-users in place of view-users", map[string]bool{
			"query-users": true, "view-clients": true, "view-realm": true}, true},
		{"query-clients in place of view-clients", map[string]bool{
			"view-users": true, "query-clients": true, "view-realm": true}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := realm()
			src.grant = c.grant

			out := &capture{t: t}
			_, err := collect.Realm(context.Background(), src,
				admin.Realm{Realm: "probe", Enabled: live()}, now, out)
			switch {
			case c.refuses && err == nil:
				t.Fatal("a realm read through a token that cannot see all of it was " +
					"collected without complaint, so the scope reports collected and the " +
					"population reads as the realm's")
			case !c.refuses && err != nil:
				t.Fatalf("a token that reads the whole realm was refused: %v", err)
			}
			// What was found is kept either way: a partial population is
			// worth having as long as nothing calls it whole.
			if c.refuses && len(out.events) == 0 {
				t.Error("nothing was emitted, so the operator sees a failure and no evidence")
			}
		})
	}
}

// Keycloak strips the enabled field from a realm listing a token cannot fully
// read, so it is a pointer and a test has to say which it means.
func live() *bool { t := true; return &t }

func dead() *bool { f := false; return &f }
