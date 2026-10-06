package collect_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
)

type probeSource struct {
	collect.Source
	configs map[string]admin.EventsConfig
	errs    map[string]error
	// denied names the reads this token is refused, by the thing being read.
	denied map[string]error
	// realmRole is the role the probe resolves a composite of.
	realmRole admin.Role
	// grant is what the token says it holds. Nil means the three reachability
	// roles, which is what most of these tests are not about.
	grant map[string]bool
	// users this realm answers with, for the tests that are about what a
	// population looks like rather than whether a read was refused.
	users []admin.User
}

func (p probeSource) RoleComposites(context.Context, string, string) ([]admin.Role, error) {
	return nil, p.denied["composites"]
}

func (p probeSource) Users(context.Context, string) ([]admin.User, error) {
	return p.users, p.denied["users"]
}

func (p probeSource) Clients(context.Context, string) ([]admin.ClientApp, error) {
	return nil, p.denied["clients"]
}

func (p probeSource) RealmRoles(context.Context, string) ([]admin.Role, error) {
	if err := p.denied["roles"]; err != nil {
		return nil, err
	}
	if p.realmRole.ID == "" {
		return nil, nil
	}
	return []admin.Role{p.realmRole}, nil
}

func (p probeSource) TopLevelGroups(context.Context, string) ([]admin.Group, error) {
	return nil, p.denied["groups"]
}

// The probe asks what roles the token holds when a listing comes back empty.
// A fake that cannot answer is told so, and gets the benefit of the doubt it
// would not get from a real Keycloak.
func (p probeSource) GrantedRoles(string) (map[string]bool, bool) {
	if p.grant == nil {
		return map[string]bool{"view-users": true, "view-clients": true, "view-realm": true}, true
	}
	return p.grant, true
}

func (p probeSource) ManagementClient(string) string { return "realm-management" }

func (p probeSource) UserRoleMappings(context.Context, string, string) (admin.MappingsRepresentation, error) {
	return admin.MappingsRepresentation{}, p.denied["usermappings"]
}

func (p probeSource) Events(context.Context, string, []string, int) ([]admin.Event, error) {
	return nil, p.denied["events"]
}

func (p probeSource) EventsConfig(_ context.Context, realm string) (admin.EventsConfig, error) {
	if err := p.errs[realm]; err != nil {
		return admin.EventsConfig{}, err
	}
	return p.configs[realm], nil
}

// refused is what Keycloak returns when a role is missing, as opposed to any
// of the other ways a call can fail. The distinction is load-bearing: only a
// refusal is evidence about the grant, so a fixture that fakes one with a
// plain error would have the tests assert that an arbitrary failure is a
// missing role.
func refused() error {
	return &admin.Error{
		Kind: admin.KindPermission, Status: 403,
		Message: "the service account lacks a realm-management role for this",
	}
}

func realms(names ...string) []admin.Realm {
	rs := make([]admin.Realm, 0, len(names))
	for _, n := range names {
		rs = append(rs, admin.Realm{Realm: n, Enabled: live()})
	}
	return rs
}

func probeFor(t *testing.T, probes []collect.Probe, realm string) collect.Probe {
	t.Helper()
	for _, p := range probes {
		if p.Realm == realm {
			return p
		}
	}
	t.Fatalf("no probe for %q", realm)
	return collect.Probe{}
}

// The whole point of a pre-flight check is to say whether last-activity will
// work before somebody waits on a collection. Answering "no" for a realm that
// can answer is the failure that makes people conclude the product is broken.
func TestAProbeReportsActivityForARealmWithEventStorageOn(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{
		"acme": {EventsEnabled: true, EnabledEventTypes: []string{"LOGIN", "CLIENT_LOGIN"}},
	}}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if !got.Reachable {
		t.Fatalf("acme is not reachable: %v", got.Err)
	}
	if !got.ActivityAvailable {
		t.Error("a realm with event storage on was reported as having no activity data")
	}
}

func TestAProbeReportsNoActivityForARealmWithEventStorageOff(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: false}}}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if got.ActivityAvailable {
		t.Error("a realm with event storage off was reported as answerable")
	}
	if got.ActivityNote == "" {
		t.Error("nothing told the operator what to turn on")
	}
}

// Events on but neither login type recorded is the subtler version of the
// same problem, and it looks fine from the events-config page.
func TestEventStorageWithoutTheLoginTypesIsNotActivity(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{
		"acme": {EventsEnabled: true, EnabledEventTypes: []string{"REGISTER"}},
	}}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if got.ActivityAvailable {
		t.Error("a realm recording no login events was reported as answerable")
	}
}

// Failing to read one realm's events config must not make the realm look
// unreachable: the identities in it can still be collected.
func TestAnEventsConfigFailureLeavesTheRealmReachable(t *testing.T) {
	src := probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		errs:    map[string]error{"acme": refused()},
	}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if !got.Reachable {
		t.Error("a realm became unreachable because its events config could not be read")
	}
	if got.ActivityAvailable {
		t.Error("activity was claimed without being checked")
	}
	if got.ActivityNote == "" {
		t.Error("the operator is not told why activity is unknown")
	}
}

// A realm somebody named and the credentials cannot see is the most useful
// thing this call can report.
func TestARealmThatWasAskedForAndIsNotThereIsReported(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}}}
	probes := collect.Probes(context.Background(), src, realms("acme"),
		map[string]bool{"acme": true, "ghost": true})
	got := probeFor(t, probes, "ghost")
	if got.Reachable || got.Err == nil {
		t.Error("a realm the credentials cannot see was reported as fine")
	}
}

func TestARealmNobodyAskedForIsNotProbed(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{
		"acme": {EventsEnabled: true}, "other": {EventsEnabled: true},
	}}
	probes := collect.Probes(context.Background(), src, realms("acme", "other"),
		map[string]bool{"acme": true})
	if len(probes) != 1 || probes[0].Realm != "acme" {
		t.Errorf("probes = %v, want only acme", probes)
	}
}

// A pre-flight check people read is a list, and a list in a different order
// every time is one somebody has to re-read from the top.
func TestProbesComeBackInAStableOrder(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{}}
	wanted := map[string]bool{}
	for _, name := range []string{"delta", "alpha", "charlie", "bravo", "echo"} {
		wanted[name] = true
	}
	var first []string
	for range 20 {
		var got []string
		for _, p := range collect.Probes(context.Background(), src, nil, wanted) {
			got = append(got, p.Realm)
		}
		if first == nil {
			first = got
			continue
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("order is not stable: %v then %v", first, got)
			}
		}
	}
	if first[0] != "alpha" {
		t.Errorf("order = %v, want alphabetical", first)
	}
}

// A permission failure reading the events config is not the realm saying it
// records nothing. Reported as such, an operator goes looking for a setting
// that may already be on.
func TestAnUnreadableEventsConfigIsUndeterminedNotUnavailable(t *testing.T) {
	src := probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		errs:    map[string]error{"acme": refused()},
	}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if !got.ActivityUndetermined {
		t.Error("a failed read was reported as a definite answer")
	}
	if got.ActivityAvailable {
		t.Error("activity was claimed without being checked")
	}
}

func TestARealmThatSaysItRecordsNothingIsADefiniteAnswer(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: false}}}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if got.ActivityUndetermined {
		t.Error("the realm answered; that is not a failure to find out")
	}
}

// A pre-flight check exists to stop somebody waiting on a collection that was
// never going to work. Reading the event configuration proves one permission
// out of five, so a token missing any of the other four passed the check and
// then failed halfway through — which is the thing the check is for.
func TestAProbeChecksEveryPermissionTheCollectionNeeds(t *testing.T) {
	for _, c := range []struct {
		name string
		deny string
		role string
	}{
		{"listing users", "users", "view-users"},
		{"listing clients", "clients", "view-clients"},
		// Being refused the role listing means no composite can be tried,
		// and view-realm is what resolving one needs. The listing itself is
		// not gated by view-realm — measured against Keycloak 26.4.7, nine
		// of the nineteen realm-management roles answer it.
		{"listing realm roles", "roles", "view-realm"},
		// Listing groups is answered by query-groups too; everything the
		// collection then does with a group — members, subgroups, roles —
		// needs view-users. Measured, not inferred.
		{"listing groups", "groups", "view-users"},
	} {
		src := probeSource{
			configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
			denied:  map[string]error{c.deny: refused()},
		}
		got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")

		if got.Reachable {
			t.Errorf("%s: a realm this token cannot collect was reported reachable", c.name)
		}
		if got.Err == nil {
			t.Fatalf("%s: nothing said why", c.name)
		}
		// The role is what an operator grants. The endpoint is what they
		// would have to look up first.
		if !strings.Contains(got.Err.Error(), c.role) {
			t.Errorf("%s: the error does not name the role to grant (%s): %v",
				c.name, c.role, got.Err)
		}
	}
}

// A token that can do everything passes, and says nothing extra.
func TestAProbeWithEveryPermissionIsClean(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{
		"acme": {EventsEnabled: true, EnabledEventTypes: []string{"LOGIN", "CLIENT_LOGIN"}},
	}}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if !got.Reachable || got.Err != nil {
		t.Errorf("probe = %+v", got)
	}
	if !got.ActivityAvailable {
		t.Error("a realm recording logins should be able to answer about activity")
	}
}

// Missing the events role is not the same as being unable to collect: the
// identities and their access are still readable, and only the activity
// answer is withheld.
func TestMissingOnlyTheEventsRoleLeavesTheRealmCollectable(t *testing.T) {
	src := probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		errs:    map[string]error{"acme": refused()},
	}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if !got.Reachable {
		t.Error("a realm whose events are unreadable is still collectable")
	}
	if !got.ActivityUndetermined {
		t.Error("the activity answer should be withheld rather than denied")
	}
}

// Listing roles and resolving a composite are different permissions, and it
// is the second that needs view-realm. Verified against a real Keycloak:
// every listing succeeded without it and the composite walk returned 403 in
// the middle of a collection, which is exactly the failure a pre-flight
// check exists to move forward.
func TestAProbeChecksResolvingACompositeNotJustListingRoles(t *testing.T) {
	src := probeSource{
		configs:   map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		realmRole: admin.Role{ID: "r-1", Name: "admin", Composite: true},
		denied:    map[string]error{"composites": refused()},
	}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")

	if got.Reachable {
		t.Error("a token that cannot resolve composites was reported able to collect")
	}
	if got.Err == nil || !strings.Contains(got.Err.Error(), "view-realm") {
		t.Errorf("the error does not name view-realm: %v", got.Err)
	}
}

// A role named once, however many reads it gates. The operator grants roles.
func TestEachMissingRoleIsNamedOnce(t *testing.T) {
	src := probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		denied: map[string]error{
			"users":  refused(),
			"groups": refused(),
		},
	}
	got := probeFor(t, collect.Probes(context.Background(), src, realms("acme"), nil), "acme")
	if got.Err == nil {
		t.Fatal("want an error")
	}
	if n := strings.Count(got.Err.Error(), "view-users"); n != 1 {
		t.Errorf("view-users named %d times, want once: %v", n, got.Err)
	}
}

// recorder answers every read with one item, and remembers which reads were
// made. One item is what makes the probe's per-item reads fire at all.
type recorder struct {
	made map[string]bool
	// eventsConfig is what this realm says it records. newRecorder sets a
	// realm that records logins, because most of these tests are about the
	// reads and not about activity.
	eventsConfig admin.EventsConfig
}

func newRecorder() *recorder {
	return &recorder{
		made:         map[string]bool{},
		eventsConfig: admin.EventsConfig{EventsEnabled: true, EnabledEventTypes: []string{"LOGIN"}},
	}
}

func (r *recorder) note(name string) { r.made[name] = true }

func (r *recorder) Users(context.Context, string) ([]admin.User, error) {
	r.note("Users")
	return []admin.User{{ID: "u1", Username: "alice"}}, nil
}

func (r *recorder) ServiceAccountUser(context.Context, string, string) (*admin.User, error) {
	r.note("ServiceAccountUser")
	return &admin.User{ID: "sa1"}, nil
}

func (r *recorder) TopLevelGroups(context.Context, string) ([]admin.Group, error) {
	r.note("TopLevelGroups")
	return []admin.Group{{ID: "g1", Name: "Platform"}}, nil
}

func (r *recorder) Subgroups(context.Context, string, string) ([]admin.Group, error) {
	r.note("Subgroups")
	return nil, nil
}

func (r *recorder) GroupMembers(context.Context, string, string) ([]admin.User, error) {
	r.note("GroupMembers")
	return nil, nil
}

func (r *recorder) GroupRoleMappings(context.Context, string, string) (admin.MappingsRepresentation, error) {
	r.note("GroupRoleMappings")
	return admin.MappingsRepresentation{}, nil
}

func (r *recorder) RealmRoles(context.Context, string) ([]admin.Role, error) {
	r.note("RealmRoles")
	return []admin.Role{{ID: "r1", Name: "platform-admin"}}, nil
}

func (r *recorder) Clients(context.Context, string) ([]admin.ClientApp, error) {
	r.note("Clients")
	return []admin.ClientApp{{ID: "c1", ClientID: "acciew", ServiceAccountsEnabled: true}}, nil
}

func (r *recorder) ClientRoles(context.Context, string, string) ([]admin.Role, error) {
	r.note("ClientRoles")
	return nil, nil
}

func (r *recorder) RoleComposites(context.Context, string, string) ([]admin.Role, error) {
	r.note("RoleComposites")
	return nil, nil
}

func (r *recorder) UserRoleMappings(context.Context, string, string) (admin.MappingsRepresentation, error) {
	r.note("UserRoleMappings")
	return admin.MappingsRepresentation{}, nil
}

func (r *recorder) GrantedRoles(string) (map[string]bool, bool) {
	r.note("GrantedRoles")
	return map[string]bool{"view-users": true, "view-clients": true, "view-realm": true}, true
}

func (r *recorder) ManagementClient(string) string { return "realm-management" }

func (r *recorder) EventsConfig(context.Context, string) (admin.EventsConfig, error) {
	r.note("EventsConfig")
	return r.eventsConfig, nil
}

func (r *recorder) Events(context.Context, string, []string, int) ([]admin.Event, error) {
	r.note("Events")
	return nil, nil
}

// The bug this guards against is the one the first version of this probe had:
// a read the collection performs that the probe does not, so `check` passes
// and the collection then fails on a permission. Reflection over the Source
// interface means adding a method to it fails here until the probe is taught
// about it or the exemption is written down.
func TestTheProbePerformsEveryReadTheCollectionCan(t *testing.T) {
	// No exemptions. The probe once answered activity from the event
	// configuration alone and left the log unread, which made it call a realm
	// reachable that the collection then failed on — so it reads one event
	// too. Anything added to Source and not read here is that bug again.
	exempt := map[string]string{}

	r := newRecorder()
	collect.Probes(t.Context(), r, realms("acme"), nil)

	iface := reflect.TypeOf((*collect.Source)(nil)).Elem()
	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		if why, ok := exempt[name]; ok {
			if r.made[name] {
				t.Fatalf("%s is exempt (%s) but the probe called it; drop the exemption", name, why)
			}
			continue
		}
		if !r.made[name] {
			t.Errorf("the collection can call Source.%s and the probe never does, so a token "+
				"denied it passes `check` and fails the collection", name)
		}
	}
}

// Every one of those reads must also be able to fail the check. A probe that
// makes a call and ignores its error is the same bug wearing a disguise.
func TestEveryProbedReadCanFailTheCheck(t *testing.T) {
	iface := reflect.TypeOf((*collect.Source)(nil)).Elem()
	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		if name == "Events" || name == "EventsConfig" {
			continue // not reachability; see the activity tests below
		}
		t.Run(name, func(t *testing.T) {
			p := probeFor(t, collect.Probes(t.Context(), &denyingOne{recorder: newRecorder(), at: name},
				realms("acme"), nil), "acme")
			if p.Reachable {
				t.Fatalf("Source.%s was refused and the realm still reported reachable", name)
			}
		})
	}
}

// denyingOne answers everything except one read, which it denies.
type denyingOne struct {
	*recorder
	at string
}

func (f *denyingOne) deny(name string) error {
	if f.at == name {
		return refused()
	}
	return nil
}

func (f *denyingOne) Users(ctx context.Context, realm string) ([]admin.User, error) {
	if err := f.deny("Users"); err != nil {
		return nil, err
	}
	return f.recorder.Users(ctx, realm)
}

func (f *denyingOne) ServiceAccountUser(ctx context.Context, realm, uuid string) (*admin.User, error) {
	if err := f.deny("ServiceAccountUser"); err != nil {
		return nil, err
	}
	return f.recorder.ServiceAccountUser(ctx, realm, uuid)
}

func (f *denyingOne) TopLevelGroups(ctx context.Context, realm string) ([]admin.Group, error) {
	if err := f.deny("TopLevelGroups"); err != nil {
		return nil, err
	}
	return f.recorder.TopLevelGroups(ctx, realm)
}

func (f *denyingOne) Subgroups(ctx context.Context, realm, id string) ([]admin.Group, error) {
	if err := f.deny("Subgroups"); err != nil {
		return nil, err
	}
	return f.recorder.Subgroups(ctx, realm, id)
}

func (f *denyingOne) GroupMembers(ctx context.Context, realm, id string) ([]admin.User, error) {
	if err := f.deny("GroupMembers"); err != nil {
		return nil, err
	}
	return f.recorder.GroupMembers(ctx, realm, id)
}

func (f *denyingOne) GroupRoleMappings(ctx context.Context, realm, id string) (admin.MappingsRepresentation, error) {
	if err := f.deny("GroupRoleMappings"); err != nil {
		return admin.MappingsRepresentation{}, err
	}
	return f.recorder.GroupRoleMappings(ctx, realm, id)
}

func (f *denyingOne) RealmRoles(ctx context.Context, realm string) ([]admin.Role, error) {
	if err := f.deny("RealmRoles"); err != nil {
		return nil, err
	}
	return f.recorder.RealmRoles(ctx, realm)
}

func (f *denyingOne) Clients(ctx context.Context, realm string) ([]admin.ClientApp, error) {
	if err := f.deny("Clients"); err != nil {
		return nil, err
	}
	return f.recorder.Clients(ctx, realm)
}

func (f *denyingOne) ClientRoles(ctx context.Context, realm, uuid string) ([]admin.Role, error) {
	if err := f.deny("ClientRoles"); err != nil {
		return nil, err
	}
	return f.recorder.ClientRoles(ctx, realm, uuid)
}

func (f *denyingOne) RoleComposites(ctx context.Context, realm, id string) ([]admin.Role, error) {
	if err := f.deny("RoleComposites"); err != nil {
		return nil, err
	}
	return f.recorder.RoleComposites(ctx, realm, id)
}

func (f *denyingOne) UserRoleMappings(ctx context.Context, realm, id string) (admin.MappingsRepresentation, error) {
	if err := f.deny("UserRoleMappings"); err != nil {
		return admin.MappingsRepresentation{}, err
	}
	return f.recorder.UserRoleMappings(ctx, realm, id)
}

// The trap the integration test pins against a real Keycloak, kept here so it
// is checked without one: an empty answer is not an empty realm.
func TestAnEmptyRealmIsNotBelievedOnItsOwn(t *testing.T) {
	for _, c := range []struct {
		name      string
		grant     map[string]bool
		reachable bool
	}{
		{"the token holds view-users, so empty means empty",
			map[string]bool{"view-users": true, "view-clients": true, "view-realm": true}, true},
		{"the token does not hold view-users, so empty means blind",
			map[string]bool{"view-clients": true, "view-realm": true, "query-users": true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := probeSource{
				configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
				grant:   c.grant,
			}
			got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
			if got.Reachable != c.reachable {
				t.Fatalf("reachable = %v, want %v: %v", got.Reachable, c.reachable, got.Err)
			}
		})
	}
}

// And when nothing can say what the token holds, the probe says that rather
// than choosing an answer — including when the realm answered with people in
// it, because a narrowed answer looks exactly like a small realm.
func TestAnUncorroboratedRealmSaysSo(t *testing.T) {
	src := unknownGrant{probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		users:   []admin.User{{ID: "u1", Username: "alice"}},
	}}
	got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
	if got.Reachable {
		t.Fatal("a realm nothing could corroborate was reported reachable")
	}
	if !strings.Contains(got.Err.Error(), "or only some") {
		t.Errorf("the error does not say what could not be told apart: %v", got.Err)
	}
}

type unknownGrant struct{ probeSource }

func (unknownGrant) GrantedRoles(string) (map[string]bool, bool) { return nil, false }

// The empty answer is not the only shape this takes. Keycloak's fine-grained
// admin permissions return a genuine subset of the users, which looks like a
// realm that small. A token without view-users cannot be believed about the
// size of a population whatever it returns.
func TestASubsetIsNotBelievedEither(t *testing.T) {
	src := probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		grant:   map[string]bool{"view-clients": true, "view-realm": true, "query-users": true},
		users:   []admin.User{{ID: "u1", Username: "alice"}},
	}
	got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
	if got.Reachable {
		t.Fatal("a token that cannot see the whole population reported the realm reachable; " +
			"the subset it returns is then reported as the realm")
	}
	if !strings.Contains(got.Err.Error(), "view-users") {
		t.Errorf("the error does not name the role: %v", got.Err)
	}
}

// Keycloak's own check for reading users is view-users OR manage-users, so a
// token holding the second sees the whole realm. Refusing it is the same
// mistake as trusting a narrower one, in the other direction: the check and
// the collection would disagree about credentials that work.
func TestManageUsersIsAsGoodAsViewUsers(t *testing.T) {
	src := probeSource{
		configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
		grant: map[string]bool{
			"manage-users": true, "view-clients": true, "view-realm": true,
		},
		users: []admin.User{{ID: "u1", Username: "alice"}},
	}
	got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
	if !got.Reachable {
		t.Fatalf("a token that can read every user was refused: %v", got.Err)
	}
}

// A 503 from the event configuration is not an answer about activity, and the
// collection fails the realm on it. The check has to say the same thing, or
// the two disagree about the same realm at the same moment.
func TestARetryableFailureIsNotAnActivityAnswer(t *testing.T) {
	src := probeSource{
		errs: map[string]error{"acme": &admin.Error{
			Kind: admin.KindUnavailable, Retryable: true, Status: 503,
			Message: "Keycloak is unwell",
		}},
	}
	got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
	if got.Reachable {
		t.Fatal("a realm the collection will fail was reported reachable")
	}
	if got.ActivityUndetermined {
		t.Error("a realm that could not be read has no activity answer to be undetermined about")
	}
}

// Only a refusal is evidence about the grant. A blip, a wrong URL, a rotated
// secret — telling an operator to add roles for any of those sends them to
// change a permission that was never the problem, and is the check claiming
// to have found something out that it did not.
func TestOnlyARefusalIsReportedAsAMissingRole(t *testing.T) {
	for _, e := range []struct {
		name string
		err  error
	}{
		{"an unwell Keycloak", &admin.Error{
			Kind: admin.KindUnavailable, Retryable: true, Status: 503, Message: "unwell"}},
		{"a rate limit", &admin.Error{
			Kind: admin.KindRateLimited, Retryable: true, Status: 429, Message: "slow down"}},
		{"a wrong path", &admin.Error{Kind: admin.KindSource, Status: 404, Message: "not found"}},
		{"a rotated secret", &admin.Error{
			Kind: admin.KindAuth, Status: 401, Message: "credentials rejected"}},
	} {
		for _, at := range []string{"users", "clients", "groups", "roles"} {
			t.Run(e.name+" on "+at, func(t *testing.T) {
				src := probeSource{
					configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
					denied:  map[string]error{at: e.err},
				}
				got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
				if got.Reachable {
					t.Fatal("a realm that could not be read was reported reachable")
				}
				if strings.Contains(got.Err.Error(), "Grant") {
					t.Errorf("reported as something to grant: %v", got.Err)
				}
				if !strings.Contains(got.Err.Error(), "could not be read") {
					t.Errorf("the message does not say the realm could not be read: %v", got.Err)
				}
			})
		}
	}
}

// The same trap as the users one, on the other half of the realm. A token
// with query-clients sees an empty client list rather than a refusal, and a
// realm collected without its clients loses its client roles and every
// service account in it while reporting itself complete.
func TestAnEmptyClientListIsNotBelievedEither(t *testing.T) {
	for _, c := range []struct {
		name      string
		grant     map[string]bool
		reachable bool
	}{
		{"view-clients", map[string]bool{
			"view-users": true, "view-clients": true, "view-realm": true}, true},
		{"manage-clients", map[string]bool{
			"view-users": true, "manage-clients": true, "view-realm": true}, true},
		{"query-clients only", map[string]bool{
			"view-users": true, "query-clients": true, "view-realm": true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := probeSource{
				configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}},
				grant:   c.grant,
				users:   []admin.User{{ID: "u1", Username: "alice"}},
			}
			got := probeFor(t, collect.Probes(t.Context(), src, realms("acme"), nil), "acme")
			if got.Reachable != c.reachable {
				t.Fatalf("reachable = %v, want %v: %v", got.Reachable, c.reachable, got.Err)
			}
		})
	}
}

// And the check says the same thing about it as the collection does. The two
// disagreeing about the same realm at the same moment is the failure this
// branch has spent seven review rounds removing.
func TestTheCheckRefusesARealmThatDidNotSayWhetherItIsEnabled(t *testing.T) {
	src := probeSource{configs: map[string]admin.EventsConfig{"acme": {EventsEnabled: true}}}
	got := probeFor(t, collect.Probes(t.Context(), src,
		[]admin.Realm{{Realm: "acme"}}, nil), "acme")
	if got.Reachable {
		t.Fatal("a realm whose own record could not be read was reported reachable, " +
			"and the collection refuses it")
	}
	if !strings.Contains(got.Err.Error(), "view-realm") {
		t.Errorf("the error does not name the role that would fix it: %v", got.Err)
	}
}

// The check reads the event log exactly when the collection would, and never
// otherwise. Reading it when the collection would not is the same
// disagreement in reverse: a check that fails on a realm the collection would
// have collected.
func TestTheCheckReadsTheEventLogExactlyWhenTheCollectionWould(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  admin.EventsConfig
		read bool
	}{
		{"storage off", admin.EventsConfig{EventsEnabled: false}, false},
		{"storage on, no login types", admin.EventsConfig{
			EventsEnabled: true, EnabledEventTypes: []string{"UPDATE_PASSWORD"}}, false},
		{"storage on, LOGIN recorded", admin.EventsConfig{
			EventsEnabled: true, EnabledEventTypes: []string{"LOGIN"}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRecorder()
			r.eventsConfig = c.cfg
			collect.Probes(t.Context(), r, realms("acme"), nil)
			if r.made["Events"] != c.read {
				t.Errorf("read the log = %v, want %v", r.made["Events"], c.read)
			}
		})
	}
}
