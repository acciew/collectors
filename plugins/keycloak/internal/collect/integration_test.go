package collect_test

import (
	"context"
	"testing"
	"time"

	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/collect"
	"go.acciew.io/collector/plugins/keycloak/internal/kctest"
)

// The resolution this collector performs is the part a fake cannot check.
// A fake answers with whatever the fixture says, so a bug in what we ask
// Keycloak for — a whole class of role never walked, say — looks identical to
// correct behaviour. Keycloak resolves the same graph itself, and comparing
// our answer with its answer is the only test that can tell those apart.
func TestOurAnswerMatchesKeycloaksOwn(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a container")
	}
	base := kctest.Start(t)
	ctx := context.Background()
	fx := kctest.SeedProbeRealm(t, base)

	client, err := admin.Dial(ctx, admin.Config{
		BaseURL: base, AuthRealm: "probe", ClientID: "acciew", ClientSecret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	realms, err := client.Realms(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var probe admin.Realm
	for _, r := range realms {
		if r.Realm == "probe" {
			probe = r
		}
	}
	if probe.Realm == "" {
		t.Fatal("the seeded realm is not visible to the collector's credentials")
	}

	out := &capture{t: t}
	if _, err := collect.Realm(ctx, client, probe, time.Now().UTC(), out); err != nil {
		t.Fatalf("Realm: %v", err)
	}

	// Keycloak's composite endpoint returns the realm roles it considers a
	// user to hold, with composites and group inheritance applied. Our
	// derived realm-role grants have to be exactly that set: anything extra
	// is a grant we invented, anything missing is access a reviewer will
	// never see.
	for _, u := range []struct{ name, id string }{{"alice", fx.AliceID}, {"carol", fx.CarolID}} {
		theirs, err := client.EffectiveRealmRoles(ctx, "probe", u.id)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{}
		for _, r := range theirs {
			want[r.ID] = true
		}
		got := out.holdsFrom(u.id)

		for id := range want {
			if !got[id] {
				t.Errorf("%s: Keycloak says they hold realm role %s and we did not derive it",
					u.name, roleName(theirs, id))
			}
		}
		// The reverse direction is checked only for realm roles, because the
		// endpoint answers about those alone; a client role we derived is
		// not evidence of a mistake here.
		realmRoles, err := client.RealmRoles(ctx, "probe")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range realmRoles {
			if got[r.ID] && !want[r.ID] {
				t.Errorf("%s: we derived realm role %q and Keycloak does not agree", u.name, r.Name)
			}
		}
	}

	// Two assumptions the unit tests encode and only a real Keycloak can
	// confirm. If a future release makes the realm listing brief, or starts
	// populating the service-account field, the fixtures would keep passing
	// while the collector quietly stopped tagging default roles or started
	// reading a field it should not.
	if probe.DefaultRole == nil || probe.DefaultRole.ID == "" {
		t.Error("GET /admin/realms no longer carries defaultRole; the default role " +
			"is identified by that id and would silently stop being tagged")
	}
	if sa, err := client.ServiceAccountUser(ctx, "probe", fx.SvcClientUUID); err != nil {
		t.Fatal(err)
	} else if sa.ServiceAccountClientID != "" {
		t.Errorf("serviceAccountClientId is now populated (%q); the collector fills that "+
			"context itself because Keycloak answered null", sa.ServiceAccountClientID)
	}

	// The specific shape that walking only realm composites missed: every
	// realm Keycloak creates has default-roles-<realm> including the account
	// client's manage-account, which is itself a composite client role.
	held := out.holdsFrom(fx.AliceID)
	nodes := out.nodes()
	if got := nodes["probe"].GetContext()["enabled"]; got != "true" {
		t.Errorf("the realm's enabled state = %q, want true", got)
	}
	var haveManageAccount, haveLinks bool
	for id := range held {
		switch nodes[id].GetName() {
		case "manage-account":
			haveManageAccount = true
		case "manage-account-links":
			haveLinks = true
		}
	}
	if !haveManageAccount {
		t.Fatal("alice does not hold account/manage-account, which every Keycloak account carries")
	}
	if !haveLinks {
		t.Error("a composite client role was emitted without walking what it contains")
	}
}

func roleName(roles []admin.Role, id string) string {
	for _, r := range roles {
		if r.ID == id {
			return r.Name
		}
	}
	return id
}

// What a differently granted token actually sees.
//
// Every claim the probe makes about roles is a claim about Keycloak, and a
// fake keyed on the same table the probe uses cannot check any of them. These
// grant real roles to a real service account and ask.
func TestWhatTheProbeSeesThroughDifferentGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a container")
	}
	base := kctest.Start(t)
	ctx := context.Background()
	kctest.SeedProbeRealm(t, base)

	dial := func(t *testing.T) *admin.Client {
		t.Helper()
		// A fresh client each time: the old one holds a token minted under
		// the old grant.
		c, err := admin.Dial(ctx, admin.Config{
			BaseURL: base, AuthRealm: "probe", ClientID: "acciew", ClientSecret: "s3cr3t",
		})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		return c
	}
	probeOf := func(t *testing.T, c *admin.Client) collect.Probe {
		t.Helper()
		realms, err := c.Realms(ctx)
		if err != nil {
			t.Fatalf("Realms: %v", err)
		}
		ps := collect.Probes(ctx, c, realms, map[string]bool{"probe": true})
		if len(ps) != 1 {
			t.Fatalf("want one probe, got %d", len(ps))
		}
		return ps[0]
	}

	// The dangerous grant. Keycloak answers /users and /groups with 200 and
	// an empty list for a token holding query-users but not view-users, which
	// is indistinguishable from a realm with nobody in it. A check that says
	// "reachable" here produces an empty population that reads as whole.
	t.Run("query roles in place of view-users do not pass the check", func(t *testing.T) {
		// Everything else granted, so nothing but the empty answer is left to
		// catch it. Dropping view-clients as well would make the check fail
		// for a different reason and prove nothing about this one.
		kctest.Regrant(t, base, "view-clients", "view-realm", "view-events",
			"query-users", "query-groups")
		t.Cleanup(func() {
			kctest.Regrant(t, base, "view-users", "view-clients", "view-realm", "view-events")
		})

		c := dial(t)
		users, err := c.Users(ctx, "probe")
		if err != nil {
			t.Fatalf("Users: %v", err)
		}
		if len(users) != 0 {
			t.Fatalf("this test is about the empty answer Keycloak gives here; it returned %d "+
				"users, so the trap it guards has moved", len(users))
		}
		if p := probeOf(t, c); p.Reachable {
			t.Fatal("a token that can see no users and no groups reported the realm reachable; " +
				"the collection it green-lights returns an empty population and calls it complete")
		}
	})

	// The same trap on the other half of the realm. Without view-clients the
	// client list comes back empty rather than refused, and a realm collected
	// without its clients loses every client role and every service account
	// in it — a third of this one's entitlements — while calling itself
	// complete.
	t.Run("query-clients in place of view-clients does not pass the check", func(t *testing.T) {
		kctest.Regrant(t, base, "view-users", "view-realm", "view-events", "query-clients")
		t.Cleanup(func() {
			kctest.Regrant(t, base, "view-users", "view-clients", "view-realm", "view-events")
		})

		c := dial(t)
		clients, err := c.Clients(ctx, "probe")
		if err != nil {
			t.Fatalf("Clients: %v", err)
		}
		if len(clients) != 0 {
			t.Fatalf("this test is about the empty answer Keycloak gives here; it returned %d "+
				"clients, so the trap it guards has moved", len(clients))
		}
		if p := probeOf(t, c); p.Reachable {
			t.Fatal("a token that can see no clients reported the realm reachable; the " +
				"collection it green-lights drops every client role and service account " +
				"and calls itself complete")
		}
	})

	// The other direction. Withholding view-events must not cost the
	// population: the identities are all still readable, and only the
	// activity answer is unavailable.
	t.Run("without view-events the realm still collects", func(t *testing.T) {
		kctest.Regrant(t, base, "view-users", "view-clients", "view-realm")
		t.Cleanup(func() {
			kctest.Regrant(t, base, "view-users", "view-clients", "view-realm", "view-events")
		})

		c := dial(t)
		p := probeOf(t, c)
		if !p.Reachable {
			t.Fatalf("view-events is not needed to read identities, but the check refused: %v", p.Err)
		}
		if p.ActivityAvailable || !p.ActivityUndetermined {
			t.Fatalf("want activity undetermined, got available=%v undetermined=%v",
				p.ActivityAvailable, p.ActivityUndetermined)
		}

		// And the collection has to agree with the check. Them disagreeing is
		// the whole failure this guards: reachable, then a partial scope.
		realms, err := c.Realms(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var probe admin.Realm
		for _, r := range realms {
			if r.Realm == "probe" {
				probe = r
			}
		}
		out := &capture{t: t}
		available, err := collect.Realm(ctx, c, probe, time.Now().UTC(), out)
		if err != nil {
			t.Fatalf("the check said reachable and the collection failed: %v", err)
		}
		if available != collect.ActivityUndetermined {
			t.Fatalf("answer = %v for a token that cannot read the event log; want undetermined, "+
				"because the realm may record activity and we were refused the answer", available)
		}
	})
}
