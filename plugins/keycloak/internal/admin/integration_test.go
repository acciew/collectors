package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.acciew.io/collector/plugins/keycloak/internal/admin"
	"go.acciew.io/collector/plugins/keycloak/internal/kctest"
)

// These run against a real Keycloak. They exist because the collector's
// assumptions are the kind a minor version can quietly invalidate, and a fake
// cannot notice when one stops being true.
//
// Each assertion below is one of the claims in
// docs/design/three-source-mapping.md that was marked verified. This is what
// keeps that document honest as Keycloak moves.
func TestAgainstARealKeycloak(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a container")
	}
	base := kctest.Start(t)
	ctx := context.Background()
	fx := kctest.SeedProbeRealm(t, base)

	c, err := admin.Dial(ctx, admin.Config{
		BaseURL: base, AuthRealm: "probe",
		ClientID: "acciew", ClientSecret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Dial against a real Keycloak: %v", err)
	}

	t.Run("users omits service accounts", func(t *testing.T) {
		users, err := c.Users(ctx, "probe")
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range users {
			if strings.HasPrefix(u.Username, "service-account-") {
				t.Errorf("GET /users returned %q; the collector relies on it not doing so", u.Username)
			}
		}
		if !hasUser(users, "alice") {
			t.Errorf("alice missing from %d users", len(users))
		}
	})

	t.Run("a service account is reached through its client", func(t *testing.T) {
		u, err := c.ServiceAccountUser(ctx, "probe", fx.SvcClientUUID)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(u.Username, "service-account-") {
			t.Errorf("username = %q", u.Username)
		}
	})

	t.Run("the group tree is not inline", func(t *testing.T) {
		top, err := c.TopLevelGroups(ctx, "probe")
		if err != nil {
			t.Fatal(err)
		}
		var parent *admin.Group
		for i := range top {
			if top[i].Name == "G" {
				parent = &top[i]
			}
		}
		if parent == nil {
			t.Fatalf("group G missing from %+v", top)
		}
		if len(parent.SubGroups) != 0 {
			t.Errorf("SubGroups came back populated with %d; the collector walks children instead",
				len(parent.SubGroups))
		}
		if parent.SubGroupCount != 1 {
			t.Errorf("SubGroupCount = %d, want 1", parent.SubGroupCount)
		}
		children, err := c.Subgroups(ctx, "probe", parent.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(children) != 1 || children[0].Name != "S" {
			t.Errorf("children = %+v", children)
		}
	})

	t.Run("group membership is direct only", func(t *testing.T) {
		top, _ := c.TopLevelGroups(ctx, "probe")
		var parentID, childID string
		for _, g := range top {
			if g.Name == "G" {
				parentID = g.ID
			}
		}
		children, _ := c.Subgroups(ctx, "probe", parentID)
		if len(children) > 0 {
			childID = children[0].ID
		}

		parentMembers, err := c.GroupMembers(ctx, "probe", parentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(parentMembers) != 0 {
			t.Errorf("the parent group reported %d members; membership is supposed to be direct only",
				len(parentMembers))
		}
		childMembers, err := c.GroupMembers(ctx, "probe", childID)
		if err != nil {
			t.Fatal(err)
		}
		if !hasUser(childMembers, "alice") {
			t.Errorf("the subgroup should have alice, got %+v", childMembers)
		}
	})

	t.Run("direct role mappings carry client roles too", func(t *testing.T) {
		m, err := c.UserRoleMappings(ctx, "probe", fx.CarolID)
		if err != nil {
			t.Fatal(err)
		}
		app, ok := m.ClientMappings["app"]
		if !ok {
			t.Fatalf("clientMappings has no entry for app: %+v", m.ClientMappings)
		}
		if len(app.Mappings) == 0 || app.Mappings[0].Name != "app-writer" {
			t.Errorf("app mappings = %+v", app.Mappings)
		}
	})

	t.Run("the composite endpoint resolves composites and group ancestry", func(t *testing.T) {
		roles, err := c.EffectiveRealmRoles(ctx, "probe", fx.AliceID)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, r := range roles {
			names[r.Name] = true
		}
		// r-parent is mapped directly and contains r-child; r-group is mapped
		// on the PARENT group while alice is only in the subgroup. All three
		// come back from one call.
		for _, want := range []string{"r-parent", "r-child", "r-group"} {
			if !names[want] {
				t.Errorf("effective roles missing %q: %v", want, keys(names))
			}
		}
		// And the realm default composite is in there, which is why it needs
		// tagging rather than showing up as a grant nobody made.
		if !names["default-roles-probe"] {
			t.Errorf("expected the realm default role: %v", keys(names))
		}
	})

	t.Run("events are off by default and record nothing", func(t *testing.T) {
		cfg, err := c.EventsConfig(ctx, "probe")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.EventsEnabled {
			t.Error("event storage should be off in a fresh realm; the collector must not assume it is on")
		}
		events, err := c.Events(ctx, "probe", []string{"LOGIN"}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 0 {
			t.Errorf("a realm with storage off reported %d events", len(events))
		}
	})
}

func hasUser(users []admin.User, name string) bool {
	for _, u := range users {
		if u.Username == name {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- fixture ---------------------------------------------------------------

// The collector only treats a 403 as a missing role when the response looks
// like Keycloak's, so that a proxy or a login page in front of it is not
// mistaken for one. That guard is only safe if every real refusal does look
// like Keycloak's — if any of them did not, the guard would turn a genuine
// missing role into "something else refused this", which is worse than the
// bug it prevents.
func TestEveryRealRefusalIsRecognisedAsOne(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a container")
	}
	base := kctest.Start(t)
	ctx := context.Background()
	fx := kctest.SeedProbeRealm(t, base)

	dial := func() *admin.Client {
		t.Helper()
		c, err := admin.Dial(ctx, admin.Config{
			BaseURL: base, AuthRealm: "probe", ClientID: "acciew", ClientSecret: "s3cr3t",
		})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		return c
	}

	// Real ids, read while the grant still allows it. A made-up id answers
	// 404 before the permission is checked, and a read that 404s says
	// nothing about how a refusal is classified.
	full := dial()
	roles, err := full.RealmRoles(ctx, "probe")
	if err != nil || len(roles) == 0 {
		t.Fatalf("RealmRoles: %v", err)
	}
	groups, err := full.TopLevelGroups(ctx, "probe")
	if err != nil || len(groups) == 0 {
		t.Fatalf("TopLevelGroups: %v", err)
	}
	aRole, aGroup := roles[0].ID, groups[0].ID

	// One role, so that every read the collection makes is refused.
	kctest.Regrant(t, base, "view-events")
	t.Cleanup(func() {
		kctest.Regrant(t, base, "view-users", "view-clients", "view-realm", "view-events")
	})
	client := dial()
	for name, read := range map[string]func() error{
		"users":              func() error { _, err := client.Users(ctx, "probe"); return err },
		"clients":            func() error { _, err := client.Clients(ctx, "probe"); return err },
		"groups":             func() error { _, err := client.TopLevelGroups(ctx, "probe"); return err },
		"realm roles":        func() error { _, err := client.RealmRoles(ctx, "probe"); return err },
		"composites":         func() error { _, err := client.RoleComposites(ctx, "probe", aRole); return err },
		"user role mappings": func() error { _, err := client.UserRoleMappings(ctx, "probe", fx.AliceID); return err },
		"group members":      func() error { _, err := client.GroupMembers(ctx, "probe", aGroup); return err },
		"group role mappings": func() error {
			_, err := client.GroupRoleMappings(ctx, "probe", aGroup)
			return err
		},
		"subgroups":       func() error { _, err := client.Subgroups(ctx, "probe", aGroup); return err },
		"client roles":    func() error { _, err := client.ClientRoles(ctx, "probe", fx.SvcClientUUID); return err },
		"service account": func() error { _, err := client.ServiceAccountUser(ctx, "probe", fx.SvcClientUUID); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := read()
			var ae *admin.Error
			if !errors.As(err, &ae) {
				t.Fatalf("want an admin.Error, got %v", err)
			}
			if ae.Status != 403 {
				t.Fatalf("this read answered %d rather than refusing, so the case it was "+
					"written for has moved", ae.Status)
			}
			if ae.Kind != admin.KindPermission {
				t.Errorf("a real Keycloak refusal was classified %v, so the operator is not "+
					"told which role to grant: %v", ae.Kind, ae)
			}
		})
	}
}
