package graph_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"go.acciew.io/collector/plugins/entra/internal/graph"
)

// The claims this collector rests on, against a real tenant.
//
// Skipped without credentials, so it costs CI nothing. Everything the README
// lists under "What has not been verified" is a question this test asks of
// Microsoft, and it logs the answer rather than assuming one: run it against a
// tenant with Entra ID P2 and the findings below are what close those rows.
//
//	ACCIEW_ENTRA_LIVE=1 ACCIEW_ENTRA_TENANT=... ACCIEW_ENTRA_CLIENT=... \
//	  ACCIEW_ENTRA_SECRET=... go test ./internal/graph -run Live -v
//
// ACCIEW_ENTRA_CLOUD names a national cloud (usgov, usgov-dod, china).
// ACCIEW_ENTRA_NEXTLINK_WAIT, such as 2h, is how long to hold a nextLink before
// following it, to find out whether it lives that long.
func TestLiveTheClaimsThisCollectorRestsOn(t *testing.T) {
	if os.Getenv("ACCIEW_ENTRA_LIVE") == "" {
		t.Skip("set ACCIEW_ENTRA_LIVE=1, with ACCIEW_ENTRA_TENANT, ACCIEW_ENTRA_CLIENT and " +
			"ACCIEW_ENTRA_SECRET, to check against a real tenant")
	}
	cloud := graph.Cloud(os.Getenv("ACCIEW_ENTRA_CLOUD"))
	if cloud == "" {
		cloud = graph.Global
	}
	hosts, ok := graph.EndpointsFor(cloud)
	if !ok {
		t.Fatalf("%q is not a cloud", cloud)
	}
	ctx := context.Background()
	c, err := graph.Dial(ctx, graph.Config{
		TenantID: os.Getenv("ACCIEW_ENTRA_TENANT"), ClientID: os.Getenv("ACCIEW_ENTRA_CLIENT"),
		ClientSecret: os.Getenv("ACCIEW_ENTRA_SECRET"), Endpoints: hosts,
	})
	if err != nil {
		t.Fatalf("signing in to %s: %v", cloud, err)
	}
	t.Logf("signed in to tenant %s on %s", c.TenantID(), cloud)

	t.Run("sign-in activity", func(t *testing.T) {
		page, err := graph.GetPage[graph.User](ctx, c, graph.UsersPath(999, true))
		var ge *graph.Error
		switch {
		case err == nil:
			t.Logf("signInActivity answered: %d users on the first page (asked for the most Graph allows with it)", len(page.Items))
		case errors.As(err, &ge):
			// The shape of the refusal a tenant without Entra ID P1 or P2 is
			// answered is the one thing here nobody has seen.
			t.Logf("signInActivity refused: HTTP %d, code %q, kind %v, taken for a missing licence: %v. %s",
				ge.Status, ge.Code, ge.Kind, ge.LicenceRequired(), ge.Message)
		default:
			t.Errorf("signInActivity: %v", err)
		}
	})

	t.Run("a group's members need no advanced query", func(t *testing.T) {
		groups, err := graph.GetPage[graph.Group](ctx, c, graph.GroupsPath(25))
		if err != nil {
			t.Fatalf("groups: %v", err)
		}
		for _, g := range groups.Items {
			members, err := graph.GetPage[graph.DirectoryObject](ctx, c, graph.MembersPath(g.ID, 999))
			var ge *graph.Error
			if errors.As(err, &ge) && ge.Kind == graph.KindBadRequest {
				t.Errorf("$select and $top on the members of %q were refused (%s): the collector assumes they need no "+
					"advanced-query headers", g.DisplayName, ge.Code)
				return
			}
			if err != nil {
				t.Logf("members of %q: %v", g.DisplayName, err)
				continue
			}
			kinds := map[string]int{}
			idOnly := 0
			for _, m := range members.Items {
				kinds[m.Kind()]++
				if m.IDOnly() {
					idOnly++
				}
			}
			if len(members.Items) > 0 {
				t.Logf("members of %q: %v, %d of them id-only (visibility %q)", g.DisplayName, kinds, idOnly, g.Visibility)
			}
		}
	})

	t.Run("a nextLink lives long enough to resume from", func(t *testing.T) {
		page, err := graph.GetPage[graph.User](ctx, c, graph.UsersPath(1, false))
		if err != nil || page.Next == "" {
			t.Skipf("no second page of users to hold a link to (err %v)", err)
		}
		wait, _ := time.ParseDuration(os.Getenv("ACCIEW_ENTRA_NEXTLINK_WAIT"))
		t.Logf("holding a nextLink for %v", wait)
		time.Sleep(wait)
		_, err = graph.GetPage[graph.User](ctx, c, page.Next)
		var ge *graph.Error
		switch {
		case errors.As(err, &ge):
			t.Logf("a nextLink held for %v was refused: HTTP %d, code %q. The collector refuses such a cursor with INVALID_CURSOR",
				wait, ge.Status, ge.Code)
		case err != nil:
			t.Errorf("following the link: %v", err)
		default:
			t.Logf("a nextLink held for %v was honoured", wait)
		}
	})

	t.Run("role assignments name their principals", func(t *testing.T) {
		page, err := graph.GetPage[graph.RoleAssignment](ctx, c, graph.RoleAssignmentsPath())
		if err != nil {
			t.Fatalf("role assignments: %v", err)
		}
		kinds, bare := map[string]int{}, 0
		for _, a := range page.Items {
			if a.Principal == nil {
				bare++
				continue
			}
			kinds[a.Principal.Kind()]++
		}
		t.Logf("%d assignments on the first page: principals %v, %d with none returned", len(page.Items), kinds, bare)
	})

	t.Run("Privileged Identity Management", func(t *testing.T) {
		for name, path := range map[string]string{
			"eligible": graph.EligibilityInstancesPath(), "active": graph.AssignmentInstancesPath(),
		} {
			page, err := graph.GetPage[graph.ScheduleInstance](ctx, c, path)
			var ge *graph.Error
			switch {
			case err == nil:
				types := map[string]int{}
				for _, in := range page.Items {
					types[in.MemberType+"/"+in.AssignmentType]++
				}
				t.Logf("%s: %d instances on the first page, by memberType/assignmentType: %v", name, len(page.Items), types)
			case errors.As(err, &ge):
				t.Logf("%s refused: HTTP %d, code %q, taken for a missing licence: %v. %s",
					name, ge.Status, ge.Code, ge.LicenceRequired(), ge.Message)
			default:
				t.Errorf("%s: %v", name, err)
			}
		}
	})

	t.Run("who is assigned an application's roles", func(t *testing.T) {
		sps, err := graph.GetPage[graph.ServicePrincipal](ctx, c, graph.ServicePrincipalsPath(graph.ServicePrincipalPageSize))
		if err != nil {
			t.Fatalf("service principals: %v", err)
		}
		types := map[string]int{}
		for _, sp := range sps.Items {
			types[sp.ServicePrincipalType]++
		}
		t.Logf("%d service principals on the first page, by type: %v", len(sps.Items), types)
		for _, sp := range sps.Items {
			as, err := graph.GetPage[graph.AppRoleAssignment](ctx, c, graph.AppRoleAssignedToPath(sp.ID))
			if err != nil {
				t.Errorf("assignments of %q: %v", sp.DisplayName, err)
				return
			}
			if len(as.Items) > 0 {
				byType := map[string]int{}
				for _, a := range as.Items {
					byType[a.PrincipalType]++
				}
				t.Logf("%q: %d assignments on the first page, by principal type: %v", sp.DisplayName, len(as.Items), byType)
				return
			}
		}
	})
}
