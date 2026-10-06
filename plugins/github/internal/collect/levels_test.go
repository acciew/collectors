package collect

import "testing"

// The ladder is real for default roles and does not exist for custom ones.
// A reviewer shown two grants that both say "write" must be able to tell
// whether they are the same access.
func TestADefaultLevelCarriesItsPlaceOnTheLadder(t *testing.T) {
	ctx := levelContext("write", "")
	if ctx["rank"] != "3" || ctx["ladder"] != "github_repository" {
		t.Errorf("context = %v, want a ranked default level", ctx)
	}
	if _, ok := ctx["comparable"]; ok {
		t.Errorf("a default level needs no comparability warning: %v", ctx)
	}
}

// A custom role is a base role plus fine-grained permissions. Giving it a
// rank would assert that it is interchangeable with the default role at that
// rung, which is exactly what it is not.
func TestACustomRoleCarriesNoRank(t *testing.T) {
	ctx := levelContext("security-reviewer", "write")
	if _, ranked := ctx["rank"]; ranked {
		t.Errorf("a custom role was given a rank: %v", ctx)
	}
	if ctx["comparable"] != "false" {
		t.Errorf("a custom role is not marked incomparable: %v", ctx)
	}
	if ctx["base_role"] != "write" {
		t.Errorf("the base role it extends was dropped: %v", ctx)
	}
}

func TestTheLadderOrders(t *testing.T) {
	for _, c := range []struct {
		a, b       string
		yes, known bool
	}{
		{"admin", "write", true, true},
		{"write", "admin", false, true},
		{"write", "write", true, true},
		{"maintain", "triage", true, true},
		{"read", "triage", false, true},
		// One custom role on either side makes the question unanswerable
		// rather than false: "false" would read as "holds less", and it does
		// not mean that.
		{"security-reviewer", "write", false, false},
		{"admin", "security-reviewer", false, false},
	} {
		yes, known := atLeast(c.a, c.b)
		if yes != c.yes || known != c.known {
			t.Errorf("atLeast(%q,%q) = %v,%v want %v,%v", c.a, c.b, yes, known, c.yes, c.known)
		}
	}
}

// Older responses carry booleans rather than a role name, and they are
// cumulative: an admin has every lower flag set too.
func TestTheStrongestBooleanWins(t *testing.T) {
	for _, c := range []struct {
		p    permissions
		want string
	}{
		{permissions{Pull: true, Triage: true, Push: true, Maintain: true, Admin: true}, "admin"},
		{permissions{Pull: true, Triage: true, Push: true}, "write"},
		{permissions{Pull: true}, "read"},
		{permissions{}, ""},
	} {
		if got := levelFrom(c.p); got != c.want {
			t.Errorf("levelFrom(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}
