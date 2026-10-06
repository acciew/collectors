package collect

import "strconv"

// GitHub's repository permissions are an ordered ladder, which is
// structurally unlike Keycloak, where a principal either holds a role or does
// not. Two things follow, and both matter to a reviewer.
//
// The ordering is real and useful: maintain is strictly more than write, so
// "who holds at least write on this repository" is a question with an answer.
// But the ordering belongs to the *default* roles only. A custom repository
// role is a base role plus a set of fine-grained permissions, so two grants
// that both read "write" are not necessarily the same access, and presenting
// them as comparable is the kind of quiet wrongness this product exists to
// avoid.
//
// So the rank travels as source context on the entitlement, and a role we
// cannot rank carries no rank at all rather than a guessed one. A consumer
// that understands GitHub can order what is orderable; one that does not
// renders the badge and stays honest.

// rungs is the default ladder, weakest first.
var rungs = []string{"read", "triage", "write", "maintain", "admin"}

// rank returns the position of a default level on the ladder, and whether it
// is on the ladder at all. A custom role is not.
func rank(level string) (int, bool) {
	for i, r := range rungs {
		if r == level {
			return i + 1, true
		}
	}
	return 0, false
}

// levelContext describes a permission level for a reviewer.
//
// A default level carries its rank so it can be ordered. A custom role
// carries the base role it extends, if GitHub told us, and deliberately no
// rank: saying it sits at the same rung as a default role would assert a
// comparability that does not hold.
func levelContext(level, baseRole string) map[string]string {
	out := map[string]string{"level": level}
	if n, ok := rank(level); ok {
		out["ladder"] = "github_repository"
		out["rank"] = strconv.Itoa(n)
		out["of"] = strconv.Itoa(len(rungs))
		return out
	}
	out["ladder"] = "github_custom_role"
	out["comparable"] = "false"
	if baseRole != "" {
		out["base_role"] = baseRole
	}
	return out
}

// atLeast reports whether a is at least as strong as b, and whether the
// question is answerable at all. It is not answerable when either side is a
// custom role.
func atLeast(a, b string) (yes, answerable bool) {
	ra, aOK := rank(a)
	rb, bOK := rank(b)
	if !aOK || !bOK {
		return false, false
	}
	return ra >= rb, true
}

// levelFrom reads a level out of the boolean permissions object, which is
// what older responses carry and what a custom role reports against. The
// strongest true wins, because the booleans are cumulative.
func levelFrom(p permissions) string {
	switch {
	case p.Admin:
		return "admin"
	case p.Maintain:
		return "maintain"
	case p.Push:
		return "write"
	case p.Triage:
		return "triage"
	case p.Pull:
		return "read"
	}
	return ""
}

// permissions mirrors the API's boolean form without importing it, so this
// file states the ladder in one place.
type permissions struct {
	Pull, Triage, Push, Maintain, Admin bool
}
