package collect

import (
	"context"
	"strings"

	"go.acciew.io/collector/plugins/entra/internal/graph"
	"go.acciew.io/collector/sdk/go/collector"
)

func (st *state) users(ctx context.Context) error {
	withActivity := st.activity.State == ActivityAvailable
	err := walk(ctx, st, func(us []graph.User) error {
		for _, u := range us {
			if err := st.emitUser(u); err != nil {
				return err
			}
			st.note("users", u.ID)
			if withActivity {
				if err := st.emitActivity(u); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return needs(err, "User.Read.All", "list the users")
}

// guestMarker is what Entra puts in the UPN of an invited external user.
const guestMarker = "#EXT#"

func isGuest(u graph.User) bool {
	return strings.EqualFold(u.UserType, "Guest") || strings.Contains(u.UserPrincipalName, guestMarker)
}

func (st *state) emitUser(u graph.User) error {
	// Absent is not disabled: Graph leaves accountEnabled out for a caller it
	// will not tell, and reading that as false would turn every grant the user
	// holds into one a reviewer skips.
	status := collector.UnknownStatus
	switch {
	case u.AccountEnabled == nil:
	case *u.AccountEnabled:
		status = collector.Active
	default:
		status = collector.Disabled
	}
	sourceType := "user"
	if isGuest(u) {
		sourceType = "guest_user"
	}
	name := u.DisplayName
	if name == "" {
		name = u.UserPrincipalName
	}
	if name == "" {
		name = u.ID
	}
	attrs := map[string]string{"upn": u.UserPrincipalName}
	setIf(attrs, "user_type", u.UserType)
	setIf(attrs, "email", u.Mail)
	// The SID is what will correlate this user with an on-premises directory.
	setIf(attrs, "on_premises_sid", u.OnPremisesSecurityIdentifier)
	return st.out.Node(collector.WithContext(
		collector.Identity(collector.IdentityKey(st.tenant, u.ID), name, sourceType, collector.Human, status),
		attrs))
}

func setIf(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}
