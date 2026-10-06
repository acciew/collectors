package collect

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"go.acciew.io/collector/plugins/keycloak/internal/admin"
)

// Probe is what a pre-flight check found out about one realm.
//
// Activity is answered here rather than left to the collection, because the
// whole value of a pre-flight check is learning that last-activity will come
// back empty before waiting on a full collection to discover it.
type Probe struct {
	Realm     string
	Reachable bool
	// Set when Reachable is false.
	Err error
	// Whether this realm can answer about last activity at all.
	ActivityAvailable bool
	// ActivityUndetermined says we could not find out, as opposed to finding
	// out there is nothing: the events config could not be read at all.
	ActivityUndetermined bool
	// Why not, or why we could not tell. Empty when activity is available.
	ActivityNote string
}

// Probes checks each realm the credentials can see, narrowed to wanted when
// wanted is non-empty.
func Probes(ctx context.Context, src Source, realms []admin.Realm, wanted map[string]bool) []Probe {
	var probes []Probe
	for _, r := range realms {
		if len(wanted) > 0 && !wanted[r.Realm] {
			continue
		}
		probes = append(probes, probeRealm(ctx, src, r))
	}
	// A realm somebody named and the credentials cannot see is the most
	// useful thing this call can report, so it is reported rather than
	// silently dropped. Sorted, because a map is not an order and a list
	// somebody reads should not shuffle between runs.
	var missing []string
	for name := range wanted {
		if !containsRealm(realms, name) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		probes = append(probes, Probe{
			Realm: name,
			Err:   fmt.Errorf("the service account cannot see this realm, or it does not exist"),
		})
	}
	return probes
}

// grantReader is a Source that can also say which roles its token carries.
//
// Optional on purpose: it is not a read the collection makes, and a Source
// that cannot answer must leave the probe no worse off than before.
type grantReader interface {
	GrantedRoles(realm string) (map[string]bool, bool)
	ManagementClient(realm string) string
}

type permission struct {
	role string
	what string
	err  error
}

// reads is what one pre-flight pass learned about a realm.
type reads struct {
	perms   []permission
	users   []admin.User
	groups  []admin.Group
	clients []admin.ClientApp
}

// perform makes one of every read a collection makes, and records which were
// refused.
//
// Checking one of them and calling it a pre-flight check is worse than not
// checking at all: an operator is told the realm is reachable, waits on a
// collection, and gets a failure naming an endpoint they then have to map to
// a role themselves. The point of this call is to name the role.
//
// The per-item reads exist because listing and opening are separate
// permissions. Measured against Keycloak 26.4.7: resolving a realm role's
// composites needs view-realm, resolving a client role's needs view-clients,
// and every listing above succeeds without either — so the composite walk is
// what fails in the middle of a collection while the check says nothing. One
// item of each is enough; the permission does not vary by item.
func perform(ctx context.Context, src Source, realm string) reads {
	var read reads
	var roles []admin.Role
	var rolesErr error

	usersErr := func() error {
		var err error
		read.users, err = src.Users(ctx, realm)
		return err
	}()
	clientsErr := func() error {
		var err error
		read.clients, err = src.Clients(ctx, realm)
		return err
	}()
	groupsErr := func() error {
		var err error
		read.groups, err = src.TopLevelGroups(ctx, realm)
		return err
	}()
	rolesErr = func() error {
		var err error
		roles, err = src.RealmRoles(ctx, realm)
		return err
	}()

	read.perms = []permission{
		{role: "view-users", what: "list the users", err: usersErr},
		{role: "view-clients", what: "list the clients", err: clientsErr},
		{role: "view-users", what: "list the groups", err: groupsErr},
	}

	// The realm-role listing is not attributed to a role, because no single
	// role owns it: measured against Keycloak 26.4.7, nine of the nineteen
	// realm-management roles answer it — the four query-* roles, view-users,
	// view-clients, view-realm, manage-realm and realm-admin. Being refused
	// it means the token holds none of those, and view-realm is the one this
	// collection needs anyway, for the composite below. It is
	// here to find a role to resolve, and only its absence is worth saying.
	switch {
	case rolesErr != nil:
		read.perms = append(read.perms, permission{role: "view-realm",
			what: "resolve a composite role, which needs a role to try",
			err:  rolesErr})
	case len(roles) > 0:
		read.perms = append(read.perms, permission{role: "view-realm", what: "resolve a composite role",
			err: func() error {
				_, err := src.RoleComposites(ctx, realm, roles[0].ID)
				return err
			}()})
	}
	if len(read.users) > 0 {
		read.perms = append(read.perms, permission{role: "view-users", what: "read a user's roles",
			err: func() error {
				_, err := src.UserRoleMappings(ctx, realm, read.users[0].ID)
				return err
			}()})
	}
	if len(read.clients) > 0 {
		read.perms = append(read.perms, permission{role: "view-clients", what: "list a client's roles",
			err: func() error {
				_, err := src.ClientRoles(ctx, realm, read.clients[0].ID)
				return err
			}()})
	}
	if c, ok := firstServiceAccount(read.clients); ok {
		var sa *admin.User
		read.perms = append(read.perms, permission{role: "view-clients", what: "read a client's service account",
			err: func() error {
				var err error
				sa, err = src.ServiceAccountUser(ctx, realm, c.ID)
				return err
			}()})
		// A service-account user is a principal the collection reads roles
		// for, and it exists whether or not the realm has any people in it.
		// It is therefore the one view-users read that does not depend on the
		// population — which is what makes an empty /users answer catchable
		// by a permission rather than by a claim in a token.
		if sa != nil {
			read.perms = append(read.perms, permission{role: "view-users",
				what: "read a service account's roles",
				err: func() error {
					_, err := src.UserRoleMappings(ctx, realm, sa.ID)
					return err
				}()})
		}
	}
	if len(read.groups) > 0 {
		g := read.groups[0]
		read.perms = append(read.perms,
			permission{role: "view-users", what: "list a group's subgroups", err: func() error {
				_, err := src.Subgroups(ctx, realm, g.ID)
				return err
			}()},
			permission{role: "view-users", what: "list a group's members", err: func() error {
				_, err := src.GroupMembers(ctx, realm, g.ID)
				return err
			}()},
			permission{role: "view-users", what: "read a group's roles", err: func() error {
				_, err := src.GroupRoleMappings(ctx, realm, g.ID)
				return err
			}()},
		)
	}
	return read
}

func firstServiceAccount(clients []admin.ClientApp) (admin.ClientApp, bool) {
	for _, c := range clients {
		if c.ServiceAccountsEnabled {
			return c, true
		}
	}
	return admin.ClientApp{}, false
}

// readsUsers and readsClients are the roles that let a token see every user,
// or every client, in a realm rather than some of them.
//
// Measured against Keycloak 26.4.7 by granting each of realm-management's
// nineteen roles alone: view-users and manage-users answer /users, /groups, a
// user's role mappings and a group's members; view-clients and manage-clients
// answer /clients, a client's roles and its service account. realm-admin does
// all of it and needs no entry, because it is a composite and arrives in the
// token expanded into every one of these.
var (
	readsUsers   = []string{"view-users", "manage-users"}
	readsClients = []string{"view-clients", "manage-clients"}
)

// doubt reports the populations this token cannot be trusted about.
//
// Keycloak answers /users, /groups and /clients with 200 and an empty list
// for a token holding the matching query-* role but not the view-* one —
// measured against 26.4.7 on a realm with four users, a group and seven
// clients. Fine-grained admin permissions go further and return a genuine
// subset. Both are populations that read as whole and are not, and neither is
// an error the reads can see.
//
// So what came back is not evidence: a narrower grant returns something that
// looks exactly like a smaller realm. Only the grant itself settles it, and
// when the grant cannot be read, nothing does.
//
// Three listings behave this way and no others. Measured on 26.4.7 against a
// realm with seven realm roles, nineteen roles on one client and a composite:
// /roles, a client's roles and a role's composites each return everything or
// 403, never a subset. /users, /groups and /clients are the ones that narrow,
// and they are the ones checked here.
func doubt(src Source, realm string, subjects []subject) []string {
	if len(subjects) == 0 {
		return nil
	}
	gr, ok := src.(grantReader)
	var roles map[string]bool
	known := false
	if ok {
		roles, known = gr.GrantedRoles(realm)
	}
	if !known {
		// Said once, however many subjects are in doubt: it is one fact
		// about the token, and repeating the paragraph per listing makes a
		// message nobody reads.
		var what []string
		for _, s := range subjects {
			what = append(what, "every "+s.what)
		}
		return []string{"nothing here can say whether this token sees " +
			strings.Join(what, " and ") + " in the realm or only some — Keycloak narrows " +
			"the answer rather than refusing, so what came back looks the same either way. " +
			"This token carries no statement of the roles it holds, so the grant cannot " +
			"settle it either. Two things do that: lightweight access tokens are on for " +
			"this client (turn them off, or tick \"Add to lightweight access token\" on its " +
			"client roles mapper), or the roles client scope has been removed from it"}
	}

	var missing []string
	for _, s := range subjects {
		if slices.ContainsFunc(s.enough, func(r string) bool { return roles[r] }) {
			continue
		}
		missing = append(missing, strings.Join(s.enough, " or ")+" (to see every "+s.what+
			", not a subset)")
	}
	if len(missing) > 0 {
		// Once, at the end, and short. The same two caveats apply to every
		// subject above; repeating them per listing buries the roles, which
		// are the part somebody acts on.
		//
		// The second matters as much as the first: a token can hold these
		// roles and still not carry them, when the client's full scope is
		// off and they are not in its scope mappings. Naming only the grant
		// would send somebody to add what they already have.
		missing[len(missing)-1] += ". If they are granted already, the client's full scope is " +
			"off and they are not in its scope mappings. Fine-grained admin permissions are " +
			"not a substitute: this collector cannot tell their subset from a whole realm"
	}
	return missing
}

// subject is one population the token has to be trusted about, and the roles
// that make it trustworthy.
type subject struct {
	what   string
	enough []string
}

func managementClient(src Source, realm string) string {
	if gr, ok := src.(grantReader); ok {
		return gr.ManagementClient(realm)
	}
	return "realm-management"
}

func probeRealm(ctx context.Context, src Source, r admin.Realm) Probe {
	realm := r.Realm
	p := Probe{Realm: realm, Reachable: true}

	// The realm listing carries the name and nothing else when the token
	// cannot read the realm itself, so an absent enabled field is a realm
	// this collection would record as disabled. The collection refuses it;
	// saying otherwise here is the two disagreeing about the same realm.
	if r.Enabled == nil {
		p.Reachable = false
		p.Err = fmt.Errorf("realm %s did not say whether it is enabled, which means this "+
			"token cannot read the realm itself. Grant its service account view-realm or "+
			"manage-realm from the %s client", realm, managementClient(src, realm))
		return p
	}
	read := perform(ctx, src, realm)

	// Only a refusal says anything about the grant. A 503, a 404, a rejected
	// secret — none of those is a missing role, and telling somebody to grant
	// one sends them to change a permission that was never the problem.
	// Reported first, because everything below reads as advice about roles.
	for _, perm := range read.perms {
		if perm.err != nil && !denied(perm.err) {
			p.Reachable = false
			p.Err = fmt.Errorf("realm %s could not be read (trying to %s): %w",
				realm, perm.what, perm.err)
			return p
		}
	}

	var missing []string
	named := false
	said := map[string]bool{}
	for _, perm := range read.perms {
		if perm.err == nil || said[perm.role] {
			continue
		}
		// One line per role rather than per read: the operator grants roles.
		said[perm.role] = true
		named = true
		missing = append(missing, fmt.Sprintf("%s (to %s: %v)", perm.role, perm.what, perm.err))
	}
	// Only for the populations no read already refused: being told to grant
	// view-clients twice, once for the refusal and once for the doubt, is
	// one message too many.
	var unsure []subject
	if !said["view-users"] {
		unsure = append(unsure, subject{"user and group", readsUsers})
	}
	if !said["view-clients"] {
		unsure = append(unsure, subject{"client", readsClients})
	}
	for _, why := range doubt(src, realm, unsure) {
		named = named || strings.HasPrefix(why, "view-")
		missing = append(missing, why)
	}
	if len(missing) > 0 {
		p.Reachable = false
		// The remedy only when a role was actually named: an answer nobody
		// could corroborate is not fixed by granting anything.
		remedy := ""
		if named {
			remedy = fmt.Sprintf(". Grant any role named here to the service account from "+
				"the %s client", managementClient(src, realm))
		}
		p.Err = fmt.Errorf("this token cannot collect realm %s: %s%s",
			realm, strings.Join(missing, "; "), remedy)
		return p
	}

	cfg, err := src.EventsConfig(ctx, realm)
	// Exactly when the collection reads the log, and never otherwise: it
	// skips the read when no login type is recorded, and a check that made a
	// call the collection would not is the disagreement in reverse.
	//
	// One event, not a page. The collection fails the realm when this read
	// fails, so a check that stopped at the configuration would call such a
	// realm reachable and be contradicted minutes later.
	logDenied := false
	if wanted := loginTypes(cfg); err == nil && len(wanted) > 0 {
		if _, e := src.Events(ctx, realm, wanted, 1); e != nil {
			// Refused is an answer about activity and not about the realm:
			// the collection degrades on it and keeps the population, so
			// this must not call the realm unreachable. Anything else is the
			// realm failing, which the collection also does.
			if denied(e) {
				logDenied = true
			} else {
				err = e
			}
		}
	}
	switch {
	case err != nil && !denied(err):
		// The collection fails the realm on this rather than answering
		// around it, so the check must say the same. Reporting "reachable,
		// activity unknown" here is the check and the collection disagreeing.
		p.Reachable = false
		p.Err = fmt.Errorf("realm %s could not be read: %w", realm, err)
	case err != nil:
		// Being refused the events config says nothing about
		// whether the identities can be collected, so the realm stays
		// reachable and only the activity answer is withheld. Withheld, not
		// denied: the operator needs to check a permission, not go looking
		// for a setting that is already on. The collection agrees — see
		// activityFor, which degrades rather than failing the realm.
		p.ActivityUndetermined = true
		p.ActivityNote = "could not read the event configuration, so whether this realm records " +
			"activity is unknown: " + err.Error()
	case !cfg.EventsEnabled:
		p.ActivityNote = "event storage is off for this realm; turning it on records from that " +
			"moment and cannot fill in the past"
	case len(loginTypes(cfg)) == 0:
		p.ActivityNote = "event storage is on but neither LOGIN nor CLIENT_LOGIN is recorded"
	case logDenied:
		// The configuration says this realm records logins and the log
		// itself is refused, so what it holds is unknown rather than empty.
		p.ActivityUndetermined = true
		p.ActivityNote = "this realm records logins but the event log cannot be read, so " +
			"whether anyone has used their access is unknown"
	default:
		p.ActivityAvailable = true
	}
	return p
}

func containsRealm(realms []admin.Realm, name string) bool {
	for _, r := range realms {
		if r.Realm == name {
			return true
		}
	}
	return false
}

// loginTypes is the event types this collector can answer activity from, of
// those a realm records. Empty means the realm answers for nobody.
func loginTypes(cfg admin.EventsConfig) []string {
	if !cfg.EventsEnabled {
		return nil
	}
	return enabledAmong(cfg.EnabledEventTypes, keycloakLogin, keycloakClientLogin)
}
