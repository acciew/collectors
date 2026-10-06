package admin

import (
	"context"
	"fmt"
	"net/url"
)

// The subset of Keycloak's representations the collector reads. Fields we do
// not use are not declared: a struct that mirrors the whole API is a struct
// that has to be maintained against every Keycloak release.

// Realm is an isolation boundary.
type Realm struct {
	ID    string `json:"id"`
	Realm string `json:"realm"`
	// Enabled is a pointer because Keycloak strips it. A token without
	// view-realm gets a realm listing carrying nothing but the name —
	// measured on 26.4.7, one key rather than a hundred and one — and an
	// absent field read as false records a live realm as disabled, which
	// turns every grant in it into one a reviewer can ignore. Nil means the
	// realm did not say.
	//
	// Enabled realms only are worth collecting, but a disabled one is still
	// reported so an operator can see it exists.
	Enabled *bool `json:"enabled"`
	// DefaultRole is the composite every account in the realm carries. Named
	// here by the realm itself, which is the only reliable way to know it:
	// the name is not derivable from the realm name (Keycloak lowercases it)
	// and an operator may have renamed the role.
	DefaultRole *Role `json:"defaultRole"`
}

// User is a principal. Service-account users are NOT returned by the users
// endpoint; they are reached through their client.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Enabled   bool   `json:"enabled"`
	// CreatedTimestamp is epoch milliseconds. Keycloak has no last-login
	// field; activity comes from the events endpoint.
	CreatedTimestamp int64 `json:"createdTimestamp"`
	// ServiceAccountClientID is set by Keycloak on a service-account user and
	// names the client it belongs to.
	ServiceAccountClientID string `json:"serviceAccountClientId"`
}

// Group is a container of users. The tree is not inline: SubGroups comes back
// empty and SubGroupCount says whether to ask for children.
type Group struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Path          string  `json:"path"`
	SubGroups     []Group `json:"subGroups"`
	SubGroupCount int     `json:"subGroupCount"`
}

// Role is a realm role or a client role.
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Composite says the role contains others; the composites endpoint says
	// which.
	Composite bool `json:"composite"`
	// ClientRole and ContainerID distinguish a client role from a realm role
	// and name the client it belongs to.
	ClientRole  bool   `json:"clientRole"`
	ContainerID string `json:"containerId"`
}

// ClientApp is what Keycloak calls a client: an application access is to.
//
// Named ClientApp rather than Client because this package's own API client is
// Client, and a Keycloak client is an application rather than a caller. The
// collector maps it to a Resource.
type ClientApp struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	// ServiceAccountsEnabled means this client has a principal of its own.
	ServiceAccountsEnabled bool `json:"serviceAccountsEnabled"`
}

// MappingsRepresentation is what the direct role-mappings endpoint returns.
// It carries both realm and client mappings, which is worth stating because
// it is easy to test with a user who has no client roles and conclude
// otherwise.
type MappingsRepresentation struct {
	RealmMappings  []Role `json:"realmMappings"`
	ClientMappings map[string]struct {
		ID       string `json:"id"`
		Client   string `json:"client"`
		Mappings []Role `json:"mappings"`
	} `json:"clientMappings"`
}

// Event is one entry from the realm event log.
type Event struct {
	// Time is epoch milliseconds.
	Time      int64  `json:"time"`
	Type      string `json:"type"`
	RealmID   string `json:"realmId"`
	ClientID  string `json:"clientId"`
	UserID    string `json:"userId"`
	IPAddress string `json:"ipAddress"`
}

// EventsConfig says whether a realm records anything at all.
type EventsConfig struct {
	EventsEnabled bool `json:"eventsEnabled"`
	// EventsExpiration is seconds, and is often unset — which means there is
	// no retention bound to read, not that retention is infinite.
	EventsExpiration  int64    `json:"eventsExpiration"`
	EnabledEventTypes []string `json:"enabledEventTypes"`
}

// Records the collector reads.

// Realms lists the realms these credentials can see.
func (c *Client) Realms(ctx context.Context) ([]Realm, error) {
	var out []Realm
	err := c.get(ctx, "/realms", nil, &out)
	return out, err
}

// Users lists a realm's users. Service accounts are not among them.
func (c *Client) Users(ctx context.Context, realm string) ([]User, error) {
	return paged[User](ctx, c, path(realm, "users"), nil)
}

// ServiceAccountUser returns the principal belonging to a client, or nil when
// the client has no service account.
func (c *Client) ServiceAccountUser(ctx context.Context, realm, clientUUID string) (*User, error) {
	var out User
	err := c.get(ctx, path(realm, "clients", clientUUID, "service-account-user"), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// TopLevelGroups lists a realm's root groups. Their children need their own
// requests.
func (c *Client) TopLevelGroups(ctx context.Context, realm string) ([]Group, error) {
	return paged[Group](ctx, c, path(realm, "groups"), nil)
}

// Subgroups lists one group's direct children.
func (c *Client) Subgroups(ctx context.Context, realm, groupID string) ([]Group, error) {
	return paged[Group](ctx, c, path(realm, "groups", groupID, "children"), nil)
}

// GroupMembers lists a group's DIRECT members. A member of a subgroup does
// not appear here, which is why the collector walks the tree itself.
func (c *Client) GroupMembers(ctx context.Context, realm, groupID string) ([]User, error) {
	return paged[User](ctx, c, path(realm, "groups", groupID, "members"), nil)
}

// GroupRoleMappings lists the roles mapped onto a group. Members inherit
// these, and so do members of its descendants.
func (c *Client) GroupRoleMappings(ctx context.Context, realm, groupID string) (MappingsRepresentation, error) {
	var out MappingsRepresentation
	err := c.get(ctx, path(realm, "groups", groupID, "role-mappings"), nil, &out)
	return out, err
}

// RealmRoles lists a realm's roles.
func (c *Client) RealmRoles(ctx context.Context, realm string) ([]Role, error) {
	return paged[Role](ctx, c, path(realm, "roles"), nil)
}

// Clients lists a realm's clients.
func (c *Client) Clients(ctx context.Context, realm string) ([]ClientApp, error) {
	return paged[ClientApp](ctx, c, path(realm, "clients"), nil)
}

// ClientRoles lists one client's roles.
func (c *Client) ClientRoles(ctx context.Context, realm, clientUUID string) ([]Role, error) {
	return paged[Role](ctx, c, path(realm, "clients", clientUUID, "roles"), nil)
}

// RoleComposites lists the roles a composite role contains, one level down.
// The transitive closure is the collector's job, because it needs the path.
func (c *Client) RoleComposites(ctx context.Context, realm, roleID string) ([]Role, error) {
	var out []Role
	err := c.get(ctx, path(realm, "roles-by-id", roleID, "composites"), nil, &out)
	return out, err
}

// UserRoleMappings returns a user's DIRECT role mappings, realm and client
// alike.
func (c *Client) UserRoleMappings(ctx context.Context, realm, userID string) (MappingsRepresentation, error) {
	var out MappingsRepresentation
	err := c.get(ctx, path(realm, "users", userID, "role-mappings"), nil, &out)
	return out, err
}

// EffectiveRealmRoles returns the realm roles Keycloak itself resolves for a
// user: composites, group inheritance and realm defaults, all applied.
//
// The collector resolves the graph independently because a review needs the
// path and this endpoint returns only the result. It is used as a check on
// our own answer, not as the answer.
func (c *Client) EffectiveRealmRoles(ctx context.Context, realm, userID string) ([]Role, error) {
	var out []Role
	err := c.get(ctx, path(realm, "users", userID, "role-mappings", "realm", "composite"), nil, &out)
	return out, err
}

// EventsConfig reports whether a realm records events at all.
func (c *Client) EventsConfig(ctx context.Context, realm string) (EventsConfig, error) {
	var out EventsConfig
	err := c.get(ctx, path(realm, "events", "config"), nil, &out)
	return out, err
}

// Events reads the realm event log, newest first, for the given types.
func (c *Client) Events(ctx context.Context, realm string, types []string, limit int) ([]Event, error) {
	query := url.Values{"max": {fmt.Sprint(limit)}}
	for _, t := range types {
		query.Add("type", t)
	}
	var out []Event
	err := c.get(ctx, path(realm, "events"), query, &out)
	return out, err
}

func path(realm string, parts ...string) string {
	out := "/realms/" + url.PathEscape(realm)
	for _, p := range parts {
		out += "/" + url.PathEscape(p)
	}
	return out
}
