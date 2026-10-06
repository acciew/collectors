package api

import "time"

// The records this collector reads. Field sets are deliberately narrow: what
// is not read cannot be misread, and every field here is one the recorded
// responses in testdata actually carry.

// Org is an organization, which is this source's scope.
type Org struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	// DefaultRepositoryPermission is the level every member holds on every
	// repository in the organization without anybody granting it. Verified
	// against a real organization: a repository with no direct collaborators
	// at all is writable by several people because of this one field.
	//
	// A pointer, because absent and "none" are different answers and only
	// one of them is a fact about the organization. GitHub returns the field
	// only to organization owners; a member's token gets a response with no
	// such key, and reading that as "the organization turned it off" would
	// drop the most far-reaching entitlement there is while reporting the
	// population as whole.
	DefaultRepositoryPermission *string `json:"default_repository_permission"`
}

// User is a principal: a member, an outside collaborator, or a bot.
type User struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	// Type is "User", "Bot" or "Organization". Bots are applications acting
	// on their own behalf, and there are usually more of them than people.
	Type string `json:"type"`
}

// Collaborator is a user together with their resolved level on a repository.
type Collaborator struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	// RoleName is GitHub's own answer for this user on this repository, with
	// the organization base permission, organization roles, team grants and
	// direct grants already combined. It says the level and not the route,
	// so it is what the collector checks itself against rather than what it
	// derives the path from.
	RoleName string `json:"role_name"`
	// Permissions is the same answer as booleans, which is what older
	// responses carry and what a custom role reports against.
	Permissions Permissions `json:"permissions"`
}

// Permissions is the boolean form of a repository level.
type Permissions struct {
	Pull     bool `json:"pull"`
	Triage   bool `json:"triage"`
	Push     bool `json:"push"`
	Maintain bool `json:"maintain"`
	Admin    bool `json:"admin"`
}

// Team is a grouping of people that also holds repository access.
type Team struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	ID   int64  `json:"id"`
	// Parent makes teams a hierarchy; a child inherits the parent's
	// repository access.
	Parent *Team `json:"parent"`
	// Permission is the team's default level on repositories it is given.
	Permission string `json:"permission"`
}

// Repo is a repository, which is this source's resource.
type Repo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	ID       int64  `json:"id"`
	Private  bool   `json:"private"`
	// Archived repositories are read-only whatever anybody's level says, so a
	// grant on one is not the access it appears to be.
	Archived bool `json:"archived"`
}

// TeamRepo is a repository together with the level a team holds on it.
type TeamRepo struct {
	Name        string      `json:"name"`
	FullName    string      `json:"full_name"`
	ID          int64       `json:"id"`
	Archived    bool        `json:"archived"`
	RoleName    string      `json:"role_name"`
	Permissions Permissions `json:"permissions"`
}

// Installation is an application installed in the organization. These are
// principals that hold access and are not people.
type Installation struct {
	ID         int64     `json:"id"`
	AppID      int64     `json:"app_id"`
	AppSlug    string    `json:"app_slug"`
	TargetType string    `json:"target_type"`
	CreatedAt  time.Time `json:"created_at"`
	// Permissions is what the application may do, as a map of area to level.
	// It is not a repository level and does not sit on the same ladder.
	Permissions map[string]string `json:"permissions"`
	// RepositorySelection is "all" or "selected".
	RepositorySelection string `json:"repository_selection"`
}

// InstallationPage is the shape this one endpoint returns. Every other list
// endpoint answers with an array; this one wraps it in an object, and a
// client that assumes otherwise reports an organization with no applications.
type InstallationPage struct {
	TotalCount    int            `json:"total_count"`
	Installations []Installation `json:"installations"`
}

// BasePermission is what the organization says every member holds, and
// whether it said anything at all.
func (o Org) BasePermission() (level string, stated bool) {
	if o.DefaultRepositoryPermission == nil {
		return "", false
	}
	return *o.DefaultRepositoryPermission, true
}
