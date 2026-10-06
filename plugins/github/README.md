# GitHub collector

Collects members, teams, repositories and installed applications from GitHub
organizations over the REST API. It never writes.

```sh
cat > github.json <<'EOF'
{
  "token": "env:GITHUB_TOKEN",
  "orgs": ["acme-org"]
}
EOF
export GITHUB_TOKEN=...
```

The Acciew host runs the collector with this configuration: a check first, then a collection.

## What it collects

| GitHub | Becomes | Notes |
|---|---|---|
| Organization | `Scope` | Carries the base permission in context |
| Member | `Identity` (human, or service for a bot) | Keyed by numeric id, not login |
| Outside collaborator | `Identity` | Not a member, so the base permission does not reach them |
| Installed application | `Identity` (service) | Its permissions are context, not entitlements |
| Team | `Grouping`, and a holder of grants | `CHILD_OF` for nesting |
| "members of *org*" | `Grouping` (synthetic) | What the base permission hangs from |
| "owners of *org*" | `Grouping` (synthetic) | What ownership-derived admin hangs from |
| Repository | `Resource` | With `archived` and `private` in context |
| A permission level on a repository | `Entitlement` | `APPLIES_TO` the repository |
| The organization's base permission | `Entitlement` | `APPLIES_TO` the **scope** — see below |

## The four routes to a repository

The effective level on a repository is the strongest of four things, and each
one is emitted as its own grant with its own route, because revoking one
leaves the others standing:

1. the organization's **base permission**, reached through membership;
2. **ownership** of the organization, which confers admin on everything;
3. a **team** the person is in, or an ancestor of it;
4. a grant made **on the repository** itself.

Leave out the first and the collector reports nobody on a repository the whole
organization can push to. Verified against a real organization on 2026-09-07:
`GET /repos/{org}/{repo}/collaborators?affiliation=direct` returned **zero
rows** while `?affiliation=all` returned several, among them an admin and writers.

## Things worth knowing before you rely on it

**No last-activity, for anybody, on purpose.** The audit log is the only
signal GitHub offers that a dormancy decision could rest on, and it is
Enterprise-gated — verified: HTTP 404 on a plan below Enterprise. The public event feed is
not a substitute: verified against a real organization, it covered public
repositories only, reached back about three weeks because it is capped by
event count rather than by time, and listed bots among the actors while
many human members never appeared at all. Reporting those members as
dormant would be a confident wrong answer, and this product would rather give
none.

**The base permission is one fact, and it is collected as one.** GitHub states
it once for the organization, so it is one entitlement applying to the scope
rather than a grant per member per repository — expanding it would emit
relationships GitHub never stated, quadratically in the size of the
organization. The consequence is real and worth stating: asking "who can write
to this one repository" does **not** include the people who can write to it
because they can write to everything. Read the organization-wide grant too.

**Repository levels are a ladder; custom roles are not on it.** Default levels
carry their rank in context so they can be ordered. A custom repository role
is a base role plus fine-grained permissions, so two grants that both read
`write` need not be the same access — a custom role carries no rank and is
marked as not comparable.

**Archived repositories are collected with their grants.** An archived
repository is read-only whatever a permission says, and `archived: true` in
the resource's context is the only place a reviewer can learn that. The grants
are still real: unarchiving is one click for anyone holding admin.

**This collector checks itself against GitHub.** GitHub will resolve the same
question independently — a level per person per repository, without the route.
Where the two disagree, a warning names both answers, because one of them is
wrong and quietly taking GitHub's number would hide a bug in the routes being
shown to people. The check costs one request per repository, so it is sampled
by default (`"verify": "sample"`, 25 repositories); `"all"` and `"off"` are
the other settings.

## Credentials

**The token must be an owner of every organization it collects.** Not merely a
member. GitHub returns an organization's default repository permission only to
owners, and that permission is what every member holds on every repository —
usually the widest access in the organization. Without it a collection would
report no access at all for people who can write to everything, so a
collection that cannot read it fails the organization rather than
under-reporting it. Listing installed applications needs ownership too.

A classic personal access token needs `read:org` and `repo`. An organization
with SAML enforced will refuse a token that has not been authorised for it,
and says so in the error.

The token is a **reference** — `env:NAME` or `file:/path` — never a literal.
Nothing that stores, hashes or logs the configuration document ever holds the
credential.

## Rate limits

5,000 requests an hour for a token. The cost of one organization is roughly
`2 + members/100 + teams + repositories`, plus one verification read per
repository sampled, which `verify` controls,, so an organization with a few
thousand repositories does not fit in one window. A collection that runs out
ends **incomplete and resumable** rather than pretending to be whole; the
cursor names the organizations already collected, so a failed one is retried
rather than skipped.

The core does not yet stitch two streams into one snapshot, so an organization
needing more than one window cannot presently be collected end to end. That is
a gap in the host, not in this plugin.

## What has not been verified

Everything above marked *verified* was checked against a real organization on
2026-09-07 (a small organization).
These were **not**, and the code follows GitHub's documentation rather than
observation:

- **Team membership, nesting and inherited repository access.** No
  organization available for testing had any teams. The collector asks GraphQL
  for `membership: IMMEDIATE` because the REST endpoint is documented to
  include child teams' members — emitted as membership, that would tell a
  reviewer to remove somebody from a team they are not in. The GraphQL query
  was verified to parse and be accepted; its answer on a populated team was
  not observed. If the immediate answer cannot be read the collector falls
  back to the transitive one and says so in a warning.
- **Custom repository roles and organization roles**, both plan-gated.
- **Outside collaborators.** The organization had none.
- **Secondary rate limits** and `Retry-After` recovery. The response shape is
  handled; it has never been triggered.
- **GitHub App authentication**, which is not implemented: token only.
- **GitHub Enterprise Server** differences.
- **Internal repository visibility**, which is a fifth term in the effective
  permission on Enterprise plans and is not modelled.
