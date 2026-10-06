# Three-source mapping: Keycloak, GitHub, AWS IAM

**Status:** design review for `api/collector/v1/collector.proto`. Written before
the contract, on purpose.

A contract designed against one source is that source's API wearing a costume.
This document maps the source-agnostic vocabulary onto three deliberately
dissimilar sources, records where each one breaks the vocabulary, and turns
those breaks into numbered requirements the contract has to satisfy.

The interesting content is not the mapping table. It is [§3, where the
vocabulary breaks](#3-where-the-vocabulary-breaks), and the requirements in
[§4](#4-what-the-contract-must-therefore-support).

**Verification status.** Claims marked **[verified]** were executed against a
real instance and the observed response is quoted or summarised here. Claims
marked **[unverified]** come from vendor documentation and prior experience and
are still hypotheses. Nothing in this release may be built as if an unverified claim
were a fact; the collector work for each source closes its own claims.

What has actually been run, and where:

| Source | Verified against | Covers |
|---|---|---|
| Keycloak | 26.4.7 in a container, fixture in [§2.2](#22-keycloak) | Identities, group tree, membership, effective roles, default roles, organizations, login events with storage on and off |
| GitHub | The live REST API against a real organization | Org base permission, collaborator affiliation, App installations |
| AWS IAM | A real account, read-only calls, 2026-09-07 ([§2.4](#24-aws-iam)) | Authorization details, credential report, trust principals |

An untagged endpoint in the tables below is documentation, not observation.

---

## 1. The vocabulary

Six types. Every one of them is a noun a reviewer would recognise without
knowing which system the data came from, which is the test that keeps the core
source-agnostic.

| Type | Meaning | The question it answers |
|---|---|---|
| `Identity` | A principal | Who? |
| `Grouping` | A container of identities | Through what? |
| `Entitlement` | A permission | Allowed to do what? |
| `Resource` | What access is to | To what? |
| `Scope` | An isolation boundary | Where? |
| `Activity` | A last-seen signal | Still needed? |

`Activity` is the odd one out: the other five describe the world, `Activity`
describes our knowledge of it. That asymmetry is the source of requirement
[R4](#r4-activity-carries-its-own-freshness).

---

## 2. The mapping

### 2.1 Summary

| Type | Keycloak | GitHub | AWS IAM |
|---|---|---|---|
| `Identity` | User; service-account user of a client, which `GET /users` does **not** return | Org member; outside collaborator; GitHub App installation | IAM user; role (as a principal); root user |
| `Grouping` | Group (hierarchical); composite role | Team (nestable) | IAM group |
| `Entitlement` | Realm role; client role | Repository permission level; org role; custom repo role | **Attached or inline policy; assumable role** — see [§3.4](#34-aws-does-not-enumerate) |
| `Resource` | Client | Repository | Account; resource ARN named in a policy |
| `Scope` | Realm | Organization | Account |
| `Activity` | Login event, if event storage is enabled | Weak; see [§3.5](#35-activity-is-three-different-things) | Access Advisor last-accessed; credential report |

### 2.2 Keycloak

Read through the Admin REST API only. No SPI, no Java.

The rows tagged **[verified]** below were run against **Keycloak 26.4.7**; the
untagged ones are from the vendor's documentation, as the verification
legend above says. The fixture:
realm `probe`; user `user1`; group `G` with subgroup `S`, and `user1` a member
of `S` only; realm roles `r-child`, `r-parent` (composite containing
`r-child`), and `r-group`; `r-parent` mapped directly to `user1` and `r-group`
mapped to the **parent** group `G`; a confidential client `svc` with a service
account.

| Concept | Endpoint | Notes |
|---|---|---|
| Realms | `GET /admin/realms` | The scope. Credentials may reach one realm or many. |
| Users | `GET /admin/realms/{realm}/users` | Paged with `first`/`max`. **[verified]** Returns `['user1']` — service-account users are **not** included. |
| Service-account identity | `GET /admin/realms/{realm}/clients/{id}/service-account-user` | **[verified]** Returns `service-account-svc`, which `GET /users` omitted. One call per client. |
| Groups | `GET /admin/realms/{realm}/groups` | **[verified]** Top level only. The response carries `subGroups: []` and `subGroupCount: 1` — the tree is *not* inline. |
| Subgroups | `GET /admin/realms/{realm}/groups/{id}/children` | **[verified]** Returns `['S']`. Paged. Walking the tree costs a request per node; `GET /groups?search=` returns matched hierarchies and may reduce that for a targeted collection. |
| Group members | `GET /admin/realms/{realm}/groups/{id}/members` | **[verified]** **Direct members only.** `G` returned `[]`; `S` returned `['user1']`. |
| Realm roles | `GET /admin/realms/{realm}/roles` | |
| Clients | `GET /admin/realms/{realm}/clients` | The resource. |
| Client roles | `GET /admin/realms/{realm}/clients/{id}/roles` | |
| Composites of a role | `GET /admin/realms/{realm}/roles-by-id/{id}/composites` | A role that contains other roles, realm or client. |
| Direct role mappings | `GET /admin/realms/{realm}/users/{id}/role-mappings` | **[verified]** Carries **both** `realmMappings` and `clientMappings`. A user with a direct `app-writer` client role returned `clientMappings: {'app': ['app-writer']}`. Direct client roles therefore cost nothing extra. |
| Effective **realm** roles | `.../users/{id}/role-mappings/realm/composite` | **[verified]** See below. Realm roles only. |
| Effective **client** roles | `.../users/{id}/role-mappings/clients/{clientUuid}/composite` | **[verified]** Returned `['manage-account', 'manage-account-links', 'view-profile']` for the `account` client. One call per user **per client**. |
| Group role mappings | `GET /admin/realms/{realm}/groups/{id}/role-mappings` | |
| Login events | `GET /admin/realms/{realm}/events?type=LOGIN&user={id}` | **[verified]** See "Last login" below. |
| Event storage config | `GET`/`PUT /admin/realms/{realm}/events/config` | `eventsEnabled`, `enabledEventTypes`, `eventsExpiration`. |
| Organizations | `GET /admin/realms/{realm}/organizations` | **[verified]** 404 `"Organizations not enabled for this realm."` by default; 200 once `organizationsEnabled` is set on the realm. |

**Effective access resolves further than expected, and that is good news.**
`/role-mappings/realm/composite` for `user1` returned:

```
['default-roles-probe', 'offline_access', 'r-child', 'r-group', 'r-parent', 'uma_authorization']
```

against a direct mapping of only `['default-roles-probe', 'r-parent']`. So a
single call resolved the composite (`r-parent` → `r-child`), the group ancestry
(`r-group` is mapped on `G`, and `user1` is only in `S`), *and* the realm's
default-role composite. **[verified]** The earlier hypothesis that group
ancestry might not be covered is closed, in Keycloak's favour.

Three consequences the contract has to absorb:

- **The composite endpoint is realm roles only.** *Direct* client roles arrive
  in the single `/role-mappings` call above; it is the *resolved* ones —
  composites and group inheritance applied to client roles — that need one call
  per user per client.

  That is a verification cost, not the collection cost. Because
  [R3](#r3-every-grant-carries-its-path) needs the path and this endpoint
  returns only the result, the collector resolves the graph itself from the
  group tree and the composite graph, which is O(users + groups + roles +
  clients). The per-user-per-client pass is how it checks its own answer, and
  it is the plugin's decision whether to run it over everything, over a sample,
  or not at all. It should be a documented plugin option rather than an
  assumption baked into the contract.
- **It returns the result, not the path.** Requirement [R3](#r3-every-grant-carries-its-path)
  needs "via group `G`" or "via composite `r-parent`", which this endpoint does
  not say. The collector must resolve the path itself from the group tree and
  the composite graph, and use this endpoint as the check on its own answer
  rather than as the answer.
- **`default-roles-{realm}` is on every user.** It is a composite granting
  `offline_access`, `uma_authorization` and the `account` client's
  `manage-account` and `view-profile`. Every user in every realm carries it. If
  it is emitted like any other grant, every review starts with four
  entitlements per person that nobody ever decided to give them. It must be
  tagged as a realm default in source context ([R8](#r8-every-record-carries-source-context))
  so a reviewer UI can fold it away.

**Last login: resolved for humans, and `LOGIN` alone is not enough.** The Admin
REST API is sufficient and no Java SPI is needed. **[verified]** against 26.4.7,
with event storage off and then on:

| Observation | Result |
|---|---|
| `UserRepresentation` fields | `createdTimestamp` and no last-login field of any kind |
| `eventsEnabled` default | `false`, with `eventsExpiration` unset |
| `GET /events?type=LOGIN` with storage off, after a successful login | `0` events |
| Same query with storage on and `LOGIN` enabled | `1` event, carrying `userId`, `clientId`, `ipAddress`, `sessionId` and `time` in epoch milliseconds |
| Filtering by `&user={id}` | works |
| The login performed while storage was off | still absent — **history is not backfillable** |
| `GET /users/{id}/sessions` | *current* sessions only (`start`, `lastAccess`); it is not a history |

**`LOGIN` covers interactive human logins and nothing else.** **[verified]** on
the same instance: a service account authenticating by `client_credentials`
produces a **`CLIENT_LOGIN`** event, not a `LOGIN`. Querying
`?type=LOGIN&user={service-account-id}` returned **zero** events while
`?user={service-account-id}` returned the `CLIENT_LOGIN`. Refresh-token use
produces `REFRESH_TOKEN`.

This matters more than it looks. [R11](#r11-non-human-identities-are-first-class)
makes service accounts first-class identities, and
[§2.2](#22-keycloak) goes out of its way to fetch them from
`/clients/{id}/service-account-user` because `GET /users` omits them. A
collector that then asks only for `LOGIN` events reports **every service
account as never used** — and a dormant-account review acts on that. The
Keycloak plugin declares at least two activity signals (`login_event`,
`client_login_event`) and emits one `Activity` record per subject per signal,
which is what the contract's per-signal shape is for.

So: **Go, not Quarkus.** The limits are what the contract must express, not
what it must fix:

- Storage is **off by default**, so most realms have no data at all until an
  operator turns it on. The plugin declares activity as a capability per realm;
  it does not assume it.
- **The event type must match the identity kind.** One query type does not
  cover the population.
- Coverage is bounded by `eventsExpiration`. A user whose last login predates
  the window is indistinguishable from a user who has never logged in — which
  is precisely the `UNAVAILABLE`-versus-absent distinction in
  [R4](#r4-activity-carries-its-own-freshness).
- **`coverage.since` is the oldest event the plugin can observe.**
  `eventsExpiration` is unset by default, and even when set it is an upper bound
  on retention rather than a statement that the realm was recording that long
  ago, so the window is never clamped to it: a realm where storage was
  switched on last week has no data from last month, and reporting a window
  that reaches back a month would mark those users `NotSeen` inside it. That is
  exactly the false claim `coverage` exists to prevent. Where the plugin can
  observe no events of a signal at all, there is no window to claim and the
  answer is `Unavailable` with no coverage, not `NotSeen`. The oldest event is
  tracked per event type, and one read of at most 5,000 events is shared by the
  signals.
- Events are per client. "Last activity" is the maximum over a user's events,
  not a single record.
- History cannot be backfilled, which is an argument for turning event storage
  on at install time rather than at first review.

### 2.3 GitHub

| Concept | Endpoint | Notes |
|---|---|---|
| Organization | `GET /orgs/{org}` | The scope. **[verified]** Carries `default_repository_permission` — see below. |
| Members | `GET /orgs/{org}/members` | `role` filter separates admins from members. |
| Outside collaborators | `GET /orgs/{org}/outside_collaborators` | Not members, but they hold access. |
| Teams | `GET /orgs/{org}/teams` | Nestable via a parent team. |
| Team members | `GET /orgs/{org}/teams/{slug}/members` | |
| Team repository access | `GET /orgs/{org}/teams/{slug}/repos` | Carries the permission level. |
| Repositories | `GET /orgs/{org}/repos` | The resource. |
| Repository collaborators | `GET /repos/{owner}/{repo}/collaborators` | **[verified]** `affiliation` is `outside`, `direct` or `all`. See below. |
| App installations | `GET /orgs/{org}/installations` | **[verified]** Returned a `total_count` against a real org. Non-human identities. |
| Custom repository roles | `GET /orgs/{org}/custom-repository-roles` | Plan-gated. |
| Organization roles | `GET /orgs/{org}/organization-roles` | **[unverified]** Enterprise-plan-gated. |

**[verified 2026-09-07]** Two more facts a collector has to be built around.
The org **audit log returned 404** on a plan below Enterprise, so the only real
last-activity signal is Enterprise-only. And the public **event feed is not a
substitute**: against a real organization it returned events for public
repositories only, reached back about three weeks because it is capped at a
few hundred events rather than by time, and listed bots among the actors while many human members never appeared at all. A dormancy
decision taken on it would be confidently wrong for anybody working in a
private repository, which in a company organization is everybody.

**[verified 2026-09-07]** GitHub's REST team-members endpoint is documented to
include the members of child teams, and GraphQL's `members(membership:
IMMEDIATE)` was verified to be accepted by the API. The distinction matters:
emitted as membership, a transitive answer states an inherited route as a
direct one, and tells a reviewer to remove somebody from a team they are not
in. Subtracting the descendants does not fix it, because somebody can be in
both a parent and a child directly and would be subtracted out of the parent
they really are in.

**The organization's base permission is an entitlement, and it is invisible in
the collaborator list you would reach for first.** **[verified]** on a real
org with a permissive base permission: `GET /repos/{o}/{r}/collaborators?affiliation=direct`
returned **nothing** for a repository on which several people in fact hold `write`. A collector that
enumerates direct collaborators reports zero access on a repository where
every member of the organization can push.

So the effective permission on a repository is the maximum of four things, not
three: the organization base permission, any organization role, team-inherited
grants, and direct collaborator grants.

**[verified 2026-09-07]** on a second real organization with a permissive base permission:
`?affiliation=direct` returned **zero** rows on a repository, and
`?affiliation=all` returned several, among them an admin and writers. The trap is
not theoretical and it is the default configuration.

**There is a fifth term on Enterprise plans**, and it is not a grant at all:
repository *visibility*. An `internal` repository is readable by every member
of the enterprise, including people outside the organization being collected,
and a `public` one by everybody. This release records visibility on the resource
and does not model the reach, because the population it would need is outside
the scope. Open question: whether enterprise-wide read access belongs in a review
is a product question.

**And the base permission is one fact, not one per repository.** A collector
that expands it into a grant edge per member per repository emits M x R
relationships the source never stated, and does so quadratically in the size of
the organization. The honest shape is an entitlement that applies to the whole
scope: a grouping for organization membership that every member belongs to, one
`HOLDS` edge from it to a `base:write` entitlement, and one `APPLIES_TO` edge
from that entitlement to the organization scope. Three shapes of edge, each one
a fact GitHub actually states.

That is why [R1](#r1-records-are-nodes-and-edges-not-rows)'s
entitlement→resource edge also accepts a scope: AWS hits the same wall the
moment a policy names `Resource: "*"`.

**[verified]** A second trap in the same call: an `affiliation` value outside
the documented set is **ignored rather than rejected**. `affiliation=team`
returned the full `all` list. A collector must not treat an unknown filter as
an error the API will report; it will silently get more rows than it asked for.

**[verified]** The same call also carries the answer, which is easy to miss:
each collaborator comes back with a `role_name` and a `permissions` object
giving that user's *effective* level on that repository, with the four terms
above already combined. That is GitHub's own resolved answer, and it is the
analogue of Keycloak's `/composite` endpoint — the thing a collector resolves
independently and then checks itself against, rather than the thing it derives
the path from, since it says the level but not the route.

Permission levels are an **ordered ladder** — read, triage, write, maintain,
admin — which is structurally unlike Keycloak, where a user either has a role or
does not. But the ladder is not the whole story: custom repository roles are a
base role plus a set of fine-grained permissions, so two grants at the same
rung are not necessarily comparable. Ordering is a property of the *default*
roles, not of GitHub permissions in general, and
[R2](#r2-entitlements-are-not-all-the-same-kind-of-claim) has to survive that.

Rate limits are the other reason GitHub is in this release. 5,000 requests/hour for a
token and installation-scaled limits for a GitHub App are documented, as are
secondary rate limits, which respond with `retry-after`. A large org with
thousands of repositories cannot be collected inside one rate-limit window,
which makes resumability a correctness requirement rather than a nicety.

### 2.4 AWS IAM

| Concept | API | Notes |
|---|---|---|
| Everything, in bulk | `GetAccountAuthorizationDetails` | Users, groups, roles, policies and attachments in one paginated call. The efficient path. |
| Users / groups / roles | `ListUsers`, `ListGroups`, `ListRoles` | The granular path. |
| Attached policies | `ListAttachedUserPolicies`, `ListAttachedRolePolicies`, `ListAttachedGroupPolicies` | Managed policies. |
| Inline policies | `ListUserPolicies`, `GetUserPolicy`, and role/group equivalents | |
| Group membership | `ListGroupsForUser` | |
| Trust policy | `GetRole` → `AssumeRolePolicyDocument` | Who may assume this role. The `Principal` may be an account, an IAM principal, `Federated` (SAML or OIDC), `Service`, or `*`. |
| Service last accessed | `GenerateServiceLastAccessedDetails` → `GetServiceLastAccessedDetails` | Asynchronous: submit a job, poll for it. |
| Credential report | `GenerateCredentialReport` → `GetCredentialReport` | CSV. `password_last_used`, per-key last-used. Documented as cached for up to four hours. |
| Role last used | `GetRole` → `RoleLastUsed`; also in `GetAccountAuthorizationDetails` | Synchronous, and it arrives with data we are already fetching. Roles are the largest identity class in most accounts. |
| Access key last used | `GetAccessKeyLastUsed` | Synchronous, per key. |

Pagination is `Marker` / `IsTruncated`. IAM throttles; a large account is not a
single request.

**[verified 2026-09-07]** against a real account. `GetAccountAuthorizationDetails`
returns `UserDetailList`, `GroupDetailList`, `RoleDetailList` and `Policies`
together with `IsTruncated` and `Marker`, and it is not fast: **many
pages over several minutes** for a few users and groups and a few
hundred roles and managed policies. Roles can outnumber users by orders of
magnitude, so "roles are the largest
identity class in most accounts" understates it — an AWS review is mostly a
review of roles.

Three shapes in that response decide the collector. A user carries `GroupList`
inline, so group membership needs no call of its own. `UserPolicyList` is
**absent entirely** when there are no inline policies, so a collector must not
assume the key. And `RoleLastUsed` arrives with the same call, as
`{LastUsedDate, Region}` — present but dateless for many roles on a page,
which is a different fact from never assumed.

**[verified 2026-09-07] The account root user is not in `UserDetailList`.** It
appears only in the credential report. It is the most privileged principal in
the account, and a collector reading only the authorization details reports an
account without it.

**[verified 2026-09-07]** All three trust-principal kinds appeared on a single
page of roles: `Service`, `AWS` and `Federated`. The federated one was an
**OIDC provider for workloads** — not a human identity provider, which the paragraph below about federated principals being "where
the humans are" does not anticipate. Both are true; a federation provider is
simply not evidence of either.

**Which side is the entitlement?** "May assume role X" can be derived from the
role's trust policy (who it names) or from the caller's identity policy (who
holds `sts:AssumeRole` on it). Neither alone is sufficient: assumption requires
both. This release derives the entitlement from the **trust policy**, because it is
returned by data we already fetch, and records the identity-policy side as
source context rather than as a second entitlement. Where the trust principal is
`*` or an external account, the entitlement's subject is outside the scope being
collected and is emitted as such rather than dropped.

**Federated principals are where the humans are, and they are not in this
source.** A trust policy naming a SAML or OIDC provider means the actual people
live in an identity provider — very often Keycloak, which is the first
collector. [R9](#r9-identity-keys-are-stable-and-source-native) scopes keys by
source, so nothing in the contract yet lets an AWS role and the Keycloak users
who can assume it be recognised as related. This release does not solve this; it must
not pretend to. Open question: cross-source identity correlation is a product
question about what a reviewer is being asked to attest to, and it should be
asked before the contract is tagged rather than after.

**Out of scope for this release:** IAM Identity Center (`sso-admin`,
`identitystore`) is a different API surface with a different model — permission
sets assigned to principals across accounts. It is where a large customer's
human access actually lives. This release collects IAM only, and the plugin README
must say so plainly rather than letting a reader assume otherwise. Open question:
whether Identity Center belongs in a later release is a customer question.

---

## 3. Where the vocabulary breaks

### 3.1 One object, two domain types

The vocabulary implies six disjoint sets. All three sources violate that, and
AWS violates it in a way that is central rather than incidental.

| Source | Object | Is a… | And also a… |
|---|---|---|---|
| AWS | IAM role | `Identity` — it is a principal that holds policies | `Entitlement` — "may assume role X" is a permission a user holds |
| Keycloak | Client with a service account | `Resource` — roles are scoped to it | `Identity` — its service account is a principal |
| Keycloak | Composite role | `Entitlement` | `Grouping` — of other entitlements |
| GitHub | Team | `Grouping` of identities | Holder of entitlements, which it confers on members |

A model where an object is assigned exactly one type cannot express any of
these. The contract must let one source object be emitted as more than one
record and cross-referenced by key. → [R1](#r1-records-are-nodes-and-edges-not-rows),
[R9](#r9-identity-keys-are-stable-and-source-native).

### 3.2 Entitlements nest, and so do groupings

- Keycloak composite roles contain roles, transitively, across the realm/client
  boundary.
- Keycloak groups contain subgroups, and subgroups inherit ancestors' role
  mappings. **[verified]** The tree is not in the response: `GET /groups`
  returns `subGroups: []` with a `subGroupCount`, so walking it costs a request
  per node. And `GET /groups/{id}/members` returns **direct members only** —
  `G` returned `[]` while its subgroup `S` returned `['user1']` — so a
  collector that treats it as membership under-reports every parent group.
- GitHub teams nest, and a child team inherits the parent's repository access.
- AWS managed policies do not nest, but a role's permissions come from several
  attached policies at once, and the role itself is reachable through a chain
  of `sts:AssumeRole`.

Two consequences. The graph needs **entitlement→entitlement** and
**grouping→grouping** edges, not only identity→entitlement. And "why does this
person have this?" is a **path**, not a fact — which is the question a reviewer
actually asks. → [R3](#r3-every-grant-carries-its-path).

### 3.3 Not every source can resolve effective access

Keycloak can, and **[verified]** it resolves further than expected: one call
returns composites, group ancestry and realm defaults together, for realm roles.
Client roles need a call per user per client, so the resolution is available but
the cost is O(users x clients).

GitHub can, approximately, and the formula has four terms rather than three: the
effective level on a repository is the maximum of the **organization base
permission**, any organization role, team-inherited grants, and direct
collaborator grants. Leave out the first and a collector reports no access on
repositories that every member can push to — **[verified]**, see
[§2.3](#23-github).

AWS cannot, and the reason is structural, not an API gap.

### 3.4 AWS does not enumerate

An AWS principal's effective permissions are the outcome of evaluating identity
policies, resource policies, permission boundaries, service control policies and
session policies together, against a specific action on a specific resource in a
specific condition context. There is no list to fetch. Computing it is the
entire business of the CIEM vendors.

**Decision: an AWS entitlement is an attached policy or an assumable
role, not a computed permission.** This is a coarse entitlement. It is honest,
it is cheap, and it is genuinely useful for the access-review question ("should
this person still have this?") even though it is useless for the least-privilege
question ("what can this person actually do?").

The danger is not the limitation; it is a reviewer seeing an AWS policy
attachment and a resolved Keycloak effective role rendered identically, and
reading both as the same strength of claim. That is a defect in an evidence
product. The contract therefore makes resolution fidelity an explicit,
non-defaultable property of every grant. → [R2](#r2-entitlements-are-not-all-the-same-kind-of-claim).

This decision gets its own ADR (0003), it is stated in the plugin's README, and
the plugin declares it in `Describe` so the core can degrade rather than
guess.

### 3.5 `Activity` is three different things

| Source | Signal | Lag | Coverage window | Confidence |
|---|---|---|---|---|
| Keycloak | Login event **[verified]** | Immediate — the event was queryable within a second | `eventsExpiration`; **zero if storage is disabled, which is the default** | Exact within the window |
| GitHub | **[verified]** Nothing usable below Enterprise. The audit log — the one real signal — returned HTTP 404 on a plan below Enterprise. The public event feed covers public repositories only and is capped by event count, not time | Varies | Partial to none | Too low to use |
| AWS | **[verified]** Credential report (`password_last_used`, per-key last-used, with its own `GeneratedTime`); `RoleLastUsed` arriving with the collection | Report cached, and it says how stale | From when AWS began recording: passwords 2014, roles 2019 | Exact when there is a record; **the absence of one is not a negative** |

Three sources, three different meanings, three different failure modes — and one
shared property: **a reviewer will treat all of them as "last used" unless we
stop them.** A dormant-account decision made on a GitHub signal that only sees
public events is a wrong decision made confidently.

Absent data must also be distinguishable from "absent activity". **[verified]**
A Keycloak realm with events disabled produced zero login events across a
successful login, and enabling storage afterwards did not backfill it. Silence
is not evidence that nobody logged in, and it never becomes evidence
retroactively.

AWS states the same problem in one word. **[verified 2026-09-07]** its
credential report answers `no_information` for a password that has never been
used *or* was last used before it began recording in 2014 — two different
facts in one value, and only one of them would justify retiring an account.
`N/A` is the same position for an access key and an empty `RoleLastUsed` for a
role. The account root came back as `no_information`: read as "never", the
most privileged principal in the account reports as dormant.
→ [R4](#r4-activity-carries-its-own-freshness).

### 3.6 Two of the three sources will not finish in one pass

GitHub and AWS both rate-limit, and both can hold more objects than one window
allows. So a collection can end early. The failure mode that matters is not
slowness — it is a **truncated population that looks complete**. An access
review over 80% of the users, presented as a review of the users, is not weak
evidence; it is wrong evidence, and the error is invisible at exactly the moment
it does damage.

Keycloak, by contrast, is typically a single fast instance and will usually
finish in one pass. Designing only against Keycloak would have produced a
contract with no answer here at all. → [R5](#r5-partial-is-loud-not-a-flag),
[R12](#r12-rate-limit-state-is-reported-not-hidden).

### 3.7 Three unrelated credential shapes

| Source | Shape | Awkward part |
|---|---|---|
| Keycloak | Client ID + secret, or a service account, against a realm token endpoint | Which realm authenticates may differ from which realms are collected |
| GitHub | GitHub App (app ID, installation ID, private key, short-lived tokens) or a PAT | App installation tokens expire during a long collection and must be refreshed mid-stream |
| AWS | `sts:AssumeRole` with an external ID, or an instance/pod role | Credentials are temporary by design and are refreshed by the SDK, not by us |

No fixed schema in the core covers these without becoming a union of every
source's fields — and the next source breaks it again. → [R6](#r6-config-is-opaque-to-the-core).

### 3.8 Enumerating scopes is itself a collection step

"Which realms / orgs / accounts can I see?" is a question answered by the
source, is limited by the credentials, and can partially fail: a token may reach
four of six organizations. The core cannot ask the user to list scopes up front
and cannot assume that a scope the user names is reachable.
→ [R7](#r7-scopes-are-discovered-and-reachability-is-reported).

### 3.9 Not every principal is a person

Keycloak service accounts, GitHub Apps and bot accounts, AWS roles assumed by
workloads. In every real org these are a large fraction of the population, and
they are reviewed differently or excluded from human review entirely. If the
contract cannot say "this is not a person", every consumer re-derives it from
name heuristics. → [R11](#r11-non-human-identities-are-first-class).

### 3.10 Nothing tells us what was deleted

Neither GitHub nor AWS offers a reliable tombstone stream for identity objects.
Keycloak's admin events can, when enabled, but that is a conditional capability
rather than a guarantee. So "incremental collection" cannot mean "apply a
delta stream" — a deletion would simply never arrive, and a revoked entitlement
would persist in the inventory forever, which is the single worst failure mode
an access-review product can have.
→ [R10](#r10-deltas-are-derived-from-complete-snapshots).

---

## 4. What the contract must therefore support

Each requirement below is traceable to a break above, and each becomes a
concrete field or rule in `collector.proto`.

### R1. Records are nodes and edges, not rows

Emit typed nodes (`Identity`, `Grouping`, `Entitlement`, `Resource`, `Scope`)
and typed edges between them. Support at minimum: identity→grouping,
identity→entitlement, grouping→grouping, grouping→entitlement,
entitlement→entitlement, entitlement→resource **or entitlement→scope**, and
**entitlement→identity**.

Two of those are easy to miss.

**Entitlement→identity**: an AWS role is emitted as two nodes — a principal and
an assumable entitlement — and if nothing links them, the two are unrelated and
"Alice may assume `OrgAdmin`, which holds `AdministratorAccess`" has no path
through the graph.

**Entitlement→scope**: some grants are stated once and cover everything in a
scope. GitHub's organization base permission and an AWS policy naming
`Resource: "*"` are both a single source fact; without a way to say "applies to
this whole scope", a collector has to fabricate one edge per resource and
claim the source said something it did not.

One source object may be emitted as more than one node. *From [§3.1](#31-one-object-two-domain-types),
[§3.2](#32-entitlements-nest-and-so-do-groupings).*

### R2. Entitlements are not all the same kind of claim

Every grant carries a non-defaultable resolution fidelity:

- `DIRECT` — the source states this grant explicitly.
- `EFFECTIVE` — the plugin resolved it through groups, hierarchy or composites,
  and stands behind it.
- `COARSE` — the grant is a container of permissions the plugin did not and
  cannot evaluate. Every AWS policy attachment is this.

No default value. A plugin author must choose, and a consumer must be able to
render the difference.

**These three values conflate two axes,** and that is a deliberate compromise
rather than an oversight: *how a grant was reached* (stated by the source, or
derived by the plugin) and *whether its content has been evaluated* (a role, or
an unevaluated bag of permissions). It works because `COARSE` dominates — a
policy reached through a group is `COARSE`, and the path says how it was
reached — and because the derivation axis is recoverable from whether the path
is empty. Three values are what a reviewer can actually be shown. **If a fourth
value is ever proposed, split the axes first**; a fourth value on a conflated
enum is where this becomes unreadable.

*From [§3.3](#33-not-every-source-can-resolve-effective-access),
[§3.4](#34-aws-does-not-enumerate).*

### R3. Every grant carries its path

"Direct", or "via group Engineering → subgroup Platform", or "via composite role
`admin` → `realm-admin`", or "via assumable role `OrgAdmin`". Structured, not a
prose string, so a UI can render it and a diff can compare it.

This is what makes a review decidable: the reviewer's real question is not
whether the person has the entitlement but *why*, because the answer determines
what revoking it would do.

**One edge per contributing path, not one per (subject, entitlement).** GitHub's
"maximum of four terms" means one person can hold the same entitlement by
several routes at once, and revoking one leaves the others standing. A model
that collapses them into a single edge with one path tells a reviewer that
removing someone from a team ends their access when it does not.

*From [§3.2](#32-entitlements-nest-and-so-do-groupings),
[§3.3](#33-not-every-source-can-resolve-effective-access).*

### R4. `Activity` carries its own freshness

Never a bare timestamp. Every activity record carries:

- `observed_at` — when the plugin read it;
- `source_lag` — how stale the source itself admits the value may be;
- `confidence` — `EXACT`, `APPROXIMATE`, or `UNAVAILABLE`;
- `coverage_window` — how far back the source can see at all;
- and the distinction between *no activity in the window* and *the source
  cannot answer*.

A plugin that cannot produce activity says so in `Describe` and emits nothing —
it does not emit zero values. *From [§3.5](#35-activity-is-three-different-things).*

### R5. Partial is loud, not a flag

`Collect` streams, and the stream ends with a completion marker carrying
per-type counts and an explicit completeness verdict. An incomplete collection
surfaces at the core boundary as an **error**, not as a successful response
carrying `complete: false` that a caller can forget to read.

**Resumption is by cursor, and it is mandatory rather than a capability.** All
three sources need it — Keycloak's O(users x clients) client-role pass included
— and a plugin that cannot resume has no honest answer when the host caps a
collection. The reference collector does it in a handful of lines: the cursor is
the number of records emitted.

**This does not contradict [R7](#r7-scopes-are-discovered-and-reachability-is-reported).**
An unreachable scope does not abandon the collection: the plugin continues past
it, the completion verdict is incomplete, and the host returns the partial
result *and* an error. Continuing to collect and reporting the result as
complete are different things, and only the second is forbidden.

*From [§3.6](#36-two-of-the-three-sources-will-not-finish-in-one-pass).*

### R6. Config is opaque to the core

The core carries an opaque configuration blob and never parses it.
`ValidateConfig` is the plugin's job, returning structured, field-addressed
errors. Secret material is referenced, not embedded — the core must be able to
log a configuration without redaction rules it would have to keep in step with
every plugin.

**The core cannot verify that last part**, and the requirement should say so
rather than imply an enforcement that does not exist. A plugin that embeds a
literal secret in its config blob is conforming as far as any check we can run
is concerned. The SDK provides a secret-reference type that refuses literals,
and the authoring guide says why; beyond that it is a discipline, not a
guarantee.

*From [§3.7](#37-three-unrelated-credential-shapes).*

### R7. Scopes are discovered, and reachability is reported

A collector can enumerate the scopes its credentials reach, and reports per
scope whether it is reachable and why not. Partial scope reachability is a
first-class result, not an error that abandons the whole collection.
*From [§3.8](#38-enumerating-scopes-is-itself-a-collection-step).*

### R8. Every record carries source context

A `source_type` on every node and edge — the source's own name for what this
is, as a first-class field rather than a bag entry, because every consumer needs
the badge — plus string key/value context from the source's vocabulary:
`realm`, `client_id`, `role_type: client|realm`, `permission_level: write`,
`policy_arn`.

String values, not a typed union. The typing that matters is the plugin's
vocabulary, and strings are what canonical-JSON hashing needs anyway.

The core never interprets it; a reviewer UI renders it, because
reviewing a Keycloak client role and an AWS policy attachment are different
mental models and flattening them into one label destroys the reviewer's ability
to judge. *From the whole of [§3](#3-where-the-vocabulary-breaks).*

### R9. Identity keys are stable and source-native

Every record carries the source's own identifier and a composite key of scope,
type and id. The contract fixes a *property*, not a format, because three
sources cannot share one: **the id survives a rename.**

- Keycloak: the UUID.
- GitHub: the **numeric database id**, with the login in source context. Not
  the login, which its owner can change; and not the node ID, which has two
  live formats (legacy and the newer global id, opt-in by header) so that a
  default flipping would rewrite every key. The numeric id is what every REST
  list endpoint returns without asking, what GraphQL calls `databaseId`, and
  what the audit log emits — so it is also the join a later activity phase
  needs.
- AWS: the **unique id** (`AIDA…`, `AROA…`), with the ARN in source context.
  The ARN embeds the name and path and is therefore *not* rename-stable for
  users and roles — keying on it would make every rename a delete plus a
  create.

A rename must not read as a delete plus a create, because in history — which is
append-only and is the evidence — that difference is permanent.

Synthetic entitlements that no source object backs (GitHub's `write@repo`)
compose an id from stable parts, and that composition is the plugin's own
compatibility surface.

*From [§3.1](#31-one-object-two-domain-types).*

### R10. Deltas are derived from complete snapshots

Absence is computed by the core, by comparing complete snapshots. There is no
delta message and no tombstone in the contract.

**There is no `incremental` capability either.** None of the three sources can
fetch less than a full population, and this requirement itself concludes that
delta streams are unusable for deletions — so a capability bit that must always
be false is noise that implies a mechanism we do not have. It can be added
without breaking anything on the day a source exists that can support it.

*From [§3.10](#310-nothing-tells-us-what-was-deleted).*

### R11. Non-human identities are first class

`identity_kind`: `HUMAN`, `SERVICE`, `MACHINE`, `UNKNOWN`. `UNKNOWN` is a valid
and honest answer; a name heuristic in the core is not.

`SERVICE` is a credentialed application principal — a Keycloak service account,
a GitHub App. `MACHINE` is a credential-less workload runtime — an AWS role
assumed by an EC2 instance or a pod. **If the three first-party collectors cannot
apply that distinction consistently, collapse both into `NON_HUMAN` before
tagging** rather than shipping a distinction nobody can make; a category that is
assigned inconsistently is worse for a reviewer than a coarser one applied
reliably.

*From [§3.9](#39-not-every-principal-is-a-person).*

### R12. Rate-limit state is reported, not hidden

A plugin reports remaining budget and retry-after hints as it streams, so the
core can pace, so a long collection is legible while it runs, and so the
difference between "slow" and "stuck" is visible without reading logs.

**Where the source exposes it.** Only GitHub publishes a budget; AWS throttles
reactively and tells you nothing until it does; Keycloak has no limit at all.
Every rate-limit field is therefore optional, and a plugin that omits them is
conforming rather than lazy.

*From [§3.6](#36-two-of-the-three-sources-will-not-finish-in-one-pass).*

### R13. Capabilities are declared, never assumed

`Describe` reports: kind and protocol version; whether activity data is
available, and which signals; whether revocation is supported (declared in
the contract, not implemented); the resolution fidelities the plugin can reach;
which record types it emits; and its known limitations in words a reviewer
could be shown.

Resumability is **not** in that list: it is mandatory
([R5](#r5-partial-is-loud-not-a-flag)). Neither is incremental collection,
which does not exist ([R10](#r10-deltas-are-derived-from-complete-snapshots)). The core degrades gracefully
against what a plugin says it can do, and a plugin that lies fails the
conformance suite. *From all of the above.*

### R14. Every node says whether it was observed or only referenced

A node is `OBSERVED` — the plugin enumerated it in a scope it collected — or
`REFERENCED` — it exists only because something else pointed at it.

[§2.4](#24-aws-iam) says an external principal named in a trust policy is
"emitted as such rather than dropped", and nothing above said how. This is how.
A referenced node makes no claim beyond existing as the subject of a grant: no
observed attributes, no activity, and its absence from a later collection is
not evidence that anything changed. Treating a referenced node like an observed
one would let an inventory quietly claim to know about principals in accounts
we have never read.

**Where the vocabulary requires a value, a referenced node gives the explicit
unknown rather than nothing.** A referenced identity still carries identity
facts, saying `UNKNOWN` for both kind and status — because "this is a
principal, and we did not look inside the account it lives in" is a different
statement from a record with the field missing, which is indistinguishable from
a plugin that forgot. It also spares every consumer a special case for the one
node type that has no facts.

*From [§2.4](#24-aws-iam), [§3.8](#38-enumerating-scopes-is-itself-a-collection-step).*

### R15. The stream has framing rules, and they are checkable

[R5](#r5-partial-is-loud-not-a-flag) implies these; writing them down is what
lets the conformance suite assert them rather than each consumer reinventing
them.

- The completion marker appears **exactly once**, as the **last** event. A
  stream that ends without one is incomplete, whatever the transport says.
- The counts in the completion marker equal what was actually emitted.
- Every key referenced by an edge, a path or an activity record was emitted as
  a node.
- **Every hop in a path is an edge that was itself emitted**, and stated
  directly rather than derived. This is the rule with teeth: it turns "the
  plugin's resolution logic is correct" into something a fixture can check, and
  it is how a Keycloak group-inheritance bug gets caught by the test suite
  instead of by a reviewer.
- A repeated node key is tolerated only if the content is identical.

*From [§3.6](#36-two-of-the-three-sources-will-not-finish-in-one-pass).*

---

## 5. What this rules out, deliberately

| Not in the contract | Why |
|---|---|
| A computed "effective permissions" field for AWS | It cannot be produced honestly ([§3.4](#34-aws-does-not-enumerate)). A field that is empty for one source and authoritative for another is worse than no field. |
| A normalised permission verb across sources | "write" on a GitHub repository, a Keycloak client role and an AWS policy are not comparable. Normalising them would invent a claim no source supports. |
| `Revoke` implemented | Declared in the contract so the shape is fixed and field numbers are reserved; not implemented. Write-back is a different risk class. |
| Point-in-time / as-of queries | Out of scope. A collector reports the state at the time it ran and answers nothing about a past moment. |
| Anything that requires a Keycloak SPI | Admin REST API only, unless the last-login investigation proves events insufficient — and then it is recorded, not built. |

---

## 6. Open questions

Engineering cannot answer these. Each is stated so it can be answered in one
line.

- Does a later release need AWS IAM Identity Center, or is plain IAM enough for
  the people this is built for? It changes the AWS collector's shape
  substantially and it is where most large-org human access lives.
- When a collection is partial, does the product refuse to produce an
  export at all, or export with the incompleteness recorded on the artefact?
  This is an auditor-acceptance question, and it decides whether R5's error is
  fatal or recoverable at the product level.
- Do we promise support for the plan-gated GitHub surfaces
  (organization roles, audit log) that only exist on Enterprise Cloud? It
  determines whether GitHub activity data is a feature or a footnote.
- Which Keycloak versions do we commit to? The Admin REST API is
  stable in practice but not contractually, and the answer sets the
  testcontainers matrix. Everything in [§2.2](#22-keycloak) is observed on
  26.4.7.
- Should a reviewer ever see that an AWS role and a set of Keycloak
  users are the same people? Federated trust policies mean the humans behind an
  assumable role live in an identity provider, not in AWS. Cross-source identity
  correlation changes what a reviewer is attesting to, so it is a product
  question, and it should be answered before the contract is tagged rather than
  bolted on after.

## 7. Claims to close before the contract is tagged

**Closed.**

1. Keycloak, composite resolution and group ancestry — closed in Keycloak's
   favour: one call resolves both, for realm roles. Client roles cost a call per
   user per client.
2. Keycloak, last login — closed. Login events with storage enabled are
   sufficient; **no Java Event Listener SPI is needed for this release**. The limits
   (storage off by default, bounded window, not backfillable) are contract
   requirements, not blockers.
3. GitHub, organization base permission and collaborator affiliation — closed
   against a real organization, and both changed the design.
4. AWS, credential report caching — documented at four hours.

**Open when this was written, since closed.**

1. GitHub: is there genuinely no first-class last-active signal outside the
   plan-gated audit log? *Closed by the GitHub collector.*
2. AWS: the actual lag on Access Advisor, and whether `RoleLastUsed` is fresh
   enough to be the primary role signal. *Closed by the AWS collector.*
3. GitHub and AWS: real rate-limit behaviour under a large-tenant collection.
   *Closed by the resumability tests.*
4. Keycloak: behaviour across the version range we commit to, once that range
   is decided. *Closed by the testcontainers matrix.*
