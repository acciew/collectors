# Microsoft Entra ID collector

Collects users, groups, service principals, directory roles and app roles, who
holds each, and when users last signed in, from one Microsoft Entra ID tenant
over Microsoft Graph, with an application token. It never writes.

**It has not been run against a live tenant.** It was built from Microsoft's
documentation and tested against a fake Graph, and what that leaves unverified is
listed at the end rather than discovered by an auditor.

```sh
cat > entra.json <<'EOF'
{
  "tenant_id": "example.onmicrosoft.com",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "client_secret": "env:ENTRA_SECRET",
  "cloud": "global"
}
EOF
export ENTRA_SECRET=...
```

The Acciew host runs the collector with this configuration: a check first, then
a collection. One configuration is one tenant; `tenant_id` is the tenant's ID or
a verified domain.

## Credentials

The collector signs in as an application registered in the tenant, with the
client-credentials flow. Give it a client secret **or** a certificate, never
both, and always as a reference, never the value:

- `"client_secret": "env:NAME"` or `"file:/path"`: the secret.
- `"certificate": "file:/path/entra.pem"` or `"env:NAME"`: a PEM holding the
  private key (RSA, unencrypted, PKCS#8 or PKCS#1) and the certificate
  registered on the application. The collector signs a client assertion with it
  (PS256, with the certificate's SHA-256 thumbprint in `x5t#S256`), using only
  Go's standard library; no authentication library is linked in.

`cloud` is `global` (the default), `usgov`, `usgov-dod` or `china`. Each has its
own sign-in and Graph hosts, from Microsoft's national-cloud page, and a token
from one is refused by the others. A redirect is never followed, so neither the
secret nor a token is sent anywhere a response points.

## Permissions

Application permissions, granted by an administrator, on the application
registration:

| Permission | Needed to |
|---|---|
| `User.Read.All` | list users |
| `Group.Read.All` | list groups and their direct members |
| `RoleManagement.Read.Directory` | list directory role definitions and role assignments |
| `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory` | list what principals are eligible for through PIM, and the role assignments that are time-bound. `RoleManagement.Read.Directory` covers both. Needed unless `pim` is off |
| `AdministrativeUnit.Read.All` | list administrative units. Needed only with `administrative_units` on |
| `Directory.Read.All` | list delegated permission grants. Far broader than the rest: needed only with `oauth2_grants` on, and never asked for otherwise |
| `Application.Read.All` | list service principals, the app roles they expose, and who is assigned them. Needed unless both `service_principals` and `app_roles` are off |
| `Organization.Read.All` | read the organization's name and creation date. Optional: without it the tenant is named by its ID |
| `Member.Read.Hidden` | read the members of groups whose membership is hidden. Needed only if the tenant has any |
| `AuditLog.Read.All` | read each user's sign-in activity, which needs this and Entra ID P1 or P2. Optional: without it, or without the licence, activity is reported as unavailable |

`collect` switches parts on and off; a flag left out keeps its default.
`service_principals` (on) writes applications and managed identities as
identities, and `app_roles` (on) writes the roles they expose and who holds
them. Both read the same list, one page of at most 100 at a time, which is what
Graph returns for service principals, and `app_roles` costs one more request
per application.

```json
"collect": {"service_principals": true, "app_roles": true, "pim": true,
            "administrative_units": false, "oauth2_grants": false}
```

`pim` (on) collects Privileged Identity Management eligibilities and
time-bound assignments, as entitlements of their own. A tenant that is not
licensed for PIM is a tenant with nothing to collect there, and the collection
says so: only a refusal with a code Graph is known to use for a missing licence
is taken for one, and any other failure of the PIM reads fails the collection,
with the line to set `"pim": false`. Only when nothing of PIM was read: a licence
does not come and go between pages, or between the two reads, so a refusal after
either one answered is a read that stopped, and the part fails as incomplete.

`administrative_units` (off) reads the units a role can be scoped to, so a role
over one applies to a named unit and not just an id. Their members are not read:
the role assignments already say who holds a role over a unit. `oauth2_grants`
(off) reads delegated permission grants, each an entitlement its client holds;
who consented is context. A client or an API that nothing else reads is named as
referenced, with its name looked up.

Nothing else is requested. `page_size` is between 100 and 999, the most Graph
returns for users and groups; leave it out for the default. It has a floor because
a collection stops a read of 100,000 pages, to end a loop, and at a page of a
handful of objects a large tenant would reach that.

## The check

Before a collection the check reads one page of each collection the collection
reads, never the whole tenant, so it cannot pass where the collection would fail,
and reports the tenant as a scope. A body that is not a page, such as `{}`, fails
it: a 200 with no `value` is not a collection that can be read. For each permission that is missing
it says one sentence naming what to grant, and only a refusal is advice to
grant something: an unwell Graph is not a permission. It also reads the members
of a few groups, and of any group with hidden membership on the first page,
because two permissions fail silently:

- A member of a type the application may not read comes back as its type and
  id with every property null, and a 200. The check, and every collection,
  reads that object directly: a refusal there is a missing permission, naming
  it, and the tenant is reported partial. A null name on an object that can be
  read is just a null name.
- The members of a hidden-membership group need `Member.Read.Hidden`. Refused,
  that group is the only thing left unread.

A dynamic group whose rule processing is paused is collected and warned about:
its members are whatever the rule last decided, and nothing is keeping them
current.

The check also asks for one user's sign-in activity. A refusal with a code
Graph is known to use for a missing licence says activity needs Entra ID P1 or
P2. Any other failure says it could not find out, which sends an operator to
check a credential rather than to buy a licence.

## Activity

Last activity is each user's `signInActivity`, and it is three facts, so it is
declared as three signals, one record per user and signal, each as of 24 hours
before it was read:

| Signal | Entra's field | What it is |
|---|---|---|
| `interactive_sign_in_attempt` | `lastSignInDateTime` | The last interactive attempt. **Counts failed attempts**, so it does not say the person got in. Recorded from April 2020 |
| `non_interactive_sign_in_attempt` | `lastNonInteractiveSignInDateTime` | The last attempt a client made on the person's behalf. Counts failed ones. From May 2020 |
| `successful_sign_in` | `lastSuccessfulSignInDateTime` | The last sign-in that succeeded. From 1 December 2023 and **not backfilled** |
| `service_principal_sign_in` | none | Always unavailable. An application's sign-ins are a separate surface that is not read |

- **A blank is never "not seen".** Entra leaves a value blank for a user who
  never signed in that way and for one whose last attempt was before Entra began
  recording it, and the two cannot be told apart. A blank is reported as
  unavailable (`entra.no-sign-in-recorded`), saying both, and no record anywhere
  says "not seen".
- **A tenant that cannot answer says so once, for everyone.** Without Entra ID
  P1 or P2, or without `AuditLog.Read.All`, the users are collected without
  asking for `signInActivity`, no activity record is written, and the scope
  reports activity as unavailable. Not knowing why is reported as undetermined,
  which points at a credential and not at a licence.
- **The window.** Each record covers from the later of when Entra began
  recording the signal and when the tenant was created (if the organization can
  be read) up to when it was read. Microsoft gives April and May 2020 as months,
  and a month is not a day, so the window starts at the end of the month: later
  is the direction that cannot claim a period in which nothing was recorded. A
  value outside that window widens it to the value, because the sighting is
  proof the source could see that far.
- Graph caps a page of users at 500 when `signInActivity` is selected, so users
  are read in pages of at most 500.

## No resume, and throttling

**Entra does not resume in v1.** A collection is one stream that reads the tenant
from the start and keeps what it needs in memory. If a stream is lost, a lapse of
the agent say, the collection starts again from the beginning. Keeping a place
across streams meant carrying, in a cursor, what each part had written, so that a
stream that picked up later could tell a node that was written from one made
since; the cursor outgrew the service's limit at a few thousand objects, and a
directory that changes between streams made the parts disagree. One stream in
memory is exact.

What the stream offers and does to fit the contract:

- **One checkpoint, before anything is sent**, `{"v":1}`: a few bytes that name no
  place. Resuming from it reads the tenant from the start, which is all it could
  do. Nothing the collector knows travels in it.
- **A cursor it is handed is set aside.** The stream says so with a warning under
  `cursor.rejected`, as the contract requires of a collector that starts over, and
  collects the whole tenant, so it ends `COMPLETE` and not `PARTIAL_STREAM`.
- **A budget is reached at the end.** The contract applies a budget at the next
  checkpoint, and there is none until the stream is done. A stream that stopped at
  a budget would be started again from the beginning, to stop at the same place.
- **A failure offers no cursor.** The stream ends `INCOMPLETE` with its cause and
  nothing to resume from; the only recovery is a fresh collection.

What a stream keeps in memory: a hash of the id of each user, group, service
principal and administrative unit it wrote (8 bytes each, so that an edge can
tell a node it wrote from one made since), the members of each group (up to 10,000
for one group and 100,000 in all, so a group is read once however many roles it
holds), and 16 bytes of a hash of each membership and grant it has sent, so none
is sent twice, a group too big to keep included. None of it is more than the
stream may send.

**The limits: a million events and two gibibytes.** The service refuses a
collection of more than 1,000,000 events (nodes, edges, activity records, and the
progress and diagnostics that go with them) or of more than 2 GiB, and with no
resume every retry would read the whole tenant to meet the same wall. So the
stream counts what it sends. At 990,000 events, or when the records come to about
1.9 GiB (2 GiB less a reserve of 100 MiB), it stops reading, ends
`SCOPE_UNREACHABLE` with the tenant partial, and says so in a diagnostic,
`entra.limit.events` or `entra.limit.bytes`, naming the limit and what to turn
off. It never sends an event past either. The last 10,000 events, and 100 MiB, are
held back from records for the diagnostics and the progress that end a stream, and
the limit's own diagnostic is not held to them: records and other events stop two
events before the limit, so it and the completion always fit. The bytes limit is
for a tenant whose events are large, such as hundreds of thousands of dynamic
groups with long membership rules; an event is counted as its message and a few
bytes of framing. What costs the most events: sign-in activity is about four
events for each user (three signals and a node), so a tenant of about 250,000
users with activity reaches it before the groups are read. To bring a tenant under
it, withhold `AuditLog.Read.All` so that users are read without their activity,
and set `service_principals`, `app_roles`, `pim`, `administrative_units` and
`oauth2_grants` to false under `collect` for what is not needed. A group held by
many roles does not multiply the cost: each membership is sent once.

The parts run in this order: users, service principals, administrative units,
groups (these write nodes, and read nothing inside a page), then group members,
who holds each application's roles, directory roles, PIM and delegated grants
(these write edges). An edge only names a node whose part has ended or failed.

- **A part that fails does not abandon the others.** An operator needs the whole
  picture to fix one thing. The reasons the tenant is not whole are kept and the
  stream ends `SCOPE_UNREACHABLE` saying all of them. A rejected credential is not
  a failed part: it ends the stream.
- **A refused permission stays one.** A reason keeps its kind, so the stream that
  reports it says `PERMISSION_DENIED` and not that the source failed.
- **Activity is decided once, before the users are read**: with the sign-in
  activity the tenant answers, or without it, and the users are read under that
  answer. A probe that an outage will not let through decides "could not find
  out" and the collection goes on; one a throttle will not let through decides
  nothing and ends the stream.
- **A 429 is honoured, then reported.** A `Retry-After` of up to a minute is
  waited out, up to four times for a request, and each wait is reported as
  `Progress` with the rate limit, so a caller can tell slow from stuck. A 429 that
  names no delay waits five seconds. A longer wait, or one that keeps coming, ends
  the stream `RATE_LIMITED`, naming how long Graph asked for, so the caller comes
  back later and nothing sits on a connection for an hour. This holds for every
  request: the pages, the single reads (the organization, the activity probe, name
  lookups, confirming that a type of member cannot be read) and the check.
- **A 503 or 504, or a failure to reach Graph, is waited out too**, for the
  `Retry-After` it names or a short backoff, twice for a request. If it lasts
  longer, or names a wait of over a minute, the read fails and so does the part it
  was reading, like any other failure of a read; the parts after it are still
  read. A refusal, and a body that is not a page, fail the part at once; so does
  a 404 that is not Graph's own (see below).
- **Silence is reported.** A read that goes quiet inside a page, such as the
  members of a thousand groups, sends `Progress` at the heartbeat the caller
  asked for.
- **A read that goes round ends.** A next-page link that Graph returns twice, or a
  page of members, assignments or roles that comes back under another link, would
  loop under its own heartbeats; it is a failure of the part instead. A read of
  more than 100,000 pages, a part's own or one inside a page, is stopped.
- **A directory read in parts is not a snapshot, and the parts agree.** The
  members of a group are read by the group members part, and again by whatever
  reads a role the group holds. A group read once is not read again, and what it
  holds is derived from that read; a larger one is read again a page at a time,
  and its memberships are sent again. Every read that finds a member states its
  `MEMBER_OF` in the same pass as the role it gives, so the hop a path goes
  through was stated by the read that found the member. An edge names a node that
  a part owns (a user, group, application or administrative unit), and the owner
  has ended or failed by then:
  - the owner **failed**: it wrote some of its nodes and not others, so what
    names them is left out and counted (`entra.edges.left-out`), and a part that
    only names that owner's nodes is not run;
  - the owner **ended and wrote** the node: the edge is written;
  - the owner **ended and did not write** it, because it was made after the part
    ran: it is written as referenced, once, and an application written as
    referenced says that its sign-ins are not collected.

  A group deleted after it was listed has no members and is not unread
  (`entra.group.gone`), and neither is an application deleted after it was listed,
  whose roles no one holds (`entra.application.gone`). That holds only for Graph's
  own not-found, an error body whose code is one of Graph's not-found codes
  (`Request_ResourceNotFound`, `ResourceNotFound`, `ErrorItemNotFound`,
  `itemNotFound`, in any case). A 404 with any other body, which is what a proxy
  or gateway answers for a path it does not know, or with any other code, is a
  read that failed: the part fails, as for a 403 that is not Graph's, and the same holds for
  a principal that all three of its reads call gone. A role an application
  gained after the applications were listed, and was assigned, is written when its
  assignment is read. What a part counted before a throttle stopped the stream is
  still said.
- Delta queries exist for users, groups and roles and are not used: absence has
  to be computed from complete snapshots, not trusted from a change feed.

## What it collects

| Entra | Becomes | Notes |
|---|---|---|
| Tenant | `Scope` | Keyed by tenant ID, named by the organization |
| User, guest | `Identity`, human | Status from `accountEnabled`; unknown if Graph does not say. A guest is `userType` Guest or a `#EXT#` UPN. The SID of a synced user is kept as context, the handle that will correlate with an on-premises directory |
| Group | `Grouping` | Static or dynamic, with the rule and its processing state, `isAssignableToRole`, visibility |
| User in a group | `MEMBER_OF`, direct | Direct members only |
| Group in a group | `CHILD_OF`, direct | From `members`. Never from `transitiveMembers`, which is a flat list with no path |
| Directory role | `Entitlement` `role:<roleDefinitionId>` | Built-in and custom, with `built_in` as context |
| Role assignment to a user | `HOLDS`, direct | Over the tenant, the entitlement applies to the tenant scope |
| Role assignment to a role-assignable group | The group `HOLDS` direct; each direct member `HOLDS` effective, through the group | One hop: such a group cannot nest or be dynamic |
| Role over an administrative unit | A separate entitlement `role:<id>:au:<unitId>` that applies to the unit | The unit is named, not read |
| Service principal | `Identity`, service for an application, machine for a managed identity | Any other type is unknown. Status from `accountEnabled`. Sign-ins are not read, and each says so |
| An application's app role | `Entitlement` `app-role:<servicePrincipalId>:<appRoleId>`, applying to the application as a `Resource` | The all-zeros role is "Default access" |
| App role assigned to a user or an application | `HOLDS`, direct | An application holding another's role is an app-only permission |
| App role assigned to a group | The group `HOLDS` direct; each **direct** member `HOLDS` effective, through the group | Members of a group inside it are not claimed: Microsoft states direct members only |
| PIM eligibility | A separate entitlement `role:<id>:eligible`, "(eligible)" | Held by a user or an application directly. Held by a role-assignable group, it is eligible for each direct member through the group, as for a role that is held |
| Time-bound active assignment | A separate entitlement `role:<id>:active` | Only an assignment an administrator made that ends. A permanent one is among the role assignments, and an activation lasts hours and derives from an eligibility |
| Administrative unit (`administrative_units` on) | `Resource` `au:<unitId>` | Otherwise a unit a role names is a referenced resource |
| Delegated permission grant (`oauth2_grants` on) | `Entitlement` `oauth2-grant:<grantId>`, applying to the API it is against; the client application `HOLDS` it, direct | `consent_type` says whether an administrator consented for everyone or one user did |

A directory role is Entra's own named permission object, as a Keycloak role is,
so grants are `DIRECT` or `EFFECTIVE`, never `COARSE`.

Entitlement ids for roles are composed, and the grammar is part of what a
snapshot history keys on:

```
role:<roleDefinitionId>[:au:<unitId> | :scope:<directoryPath>][:eligible | :active]
```

`role:<id>` is the role, held, over the whole tenant; `:au:<unitId>` or
`:scope:<directoryPath>` is the same role over a narrower scope; `:eligible` and
`:active` are the PIM states. Each is a different entitlement because edge
identity is type, ends and path: eligible and held to one entitlement would be
one edge, and the history would merge who can become an administrator with who
is one. App roles are `app-role:<servicePrincipalId>:<appRoleId>`.

## What it does not collect

- **Conditional Access.** A grant shown here may be limited, or refused, by a
  policy this data does not show.
- **Azure RBAC.** Subscription and resource-group roles are a different API.
- **Workload roles and licences.** Exchange, SharePoint and Teams roles, and
  licences, are not directory roles.
- **Other tenants.** A guest is collected as this tenant sees them.
- **Devices and contacts as group members.** They are counted in a diagnostic,
  not collected.
- **Nested groups under an app role.** Counted in a diagnostic, not expanded.
- **Service principals as group members**, so long as Graph does not list them.
  Microsoft documents that the v1.0 endpoint listing a group's members returns
  none, and this collector reads v1.0 only. If it returns one, it is a member like
  any other, and a role it holds through the group is a path over that stated
  membership.

## What has not been verified

This collector was built from Microsoft's documentation and run against a fake
Graph. Nothing below has been seen against a tenant, and each is a limitation
and not a fact. The fake issues real tokens and checks real client assertions,
but it models only what Microsoft documents, so a behaviour that is not
documented is one no test can quietly depend on.

**Licences and errors**

- The refusal a tenant without Entra ID P1 or P2 is answered when
  `signInActivity` is selected. `Authentication_RequestFromNonPremiumTenantOrB2CTenant`
  and `AadPremiumLicenseRequired` are taken for a missing licence; a refusal of
  any other shape is reported as "could not find out", never as a missing
  licence.
- What Graph answers the PIM reads in a tenant not licensed for PIM, and whether
  PIM works at all on a P2 tenant: no PIM read has been made against a live
  tenant. The same two codes are taken for a missing licence; another code fails
  the collection, with the line to turn PIM off.
- Application permissions need administrator consent. That is Microsoft's
  documented model, and it is not checked here.
- That a missing permission is a 403 with a Graph error body, and not an empty
  answer, for every read except the group members described above.

**Group members**

- A member that comes back with a null name is confirmed as a missing permission
  by a 403 on reading the object itself. That a 403 is what Graph answers
  there, and that it is the same for every object of the type, is assumed.
- That the members of a hidden-membership group are refused with a 403 when
  `Member.Read.Hidden` is missing is assumed from Microsoft's statement that the
  permission is required.
- `$select` and `$top` on a group's members are used without the advanced-query
  headers. Microsoft's page says query parameters on that endpoint are supported
  "only with advanced query parameters" without saying whether `$top` and
  `$select` need them. The headers are not sent, because they read from an index
  that may be out of date and a review needs the directory as it is.
- Service principals as members of a group are absent from the v1.0 members
  list. Microsoft's page for that call still says so, as a known issue (the page
  was last updated in March 2026), and gives the beta endpoint, or reading
  `/groups/{id}?$expand=members` (which returns at most 20 members), as the way
  round. Neither is used: beta is not a stable contract, and a cap of 20 would
  lose users. So the memberships of applications in groups, and the roles an
  application holds through a group, are not collected from v1.0 today. If Graph
  lists them, they are handled as any member is: written by the service
  principals part, or as referenced if it did not list them, and left out and
  counted if that part failed. No test against Graph has seen one.
- A role assignment whose principal comes back null is resolved by reading the id
  as a user, a group and a service principal in turn. That all three answering
  Graph's own not-found means the principal is gone, and that this is what Graph
  answers for an id of another type, is assumed; one refused, or answered with a
  404 that is not Graph's, is a reason the tenant is not whole.
- That the group is hidden when its members are refused is found by reading the
  group's `visibility`; a group that cannot be read is not known to be hidden, and
  the refusal is reported as the group permission.

**Roles**

- Whether the instance lists include a principal's own eligibility when it comes
  through a group. Instances whose `memberType` is `Group` or `Inherited` are
  skipped and the group's own instance is expanded to its direct members; a
  tenant where Graph lists only the per-member instances would show fewer
  eligibilities than it has.
- Whether a time-bound assignment made through PIM also appears among the role
  assignments. If it does, the same person holds both `role:<id>` and
  `role:<id>:active`.
- That a schedule instance's end date is not carried: the contract's edge has no
  field for it.
- Whether the members of a group inside a group assigned an app role hold it.
  Microsoft states that direct members do and is silent on nested ones, so only
  direct members are shown and the nested groups are counted.
- How long an app role assignment takes to appear. Microsoft notes a replication
  delay on the list of who is assigned an application's roles and gives no
  figure.
- That a delegated grant's client is the right holder. A grant that one user
  consented to lets the client act as that user only; it is recorded as the
  client's, with the user as context. The paging of that list is not
  characterised, and no page size is requested.

**Paging and scale**

- That Graph's next-page links are on the host the client was configured for, and
  that Graph never answers a valid empty collection without a `value`. A link to
  another host is not followed, and a page with no `value` is an error.
- The patience for an outage, a backoff of two seconds a try and two tries, and
  for a throttle, a minute at most and four tries: chosen, not measured.
- That a tenant of tens of thousands of objects fits in memory in one stream: it
  does in the fake, at about a hash and a few records for each object, and has not
  been tried on a real one.
- Real throttling: how often Graph answers 429 for a tenant of a given size, and
  whether the waits here are enough. Microsoft publishes limits per tenant size
  and says a 429 is possible below them.
- A tenant of fifty thousand users, or five thousand service principals. The
  second costs a request per application for its role assignments, and Graph
  returns a hundred service principals a page.
- The month on which Entra began recording each sign-in signal. Microsoft gives
  April 2020 and May 2020, and the window starts at the end of the month.

**Clouds**

- The hosts of the national clouds are the ones Microsoft lists. No national
  cloud has been reached, and which API versions each supports has not been
  checked beyond Microsoft's own table.

## Checking it against a tenant

The claims above are questions for Microsoft, and two tests ask them. Both are
skipped unless `ACCIEW_ENTRA_LIVE=1`, so they cost CI nothing; give them an
application registered in a tenant, ideally one with Entra ID P2 or a trial of
it, and they log what Graph answers where this README assumes:

```sh
export ACCIEW_ENTRA_LIVE=1 ACCIEW_ENTRA_TENANT=example.onmicrosoft.com \
  ACCIEW_ENTRA_CLIENT=00000000-0000-0000-0000-000000000000 ACCIEW_ENTRA_SECRET=...
go test ./internal/graph   -run Live -v   # the claims, one at a time
go test ./internal/collect -run Live -v   # a whole collection, held to the contract
```

`ACCIEW_ENTRA_CLOUD` names a national cloud, `ACCIEW_ENTRA_FLAGS` sets the
`collect` flags, and `ACCIEW_ENTRA_NEXTLINK_WAIT` (such as `2h`) holds a
`nextLink` that long before following it.
