# 0007. The GitHub collector's shape, and why it needed no contract change

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** the project, from the analysis in
  [the three-source mapping](../design/three-source-mapping.md#23-github).

## Context

GitHub is in this release for one reason: it is structurally unlike Keycloak, and
if the contract has to change to accommodate it, that is the point, and the
change should be made before the first tag.

Four things about GitHub have no analogue in Keycloak.

An organization has a **base permission** that every member holds on every
repository, and GitHub states it once, on the organization. It is invisible in
the collaborator list a collector would reach for first. Verified against a
real organization: `?affiliation=direct` returned nothing on a repository that
several people can push to.

Repository permissions are an **ordered ladder** — read, triage, write,
maintain, admin — where Keycloak has a set of roles a principal either holds
or does not. And **custom repository roles sit alongside the ladder without
being on it**: a custom role is a base role plus fine-grained permissions, so
two grants that both read `write` need not be the same access.

GitHub will **resolve the question itself**. Each collaborator comes back with
the level GitHub computes for them, with every term already combined — but
without the route, which is the part a reviewer acts on.

And GitHub **rate-limits**. A large organization does not fit in one window,
so a collection ending early is an ordinary outcome rather than a failure.

## Decision

**No change to the contract was needed.** Every break above is expressed with
what `collector.proto` already has. That result is worth stating explicitly,
because it was the question being asked; the reasoning for each is below,
so a reader can disagree with a specific one rather than with the conclusion.

**The base permission is one entitlement applying to the scope.** A synthetic
grouping holds every member; one `HOLDS` edge gives it the entitlement; one
`APPLIES_TO` edge points at the organization rather than at any repository.
Each member gets one derived `HOLDS` so that asking what a person holds
answers with their most far-reaching access — one edge per member, not one per
member per repository. Expanding it would emit relationships GitHub never
stated, quadratically: 5,000 members over 2,000 repositories is ten million
edges for a single fact.

The cost is real and is stated in the plugin's README and its declared
limitations: asking who can write to *one* repository does not include the
people who can write to *everything*.

**The ladder travels as source context, and custom roles carry no rank.** A
default level carries its rank and the ladder it belongs to; a custom role
carries the base role it extends and is marked as not comparable. A consumer
that understands GitHub can order what is orderable, and one that does not
renders the badge. The alternative — a normalised strength on the contract —
would invite comparison of a GitHub `write` with an AWS policy attachment,
which is the confusion the fidelity enum exists to prevent.

**Ownership is a grouping, because a derived grant must say what it came
through.** An organization owner administers every repository by virtue of the
role. The contract rejected the first attempt at this: an `EFFECTIVE` edge
with no path. It was right to. "Alice has admin on service" is not something a
reviewer can act on; "via being an owner of acme-org" tells them exactly what
taking it away would mean. The rule forced a better model rather than needing
a change.

**GitHub's own answer is a check, not the answer.** The collector derives
grants with their routes and then compares its result with GitHub's resolved
level. A disagreement is a warning naming both, because one of them is wrong
and quietly taking GitHub's number would hide a bug in the routes being shown
to people. It costs a request per repository, so it is sampled by default.

**Identities are keyed by GitHub's numeric database id.** R9 fixes a property,
not a format: the id must survive a rename. A login does not.

**No last-activity at all.** Nothing GitHub offers below Enterprise
supports a dormancy decision, and the collector declares that rather than
producing a signal that would be confidently wrong.

## Alternatives rejected

### Expanding the base permission into a grant per member per repository

Accurate per repository, and quadratic. It also states relationships the
source never made, which is the thing that makes an inventory untrustworthy in
a way no amount of correctness elsewhere repairs. The honest shape is the one
GitHub uses.

### A fourth fidelity value for "resolved by the source rather than by us"

Tempting when GitHub hands over its own answer. R2 says plainly: if a fourth
value is ever proposed, split the axes first. And the value would not earn its
place — GitHub's answer has no route, so it is not a grant we could emit at
all, only a number to check ours against.

### Ordering repository levels with `INCLUDES` edges between rungs

It would express the ladder in the graph rather than in context, and it would
multiply every derived edge by the number of rungs below the one held: an
admin on a repository would hold five entitlements instead of one. The
ordering is a property of GitHub's *default* roles, not of its permissions in
general, so the graph would also be asserting an ordering that custom roles
break.

### Taking REST's team membership at face value

It is transitive: it includes the members of child teams. Emitted as
membership, that states an inherited route as a direct one and tells a
reviewer to remove somebody from a team they are not in. Subtracting the
descendants is wrong in the other direction, because somebody can be in both a
parent and a child directly. The collector asks GraphQL for immediate
membership and says so in a warning when it cannot.

## Consequences

Easy: adding a source whose model is unlike the ones already here — the
contract absorbed a second one without moving.

Hard, and stated: a reviewer asking about one repository has to read the
organization-wide grants too. A large organization needs more than one
rate-limit window, and the core does not yet stitch two streams into one
snapshot, so such an organization cannot presently be collected end to end.
That is a gap in the core, not in the contract.

To live with: a team that grants access to many repositories produces derived
edges proportional to its membership times its repositories. That is the true
size of that organization's access, and R3 asks for it, but it is where the
"one fact covering many" answer does not reach — `APPLIES_TO` a scope covers
"every repository in the organization", not "these two thousand".

## Revisit when

An Enterprise organization is available to test against. Three things are
gated behind one: the audit log, and with it any activity at all; custom
repository roles and organization roles; and internal-repository visibility,
which is a fifth term in the effective permission that this release does not model.

Also revisit when the core learns to stitch resumed streams, because that is
what makes a large organization collectable at all.
