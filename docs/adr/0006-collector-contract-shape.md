# 0006. Collector contract shape

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** designed against
  [the three-source mapping](../design/three-source-mapping.md), whose R1–R15
  are the requirements this shape has to satisfy.

## Context

`api/collector/v1/collector.proto` is the contract. Once a plugin we did not
write depends on it, changing it breaks someone else's build, so the shape has
to be right before the first tag rather than after.

The requirements come from mapping the vocabulary onto Keycloak, GitHub and AWS
IAM and writing down where each source broke it. This ADR records the decisions
that were not obvious once those requirements were fixed.

## Decision

### A flat node with the type in the key, not a `oneof` per record type

`Node` carries `Key{scope, type, id}` and a `source_type` string; only
`Identity` has structured facts, in a sub-message required iff the key type is
`IDENTITY`.

The type has to live in the key regardless, because an AWS role is
`(account, IDENTITY, AROA…)` **and** `(account, ENTITLEMENT, AROA…)` — one
source object, two nodes, and edges reference keys. Given that, a `oneof` with
four empty arms would be a second discriminator that can disagree with the
first, in exchange for a Go type switch the SDK provides anyway.

The *stream* is a `oneof`, because there the arms genuinely differ.

### `Path` is a list of node keys, with no per-hop edge type

The edge type of each hop is determined by the node types at its ends:
Identity→Grouping is `MEMBER_OF`, Grouping→Grouping is `CHILD_OF`,
Entitlement→Entitlement is `INCLUDES`, and so on. Storing it would be redundant
data waiting to disagree with the nodes.

This buys the rule that makes R3 checkable rather than decorative: **every hop
in a path is an edge that was itself emitted, directly stated rather than
derived.** A path is a walk over source-stated facts. That turns "the plugin's
resolution logic is correct" into something a fixture can assert, which is how
a Keycloak group-inheritance bug gets caught by the test suite instead of by a
reviewer looking at wrong evidence.

The case that looked like it needed a special hop — GitHub's organization base
permission, which grants every member access to every repository without any
collaborator record — is modelled honestly without one: emit a `Grouping` for
organization membership that every member is `MEMBER_OF` and that `HOLDS` the
permission. The path is then a real walk like any other.

That was half an answer, and a contrarian review found the other half. The
first version still needed a `HOLDS` edge per repository, so the plugin would
be fabricating M x R relationships from one stated fact, and asserting a
fidelity for each: `DIRECT` would be false, because the source states nothing
per repository; `EFFECTIVE` needs an intermediate node that does not exist;
`COARSE` would be wrong, because a repository permission level is evaluated,
not a bag of unevaluated ones. Every value was a lie.

**`APPLIES_TO` therefore accepts a `Scope` as well as a `Resource`.** The base
permission becomes one entitlement applying to the whole organization, and the
grant is one `HOLDS` edge from the membership grouping. AWS meets the same wall
the moment a policy names `Resource: "*"`, and the same shape answers it.

### `ACTS_AS`, an entitlement→identity edge

Without it the AWS role's two nodes are unrelated and "Alice may assume
`OrgAdmin`, which holds `AdministratorAccess`" has no path through the graph.
It was missing from R1 as first written; the requirement was corrected.

### `_UNSPECIFIED` is invalid on the wire, enforced in four places

proto3 forces every enum to have a zero value and buf requires it to be
`_UNSPECIFIED`. So the enum cannot make "the author forgot" impossible; only
convention can, and convention is what the contract is trying to replace.

The rule is: **zero is invalid for every enum in the contract; unknown non-zero
values are tolerated.** Where "we do not know" is an honest answer there is an
explicit `_UNKNOWN` value, and it is never zero — `IDENTITY_KIND_UNKNOWN` is 4.

Enforcement lives in one hand-written implementation in the contract module,
called from four places:

1. the **SDK**, before every emit, so a plugin author sees the error;
2. the **host**, on every received event, failing the collection as a contract
   violation attributed to the plugin — this is the load-bearing one, because a
   plugin written against an HTTP transport in another language never touches
   our SDK;
3. the **conformance suite**, for a friendlier report;
4. an end-to-end test with a fake collector that emits zero, proving (2).

### The contract module contains hand-written code

The rules above are part of the contract, not part of any consumer. If the SDK,
the host and the conformance suite each implemented them, they would drift, and
the drift would show up as a plugin that passes conformance and fails in
production. One implementation, in the module all three already depend on.

This reverses the "nothing hand-written goes here" line that `api/doc.go`
carried when the module held only generated code.

### A clean stream close is not success

Over gRPC, a stream that ends without error looks successful. For an evidence
product it is not: a truncated population that looks complete is worse than a
failure, because the error is invisible exactly when it does damage.

The rule, stated transport-neutrally so it survives ADR-0002 being revisited:
**a stream is successful if and only if its last event is a `Completion` with
`VERDICT_COMPLETE`.** A clean close without one is incomplete with cause
`PLUGIN_ERROR`. Events after a `Completion` are a contract violation.

A plugin that stops deliberately closes cleanly after an `INCOMPLETE`
completion carrying a resume cursor; a plugin that crashes produces a transport
error. Different endings, different recoveries.

The host surfaces this as `(snapshot, error)` with **both** non-nil on an
incomplete collection. The partial data is right there for whichever answer the
open question about partial exports gets, and Go's error handling makes the
error hard to drop.

### Resume is mandatory; there is no incremental capability

Every first-party source needs resumption, including Keycloak — its effective
client roles cost one request per user per client. A plugin that cannot resume
has no honest answer when the host caps a collection, so a capability that must
always be true is not a capability.

`incremental` is the opposite case: a capability that must always be false. No
first-party source can fetch less than a full population, and R10 concludes delta
streams cannot carry deletions. A bit that is always false implies a mechanism
we do not have. Its field number is reserved with the reason.

### Activity is a `oneof`, not a timestamp with a confidence enum

`seen` / `not_seen` / `unavailable` as three arms makes the invalid
combinations inexpressible — an unavailable result with a timestamp, or a bare
timestamp with no coverage — and makes a missing answer detectable, which a
scalar field cannot be.

`coverage.since` is required. An absent lower bound would read as "we see
everything", and that is the one lie in this contract a reviewer could not
detect: a user whose last login predates the retention window looks exactly
like a user who never logged in.

### `reserved` records a rejection; it does not hold a slot

Under buf's `FILE` breaking category a `reserved` statement is itself
permanent. Thirteen field numbers across the contract are reserved with a comment
saying what was considered and why it lost. A future field takes a fresh number
and reads the comment; it does not claim the reserved one.

### Reserved *names* turn prohibitions into compile errors

`reserved` also takes names, and protoc rejects any field that uses one. That
makes it a guard rail rather than a note, and the things worth guarding are
exactly the ones a future contributor — or a future agent — would add in good
faith without knowing why they must not:

| Message | Reserved names | What it prevents |
|---|---|---|
| `CollectRequest` | `as_of`, `at`, `point_in_time`, `since`, `delta`, `incremental` | A request for the source's *past* state. No first-party source can answer one. |
| `CollectResponse` | `tombstone`, `deleted`, `delta`, `removed` | A deletion stream. R10: absence is computed from complete snapshots. |
| `Node`, `Edge` | `permission`, `permissions`, `effective_permissions`, `verb`, `action` (and `level` on `Edge`) | A normalised permission verb, or a computed permission set for AWS. Both ruled out by ADR-0003. |
| `Completion` | `complete`, `partial`, `success`, `ok` | A boolean completeness flag — the precise failure mode R5 exists to prevent, because a caller can forget to read it. |
| `Activity` | `last_seen`, `timestamp`, `last_activity`, `last_used` | A bare top-level timestamp, bypassing the oneof and its coverage window. |
| `IdentityFacts` | `enabled`, `disabled`, `active` | A bool whose false default reads as "disabled" when the author forgot it. |
| `Capabilities` | `resume`, `resumable` | Re-introducing resume as a capability when it is mandatory. |

Verified: adding `as_of` to `CollectRequest` and `permission` to `Edge` both
fail to build with "use of reserved message field name".

A reservation cannot be removed under `FILE`, so this is a decision that
outlives everyone who remembers making it. That is the point.

## Alternatives rejected

### `protovalidate` instead of hand-written validation

The obvious choice: express the constraints as proto options and get validation
generated. Rejected: it puts a validation runtime in the module
that every plugin imports, and it cannot express the rules that actually matter
here — "every hop in a path is an edge that was emitted" is a property of a
stream, not of a message.

### A normalised permission model

A `Permission` or `Level` enum across sources, so that "write" means one thing.
Rejected because it would be an invention. GitHub `write`, a Keycloak client
role and an AWS policy attachment are not comparable, and a contract that says
they are has manufactured a claim no source supports. GitHub's ladder rank goes
in source context as GitHub's own fact.

### One edge per (subject, entitlement)

Simpler, and wrong. A person can hold the same entitlement by several routes at
once, and revoking one leaves the others. Collapsing them tells a reviewer that
removing someone from a team ends their access when it does not. Edge identity
includes the path.

### Generated gRPC stubs in a separate Go package

The design proposed splitting the service stubs out so that importers of the
messages never compile a transport. It is the right instinct and we are not
doing it, because it cannot be had cheaply: `protoc-gen-go-grpc` derives its
output package from `go_package`, so a separate Go package requires a separate
proto package, and buf's `PACKAGE_SAME_GO_PACKAGE` correctly forbids the
halfway version.

The cost of not doing it is close to zero in practice. Every Go consumer of the
contract — the host, the SDK, the conformance suite, any Go plugin — needs the
transport anyway. The isolation that ADR-0002 actually depends on is that no
*domain* package sees contract types at all. That is enforced in the host's own
repository, where only the plugin-host package may import the contract; here,
the SDK, the conformance suite and the collectors import it.

### The stream rules are checked where the data is bounded

`StreamChecker` in the contract module implements R15, and a contrarian review
made the obvious point about it: referential integrity and path walks cannot be
answered until every record has arrived, so the checker is linear in the size
of the tenant. Measured at roughly 270 bytes per edge after tightening it, and
it was 436 before. For a conformance fixture that is nothing. For a
fifty-thousand-user tenant, sitting alongside the host's own copy of the same
graph, it is the wrong place for the check to live.

So the rules are split by where the data is bounded:

| Rule | Where it runs |
|---|---|
| Every record-level rule in `validate.go` | The host, streaming. O(1) per record, retains nothing. |
| Completion present, exactly once, last; counts agree; checkpoint offered | The host, per stream. Constant state. |
| Referential integrity; path walks; activity uniqueness | The **store**, after load — a foreign key and a recursive query over data that is on disk anyway. And the **conformance suite**, over bounded fixtures. |

That is not a weakening. The store is a better place for referential integrity
than a hash map: it is the only place that can also check it against records
from a *previous* collection, which is what catches a plugin whose keys are not
actually stable across runs.

`StreamChecker` remains the conformance suite's implementation and the one
tests use, which is what keeps the rules stated once.

## Consequences

- The contract is frozen from the commit that lands it: `buf breaking` runs
  against `origin/main` with the `FILE` category, so a renumber, rename, type
  change or `oneof` change fails CI. Verified.
- `validate.go` and the stream checker enforce the rules above, in one
  implementation that the SDK, the host and the conformance suite share.
- The conformance suite has real assertions to make: capabilities match
  behaviour, paths are walks, counts match, resume produces the union.
- A reviewer UI can render a badge (`source_type`), a strength (`fidelity`),
  a route (`path`) and a caveat (`limitations`, `Activity.coverage`) without
  knowing what a realm is.
- We cannot answer "who can read this bucket". Nothing in the contract implies
  we can.

## Revisit when

- A fourth `Fidelity` value is proposed. Split the two axes it conflates first;
  a fourth value on a conflated enum is where this becomes unreadable.
- A source appears that can genuinely fetch less than a full population, at
  which point `incremental` gets a real mechanism and a fresh field number.
- A non-Go plugin is written, which is the first real test of whether the
  contract is transport-neutral in practice rather than in intent.
