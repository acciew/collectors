# Acciew Go SDK — compatibility policy

`go.acciew.io/collector/sdk/go`

This document is a commitment, not an intention. Once a plugin you did not
write is running in someone else's cluster, breaking any of the promises below
is a trust breach rather than a release note. It was published before the first
tag on purpose: a compatibility policy written after third parties exist is
written under pressure.

## What is covered

Three separable things, with different rules:

| Surface | What it is | Rule |
|---|---|---|
| **The wire contract** | `api/collector/v1` — the protobuf messages and service | Never broken within a major version. See below. |
| **The Go SDK** | this module | Semantic versioning, with the v0 caveat below. |
| **The transport** | how bytes move between host and plugin | Deliberately *not* part of the contract. See [ADR-0002](../../docs/adr/0002-plugin-transport.md). |

The split matters. A plugin author writes against the contract and the SDK. The
transport is ours to change, and the SDK exists so that changing it does not
reach you.

## The wire contract

**Field numbers are never reused.** A removed field's number and name are moved
to `reserved` in the same commit that removes them. There is no exception to
this, including for fields we believe nobody ever set.

**The protocol version is negotiated in the handshake.** A plugin declares the
protocol versions it implements; the host declares the versions it supports;
they agree on the highest in common. A plugin that cannot agree fails to start
with a message naming both sides' ranges — it does not start and then
misbehave.

**Within `collector/v1`, these are non-breaking** and may happen in any release:

- adding a new message, or a new field to an existing message;
- adding a new enum value, provided consumers already handle unknown values —
  the SDK's helpers do;
- adding a new RPC;
- adding a new capability to `Describe`.

**These are breaking** and require `collector/v2`, with `v1` supported
alongside it for the deprecation window below:

- removing or renaming a field, message, RPC or enum value;
- changing a field's type or cardinality;
- changing the meaning of an existing field, which is the one people forget —
  a field that silently starts meaning something else is worse than a field
  that disappears, because it fails quietly;
- making an optional field required, or tightening validation on an existing
  one.

**Unknown fields are preserved, never rejected.** A newer host talking to an
older plugin, or the reverse, must degrade rather than fail.

## The Go SDK

Semantic versioning on `go.acciew.io/collector/sdk/go`.

**While the module is v0**, the exported Go API may change in a minor release.
This is the standard Go v0 meaning and it is the honest state of things today.
What does *not* change during v0: the wire contract rules above. A v0 SDK
release will not silently reuse a field number.

**From v1 onward**, the exported API follows semver strictly: no removals or
signature changes outside a major version.

Anything under an `internal/` directory in this module is not part of the API
and may change at any time.

## Deprecation window

When a contract major version is superseded, the previous one is supported for
**at least twelve months** from the release that introduces its successor, and
the host speaks both for that whole period. Deprecations are announced in the
release notes of the version that introduces the replacement, not in the one
that removes the old thing.

## What a plugin must do to hold up its end

- **Declare capabilities honestly in `Describe`.** The host degrades gracefully
  against what you say you can do. A plugin that claims activity data and emits
  zero values is worse than one that claims nothing, because the reviewer sees
  a timestamp and believes it.
- **Handle unknown enum values.** You will receive them from a newer host.
- **Never treat an unrecognised field as an error.**
- **Say what kind of failure an error is, when you know.** Two optional
  interfaces, both found through `errors.As` so wrapping is fine:
  `Faulty` (`Fault() Fault`) classifies the failure — auth, permission, rate
  limited, unavailable — and `Retryable` (`CanRetry() (bool, time.Duration)`)
  says whether waiting would help and for how long. They are separate
  questions on purpose: a rate limit that names no delay is still a rate
  limit, and an outage that names one is still an outage. Implement neither
  and every failure reaches the operator as a plain source error, so "wait"
  and "go and change something" read the same.
- **Pass the conformance suite.** `sdk/conformance` is what turns the promises
  above into something checkable. It asserts that declared capabilities match
  observed behaviour; a plugin that lies fails it.

## What the host promises you

- It will not call an RPC your declared protocol version does not contain.
- It will not require a capability you did not declare.
- It surfaces your structured errors and logs as yours, attributed to your
  plugin, rather than flattening them into a host error.
- A partial collection is reported as partial. The host will never present your
  incomplete result as a complete one — see requirement R5 in the
  [three-source mapping](../../docs/design/three-source-mapping.md).
