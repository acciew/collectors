# 0002. Plugin transport

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** the project. This ADR records the trade-off and the isolation
  requirement that keeps the default reversible.

## Context

Collectors run as separate processes. The core launches them, hands them
configuration, and reads a stream of inventory records back. The question is
what runs between the two processes.

This decision has an unusual property: it is **not primarily a technical
choice**. The transport determines who can write a collector. gRPC over a Unix
socket means a collector author writes Go (or generates stubs, links a gRPC
library, and implements a handshake). HTTP over a Unix socket means a
collector could be a Python script, a shell script that shells out to `aws`,
or a Node service someone already has.

For an open-source collector SDK, the size of the set of people who can write a
collector in an afternoon matters. It is not a variable engineering gets to set
alone: it depends on who the authors turn out to be, which is still open.

So the requirement is to pick a working default now and to **make the choice
cheap to revisit later**.

## Decision

**Default to HashiCorp go-plugin, gRPC over a Unix domain socket.**

**Isolate it.** The transport is an implementation detail of
`internal/pluginhost`. No package outside `internal/pluginhost` may name
go-plugin, gRPC, sockets, or subprocesses. The rest of the core sees a Go
interface over domain types; a plugin sees the SDK.

**Negotiate a `kind` in the handshake, not just a version.** `collector/v1` is
the first kind. Notifier, exporter, enricher and revoker become new *contracts*
later rather than a new *mechanism*. A host that only knows how to launch
collectors is a host that has to be rewritten the first time we need anything
else.

**Keep the protocol definition transport-neutral.** The contract in
`api/collector/v1/collector.proto` is protobuf as a schema. Protobuf serialises
fine over HTTP, and the same message definitions survive a transport change.
The commitments in the contract — field numbers are never reused, the protocol
version is negotiated at handshake — are properties of the schema, not of gRPC.

## Alternatives rejected

### HTTP over a Unix socket, as the default

The accessibility argument is real and it is the strongest argument against the
decision above. A collector that is a fifty-line Python script is a collector
that gets written.

Rejected as the *default* for this release because go-plugin gives us, on day one and
for free, the things a hand-rolled HTTP host has to earn: process lifecycle and
supervised shutdown, mutual handshake with version negotiation, a magic cookie
so a stray binary cannot be mistaken for a plugin, log and stderr passthrough
into the host's structured logger, and typed streaming with cancellation.
Rebuilding those correctly is a fortnight that the first release should spend on the
contract and the Keycloak collector instead.

This is a deferral, not a refusal. The isolation requirement above exists
entirely so that this alternative stays cheap.

### Plugins compiled into the binary (Go plugin registry, or `plugin.so`)

The simplest thing that could work, and it is how many Go tools do it. Rejected
on the central architectural claim: if a collector is a Go package the core
imports, then the core imports Keycloak, and the boundary that this whole
architecture exists to create is gone on the first commit. `plugin.so` also
requires exact toolchain matching and does not work on all target platforms.

### WASM

Attractive on isolation and on the multi-language argument at once. Rejected for
the first release: the host runtimes are young, the
host-call story for outbound HTTP with corporate proxies and custom CAs is
immature, and debugging a failing collection inside a WASM sandbox is a much
worse experience for both humans and agents than reading a subprocess's stderr.

### stdin/stdout with newline-delimited JSON

Maximally accessible, zero dependencies, and genuinely tempting. Rejected
because it has no answer for concurrent streams, backpressure, or
cancellation mid-collection — and cancellation mid-collection is exactly the
case that matters when a source starts rate-limiting. It also gives up typing at
the moment we most want it: at the boundary with third-party code.

## Consequences

- First-party collectors are Go programs. That is fine: all three are ours.
- `internal/pluginhost` carries the transport's dependencies. They must not
  leak: the import linter forbids the reverse direction, and code review has to
  hold the line on this one, because a `google.golang.org/grpc` import in
  `internal/inventory` would pass every automated check we have.
- The SDK's public surface must not expose go-plugin types either. A plugin
  author implements an interface over domain types and calls `sdk.Serve`. If
  a plugin author has to know that gRPC exists, the transport is not isolated
  and the alternative above has become expensive again.
- Switching to HTTP later means rewriting one package and re-releasing the SDK.
  Plugins' domain logic — the part that is actually hard — is untouched.

## Revisit when

- Non-Go collector authors turn out to be a meaningful part of the audience.
- Someone outside the team tries to write a collector and the first thing they
  hit is the gRPC toolchain.
- We need a collector to run somewhere a subprocess cannot: in-cluster as a
  separate deployment, or on the customer's side of a network boundary.
