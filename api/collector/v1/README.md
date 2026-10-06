# `collector/v1`

The collector contract: `collector.proto`, the Go generated from it, and the
contract rules protobuf cannot express.

Two commitments hold from the first tag, and both are checked rather than
promised:

- **Field numbers are never reused.** A removed field's number is reserved.
  `task proto:breaking` compares against `origin/main` with buf's `FILE`
  category, the strictest, so a renumber or rename fails CI.
- **The protocol version is negotiated in the handshake** (`api/plugin/v1`),
  not assumed.

`reserved` also carries names, and protoc rejects any field that uses one.
That is how rules we decided on became compile errors rather than things to
remember: `as_of` on `CollectRequest`, `permission` on `Node`
and `Edge`, `tombstone` on `CollectResponse`, and others. See
[ADR-0006](../../../docs/adr/0006-collector-contract-shape.md).

`validate.go` and `streamcheck.go` are hand-written and live here on purpose:
the SDK, the plugin host and the conformance suite must apply exactly the same
rules, and three implementations would drift.

Once anything outside this repository builds against this contract, breaking it
is a trust breach rather than a release note.
