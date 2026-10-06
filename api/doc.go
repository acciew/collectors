// Package api is the root of the collector contract module.
//
// This module is separate so that a collector author depends on the contract
// without depending on anything else of ours. It carries the contract and
// nothing else:
//
//	api/collector/v1/     collector.proto and the Go generated from it
//	api/plugin/v1/        the handshake a host and a collector negotiate
//
// Besides the generated code, this module is where the contract's semantic
// rules live — the ones protobuf cannot express, such as "a grant's fidelity is
// never unspecified" and "every hop in a path is an edge that was itself
// emitted". They live here rather than in the SDK because the SDK, the plugin
// host and the conformance suite all have to apply exactly the same rules, and
// one implementation is the only arrangement in which they cannot drift apart.
// See docs/adr/0006-collector-contract-shape.md.
package api
