# Writing a collector

The authoring guide is not written yet. A collector is a separate program that
the Acciew host launches and talks to over the contract in [`api/`](../../api).
Until the guide exists, start from:

- [`sdk/go/README.md`](../../sdk/go/README.md): the SDK, and what it promises
  about compatibility.
- [`sdk/examples/minimal`](../../sdk/examples/minimal): a complete collector in
  its own module, built the way a third party would build one. Its tests run the
  conformance suite against it.
- [`sdk/conformance`](../../sdk/conformance): the suite to run against your own
  collector. A check that fails names the rule from the design notes it enforces.
- [`docs/design/three-source-mapping.md`](../design/three-source-mapping.md):
  the vocabulary, how Keycloak, GitHub and AWS IAM map onto it, where each one
  breaks it, and the requirements those breaks put on the contract. This is why
  the contract looks the way it does.
- [`docs/adr/0002-plugin-transport.md`](../adr/0002-plugin-transport.md): how
  collectors are launched and talked to, and why an author should never have to
  know.
