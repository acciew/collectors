# Contributing

We are not accepting outside code contributions yet. Issues are welcome.
Before the first outside contribution is merged we will publish the agreement
it needs (a DCO or a CLA).

## What belongs here

Only first-party collectors live in this repository, together with the contract,
the SDK and the conformance suite. A collector written by someone else belongs
in its own repository, built against the SDK and checked with the conformance
suite. We will list those rather than host them.

## How a change is made

- Write the failing test first, then the code that passes it.
- `./bin/task ci` must pass. It is exactly what CI runs.
- A collector never writes to its source. A change that makes one do so will not
  be accepted.
- A collector never reports "unknown" as "none". If a source cannot answer, the
  collector says so.
- Adding a collector adds an import rule for it in `importlint.json`, so that it
  cannot start importing another collector.

## Releases

Every module is tagged together, from one commit, with one version number. The
test-only `plugins/keycloak/integration` module is the exception: it is never
tagged.

The binaries are built by the `release` workflow: run it from `main` with a
version, and it runs everything CI runs, builds one archive per platform (Linux
and macOS, amd64 and arm64) holding the three collectors, writes `SHA256SUMS`,
attests how they were built, and leaves a draft release. Publishing the draft
creates the `v<version>` tag. The module tags (`api/v<version>`,
`sdk/go/v<version>` and so on) are made by hand at the same commit.
