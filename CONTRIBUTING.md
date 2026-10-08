# Contributing

We are not accepting outside code contributions yet. Issues are welcome.

When we do, contributions are made under the
[Developer Certificate of Origin](https://developercertificate.org/): sign each
commit off with `git commit -s`. There is no CLA, and you keep your copyright.
"The Acciew Authors", in `NOTICE`, are the people whose commits are in this
repository's history.

The `dco` check fails a pull request with a commit that is not signed off. To
fix one that is already open:

```sh
git rebase --signoff origin/main && git push --force-with-lease
```

Edits made in the browser are signed off by GitHub, which this repository
requires.

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

To release `X`:

1. `./bin/task release:bump VERSION=X` and `./bin/task tidy`, in a pull request
   of their own, and merge it. Whoever installs a module ignores the replace
   directives and gets what its `go.mod` requires, so every module has to
   require its siblings at `vX` before the tags exist. It also moves the
   built-in version of the plugins, which an unstamped build reports, to
   `X-dev`. Until the tags exist, `main` requires versions that are not there,
   so go straight on to steps 2 and 3.
2. Run the `release` workflow from `main` with `X`. It checks that bump, runs
   everything CI runs, builds one archive per platform (Linux and macOS, amd64
   and arm64) holding the collectors and the agent, writes `SHA256SUMS`, attests how
   they were built, and leaves a draft release.
3. Tag the commit the workflow ran on, once for each module that is tagged
   (`api/vX`, `sdk/go/vX`, `sdk/conformance/vX`, `sdk/examples/minimal/vX`,
   `plugins/keycloak/vX`, `plugins/github/vX`, `plugins/awsiam/vX`,
   `plugins/entra/vX`, `cmd/acciew-agent/vX`), and push the tags. Then publish the draft, which
   creates `vX`.
