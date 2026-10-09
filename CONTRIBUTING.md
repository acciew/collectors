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
   of their own, and merge it. Whoever requires a module ignores its replace
   directives and gets what its `go.mod` requires, so every module has to
   require its siblings at `vX` before the tags exist (the verifier has no
   sibling to require, so for it only the built-in version moves). It also moves
   the built-in version of the plugins, the agent and the verifier, which an
   unstamped build reports, to `X-dev`. Until the tags exist, `main` requires
   versions that are not there, so go straight on to steps 2 and 3.
2. Run the `release` workflow from `main` with `X`. It checks that bump, runs
   everything CI runs, builds one archive per platform (Linux and macOS, amd64
   and arm64) holding the collectors, the agent and the verifier, and for Windows (amd64 and arm64)
   a zip holding the verifier alone, writes `SHA256SUMS`, attests how
   they were built, and leaves a draft release.
3. Tag the commit the workflow ran on, once for each module that is tagged
   (`api/vX`, `sdk/go/vX`, `sdk/conformance/vX`, `sdk/examples/minimal/vX`,
   `plugins/keycloak/vX`, `plugins/github/vX`, `plugins/awsiam/vX`,
   `plugins/entra/vX`, `cmd/acciew-agent/vX`, `verify/vX`), and push the tags. Then publish the
   draft, which creates `vX`.

`go install pkg@vX` is not the same as requiring a module: it refuses a module whose
`go.mod` has replace directives, and the modules of the collectors, the agent and the
reference collector have them. The verifier's module has none and requires nothing, so
the verifier is the one command in this repository that installs that way
(`go install go.acciew.io/collector/verify/cmd/acciew-verify@vX`, through the `verify/vX`
tag, reporting `X`); the agent and the collectors are installed from the archives, and
no document says to `go install` them.

Which build a binary from an archive is: `--version`, which the release stamps, the
`vcs.revision` in its build information, and the attestation on its archive. Its build
information records its main module as a version of the commit and the other modules of
this repository as `(devel)`, because the tags are made after the build, from a workspace;
that is not the version, and `govulncheck -mode=binary` cannot match a module of ours by it.
