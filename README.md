# Acciew collectors

The open-source part of Acciew: the contract, the SDK and the collectors that
read access out of the systems a company actually runs on. It is public so that
a security team can read exactly what touches their systems before they grant
anything.

A collector is a separate program. It reads one source, never writes to it, and
hands what it found to the Acciew host over a local connection. The host, the
inventory, the review workflow and the web app are not in this repository.

## What each collector reads

| Collector | Reads | Credential it needs | Writes? |
|---|---|---|---|
| [`plugins/keycloak`](plugins/keycloak) | Users, groups, realm and client roles, composites, role mappings; login events if the realm stores them | A service account holding the `realm-management` roles `view-users`, `view-clients`, `view-realm`, and `view-events` for activity. `manage-*` roles are accepted in place of `view-*`; the `query-*` roles are refused | Never |
| [`plugins/github`](plugins/github) | Organization members and roles, teams, outside collaborators, repository access, installed applications. **No activity**, on purpose | A token belonging to an owner of each organization read (a classic token needs `read:org` and `repo`). A narrower credential is not verified yet | Never |
| [`plugins/awsiam`](plugins/awsiam) | IAM users, groups, roles, attached policies, trust policies, the credential report | `iam:GetAccountAuthorizationDetails`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListAccountAliases`, and `sts:GetCallerIdentity` (which needs no permission). `sts:AssumeRole` when it is configured to read another account. The AWS-managed `SecurityAudit` policy covers the IAM calls. Not yet run against a live account | Never. `GenerateCredentialReport` asks AWS to build a report and changes nothing |

Each collector's README says what it collects, what it deliberately does not,
and what has not been verified.

## Checking a collector yourself

- Every request a collector makes is in its own module: `internal/admin`
  (Keycloak), `internal/api` (GitHub) and `internal/iam` (AWS, through the AWS
  SDK). The tests that start a real Keycloak, and the helper that seeds it, are in
  `plugins/keycloak/integration`, a module of its own, so the collector's `go.mod`
  carries no container library.
- A credential is never written into a configuration. It is a reference
  (`env:NAME` or `file:/path`) resolved inside the collector's own process, or it
  comes from the cloud SDK's own chain. The one literal is an AWS external ID,
  which AWS describes as an identifier and not a secret.
- Collectors do not import each other, and the SDK imports no collector. CI
  enforces both (`importlint.json`).

## Layout

```
api/                  the collector contract: protobuf types and the handshake
sdk/go/               the plugin SDK, what a third-party author imports
sdk/conformance/      the suite an author runs against their collector
sdk/examples/minimal/ the reference collector
plugins/              first-party collectors: keycloak, github, awsiam
docs/                 decision records, the source mapping, the authoring notes
tools/                pinned developer tooling
```

`api`, `sdk/go`, `sdk/conformance`, `sdk/examples/minimal` and each directory
under `plugins/` is its own Go module, and all of them are tagged together from
one commit. `plugins/keycloak/integration` is also a module, but it is only
tests: never installed, never tagged. The repository root and `tools/` have
`go.mod` files for tooling only. Import paths start with `go.acciew.io/collector`.

## Building

Needs Go 1.26+. Docker is needed only for the Keycloak integration test.

```sh
mkdir -p bin && GOWORK=off GOBIN="$PWD/bin" go -C tools install tool
./bin/task --list
./bin/task ci       # exactly what CI runs
./bin/task build    # every collector into ./bin
```

## Writing your own collector

See [`docs/plugins/README.md`](docs/plugins/README.md). Run the conformance suite
against it; it is the same one the first-party collectors pass.

## Security

Please do not open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
