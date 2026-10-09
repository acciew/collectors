# Acciew collectors

The open-source part of Acciew: the contract, the SDK and the collectors that
read access out of the systems a company actually runs on. It is public so that
a security team can read exactly what touches their systems before they grant
anything.

A collector is a separate program. It reads one source, never writes to it, and
hands what it found to the Acciew host over a local connection. The host, the
inventory, the review workflow and the web app are not in this repository, with
one exception: [`acciew-agent`](cmd/acciew-agent), the host a customer runs in
their own network for sources the service cannot reach. It is here for the same
reason the collectors are: it handles credentials, and you should be able to read
it.

Four collectors are here: Keycloak, GitHub, AWS IAM and Microsoft Entra ID, the
last of which is in no release yet. They are the first, not the set. The
contract and the SDK are how every other one is written, by us or by anyone, and
`sdk/conformance` is the suite an author runs against theirs. A collector
written by someone else lives in its own repository; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## What each collector reads

| Collector | Reads | Credential it needs | Writes? |
|---|---|---|---|
| [`plugins/keycloak`](plugins/keycloak) | Users, groups, realm and client roles, composites, role mappings; login events if the realm stores them | A service account holding the `realm-management` roles `view-users`, `view-clients`, `view-realm`, and `view-events` for activity. `manage-*` roles are accepted in place of `view-*`; the `query-*` roles are refused | Never |
| [`plugins/github`](plugins/github) | Organization members and roles, teams, outside collaborators, repository access, installed applications. **No activity**, on purpose | A token belonging to an owner of each organization read (a classic token needs `read:org` and `repo`). A narrower credential is not verified yet | Never |
| [`plugins/awsiam`](plugins/awsiam) | IAM users, groups, roles, attached policies, trust policies, the credential report | `iam:GetAccountAuthorizationDetails`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListAccountAliases`, and `sts:GetCallerIdentity` (which needs no permission). `sts:AssumeRole` when it is configured to read another account. The AWS-managed `SecurityAudit` policy covers the IAM calls. Not yet run against a live account | Never. `GenerateCredentialReport` asks AWS to build a report and changes nothing |
| [`plugins/entra`](plugins/entra) | Users, guests, groups and their nesting, directory roles and who holds them (held, eligible or time-bound through PIM), service principals, app roles and who holds them, and when users last signed in. Administrative units and delegated permission grants when asked | An application registration in the tenant with admin-consented application permissions: `User.Read.All`, `Group.Read.All`, `RoleManagement.Read.Directory` and `Application.Read.All`, then `AuditLog.Read.All` (with Entra ID P1 or P2) for activity, `Member.Read.Hidden`, `Organization.Read.All`, and `AdministrativeUnit.Read.All` or `Directory.Read.All` only for the optional parts. A client secret or a certificate, as a reference. Not yet run against a live tenant | Never |

Each collector's README says what it collects, what it deliberately does not,
and what has not been verified.

## Checking a collector yourself

- Every request a collector makes is in its own module: `internal/admin`
  (Keycloak), `internal/api` (GitHub), `internal/iam` (AWS, through the AWS
  SDK) and `internal/graph` (Entra, over `net/http`). The tests that start a real
  Keycloak, and the helper that seeds it, are in `plugins/keycloak/integration`,
  a module of its own, so the collector's `go.mod` carries no container library.
- A credential is never written into a configuration. It is a reference
  (`env:NAME` or `file:/path`) resolved inside the collector's own process, or it
  comes from the cloud SDK's own chain. The one literal is an AWS external ID,
  which AWS describes as an identifier and not a secret.
- A release's archives are listed with their digests in `SHA256SUMS` and carry a
  build provenance attestation, which names the workflow run and commit that
  built them. `acciew-collector-<name> --version` says which build you have; so do
  `acciew-agent` and `acciew-verify`.
  The check needs a recent `gh`: 2.102 verified the v0.1.1 archives, 2.52 could
  not read the signing roots.

  ```sh
  gh attestation verify <archive> --repo acciew/collectors \
    --signer-workflow acciew/collectors/.github/workflows/release.yml
  ```
- Collectors do not import each other, and the SDK imports no collector. CI
  enforces both (`importlint.json`). The agent imports no collector either, and
  nothing imports the agent.
- The agent makes outbound HTTPS requests only, holds a key and not a secret, and
  reads a source credential only from the environment variable or file on its own host that the operator listed.
  Its README says what it sends, and [`docs/agent-protocol.md`](docs/agent-protocol.md)
  is the protocol.

## Checking an evidence pack

[`verify/`](verify) is the checker for the evidence Acciew exports: `acciew-verify pack <folder|archive.zip>`
checks a pack against its manifest, each log against its anchor, and the manifest, `campaign.json` and the
workflow log against one another. It is one module, standard library only, that imports nothing else
here. [`verify/README.md`](verify/README.md) says what a pass shows and what it does not,
[`docs/evidence-format.md`](docs/evidence-format.md) is the format it checks, and
[the decision record](docs/adr/0015-evidence-verifier.md) says why it is built this way.

`acciew-verify` is in each release's archive, beside the collectors and the agent, for Linux and
macOS on amd64 and arm64. On Windows, download `acciew-verify-X.Y.Z-windows-amd64.zip` (or `-arm64`)
from the release: it holds only `acciew-verify.exe` and the licence, notice and README files, in a
folder named like the zip. Unzip it, then run the program from that folder in a terminal:

```powershell
cd .\acciew-verify-X.Y.Z-windows-amd64
.\acciew-verify.exe pack C:\path\to\pack.zip
```

The zip is listed in `SHA256SUMS` and attested like the other archives. To compare its digest, run this
in PowerShell with the digest from `SHA256SUMS`; it prints `True` (`Get-FileHash` writes capitals and
`SHA256SUMS` lower case, and `-eq` ignores case):

```powershell
(Get-FileHash .\acciew-verify-X.Y.Z-windows-amd64.zip).Hash -eq '<digest from SHA256SUMS>'
```

The verifier also installs with Go, at the version of a release:

```sh
go install go.acciew.io/collector/verify/cmd/acciew-verify@vX.Y.Z
acciew-verify version
```

The archive's attestation (above) is how to check that the binary in it is the one the release
workflow built. A release that has not been cut has no archive, and the module has no tag until it
is.

## Layout

```
api/                  the collector contract: protobuf types and the handshake
sdk/go/               the plugin SDK, what a third-party author imports
sdk/conformance/      the suite an author runs against their collector
sdk/examples/minimal/ the reference collector
plugins/              first-party collectors: keycloak, github, awsiam, entra
cmd/acciew-agent/     the agent: runs collectors in a customer's network, uploads over HTTPS
verify/               the evidence verifier: reads exported logs and packs and checks them against themselves
docs/                 decision records, the source mapping, the authoring notes
tools/                pinned developer tooling
```

`api`, `sdk/go`, `sdk/conformance`, `sdk/examples/minimal`, `cmd/acciew-agent`, `verify` and
each directory under `plugins/` is its own Go module, and all of them are tagged together from
one commit. `plugins/keycloak/integration` is also a module, but it is only
tests: never installed, never tagged. The repository root and `tools/` have
`go.mod` files for tooling only. Import paths start with `go.acciew.io/collector`.

## Building

Needs Go 1.26+. Docker is needed only for the Keycloak integration test.

```sh
mkdir -p bin && GOWORK=off GOBIN="$PWD/bin" go -C tools install tool
./bin/task --list
./bin/task ci       # exactly what CI runs
./bin/task build    # every collector, the agent and the verifier, into ./bin
```

## Writing your own collector

See [`docs/plugins/README.md`](docs/plugins/README.md). Run the conformance suite
against it; [`sdk/examples/minimal`](sdk/examples/minimal) is a collector that
passes it.

## Security

Please do not open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
