# AWS IAM collector

Collects users, groups, roles and policy attachments from one AWS account's
IAM. It changes no access, and the only call it makes that is not a read is
asking AWS to generate a credential report.

```sh
# Credentials come from the AWS SDK's own chain: environment, shared config,
# an instance or pod role. Nothing about them is in the configuration.
echo '{}' > aws.json
```

The Acciew host runs the collector with this configuration: a check first, then a collection.

To read another account, assume a role into it:

```json
{
  "role_arn": "arn:aws:iam::123456789012:role/AcciewReader",
  "external_id": "your-external-id",
  "region": "us-east-1"
}
```

## The one thing to understand first

**An entitlement here is a container of permissions nobody evaluated.**

An AWS principal's effective permissions are the outcome of evaluating
identity policies, resource policies, permission boundaries, service control
policies and session policies together, against a specific action on a
specific resource in a specific condition context. There is no list to fetch
and there cannot be one — computing it well is the entire business of the CIEM
vendors.

So a grant here says "alice holds the policy `AdministratorAccess`", not
"alice can delete this bucket". That is honest, cheap, and genuinely useful
for the access-review question — *should this person still have this?* — while
being useless for the least-privilege question — *what can this person
actually do?*

Every grant is marked **coarse**, which is why: a reviewer must never be shown
an AWS policy attachment and a resolved Keycloak role rendered as the same
strength of claim. See [ADR-0003](../../docs/adr/0003-coarse-entitlements-for-aws-iam.md).

## What it collects

| AWS | Becomes | Notes |
|---|---|---|
| Account | `Scope` | |
| IAM user | `Identity` | Keyed by unique id (`AIDA…`), not ARN |
| Account root user | `Identity` | Marked as such — see below |
| IAM group | `Grouping` | |
| IAM role | `Identity` **and** `Entitlement` | Joined by `ACTS_AS` |
| Managed policy | `Entitlement` | Keyed by ARN |
| Inline policy | `Entitlement` | Keyed by principal and name |
| A trust policy entry | A `HOLDS` on the role entitlement | Including principals outside the account |

**A role is two things at once.** It is a principal that holds policies, and
"may assume it" is a permission somebody holds. One object, two nodes, joined
by an edge that says holding the entitlement lets you act as the identity.
This is the case the whole contract was shaped around, and AWS is where it
stops being an edge case: verified on a real account, roles
outnumbered users by a wide margin.

**The account root is collected separately, because AWS does not return it.**
`GetAccountAuthorizationDetails` does not include the root user. It is the
most privileged principal in the account, and it appears only in the
credential report.

**Principals outside the account are named, not dropped.** "Anybody in account
444455556666 may assume this role" is precisely the finding a reviewer wants.
They are recorded as *referenced* rather than enumerated, because that is what
they are: named to us, never read.

**A trust entry with a condition says so.** Assumption may be allowed only
when a condition holds — a source IP, an MFA claim, a matching OIDC subject —
and this collector does not evaluate conditions. Every GitHub Actions role
uses that shape, and "may assume this role" without "when" would overstate it,
so the grant is marked as carrying an unevaluated condition.

## Activity, and the sentinel that makes it dangerous

Three signals, and a user has two of them because a console password and an
access key are different facts. Verified on a real account: one user last
signed in long ago with no active key, another used a key recently.
Merging them would lose which credential to take away.

| Signal | From | Recording began |
|---|---|---|
| `console_password` | Credential report | October 2014 |
| `access_key_N` | Credential report, per key | April 2015 |
| `role_last_used` | Arrives with the collection itself | The trailing 400 days only |

**AWS answers `no_information` for a password that has never been used *or*
was last used before it began recording.** Two different facts in one value,
and only one of them would justify retiring an account. `N/A` is the same
position for an access key, and an empty `RoleLastUsed` for a role. Every one
of them is reported as *unanswerable* rather than as *unused*. Verified: the
account root came back as `no_information`, and reading that as "never" would
report the most privileged principal in the account as dormant.

Every coverage window starts where AWS starts reporting, and no earlier:
before then it has nothing to say about anybody. For a role that is the
trailing 400 days.

## Cost

`GetAccountAuthorizationDetails` returns everything in one paginated call, and
it is not fast: verified on a real account, **many pages over
several minutes** for a few hundred roles and policies. IAM throttles, and a collection that is
throttled ends incomplete and resumable rather than pretending to be whole.

## Credentials

Whatever the AWS SDK's chain resolves: environment variables, a shared config
profile, an instance or pod role, or a role assumed with `role_arn`. Nothing
about credentials is in the configuration document, and there is no secret to
reference — AWS credentials are temporary by design and rotate without us.

Read-only is enough: `iam:GetAccountAuthorizationDetails`,
`iam:GenerateCredentialReport`, `iam:GetCredentialReport`,
`iam:ListAccountAliases`, `sts:GetCallerIdentity`. The AWS-managed
`SecurityAudit` policy covers all of them.

`GenerateCredentialReport` is the one call that is not a read — it asks AWS to
produce the report, and there is no way to get one without it. It changes
nothing about access.

Without permission for the report the collection still runs: roles keep their
last-used, because that arrives with the collection itself, and the users are
reported as unanswerable rather than as never having signed in. The host's check
says so before you wait on a collection.

## What has not been verified

The API facts above were checked against a real account on
2026-09-07 through direct calls: the shape of the authorization details, that
role last-used arrives with them, that the root user is absent from them, the
credential report's columns and its sentinels, and all three trust-principal
kinds. Those are pinned by tests.

**The collector binary itself has not been run end to end against a live
account.** The mapping and the parsing are tested against the shapes a real
account returned; the SDK adapter that fetches them is not. Run
`ACCIEW_AWS_LIVE=1 go test ./internal/iam/ -run Live -v` with credentials
resolvable to close that, and the same test checks every claim above.

Also not verified, and following AWS's documentation rather than observation:

- **Throttling** and recovery from it.
- **Cross-account role assumption** with an external id.
- **A permissions boundary**, which is not collected at all: it constrains
  what a policy grants, so an entitlement here can overstate what the
  principal can do even more than the coarse marking already says.
- **Trust-policy conditions are marked, never evaluated.** A conditional grant
  is flagged as one; what the condition actually permits is not worked out.
- **Whether an IAM user is a person.** AWS does not say, so neither does this:
  the kind is unknown rather than guessed from the name. A user with no
  console password and no active access key is reported disabled, because
  there is nothing left to sign in with, and a user whose credentials could
  not be read has an unknown status rather than an assumed one.
- **Service control policies**, for the same reason and at the organisation
  level.
- **IAM Identity Center**, which is a different API surface and is where a
  large organisation's human access actually lives.
