# 0003. Coarse entitlements for AWS IAM

- **Status:** Accepted
- **Date:** 2026-09-05
- **Deciders:** the project, from the analysis in
  [the three-source mapping](../design/three-source-mapping.md#34-aws-does-not-enumerate).

## Context

For Keycloak, "what can this person do" is a list you can fetch. For AWS IAM it
is not, and the reason is structural rather than an API gap.

An AWS principal's effective permissions are the outcome of evaluating, for a
specific action on a specific resource in a specific condition context:
identity policies, resource policies, permission boundaries, service control
policies and session policies. There is no endpoint that returns the set. There
cannot be one, because the set is not finite in any useful sense — it is a
function over the cross product of every action and every resource in the
account.

Computing it well is an entire product category. That is what the CIEM vendors
sell, and it is not what this collector sets out to be.

Meanwhile the access-review question is narrower than the least-privilege
question, and this matters more than it first appears:

- **Least privilege asks:** what can this person actually do? That needs
  evaluation.
- **Access review asks:** should this person still have this? That needs a
  stable, nameable thing a human can recognise and decide about.

"Alice has `AdministratorAccess` attached" is a decidable review item. It is not
an answer to what Alice can do, and the difference has to survive all the way to
the reviewer.

## Decision

**An AWS entitlement is an attached or inline policy, or an assumable role. It
is not a computed permission.**

Concretely:

- A managed policy attached to a user, group or role is one entitlement.
- An inline policy on a user, group or role is one entitlement.
- A role that a principal may assume is one entitlement of that principal.
  This release derives this from the role's **trust policy** — the principals it
  names — because that data arrives with calls we already make. The caller-side
  `sts:AssumeRole` grant is recorded as source context, not as a second
  entitlement.

**Every AWS grant is marked `COARSE`** in the contract's grant-fidelity field.
That field has no default: a plugin author must choose, and a consumer can tell
a coarse claim from a resolved one. A Keycloak effective role and an AWS policy
attachment are not the same strength of claim, and an evidence product that
renders them identically has a defect, not a cosmetic problem.

**The plugin declares this in `Describe`**, so the core degrades against what
the plugin says it can do rather than assuming. **The plugin README says it in
plain words**, because a limitation only a careful reader finds is a limitation
that will be discovered by an auditor instead.

## Alternatives rejected

### Evaluate the policies ourselves

Write an IAM policy evaluation engine: parse policy documents, apply the
evaluation logic, produce effective permissions.

Rejected on scope and on honesty. The evaluation rules are intricate and
under-specified in places, they change, and an engine that is 95% correct is
worse than no engine at all in this context — it produces confident wrong
answers in exactly the cases (a boundary, an SCP, a condition key) where the
answer mattered. An evidence product cannot carry a subtly wrong permission
model.

### Use `SimulatePrincipalPolicy`

AWS does provide evaluation: `SimulatePrincipalPolicy` answers whether a
principal is allowed a given action on a given resource, using the real engine.
This is the strongest alternative and it deserves a real answer rather than a
dismissal.

Rejected because it answers a question we cannot ask at collection time. The
API takes actions and resources as **input**; it does not enumerate. To
discover what a principal can do we would have to supply candidate pairs, and
the candidate set is every action of every service crossed with every resource —
tens of thousands of actions before resources are considered, one throttled API
call per batch, per principal. There is no complete result at the end of it,
only a large sample, and a sample presented as a population is precisely the
failure mode the contract's completeness rules exist to prevent.

It remains the right tool for a different question — "can Alice delete this
bucket?" — asked interactively about one principal and one resource. That is a
future feature, not a collection strategy.

### Use IAM Access Analyzer

Access Analyzer finds resources shared externally and can validate policies. It
is genuinely useful and answers a different question: which resources are
exposed, not what a principal holds. It does not enumerate a principal's
permissions, so it does not remove the need for this decision.

### Leave AWS out of this release

Ship Keycloak and GitHub, add AWS when it can be done properly.

Rejected because AWS is in this release precisely *because* it does not fit. It is
the source that forces the contract to admit that entitlements differ in kind —
without it, the contract would quietly assume every source can resolve effective
access, and that assumption would be discovered by the first person to write a
collector for something that cannot. The friction is the point.

## Consequences

- The contract carries a non-defaultable fidelity on every grant, and the
  conformance suite has to check that a plugin sets it honestly. A plugin that
  marks a coarse grant `EFFECTIVE` is lying in a way no type system catches.
- A reviewer UI has to render `COARSE` differently, and the reviewing question
  has to be phrased differently: "should Alice still have `AdministratorAccess`
  attached" rather than "should Alice still be able to do X". Open question: how
  that is worded is an auditor-acceptance question.
- We cannot answer "who can read this bucket" from the inventory. We should not
  imply that we can.
- Policy documents are collected as source context, so the data needed for a
  future evaluation layer is retained from the first collection. History cannot
  be backfilled; keeping the documents now costs almost nothing and preserves
  the option.
- IAM Identity Center is out of scope for this release and is where most large-org
  human access actually lives. This ADR does not cover it.

## Revisit when

- A customer's review is blocked because a coarse entitlement is not decidable
  in practice — that is the signal that the reviewer needs more than the policy
  name, and it is a customer finding, not an engineering one.
- We want to answer a targeted "can this principal do this specific thing"
  question, at which point `SimulatePrincipalPolicy` is the tool and this ADR
  does not stand in the way.
- IAM Identity Center comes into scope, which changes what an AWS identity even
  is.
