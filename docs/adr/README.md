# Architecture decision records

One file per decision, numbered, never renumbered. A superseded ADR stays in
place with its status changed and a link forward; deleting it destroys the
reasoning a future reader needs.

Every ADR states **the alternative that was rejected and why**. An ADR that only
describes what we did is a changelog entry, not a decision record.

Start from [`0000-template.md`](0000-template.md).

These are the decisions about the contract, the SDK and the collectors. The
numbering is shared with the private repository that holds the host, the
inventory and the product, so numbers here are not consecutive. Where an ADR
mentions the host (`internal/pluginhost`) it means that private code; the
contract it speaks is defined in this repository.

## Index

| # | Title | Status |
|---|---|---|
| [0002](0002-plugin-transport.md) | Plugin transport | Accepted |
| [0003](0003-coarse-entitlements-for-aws-iam.md) | Coarse entitlements for AWS IAM | Accepted |
| [0006](0006-collector-contract-shape.md) | Collector contract shape | Accepted |
| [0007](0007-github-collector-shape.md) | The GitHub collector's shape, and why it needed no contract change | Accepted |
| [0015](0015-evidence-verifier.md) | Publish the evidence verifier, and make its format a document | Accepted |
