# verify

The open-source checker for the evidence Acciew exports. It reads exported files and
checks them against themselves, with the Go standard library alone and no code from
the rest of this repository (`importlint` enforces the second).

What the formats are is written down in [`docs/evidence-format.md`](../docs/evidence-format.md).
The code here implements that document and the document is the authority: a
disagreement between them is a bug in one of the two.

This is not released yet. Today there are three packages:

- [`chain`](chain): the hash chain over the entries of a log, and the anchor that names its end.
- [`collection`](collection): the collection log: its wire types, the canonical form and digest of a collection, and a strict reader that checks a log and its anchor.
- [`workflow`](workflow): the workflow log: events as the text their digest is taken over, in the one form lines are written in, and a strict reader that checks a log and its anchor.

The command that checks a whole export, and the statement of what a passing check
shows and what it cannot show, arrive with it.
