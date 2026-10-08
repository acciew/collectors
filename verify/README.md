# verify

The open-source checker for the evidence Acciew exports. It reads exported files and
checks them against themselves, with the Go standard library alone and no code from
the rest of this repository (CI enforces both).

What the formats are is written down in [`docs/evidence-format.md`](../docs/evidence-format.md).
The code here implements that document and the document is the authority: a
disagreement between them is a bug in one of the two.

This is not released yet. Today there is one package:

- [`chain`](chain): the hash chain over the entries of a log, and the anchor that names its end.

The command that checks a whole export, and the statement of what a passing check
shows and what it cannot show, arrive with it.
