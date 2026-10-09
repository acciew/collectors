# 0015. Publish the evidence verifier, and make its format a document

- **Status:** Accepted
- **Date:** 2026-10-08
- **Deciders:** the project

## Context

Acciew records what each system it collects from reported, chains the records so that
a log can be checked against itself, and hands a buyer an evidence pack for a review:
a register, the logs the review rests on, the collections it was locked from, and a
manifest of digests. The point of the pack is that an auditor, who has no reason to
trust the service, can check it.

Checking it with the service's own code asks the auditor to trust that code. The
check has to be code the auditor can read, build and run on their own, and the
format it checks has to be written down well enough that they could write the check
themselves. Three things made that more than a matter of publishing a file:

- The digest of a collection is taken over a canonical text that was, until now, the
  output of a program. A second program gets the same digest only if it reproduces
  every escape, every ordering rule and the way a time with a fraction is printed.
- Go's JSON decoder reads a repeated member by the last, a member name in any case,
  and a missing or null member as empty. A file that two readers read two ways has not
  been checked by either.
- What a check shows is easy to overstate. A chain that the party holding it can
  rewrite, together with its anchor, shows that the files agree with each other and
  nothing more.

## Decision

**The verifier reads the exported formats and nothing else.** It parses the files a
pack contains. It does not know the service's types or how a pack is built.
The one piece of the service's vocabulary a digest depends on, the names of the five
kinds of node in a key, is a table in the specification.

**One module, standard library only: `go.acciew.io/collector/verify`**, in this
repository, with the command at `verify/cmd/acciew-verify`. It imports nothing else of
this repository, and nothing else in this repository imports it; `importlint.json`
enforces both. It is tagged with the other modules, from one commit, with one version.

**The format is a document: [`docs/evidence-format.md`](../evidence-format.md), "Evidence
export format 1".** It is normative and written to be implemented from. The Go it
relies on is stated, not left implicit: how a fraction of a second is printed, which
characters a string escapes, that keys are sorted, what an invalid byte becomes. The
code implements the document; a disagreement is a bug in one of them.

**Readers are strict from the first release.** An anchor carries `"format":1` and a
manifest `"version":1`, and the verifier reads that before it judges anything else. A
format it does not know is reported as that, "not a format this verifier knows", and
never as altered. Every reader refuses a repeated member, a member in another case, and
a line that is not exactly the one form lines are written in. It refuses a member it
does not know too, but says that, `unknown-member`, and not that anything disagrees: it
may be an optional member a later revision added, and the verifier is older than the
file. Anything past a bound is `limit`, and is not checked. Both exit with status 2,
"could not be checked". Any change to a digest, a chain value, the shape of a line or an anchor, or the
rendering of a key is a new format that is read alongside this one; an optional member
that leaves every digest as it was may be added within format 1, with the specification
amended first.

**The test vectors are committed files.** `verify/vectors` holds logs and packs, good
and altered in one named way each, with what a verifier must say of each. A verifier in
any language, and the service that writes the formats, run the same files. They are
reviewed in the diff; the test that makes them compares with what is committed, and
with `-update` writes candidates for a person to read, never over the committed files.

**The claim is stated and kept small.** The command and the README say, in the same words:

> What a pass shows: the files are the ones this manifest names; each collection log and the workflow log is hash-chained and checkable against itself and its anchor; and the manifest, campaign.json and the workflow log name the same collections and the same lock, and each log ends where the manifest says it does.
>
> What it does not show: that Acciew made the pack. Nothing inside a pack ties its manifest to anything outside it, so files, logs, anchors and manifest rewritten together pass. To know that this is the manifest Acciew made, compare the manifest digest this check prints with the pack.built record Acciew keeps for it, obtained from Acciew directly and not from whoever handed over the pack; that record is itself on a log Acciew holds, so it shows what Acciew says it handed out, and nothing more. Nothing is signed. It does not show that a collection was complete or true, when anything was made, or who is behind an actor id or a typed name; that a stored collection in snapshots/ is the one its log entry records, since it is tied to the manifest's digest of the file and no further; or that the register, the report or the document say what document.json says.

The words are "hash-chained, checkable against itself". The command prints them after
each check.

**The command exits 0 when what it checked verifies, 1 when it does not, and 2 when it
could not check** (unreadable, a format it does not know, a member of a file that it does
not know, a bound exceeded, a mistake in the command line). A pack is read where it is, as a folder or an archive; nothing is
extracted, and names, links and sizes are judged before anything is read.

## Alternatives rejected

### A module path with its own prefix, `go.acciew.io/verify`

It names the thing better. A Go import prefix maps to one repository, so it needs a
repository of its own, with its own releases, issue tracker and tooling for a
standard-library-only module of a few thousand lines. A module path is an identifier and
not a description, and `collector` is already the prefix of the agent, which is not a
collector either. Moving later is a breaking change for everyone who imported the path.

### Sharing the service's code, so that there is one implementation

One implementation cannot disagree with itself, which is the failure an auditor is
checking for. It would also put the service's types, and the code that builds the
formats, inside the thing an auditor is asked to read. The vectors, which the service
runs too, are what keep two implementations from drifting.

### Reading leniently, and accepting what the service happens to write

Go's default reading would accept the files the service writes today, and a file with a
second `"digest"` member, or `"Body"` for `"body"`, would pass as well, to be read
another way by the next tool. Accepting an anchor with no `format` as format 1 would
have been defensible if files without it existed outside the service. None do, so there
is no leniency to carry.

### Signing the pack

A signature would say who made the pack, which a chain does not. It needs keys, their
custody and a way for an auditor to learn which key to trust, and none of that changes
what the logs inside record. It is not done, and the command says nothing is signed.

## Consequences

An auditor can build the verifier from this repository with a Go toolchain and no
dependencies, and write another from the specification. The format is now a public
contract: a change to what the service writes needs the specification and the vectors
changed first, in this repository, and a new format number if a digest moves.

The verifier is stricter than the service's own reading was, so the service's writers
must write exactly the forms the specification gives. That is the intent, and it is
tested with the vectors on both sides.

What the check does not show stays true and is said in the README and by the command.
Keeping the ends of the logs somewhere other than with whoever holds the logs is the
further answer to a whole chain being rewritten, and is not part of this.

## Revisit when

An auditor asks to re-derive a collection's digest from the stored collection in a pack,
which needs the format of the stored collection specified; or the first change to a
digest or a chain value is wanted, which is format 2; or a way to keep the ends of the
logs outside the service exists.
