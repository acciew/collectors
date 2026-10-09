# verify

The open-source checker for the evidence Acciew exports. It reads exported files and
checks them against themselves, with the Go standard library alone and no code from
the rest of this repository (`importlint` enforces the second).

What the formats are is written down in [`docs/evidence-format.md`](../docs/evidence-format.md).
The code here implements that document and the document is the authority: a
disagreement between them is a bug in one of the two.

## Checking an evidence pack

An auditor who is handed an evidence pack, as a folder or as a ZIP archive, can check it with this code
and nothing else. The command reads files and writes nothing; it makes no network call and runs nothing.

```sh
acciew-verify pack <folder|archive.zip>
acciew-verify history <folder> [--source NAME]     # collection logs: NAME.jsonl with NAME.head
acciew-verify workflow <folder> [--name NAME]      # a workflow log: NAME.jsonl with NAME.head
acciew-verify version
```

From a checkout, in this folder: `go run ./cmd/acciew-verify pack <place>`. An archive is read in
place and not unpacked. Check the archive as it was handed over: a folder that has been opened may hold what
the operating system left in it, which is noted and not read.

| Exit status | Means |
|---|---|
| 0 | what was checked verifies |
| 1 | it does not: the files disagree with each other |
| 2 | it could not be checked: unreadable, a format this verifier does not know, a member of a file that it does not know (the file may be newer than it), a bound exceeded, or a mistake in the command |

**Bounds.** The command takes in no more than: 10,000 files and folders in a pack; 2 GiB for a file and 8 GiB in all; for an archive entry past 1 MiB, 500 times its compressed size; 64 MiB for a line of a log; and 64 MiB each for `manifest.json`, `manifest.sha256` and `campaign.json`. A pack or a line past a bound is not checked: that is exit status 2, and it says nothing about the pack. `--max-bytes N` raises the size of a pack and of a file in it, and `--max-line-bytes N` the length of a line, for a pack that is meant to be that large. The bounds in force are printed on every check, and with the refusal when a bound stops a pack. `--max-bytes` is at most 1 PiB. What the files must be is written down in [`docs/evidence-format.md`](../docs/evidence-format.md).

### What a pass shows, and what it does not

What a pass shows: the files are the ones this manifest names; each collection log and the workflow log is hash-chained and checkable against itself and its anchor; and the manifest, campaign.json and the workflow log name the same collections and the same lock, and each log ends where the manifest says it does.

What it does not show: that Acciew made the pack. Nothing inside a pack ties its manifest to anything outside it, so files, logs, anchors and manifest rewritten together pass. To know that this is the manifest Acciew made, compare the manifest digest this check prints with the pack.built record Acciew keeps for it, obtained from Acciew directly and not from whoever handed over the pack; that record is itself on a log Acciew holds, so it shows what Acciew says it handed out, and nothing more. Nothing is signed. It does not show that a collection was complete or true, when anything was made, or who is behind an actor id or a typed name; that a stored collection in snapshots/ is the one its log entry records, since it is tied to the manifest's digest of the file and no further; or that the register, the report or the document say what document.json says.

For a folder of logs, `history` and `workflow` say:

What a pass shows: each log is hash-chained and checkable against itself and its anchor: every entry holds the digest of its content, every link names the entry before it, and the last entry is the one the anchor names. It does not show who wrote a log or when, that what it records is true, or that whoever holds both a log and its anchor did not rewrite both.

And when something does not verify:

A check that fails says the files disagree with each other. It does not say who changed anything, or when.

The command prints the words that apply after each check, and a test fails if they differ from these.

## The packages

This is not released yet. The packages are:

- [`chain`](chain): the hash chain over the entries of a log, and the anchor that names its end.
- [`collection`](collection): the collection log: its wire types, the canonical form and digest of a collection, and a strict reader that checks a log and its anchor.
- [`workflow`](workflow): the workflow log: events as the text their digest is taken over, in the one form lines are written in, and a strict reader that checks a log and its anchor.
- [`pack`](pack): an evidence pack, as a folder or a ZIP archive read in place: its files against the manifest, each log against its anchor, and the manifest, `campaign.json` and the workflow log against one another.
- [`vectors`](vectors): the test vectors of the format, as committed files, for a verifier in any language and for the service that writes the formats.
- [`cmd/acciew-verify`](cmd/acciew-verify): the command.
