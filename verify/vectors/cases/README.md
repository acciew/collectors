# Test vectors

Each folder under here with a `case.json` is one case. See the package comment of
`verify/vectors` for what they are, and `gen_test.go` for how they are made and why
they are not remade by anything that merely uses them.

`case.json` members: `kind` (`collection`, `workflow` or `pack`); `base` (another
case this one is a change to, which then holds only the files that differ) and
`delete` (paths of the base that this case lacks); `verified`; `reason` (for a log
that does not verify, the reason code); `findings` (for a pack, each "reason path");
`error` (for a pack that cannot be checked, the reason code); `digests` (for a log,
the digest of each entry); `chains` (for a log, the chain value of each entry, computed from
its sequence, time, digest and previous); `note`.

The files of a case are in its `files/` folder. A log case has `x.jsonl` and
`x.head`; a pack case has the files of the pack at their paths.
