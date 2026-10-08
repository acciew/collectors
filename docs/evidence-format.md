# Evidence export format 1

This document is the format of the files Acciew exports as evidence, and the rules a
verifier applies to them. It is normative: the verifier in [`verify/`](../verify) implements
it, and anyone can write another from this page alone. "Must" and "must not" are meant as
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

A part of an export that has no section here is not covered by this document.

## What a check shows

A check shows that the files agree with each other: every entry holds the chain value its
fields give, every entry names the one before it, and the last entry is the one the anchor
names. It does not show who wrote the files or when, that what they record is true, or that
nobody who holds both a log and its anchor rewrote the two together. Nothing here is signed.

Say "hash-chained, checkable against itself". Do not describe it as proof against alteration.

## Conventions

- Text is UTF-8. A hash is taken over the bytes of a string exactly as written here.
- A hash is written as lowercase hexadecimal. Hashes are compared as strings, byte for byte,
  and are never case-folded.
- A number is a non-negative integer in decimal without a sign, a fraction or an exponent.
- An instant is written as RFC 3339 in UTC: `YYYY-MM-DDTHH:MM:SS`, then a fraction only if the
  nanosecond part is not zero, then `Z`. The fraction is a dot and the digits of the
  nanoseconds with trailing zeros removed, so half a second is `.5` and a second and a
  millisecond is `.001`. Years run from 0000 to 9999. An instant that is given with an offset
  is the same instant, and is written in UTC before it is hashed.

## The chain

A log is a sequence of entries, oldest first. Each entry has a position, a time, a digest of
what it holds, and a link to the entry before it.

An entry has these fields, which the chain covers:

| Field         | Meaning                                                                          |
|---------------|----------------------------------------------------------------------------------|
| `sequence`    | A number from 1 to 18446744073709551615 (2^64 - 1). 1 for the first entry, then 2, 3, and so on without gaps. |
| `recorded_at` | The instant the entry was written.                                               |
| `digest`      | A string. The digest of the entry's content; the chain does not interpret it.    |
| `previous`    | The `chain` value of the entry before this one. The empty string for the first.  |
| `chain`       | The value below.                                                                 |

### Chain value

The chain value of an entry is the SHA-256 of the UTF-8 string

```
<sequence> LF <recorded_at> LF <digest> LF <previous>
```

where `LF` is a line feed (U+000A), `sequence` is in decimal, `recorded_at` is the instant in
UTC as above, and `digest` and `previous` are the entry's strings as they are written. There is
no line feed after `previous`, which is empty for the first entry, so the first entry's string
ends in a line feed. The position is in the string so that two identical entries one after the
other get different values.

Worked example, which can be checked with `printf` and `shasum -a 256`. Take the digests
`d1`, `d2` and `d3`, the SHA-256 of the strings `first run`, `second run` and `third run`:

```
d1 = 7d48a58261da7384cdc61ebe4735a8664ac5cdc8abb9d0cdcfa3e77cff58e7de
d2 = 791d43e21f7b8031e0a268cf4fef3379cea793a242094611c76b486ad3dd3150
d3 = 7639e48f6cb67b4a04ab8eefc79674becf5c3f8d1614e70fb44ab436ff973681
```

| sequence | recorded_at                      | digest | previous | chain value                                                        |
|----------|----------------------------------|--------|----------|--------------------------------------------------------------------|
| 1        | `2026-01-02T03:04:05Z`           | `d1`   | (empty)  | `9d5b80b6185e3ac33be500a8d82ba82d7b5e95a6d2dd303cae45064cfd25c4dc` |
| 2        | `2026-01-02T03:04:06.5Z`         | `d2`   | entry 1  | `21112c55263d3ac28a443bb29db6ff17b225eb560632f68d6eba573ab2528171` |
| 3        | `2026-01-02T03:04:07.123456789Z` | `d3`   | entry 2  | `bfffc5468dcd41f16a86e014e01d9a29b102be7d0f980ca1591990c25f988c5f` |

The first of them is the SHA-256 of `1`, a line feed, `2026-01-02T03:04:05Z`, a line feed, `d1`
and a line feed.

### Checking a log

A verifier goes through the entries in order and reports the first one that fails:

1. **Position.** The entry at position *n* (counting from 1) has `sequence` *n*. This catches
   an entry that is missing, repeated or out of place.
2. **Link.** The entry's `previous` is the empty string if it is the first, and otherwise the
   `chain` of the entry before it.
3. **Value.** The entry's `chain` is the chain value computed from its own fields.

An empty log has nothing to disagree with. A fault names the entry it was found at and says
that the file and its chain disagree. It does not say who changed anything, or why.

A chain does not see its own end being cut off: removing the last entries leaves every
remaining link intact. That is what the anchor is for.

## The anchor

Each log has an anchor, in a file of its own, that names the last entry. Where the file lives
is part of the section for each kind of log.

An anchor is one JSON object on one line, with these members in this order and no spaces
between tokens:

```json
{"format":1,"sequence":3,"chain":"bfffc5468dcd41f16a86e014e01d9a29b102be7d0f980ca1591990c25f988c5f"}
```

| Member     | Meaning                                                        |
|------------|----------------------------------------------------------------|
| `format`   | The number 1: this version of this document.                   |
| `sequence` | A number from 0 to 18446744073709551615 (2^64 - 1): the `sequence` of the last entry. |
| `chain`    | A string. The `chain` of the last entry.                       |

A number outside the range of its member is refused as unreadable, so a `sequence` of 2^64 is
not read as a smaller one. The file may end in one line feed. Nothing else may follow the object.

### Reading an anchor

A verifier reads the `format` member first, and before it judges anything else. If there is no
`format`, or it is not exactly `1`, the verifier says the anchor is **in a format it does not
know** and stops: that is a statement about the verifier, not about the file, and it must not
be reported as an alteration. A newer verifier may read what an older one cannot.

Then it refuses an anchor that is not exactly the form above: a member it does not know, a
repeated member, a member name in another case, members in another order, other spacing or spelling of
the same object, a value of another kind, or anything after the object but one line feed. An anchor is about a hundred bytes; a verifier refuses a file of
more than 1024 bytes without parsing it, and says only that it is longer than an anchor of
format 1 may be: it may be an anchor of a format it does not know.

### Checking an anchor against a log

Run after the log itself has been checked. With *last* the final entry of the log:

| The log and the anchor                                                         | Outcome           |
|--------------------------------------------------------------------------------|-------------------|
| no entries, no anchor                                                          | agree             |
| entries, no anchor                                                             | `anchor-missing`  |
| an anchor, no entries                                                          | `entries-missing` |
| `sequence` is greater than *last*'s                                            | `tail-cut`        |
| `sequence` and `chain` are *last*'s                                            | agree             |
| `sequence` is less than *last*'s, and `chain` is the chain of that entry       | `anchor-stale`    |
| anything else                                                                  | `anchor-mismatch` |

`tail-cut` is entries removed from the end, or an anchor that belongs to a longer log.
`anchor-stale` is an anchor that was not brought up to date, or an older one put back. Both
are failures: the anchor must name the last entry exactly.

## Compatibility

`format` is the version of this document. A change to the chain value, the digest of any kind
of entry, the shape of a line or of an anchor, or the rendering of a key is a new format,
and the new format is read alongside this one.

A field may be added within format 1 only if it is optional and leaves every digest and chain
value already written as it was. The section describing it is amended first, with an example.
Readers refuse a field they do not know, rather than ignore it and compute a value that was
never meant, so an older verifier says that it does not know a field and does not report an
alteration.
