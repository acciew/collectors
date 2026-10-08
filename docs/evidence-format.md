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
- A number is an integer in decimal, with no plus sign, fraction, exponent or leading zeros. A
  position (`sequence`) is never negative.
- An instant is written as RFC 3339: `YYYY-MM-DDTHH:MM:SS`, then a fraction only if the
  nanosecond part is not zero, then `Z` for UTC or an offset such as `+02:00`. The fraction is
  a dot and the digits of the nanoseconds with trailing zeros removed, so half a second is `.5`
  and a second and a millisecond is `.001`. Years run from 0000 to 9999. In anything that is
  hashed, an instant is first converted to UTC and written with `Z`; an instant given with an
  offset is the same instant.

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

## Strings

Wherever this document says a string is written, it is written as a JSON string in exactly
this way, which is the way Go's `encoding/json` writes one. Hexadecimal digits are lowercase.

| The character                              | Is written as                      |
|--------------------------------------------|------------------------------------|
| `"`                                        | `\"`                               |
| `\`                                        | `\\`                               |
| U+0008, U+000C, U+000A, U+000D, U+0009     | `\b`, `\f`, `\n`, `\r`, `\t`       |
| any other of U+0000 to U+001F              | `\u00xx`, for example `\u001f`     |
| `<`, `>`, `&`                              | `\u003c`, `\u003e`, `\u0026`       |
| U+2028, U+2029                             | `\u2028`, `\u2029`                 |
| anything else, including `/`, U+007F and every non-ASCII character | itself, as UTF-8 |

A byte that is not part of a valid UTF-8 sequence is written as the six characters `\ufffd`,
once for each such byte, where a genuine U+FFFD is written as itself. A writer never records a
string that is not valid UTF-8, and a verifier refuses a line that is not, so this only
settles what a program that is handed one must write. Text is compared and sorted as the bytes
of its UTF-8.

## The collection log

A collection log is two files that share a name: `<name>.jsonl`, the entries, and
`<name>.head`, its anchor ([The anchor](#the-anchor)). A name is 1 to 128 bytes, is not `.` or
`..`, and contains none of `/`, `\` and NUL.

An entry is one line of the log, and the log ends with a line feed. There are no empty lines.
A line is valid UTF-8 and holds one JSON object, written with no whitespace between tokens and
with the members in the order below. Strings are written as above and numbers as the Conventions say. A list is `[` and `]` around its
items separated by `,`.

Instants in a line are written as the Conventions say, with `Z` for UTC. A line may carry
another offset, as `+02:00`; the instant it names is the one that is hashed.

| Member        | Value                                                                          |
|---------------|--------------------------------------------------------------------------------|
| `sequence`    | As in [the chain](#the-chain).                                                 |
| `recorded_at` | As in the chain.                                                               |
| `digest`      | The digest of `run`: see below.                                                |
| `previous`    | As in the chain.                                                               |
| `chain`       | As in the chain.                                                               |
| `run`         | An object: one collection.                                                     |

`run` has these members. A number marked *int32* is in the range of a signed 32-bit integer
and one marked *int64* in that of a signed 64-bit integer; a number outside its range is
refused.

| Member       | Value                                                                              |
|--------------|------------------------------------------------------------------------------------|
| `source`     | A string: the collector that produced it.                                          |
| `started_at` | An instant: when the collection began.                                             |
| `whole`      | `true` or `false`.                                                                 |
| `verdict`    | An *int32*. An enumeration, written as its number.                                 |
| `cause`      | An *int32*. An enumeration.                                                        |
| `scopes`     | A list of scopes, or `null`. An empty list means the same as `null`.               |
| `counts`     | An object with the *int64* members `identities`, `groupings`, `entitlements`, `resources`, `grants`, `referenced`, in that order. |
| `observed`   | A list of grants, or `null`. An empty list means the same as `null`.               |

A **scope** has the members `id` (a string), `status` (an *int32*), `reason` (a string, left
out when empty), `activity_available` (a boolean) and `activity_undetermined` (a boolean, left
out when false), in that order.

A **grant** has the members `identity` (a key), `entitlement` (a key), `fidelity` (an *int32*)
and `via` (a list of keys, left out when empty), in that order.

A **key** has the members `scope` (a string), `type` (an *int32*) and `id` (a string), in that
order.

A line that is not exactly this is refused: a member that is not listed, a repeated or missing
one, a member in another order, in another case or spelled with an escape, a member written
out that is to be left out, a `null` where a value is required, a value of another kind or
outside its range, other spacing, or a time written any other way than as above. A verifier
that read such a line leniently would read something other than what another reader reads.

### The digest

The digest of an entry is the SHA-256 of the UTF-8 text of the **canonical form** of its `run`,
as lowercase hexadecimal. It is taken over the record and not over the line, so that how a line
happens to be spaced or ordered cannot change it.

### The canonical form

The canonical form is JSON written as the Strings section says, with no whitespace, with these
members in this order and no others:

```
{"source": …, "started_at": …, "whole": …, "verdict": …, "cause": …,
 "scopes": …, "counts": …, "observed": …}
```

- `source`, `whole`, `verdict`, `cause` and `counts` are as in the line. `verdict`, `cause`,
  every `status` and every `fidelity` are numbers, never words.
- `started_at` is the instant in UTC, written as the Conventions say, with the fraction Go
  prints: `.5` and not `.500`, `.000000001` for one nanosecond, no fraction at all for a whole
  second.
- `scopes` is a list of scopes in order of `id`, compared as bytes, or `null` if there are none.
  Each scope is the object with `id`, `status`, `reason`, `activity_available` and, only when it
  is true, `activity_undetermined`, in that order. `reason` is always present, as `""` when it is
  empty. Scopes with the same `id` are put in the order of the bytes of that object as it is
  written, so the order is total whatever order the run gave them in.
- `observed` is a list of grants in the order below, or `null` if there are none. Each grant has
  `identity` and `entitlement`, each the **text of a key** (below), then `fidelity`, then `via`:
  a list of the texts of its keys in the order the run gives them, or `null` if it has none.

The **text of a key** is `<scope>/<type name>/<id>`, the three parts joined by `/` and none of
them escaped or checked. The type name is, by the type's number:

| Type | 1        | 2        | 3           | 4        | 5     | 0           | any other number *N*  |
|------|----------|----------|-------------|----------|-------|-------------|-----------------------|
| Name | identity | grouping | entitlement | resource | scope | unspecified | `unrecognised(N)`     |

with *N* in decimal, and a minus sign if it is negative. A new type of node, with a name, is a
new format. Until then a number with no name is hashed as `unrecognised(N)`.

The **order of grants** is the order of this text for each grant, compared as bytes:

```
<identity text> NUL <entitlement text> NUL <via texts joined by ">"> NUL <fidelity in decimal>
```

where `NUL` is the byte U+0000. Each part is followed by a NUL so that one part cannot run into
the next: `s/identity/a` comes before `s/identity/a0` because NUL is below `0`, and without it
the order would be the other way about.

A `>` or a NUL inside the text of a key can make two different grants read alike. Grants whose
text is equal are put in the order of the bytes of the grant as the canonical form writes it, the
object `{"identity":…,"entitlement":…,"fidelity":…,"via":…}`. Grants that are equal there too are
the same record, so the order is total and the digest does not depend on the order the grants
arrived in. For example, a route through one key whose `id` is `g>s/grouping/h` and a route
through two keys, `g` and `h`, read alike; the route through two comes first, because after
`"via":["s/grouping/g` it has `"` where the other has `\u003e`.

### Worked examples

A collection with one scope, one grant and a route of one key:

```json
{"source":"keycloak","started_at":"2026-09-05T12:00:00Z","whole":true,"verdict":1,"cause":0,"scopes":[{"id":"realm-a","status":1,"reason":"","activity_available":true}],"counts":{"identities":4,"groupings":1,"entitlements":2,"resources":0,"grants":5,"referenced":0},"observed":[{"identity":"realm-a/identity/alice","entitlement":"realm-a/entitlement/admin","fidelity":2,"via":["realm-a/grouping/platform"]}]}
```

Its digest is `7b1fcc8b50238a323ca9dafdb2edf97507bca262746b1f2f4a833e2db44d0285`, which can be
checked with `printf '%s' '<the line above>' | shasum -a 256`.

A collection with nothing in it but a name that needs escaping, `a<b>&c`, U+2028 and `é`, and a start
time given with an offset, `2026-01-02T05:04:05.25+02:00`:

```json
{"source":"a\u003cb\u003e\u0026c\u2028é","started_at":"2026-01-02T03:04:05.25Z","whole":false,"verdict":0,"cause":0,"scopes":null,"counts":{"identities":0,"groupings":0,"entitlements":0,"resources":0,"grants":0,"referenced":0},"observed":null}
```

Its digest is `495983f446860798f67b7af20866ea989b1cd8e9c4fa8bfcb00f98a91ee99ab8`. The `\u2028`
is the six characters, not the separator.

### Checking a collection log

A verifier reads the anchor first, then the lines in order, and names the first fault it comes
to:

1. **Anchor.** The anchor is read as [Reading an anchor](#reading-an-anchor) says. An anchor that
   is not in format 1 is `format`, and one that is not in the form anchors are written in is
   `unreadable`, before any line of the log is read. A missing anchor is not yet a fault.
2. **Line.** For each line in turn: it ends with a line feed, is not empty, is valid UTF-8, is no
   longer than the verifier's bound, and is exactly an entry as above. A line past the bound is
   refused and not skipped; the bound is a property of the verifier, and the reference verifier
   takes lines of up to 64 MiB unless it is told more.
3. **Digest.** The entry's `digest` is the digest of its `run`.
4. **Chain.** Position, link and value, as in [Checking a log](#checking-a-log).
5. **No anchor.** If there is no anchor, the first entry that has passed the three checks above is
   `anchor-missing`, and nothing after it is read.
6. **Anchor against the entries.** After the last line, the anchor is checked against the
   entries, as in [Checking an anchor against a log](#checking-an-anchor-against-a-log).

So when faults coexist, the one named is the first in this order: a log with no anchor and a fault
in its first entry is that fault, and one with no anchor and a fault in its third entry is
`anchor-missing`; an anchor in a format this verifier does not know is `format` whatever the lines
hold. An entry is judged as an entry before it is judged against the anchor. A reimplementation
that reads the lines first and the anchor after would name a different fault in these cases.

A log without a final line feed is refused as cut short: a line that was being written when
something stopped is not an entry, and is not skipped.

A log that is missing, an anchor that cannot be read, or a file that is a link, a directory or
a device is `unreadable`: that says the verifier could not check, and nothing about the log.

## The workflow log

A workflow log is the record of what was done in a review: decisions, locks, assignments and
whatever else the service recorded, one event to an entry. It is two files that share a name,
`<name>.jsonl` and `<name>.head`, named as for a collection log; in a pack they are
`workflow/workflow.jsonl` and `workflow/workflow.head`.

A line is written as the lines of a collection log are: valid UTF-8, ending in a line feed, no
empty lines, one JSON object written with no whitespace between tokens, strings as in
[Strings](#strings). Its members, in this order, are `sequence`, `recorded_at`, `digest`,
`previous`, `chain` and `body`. The first five are those of [the chain](#the-chain), with two
differences: `recorded_at` is always in UTC and written with `Z`, and `digest` is the digest of
the body.

`body` is the event, a JSON value written compactly: no whitespace outside strings, and `<`, `>`,
`&`, U+2028 and U+2029 inside strings written as escapes, as in Strings. Nothing else in it is
respelled: an escape such as `\u0041` stays as it is, and a number stays as the digits it was
written with.

The **digest** of an entry is the SHA-256 of the bytes of its `body` exactly as they stand in the
line, from the first byte of the value to the last, as lowercase hexadecimal. It is taken over
the text and not over a reading of it, so it does not depend on how a program would read a number
or order the members of an object. For example, the body

```json
{"type":"pack.built","actor":"admin:1"}
```

has the digest `b3b19a7a0bdb041196b600216458e41d097d59dc5ef8ac730589fd9c0d5c3510`, which
`printf '%s' '<the body>' | shasum -a 256` gives. A whole line:

```json
{"sequence":1,"recorded_at":"2026-10-06T12:00:00.123456Z","digest":"eced2aa288415d40918b78ed356717eeb5578991756990d32889b724232ea053","previous":"","chain":"f14d723a934dc1ca7cb4924961dba37d91c82e7cacd5148ca157556414e302fa","body":{"type":"example.created","actor":"system","data":{"name":"Acme \u003c\u0026\u003e Co"}}}
```

A line that is not exactly this is refused as a line: a member that is not listed, a repeated or
missing one, a member in another order, case or spelling, a `null` where a value is required,
other spacing in the line or the body, a time not in UTC or written another way, or a body with
`<`, `>`, `&`, U+2028 or U+2029 in a string that is not written as an escape. A line past the
verifier's bound is refused and not skipped, as in a collection log. JSON nested deeper than ten
thousand levels is refused, which is the limit of the reference verifier's JSON reader.

### The event

A body is an event: a JSON object with the members `type` and `actor`, each a string that is not
empty, and, if it has one, `data`, an object. The service writes them in that order, with the
members of `data` in order of name; a verifier does not require the order, because the digest
covers the bytes. `type` says what happened, as in `collection.completed`, and `actor` who did it:
`system`, or a kind and an identifier such as `admin:<id>`. `data` is the rest.

A body that is not an object, has no `type` or no `actor`, has either empty or not a string,
has `data` that is not an object, or has another member than these three is refused as
`event`, and so is one that repeats a member, at the top level or in `data`, or spells a member
name in another case. A member name is compared as the text it stands for, so `"t\u0079pe"` is
`type`.

A verifier does not interpret `data`, or the type, beyond that: a type it has never heard of is
chained like any other, and the log is evidence that it was not cut or reordered, and nothing
more. Which types an evidence pack reads, and what it reads from them, is described with the pack.

### Checking a workflow log

A verifier reads the anchor first and the lines in order, and names the first fault it comes
to, as for a collection log, with the checks of a line in this order:

1. **Line.** As above.
2. **Digest.** The `digest` is the digest of the `body`.
3. **Event.** The body is an event.
4. **Chain.** Position, link and value, as in [Checking a log](#checking-a-log).

Then, as for a collection log: with no anchor, the first entry that has passed these is
`anchor-missing`, and after the last line the anchor is checked against the entries. A log
without a final line feed is refused as cut short.

## Reason codes

A verifier names what it found with one of these. They are stable names: a program may switch on
them, and the test vectors name them.

| Code              | Meaning                                                                         |
|-------------------|---------------------------------------------------------------------------------|
| `name`            | The name is not one a log can have.                                             |
| `unreadable`      | A file is missing, is not a plain file or cannot be read; or an anchor is not in the form anchors are written in. |
| `line`            | A line is not an entry in the form above.                                       |
| `digest`          | An entry's `run` (or, in a workflow log, `body`) is not the one its `digest` is of. |
| `sequence`        | An entry is not at the position its `sequence` says.                           |
| `link`            | An entry does not name the one before it.                                       |
| `event`           | A body of a workflow log is not an event.                                       |
| `chain-value`     | An entry's `chain` is not the value its fields give.                            |
| `anchor-missing`  | There are entries and no anchor.                                                |
| `entries-missing` | There is an anchor and no entries.                                              |
| `tail-cut`        | The anchor names an entry past the end of the log.                              |
| `anchor-stale`    | The anchor names an entry before the end of the log.                            |
| `anchor-mismatch` | The anchor and the log name different chain values for one entry.               |
| `format`          | The anchor is in a format this verifier does not know.                          |

## Compatibility

`format` is the version of this document. A change to the chain value, the digest of any kind
of entry, the shape of a line or of an anchor, or the rendering of a key is a new format,
and the new format is read alongside this one.

A field may be added within format 1 only if it is optional and leaves every digest and chain
value already written as it was. The section describing it is amended first, with an example.
Readers refuse a field they do not know, rather than ignore it and compute a value that was
never meant, so an older verifier says that it does not know a field and does not report an
alteration.
