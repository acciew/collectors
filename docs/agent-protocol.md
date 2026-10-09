# The agent protocol (`/agent/v1`)

This is the wire protocol between the Acciew service and [`acciew-agent`](../cmd/acciew-agent). It is published
here, beside the agent's source, because the agent runs inside a customer's network and the people who read it
should not need access to the service's repository to see what it says to the service.

An agent is a program in a customer's network that runs collectors there and sends what they find up to the service
(decision record 0016, in the service's repository). It only ever makes outbound HTTPS requests, to the
service's public address, and holds no secret that works for long. The path carries the version: `/agent/v1`. Everything is JSON; errors are
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem documents.

## Identity (decision record 0017)

The agent makes an **Ed25519 key pair** and keeps the private key (a file only its owner can read). The service keeps the public key.

### Enrol: `POST /agent/v1/enroll`

A tenant administrator mints an enrolment token in the service: 256 bits, good once and for
an hour, shown once. The agent sends

```json
{"token": "acc_enr_…", "name": "plant-1 edge", "versions": {"agent": "0.1.0", "protocol": "1"}, "public_key": "<standard base64 of the 32-byte key>"}
```

and is answered `201` with `{"agent_id": "<tenant>.<agent>", "fingerprint": "ab12-…", "state": "pending"}`. The **fingerprint** is the
first 16 bytes of the SHA-256 of the public key, in hexadecimal, in eight groups of four. The agent **prints it locally**, and the
administrator types it into the service to confirm it; until then the agent is offered nothing. A proxy that used the
token first, or swapped the key, shows a fingerprint the agent never printed. A token that is unknown, used, expired or not one is `401`;
a key already enrolled is `409`; at most ten tries from one address in a burst, then one every ten seconds (`429`, `Retry-After`).
The other addresses (`token`, `rotate`, `hello`, and the job addresses that follow) share one limit per address of the caller: a burst of sixty, then one a second, answered `429` with `Retry-After`; agents behind one address share it.

### Get an access token: `POST /agent/v1/token`

The agent signs an **assertion**, a compact JWT, and sends `{"assertion": "<jwt>"}`:

- header: `{"alg": "EdDSA", "typ": "JWT", "kid": "<agent_id>"}` (no other algorithm is accepted);
- claims: `iss` and `sub` are the `agent_id`; `aud` is the service's public address followed by `/agent/v1/token`; `iat` and `exp` are
  seconds since the epoch, with `exp - iat` of at most 120; `jti` is a fresh random string (up to 128 characters), which the service
  refuses to see twice. The service allows a minute of difference between the clocks.

It is answered `200` with `{"access_token": "acc_agt_…", "token_type": "Bearer", "expires_at": "…", "expires_in": 3600}`. Whatever is
wrong with an assertion (a bad signature, an unknown agent, the wrong audience, an old one, a used one) is one `401` that says nothing of
which. An agent that has proved it holds its key but is pending or revoked gets `403` with `{"state": "pending"}` or `{"state": "revoked"}`.

### Change the key: `POST /agent/v1/rotate`

An assertion whose `aud` ends in `/agent/v1/rotate`, signed by the **old** key, with the extra claim `new_key` (standard base64 of the new
public key), together with the **new** key's signature over the same bytes: `{"assertion": "<jwt>", "new_key_signature": "<base64url of the
signature of header.payload>"}`. An access token alone cannot register a key, and a key cannot be registered by someone who does not hold
it. `200` with the new fingerprint. The agent stays confirmed. The access tokens the old key got stop working at once (a key changed
after a leak cuts off whoever holds a token made with it), so the agent asks for a new one with the new key.

An assertion is for one use, and is remembered five minutes past its own end; one that lasts more than two minutes is refused.

### Say hello: `GET /agent/v1/hello`

With `Authorization: Bearer <access token>`: `200` with the agent's id, name and state; `401` once the token has run out or the agent has
been revoked. (The key being registered is checked on every call.)

## Jobs (decision record 0018)

The service owns every schedule; an agent has none. All of these take `Authorization: Bearer <access token>` (a `401` for anything else,
and for an agent that is revoked).

### Ask for work: `GET /agent/v1/jobs`

Held for 30 to 60 seconds (jittered) until there is a run of one of the agent's connections to do. `204` with no body: none, ask again. An agent holds one poll at a time: a newer poll replaces an older (which is answered `204`). The service lifts its own read and write deadlines for a poll and for a chunk upload (ten minutes for the chunk to arrive), so a slow uplink is not cut off.
`200` with the job:

```json
{"run": "…", "stream": "…", "attempt": 1, "source_id": "…", "collector": "keycloak", "config": {…}, "scopes": [], "budget": null,
 "resume_cursor": null, "resume_events": 0, "lease_until": "…", "lease_seconds": 300, "heartbeat_seconds": 100, "chunk_bytes": 8388608}
```

`config` is the connection's configuration as stored: a secret in it is a reference (`env:NAME`, `file:/path`) that the agent resolves
where it runs, and the service has no value for it. `resume_cursor` is `null` for a run that starts from the beginning, and
`{"token": "<standard base64>"}` for one that goes on from where an earlier attempt got to (below): the agent passes the token to the
collector as `CollectRequest.resume_from`. `resume_events` is how many events the earlier streams of the run contribute to the collection
(those up to the checkpoint each was resumed from): the limit of 1,000,000 events is for the whole collection, so what this attempt may send is that
less what is spent. `stream` is the stream this attempt writes to; `attempt` counts the times the run was
offered. An agent holds one job at a time, so while it holds one it is told `204`. `429` (with `Retry-After`) once it has had its
jobs for the day.

### Hold the job: `POST /agent/v1/streams/{stream}/heartbeat`

Every `heartbeat_seconds` while the job runs. `200` with `{"lease_until", "lease_seconds"}`. A job whose lease lapses is offered again
(to this agent, as a new attempt with a new stream); eight starts fail the run, and so does a lease that lapsed and was not taken up again for a day. A run nobody asked for in a week, and every run of an agent that is cut off, fail too, and what their streams held is let go.

### Send what was found: `PUT /agent/v1/streams/{stream}/chunks/{n}`

The body is a chunk: the gzip of whole frames, each frame an unsigned varint length and that many bytes of a `CollectResponse`
protobuf (no frame is cut across two chunks; a frame is at most 4 MiB, a chunk at most 8 MiB, and it inflates to at most 64 MiB).
Chunks are numbered from 0 and go up in order and once; a stream has at most 1024 chunks, and a collection (the streams of a run, each to its checkpoint) at most 1,000,000 events and 2 GiB inflated: a source with more is refused until the limit is configurable, and an agent that sees it would pass the limit gives the job up (`/abort`) and says so, instead of sending what the service must then refuse. Headers: `X-Acciew-Sha256: <hex of the body>` (checked when given: `422` and
nothing stored when it is not the body's), and `X-Acciew-Final: true` on the last chunk, which carries the `Completion`.

The agent also says which collector file it ran, on every chunk: `X-Acciew-Collector-Sha256: <SHA-256 of the collector's file as 64 lower-case hex characters, read just
before the agent started it>` and `X-Acciew-Collector-Version: <the version the collector gave in its handshake>` (1 to 64 characters of
`0-9A-Za-z._+~-`). Each is optional: an agent that predates them sends neither, a file the agent could not read has no digest, and a version
that cannot go in a header is left out. A service that does not know them ignores them, and one that does reads a chunk without them as it
always did. They are the agent's word, and the protocol gives the service nothing to check them against.

- `201` `{"status": "stored"}`; `200` `{"status": "duplicate"}` for a chunk that arrived before, the same, so an upload whose answer was
  lost is sent again.
- `409` with a `code`: `out_of_order` (with `next`, the number wanted), `chunk_conflict` (that number arrived before with other bytes:
  the stream is refused and the run has failed), `lease_lost` (the run is on another attempt: stop this job and ask for work),
  `stream_closed` (the last chunk is in, or the run has ended).
- `413` over a chunk's cap; `422` for an empty body or a wrong digest; `404` for a stream that is not this agent's.
- `503` with `Retry-After` when the service is reading as many chunks as it will at once: send it again. A chunk that cannot be taken (the
  `404` and `409` above, a number that is not the next) is refused before its body is read, and one that arrived before is not read again.

A chunk that is taken also holds the job for another lease.

**The service reads each chunk as it arrives**, and keeps nothing of one that is not well formed: not gzip, a frame cut off, a frame
over 4 MiB, an event after the completion, a checkpoint with no cursor or a cursor over 64 KiB are `422`. A **completion** may only be in
the last chunk (`X-Acciew-Final: true`); the service notes where the last **checkpoint** in each chunk falls and the cursor it carries.

**Ending a stream early.** An agent that cannot go on (its spool is full) cancels the collector, sends the frames up to its last
checkpoint as the last chunk with `X-Acciew-Final: true` and **no completion**, and asks for work again: the answer to that chunk says
`"ended_early": true`, and the same run is offered at once as a new attempt with a new stream. The same happens when a lease lapses
without the agent saying anything.

**Resuming.** If the stream before the new attempt carried a checkpoint, the job's `resume_cursor` is that checkpoint's cursor; the
earlier stream is kept, to the checkpoint, and the new one is sent from chunk 0 on its own stream id, carrying only what the collector
sends after the cursor. If there was no checkpoint the job starts from the beginning and the earlier stream is let go. A collector that
cannot use the cursor starts over and says so in a `cursor.rejected` diagnostic: its stream then stands alone. A stream that resumed
ends with the completion the contract asks of it: INCOMPLETE with the cause PARTIAL_STREAM when it ran to the end.

**Reading.** When the last chunk with a completion is in, the service reads the streams of the run as one collection: each earlier
stream to its checkpoint, then the last stream whole. A record sent again that an earlier stream sent before its checkpoint, a stream
that resumed and says it is complete, and counts that are not what the last stream sent each fail the run, naming what. The collection
is whole only if the last stream ended as a continuation does and every scope any stream saw is COLLECTED or SKIPPED in it; its counts
are those of the records read.

Once the last chunk with a completion is in, the service reads the stream with the same code that checks a collector's output on any
host; events the contract forbids fail the run, naming what. A stream that ends without a `Completion` is not read: it ended early (see
above) and the run is offered again. A collector that crashes ends its streams that way each time, and a run is started up to eight
times before it is given up on, with `the agent ended its stream before the collector finished` if the stream of its last start ended early and
`the agent stopped answering 8 times` if it went quiet. The service trusts nothing in a stream.

### Say the job cannot be done: `POST /agent/v1/streams/{stream}/abort`

`{"reason": "…"}` (a sentence, up to 500 characters): the run fails with `the agent gave up: …`. `204`; `409` once it has no more to give.

## Revocation

A tenant administrator deletes the agent in the service: no new tokens, and the ones it holds stop working at once.

## What the service can and cannot know

It can know which key made a request, that an assertion was not used twice, and what the agent says of itself (shown, never trusted).
It holds no source credentials and no private keys. It cannot know that the agent's host is uncompromised.
