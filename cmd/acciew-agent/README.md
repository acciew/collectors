# acciew-agent

The agent runs [collectors](../../README.md) inside your network and sends what they find to the
Acciew service. Use it when the system to be reviewed cannot be reached from the internet: the
service cannot call in, so the agent calls out.

It is the second program that hosts collectors; the first is the service itself, for sources it can
reach. A collector does not know which is running it.

## What it does and does not do

- **Outbound HTTPS only.** It makes requests to the service's address and to nothing else. It
  listens on no port. Plain `http://` is refused, except to the machine itself for trying it out;
  redirects are not followed, so a token cannot be sent somewhere nobody configured. Proxies are
  taken from `HTTPS_PROXY` and friends.
- **It holds a key, not a secret.** At enrolment it makes an Ed25519 key. The private half stays
  in a file only its owner can read (a key that others can read is refused at startup) and is
  never sent: not in a request, a header, a log line or an upload. The service holds the public
  half. To act, the agent signs a one-minute assertion and trades it for an access token of an hour.
  What a proxy in the path captures stops working within the hour, or at once when an
  administrator deletes the agent.
- **Source credentials stay here.** A job's configuration names a credential as a reference,
  `env:NAME` or `file:/path`, and the service has no value for it. The agent reads the value on this
  host, into a file of its own (mode 0600, in a directory made for the run, in memory where there is
  any), and hands the collector that file. The collector is started with none of the agent's
  environment except proxy and certificate settings. The files are removed when the job ends.
- **It checks what it is sent to upload.** Every event a collector sends goes through the
  contract's own validation before it is kept. A collector that breaks the contract gets its job
  given up, with the rule named; its output is never uploaded as though it were fine.
- **It stops when it is told to.** If the service gives a job to another attempt (`lease_lost`,
  `stream_closed`), the collector is killed at once and the spooled events are deleted.

## Install

The release archive holds `acciew-agent` beside the collectors. By default the agent looks for
`acciew-collector-<name>` in the directory it sits in, so unpacking the archive is the install. The
archives are listed in `SHA256SUMS` and carry a build provenance attestation; see the repository
README for how to check them. `acciew-agent version` says which build you have.

Linux and macOS, amd64 and arm64.

## Enrol

An administrator makes an enrolment token in the service: single-use, good for an hour.

```sh
acciew-agent enroll --url https://acciew.example.com --token acc_enr_… --name "plant-1 edge" \
  --state-dir /var/lib/acciew-agent
```

This makes the key, registers its public half, and prints the agent's **fingerprint**. Give the
fingerprint to an administrator, who compares it with the one the service shows and confirms it.
Until then the agent is offered no work. The agent computes the fingerprint itself from its own key
and refuses to go on if the service reports a different one: that is a proxy that used the token
first, or swapped the key.

Putting the token in the environment (`ACCIEW_ENROLMENT_TOKEN`) keeps it out of the process list.

## Run

```sh
acciew-agent run --state-dir /var/lib/acciew-agent
```

It runs until it gets SIGINT or SIGTERM. It waits (politely, with backoff) while its fingerprint is
unconfirmed, asks for work by long poll, and does one job at a time. A job that is running when the
agent is stopped is not given up: its lease lapses and the service offers it again.

Credentials the collectors need go in the agent's environment or in files; the connection in the
service names them, and `--secret-env` / `--secret-path` say which names a job may use. With systemd:

```ini
[Service]
User=acciew-agent
Environment=ACCIEW_AGENT_STATE_DIR=/var/lib/acciew-agent
EnvironmentFile=/etc/acciew-agent/credentials   # KC_CLIENT_SECRET=…, mode 0600
ExecStart=/opt/acciew/acciew-agent run --secret-env KC_CLIENT_SECRET
Restart=always
```

| Flag | Meaning |
|---|---|
| `--state-dir` | Where the key and the enrolment are kept (env `ACCIEW_AGENT_STATE_DIR`; default is under the user's config directory). One agent per directory; a second `run` is refused. |
| `--collectors-dir` | Where the `acciew-collector-<name>` programs are. A job names a collector, never a path. Default: the directory the agent is in. |
| `--secrets-dir` | The directory each run's secret files are made in (a directory of its own, with a random name, inside it). It must be a real directory (not a link) owned by the agent's user that nobody else can enter, or it is refused; one that is not there is made, mode 700. Dedicated to this agent: its leftover `acciew-run-*` directories are removed at start, found by the device and inode of the state directory, so a restart that spells it another way (relative, through a link, in another case on a macOS filesystem) finds them. A state directory that was deleted and made again is a new agent, and what the old one left in `/dev/shm` stays until reboot. Default: `/dev/shm`, memory, where there is one; otherwise `run/` in the state directory. |
| `--pass-env NAME` | An environment variable a collector may inherit, besides `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (and lowercase) and `SSL_CERT_FILE`, `SSL_CERT_DIR`. Repeatable. One named like a secret (`AWS_SECRET_ACCESS_KEY`, `*_PASSWORD`, `*_TOKEN`, `*_SECRET`, `*_KEY`; not `*_KEY_ID`) is a credential and is kept out of what the service is sent, see below. |
| `--secret-env NAME` | Lets jobs name `env:NAME`. Repeatable. Without it, no `env:` reference is resolved. |
| `--secret-path PATH` | Lets jobs name `file:` references to this file, or to files under this directory (links that leave it are refused). Absolute; repeatable. Without it, no `file:` reference is resolved. |
| `--allow-any-secret-reference` | **Dangerous.** Lifts both lists: a job may name any variable and any file the agent's user can read. See below. |
| `--spool-mib` | The most one job's events may take on disk (default 2048). |
| `--verbose` | Log each chunk accepted. |

### What a job may ask the agent to read

The service writes a job's configuration, so it chooses which environment variable or file the
agent reads for a collector, and the collector sends the credential to the address that same
configuration names. A job could otherwise name `file:/home/you/.ssh/id_rsa` and a host of its own.
So **nothing is resolved until you list it**: start the agent with `--secret-env NAME` for each
variable and `--secret-path` for each credential file (or the directory that holds them) that a
connection may use. A job that names anything else is given up, with a reason that names the
reference (never its value) and the flag that would allow it. An agent started with no list says so
and gives up every job that names a credential.

Always refused, whatever is listed: `/proc`, `/sys`, `/dev` (`file:/proc/self/environ` is the
agent's whole environment), the agent's own state directory, and the directory its secret files
are made in. A path is checked as written and again with links followed: a link inside a listed
directory that leads out of it is refused.

`--allow-any-secret-reference` removes both lists. Use it only if you trust the service with every
variable and every readable file of the agent's user, and run that user with nothing else to read.

A job names at most 32 references, however it spells them, and the places they lead to may hold
4 MiB in all; each place is read and written once. A named path is checked by what it is (the same
file or directory by `os.SameFile`, whatever its case or link), so on macOS the key is the key under
any spelling, and a hard link to it is the key. Only regular files are read: a pipe is refused.

### What a compromised service can and cannot do

It **can** send jobs to the collectors you installed, with any configuration it writes; read what
those collectors read from your systems, which is the product; and point a collector that holds a
credential you listed at an address of its choosing, so that the collector sends that credential
there. The agent cannot stop that last one: which fields of a collector's configuration are the
addresses a credential goes to is the collector's own knowledge, and a rule over strings that look
like URLs would give a sense of safety it does not earn. It is out of scope for the agent (a
`--secret-host` pin was considered and not built for this reason). What does stop it is the network:
let the agent's host reach the service and the systems the collectors read, and nothing else.

It **cannot** read the agent's key or any file in its directory; have a variable or file read that you
did not list, or `/proc`, `/sys`, `/dev`; get the agent's environment into a collector; or receive a
credential in an event, in the exact value of a reference and the encodings listed under "What is
kept out of what the service is sent" (the parts read out of a value's structure are best effort). A
job whose credentials come to more than 200,000 patterns to look for is refused, never watched for in
part. The service holds no credential of yours, and the agent listens on no port.

## Change the key

```sh
acciew-agent rotate --state-dir /var/lib/acciew-agent
```

Makes a new key, has the old key sign for it, and swaps it in only once the service has taken it.
The new key is stored beside the old before the request is sent, so a lost answer cannot lock the
agent out; whichever key the service accepts is kept. The agent stays confirmed. A running agent
finds the new key on disk when its old one is refused, so `rotate` may be run beside `run`. Two
rotations at once are refused (a lock in the state directory): they would overwrite each other's
pending key. Rotate after a key may have been seen.

## What the agent sends

- At enrolment: the token, a name, its version and the protocol version, and the **public** key.
- To get a token: a signed assertion (id, audience, times, a random id). No secret.
- To report: heartbeats; chunks of events (a gzip of length-prefixed contract messages, each with
  its SHA-256); and, when it cannot do a job, one sentence of reason.

A reason is written in the agent's own words: what a collector wrote in a sentence is never copied
into it, only the collector's name, a field, a code or a contract rule, and the status the transport
gave. The sentence is in the agent's log. Everything the agent resolved on this host is scrubbed
from reasons and from the log, as it is, JSON- or Go-quoted, in base64 (both alphabets, with or
without padding), in hex and URL-escaped, and, in the log, with a quote written as the collector host's
logger writes one inside a quoted value (`\"`). Whitespace in a reason is collapsed after that, and the
reason is searched again. The events are the collection, which is the product.

### What is kept out of what the service is sent

Before an event is kept for upload it is searched for the credentials the job resolved. There are two
classes, and only the first is a guarantee.

**Guaranteed: the exact value of every reference, in the encodings listed.** Each resolved value of
8 bytes or more, as it is, JSON-quoted (Go's encoder with and without HTML escaping, with `/` written
`\/` as PHP and some Java do, and with every character outside ASCII written `\uXXXX`, in lower or
upper case, as Python, PHP, Java and .NET do), Go-quoted, in base64 (standard and URL alphabets, with and
without padding, and inside longer data at each of the three alignments, from 8 bytes), in hex (lower
or upper case) and URL-escaped, is looked for in the bytes of every event and in its text (every
string and bytes field, a value printed as the code and the message of one event, a value printed in
two pieces in the same field of two events, when the first piece is no longer than 64 KiB or the
longest thing looked for, whichever is less; the agent keeps that much of each of 64 fields, and follows
at most 4096 places in it where the value may have begun; only a value that starts with a run of one
byte, or of two alternating, longer than 4 KiB can get past that). A hit gives the job up, kills the collector and deletes
the spool; the event is not uploaded, and the reason and the log name the reference that matched
(`env:DB_PASSWORD`) and how it was written, never the value. The same forms are scrubbed from the
reasons and the log, and a value of 4 to 7 bytes is scrubbed there and not looked for in events, since
it is found by chance in ordinary data. The same holds for a `--pass-env` variable named like a secret (its value, as a reference's), for the
password of an address in any `--pass-env` variable, and for the `aws_secret_access_key`,
`aws_session_token` and `aws_security_token` in the AWS credentials and config files a collector is
pointed at: the file `AWS_SHARED_CREDENTIALS_FILE` or `AWS_CONFIG_FILE` names, or `$HOME/.aws/credentials`
and `$HOME/.aws/config` when `HOME` is passed. Those files are read when the job starts, from the
operator's own host, wherever `--secret-path` points; the agent's own files, `/proc`, `/sys` and
`/dev` are refused. A file that is not there, that the agent cannot read (as the collector, running as
the same user, cannot), that is not a file, or that is not at an absolute path (a relative `HOME`, an
unexpanded `~`) is skipped with a line in the agent's log, as the AWS SDK goes on without it; one
too big to watch for gives the job up. Values in quotes are watched for with and without them, and a
value of under 8 bytes is left out (a LocalStack `test` is a word, not a key).
If the credentials a job names come to more than 200,000 patterns to look for, the job is refused.

**Best effort: what is read out of the structure of a value.** A credential is often a file or a string
with the secret inside it, and a collector may say the rest. These parts are looked for as well, each
only when it is clearly the part that unlocks, so that a collector can still name its endpoint, its
account and its settings:

- a JSON file: the string under a field named like a secret, compared without case and split into
  words at underscores, dashes, dots, spaces and changes of case; a name that ends in one of the
  listed names as a word counts (`bind_password`, `bindPassword`, `app_secret`, `github_token`).
  `password`, `passwd`, `pwd`, `pass`, `passphrase`, `secret`, `client_secret` (and `clientSecret`): any
  value of 8 bytes or more, whatever it looks like, since the name says what it is. `token`,
  `access_token`, `refresh_token`, `api_key`, `access_key`, `master_key`, `private_key`, `credentials`,
  `AccountKey`, `SharedAccessKey`, `SecretAccessKey`, `SessionToken` and the others in that list: a
  value of 16 bytes or more with some variety in it that is not a URL, an address, a host name, a
  number, a path or the id of an access key (`AKIA...`, `ASIA...`). A name that only contains one (`password_policy`, `token_endpoint`) or that runs the words
  together (`bindpassword`) does not. Not the settings in the file (`token_endpoint_auth_method`,
  `authority_host`, `key_vault`, the account's address and id);
- an address or a connection string: the password of `user:password@host`, `redis://:password@host`, a
  driver's `user:password@tcp(host)/db` (the password may hold a slash), `https://token@host`; the
  parameters named as above, and `sig`, `code`, `key`, of a query, of `a=b;c=d` text or of the lines of
  a `.env` file (`DB_PASSWORD=...`), in quotes or in the braces of ODBC. Not the scheme, the host, the
  account name, the protocol or the options;
- a signed token (`eyJ...`): its payload and signature, not its header, which is in every token;
- a PEM text: each line of a private key (`PRIVATE KEY`, `RSA`, `EC`, `OPENSSH`, `ENCRYPTED`), not its
  armour, and not the lines of a certificate, which is public. Other multi-line text: each line of 16
  bytes or more;
- a plain token of 24 bytes or more: its first and last 16 bytes.

A boolean, a null, a number of under 8 digits or a word such as `none`, `enabled` or `off` under a
secret's name (`has_password: "true"`) is never taken, not even to scrub.

Not covered by either: a piece from the middle of a credential; a credential with its case changed
(hex is looked for in lower and upper case, not mixed); one split over different fields of different
events; any transformation not listed; a secret inside a string in a JSON file under a name that is not
a secret's; an address whose password holds a slash or a quote and has a scheme or no driver form. The
agent cannot know what a collector does to a value it was handed, and a derived part that is also
ordinary text will be refused for a coincidence once in a while, for instance a user named like his
password; the log says which reference it was. Other `--pass-env` variables are settings (a region, a
path), not credentials. A credential should go to a collector as a reference.

**Running the AWS IAM collector under the guarantee.** It takes no reference: it reads the AWS SDK's
own environment, and a collector is given only `PATH` and `--pass-env`. Start the agent with
`--pass-env AWS_ACCESS_KEY_ID --pass-env AWS_SECRET_ACCESS_KEY` (and `--pass-env AWS_SESSION_TOKEN` for
temporary keys), or with `--pass-env AWS_SHARED_CREDENTIALS_FILE` (and `AWS_PROFILE`) to use a file.
The secret key and the token are then kept out of events, reasons and the log; the key id is a
setting. Outside the guarantee, because the agent never sees them: credentials the SDK fetches itself
(the instance metadata service, IRSA and Pod Identity with `AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, whose files are not read, the SSO cache under
`~/.aws/sso/cache`, and `credential_process`). A reference of the form `env:` or `file:` for this
collector is the better way and is not built yet.

The wire protocol is [`docs/agent-protocol.md`](../../docs/agent-protocol.md).

## How a job ends

| | |
|---|---|
| Uploaded | The last chunk is in. Whether the collection was whole is read from its completion by the service. If the last chunk carried no completion, the service says so (`ended_early`) and offers the job again at once, resumed. |
| Given up | The collector is not installed, a reference does not resolve or is not listed, the collector refuses its configuration, it breaks the contract (an event the contract forbids, a resumed stream that says it is complete) or echoes a credential, or the upload fails for ten minutes. The service is told why, in the agent's words. |
| Lease lost | The service moved the job. The collector is killed; nothing more is sent. |
| Stopped | The agent was asked to stop. Nothing is sent; the job lapses. |

A stream **ends early** when the collector closes it without a completion or dies, when the spool
is full (`--spool-mib`; room is kept at the end of its cap for the completion), when it has all the
chunks or bytes the service allows a stream (1000 of its 1024 chunks, 1.9 of its 2 GiB compressed), or
when the service refuses a chunk as too large. The collector is stopped and the last chunk, which
carries no completion, ends the stream at its last checkpoint. The service answers `ended_early` and
offers the job again at once, with the cursor of the last checkpoint it was sent, on a new stream
with chunks numbered from 0; it stitches the streams of a run into one collection, and fails a run
that has been started eight times. So a collection too big for the spool, or a collector that dies
once, arrives as several streams. Events after the last checkpoint that an earlier chunk already
carried are dropped by the service, which keeps a stream to its last checkpoint; a stream that fills
up before any checkpoint has gone up cannot be resumed, and the job is given up instead of repeating
itself. A collector's own error that the agent cannot receive (an event over 4 MiB) is given up, not
retried.

**A source that holds too much is given up, not split.** The service reads a collection in memory and
refuses one of more than 1,000,000 events or 2 GiB inflated, counted over all the streams of the run.
Ending a stream early cannot help with that: the next stream would only add to what is already too
much. The job says how many events the earlier streams of the run contribute (`resume_events`), and the
agent stops, with an abort that says `this source holds more than 990,000 events, the most one
collection may hold`, when this stream would pass 990,000 less that (the chunk that carries the
completion may go to the service's 1,000,000, since a collection that is whole is not thrown away
for a margin). The service does not say how much data the earlier streams hold, so the agent keeps
that account itself, for the run: 1.9 GiB for the whole collection, less what its streams sent, kept
to their last checkpoints. It is kept while the run may be offered to the agent again (a lost lease,
a stop) and dropped when the run ends; a stream whose collector says it could not use the cursor
(`cursor.rejected`) stands alone, and its account starts again at nothing. After a restart of the
agent the account starts again at nothing too, and a collection that is too big for the service is
then refused when it is read, which fails the run with the service's message.

The agent does not ask for work while it holds a job, and asks again at once when one ends. It holds
one poll at a time (the service answers a newer poll and drops an older). A chunk answered `503` with
`Retry-After` is waited for as asked and not counted as failing; a chunk is sent again with the
bytes it had, and a number the service has seen is answered from its digest (`200 duplicate`, or
`409 chunk_conflict` if the bytes ever differed).

A job that carries a cursor is run with it as the collector's `resume_from`. The collector decides
what its stream then says: a stream that resumed ends INCOMPLETE with `PARTIAL_STREAM`, and the
agent sends the completion as the collector wrote it. The service reads each chunk as it arrives and
refuses one that is not well formed (422, nothing kept); the agent sends such a chunk three times and
then gives the job up.

## Files

In the state directory: `agent.key` (PKCS#8 PEM, mode 0600), `agent.json`, `agent.key.next` (only
during a rotation), `lock`, and `spool/` (a job's events while they wait; empty between jobs).

## Not done, and not verified

- **Not run against the real service.** It is tested against a fake that applies the service's
  rules for assertions, tokens, leases and chunks (written from the service's code), with real
  collectors as child processes. The first run against the service may find a difference.
- **A job with a budget is given up**, not run: the protocol does not say what one looks like (the
  service sends `null`). A resume cursor is honoured.
- **It does not report the collector binary's digest** to the service: the protocol has no field.
- No Windows build. No mTLS: the agent authenticates with its key, which survives the
  TLS-inspecting proxies that client certificates do not.
- The agent trusts the files in `--collectors-dir`; whoever can write there can run code as the
  agent. It warns if the directory is writable by others.
