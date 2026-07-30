# hrp — HTTP record & replay proxy

[![CI](https://github.com/nhan4013/hrp/actions/workflows/ci.yml/badge.svg)](https://github.com/nhan4013/hrp/actions/workflows/ci.yml)

A single-binary, language-agnostic HTTP proxy that records real traffic to a
third-party API into a plain-YAML *cassette*, then replays it so your tests run
without touching the network.

Point your app at the proxy instead of at the vendor. No application code
changes, no per-language library, no JVM.

```
┌──────────────┐        ┌──────────────────┐        ┌──────────────┐
│  your app    │  HTTP  │   hrp (proxy)    │  HTTP  │  third-party │
│ (any lang)   │───────>│  record | replay │───────>│  API         │
└──────────────┘        └────────┬─────────┘ (record └──────────────┘
                                 │            only)
                                 v
                        ┌──────────────────┐
                        │ cassettes/*.yaml │
                        └──────────────────┘
```

## Status

Work in progress — this is a learning project, built in the open.

- [x] Reverse proxy: graceful shutdown, structured logging, 502 on upstream failure
- [x] Record: request/response pairs into a human-readable YAML cassette
- [x] Header redaction, default-deny, no configuration required
- [x] Replay: serves from the cassette, never touches the network
- [x] Matching engine with a diff that names the field that differs
- [x] `auto` mode: replay what is known, record what is not
- [x] `hrp inspect`: list a cassette's interactions
- [x] Body redaction (JSON field paths, regex) and `hrp scan`
- [x] Fault injection: latency, error rate, forced timeout
- [x] Config file, `hrp.yaml`
- [x] Golden-file tests and CI
- [x] MITM forward proxy, so `HTTPS_PROXY=localhost:8080` is all you need
- [ ] Release binaries and a Docker image

> **Check a cassette before you commit it.** Sensitive headers are redacted with
> no configuration, but which body field holds a card number is specific to your
> API, so body redaction has to be declared in `hrp.yaml`. Run `hrp scan` — it
> exits non-zero when it finds something, so it works as a pre-commit hook.

## Try it

```sh
make build

# forward traffic and record it
./bin/hrp record -u https://sandbox.payment-vendor.com -c ./cassettes/payment.yaml

# point your app at the proxy instead of the vendor
curl -X POST localhost:8080/v1/charges \
     -H 'authorization: Bearer sk_live_xxx' \
     -H 'content-type: application/json' \
     -d '{"amount":1500000}'
```

Stop the proxy with Ctrl-C and the cassette is on disk:

```yaml
version: 1
name: payment
upstream: https://sandbox.payment-vendor.com
interactions:
    - id: 5f0a826eaec3
      request:
        method: POST
        path: /v1/charges
        headers:
            authorization:
                - <REDACTED>
            content-type:
                - application/json
        body: '{"amount":1500000}'
        body_hash: sha256:509f013f3f61a9a3...
      response:
        status: 201
        body: '{"id":"ch_123","status":"succeeded"}'
        duration_ms: 342
```

The same logical call recorded from a Python service matches the same call made
from Go or Node: client-specific and hop-by-hop headers are dropped, so the
cassette is portable rather than tied to whichever HTTP library recorded it.

### Replay it

Now unplug the network. No upstream needed — replay never leaves the machine.

```sh
./bin/hrp replay -c ./cassettes/payment.yaml
```

A hit is served straight from the cassette, tagged `X-Hrp-Replay: hit`. JSON key
order does not matter: a client that serializes its map differently is still
making the same call.

A miss returns **599** — a status no real API uses, so it can never be confused
with a genuine vendor error — and a body that tells you exactly what went wrong
instead of just "no match found":

```
No recorded interaction matches POST /v1/charges

  Closest candidate: 0a3419e68eab (POST /v1/charges), score 0.90
  Differs on: body

  [body]
    - recorded: {"amount": 1500000, "currency": "VND"}
    + incoming: {"amount": 2000000, "currency": "VND"}
      amount: recorded 1500000, incoming 2000000
```

Candidates are ranked, with method and path weighted highest, so the diff you
are shown is against the interaction you probably meant.

Replay never rewrites the cassette. Hit counts stay in memory, so a passing test
suite leaves a clean working tree.

### Leave it on `auto` while you work

`auto` replays what it has and records what it does not, so the cassette fills in
as you go. New calls reach the vendor once; every repeat is served locally.

```sh
./bin/hrp auto -u https://sandbox.payment-vendor.com -c ./cassettes/payment.yaml
```

### Look inside a cassette

```
$ hrp inspect ./cassettes/payment.yaml
./cassettes/payment.yaml
3 interaction(s)

ID            METHOD  PATH         QUERY         STATUS  REQ  RESP  MS   HITS
8fa13f7c4e58  GET     /v1/ready    -             201     -    53B   1    0
3992f97c9faf  POST    /v1/charges  currency=VND  201     18B  75B   41   2
12609b2f15d0  POST    /v1/charges  -             201     18B  75B   40   0
```

`--sort path` or `--sort status` to reorder. Sizes are of the original payload,
not of its stored form, so a base64 body does not look a third larger than it is.

## Commands

| Command | What it does |
|---|---|
| `hrp record -u URL -c FILE` | Forward upstream and record every interaction |
| `hrp replay -c FILE` | Serve from the cassette; never touch the network |
| `hrp auto -u URL -c FILE` | Replay what is recorded, record what is not |
| `hrp proxy -u URL` | Forward upstream, record nothing |
| `hrp mitm <record\|replay\|auto\|proxy> -c FILE` | Same modes, as a forward proxy with TLS MITM: the app is unchanged, only `HTTPS_PROXY` points here |
| `hrp ca install` | Create the development CA `mitm` uses, and show how to trust it |
| `hrp inspect FILE` | List a cassette's interactions as a table |
| `hrp scan FILE...` | Look for secrets a cassette should not carry; exits non-zero if found |

Shared flags: `-l/--listen` (default `:8080`), `-u/--upstream`, `-c/--cassette`,
`--name`, `--config`. `replay` and `auto` also take `--ignore-query` for the
timestamps and nonces that change on every call. An explicit flag beats the
config file, which beats the default.

Matching is on method, path, query and body. Headers take no part: they differ
per HTTP client, and the ones carrying secrets are redacted on both sides anyway.

## HTTPS without changing the app

Everything above points the app at hrp instead of at the vendor. `hrp mitm`
goes the other way: the app keeps its real base URL, and only the environment
changes. Each CONNECT tunnel is terminated with a per-host certificate signed
by a local development CA, so HTTPS traffic is recorded and replayed the same
way plain HTTP is.

```sh
hrp ca install                                # once: create the CA, then trust it
export REQUESTS_CA_BUNDLE=~/.hrp/ca.pem       # what your HTTP client trusts

hrp mitm record -c ./cassettes/payment.yaml &
HTTPS_PROXY=localhost:8080 ./myapp            # app unchanged
```

`mitm` takes the same subcommands — `record`, `replay`, `auto`, `proxy` — and
the same flags, minus `--upstream`: every request names its own.

A forward proxy fills one cassette from many vendors, so interactions recorded
this way carry `scheme` and `host`, and matching compares them:
`/v1/charges` on one vendor is not `/v1/charges` on another. Cassettes recorded
through the reverse proxy carry no host and match exactly as before — an absent
host is a wildcard.

The CA key signs for *any* host. It is written with 0600 permissions under
`~/.hrp/`, it exists for development, and it must stay out of git — `ca install`
prints the per-tool and system-wide ways to trust the certificate and the
warning that goes with them.

## Keeping secrets out of the cassette

Redaction runs on the write path only. A cassette gets committed, and one leaked
token stays leaked for the whole of that repository's history.

Sensitive headers — `authorization`, `cookie`, `set-cookie`, `x-api-key` and
friends — are redacted with no configuration at all. Bodies need rules, because
which field holds a card number is specific to your API:

```yaml
redact:
  headers: [x-vendor-signature]
  json_fields: [card.number, cvv, id_number]   # structural, reaches numbers too
  patterns:                                    # textual, reaches into strings
    - name: card_number
      regex: '\b\d{13,19}\b'
```

`json_fields` walks the decoded document, so it can redact a secret stored as a
JSON *number*, and it traverses arrays element-wise. `patterns` apply to header
values and to JSON string values — never to bare numbers, because rewriting one
would turn `"amount":4111111111111111` into invalid JSON.

**Known limitation:** JSON encoded inside a JSON string is not walked
structurally, so `json_fields` cannot reach into a payload a vendor echoes back as
a string. `patterns` do reach inside those strings, which is what makes them the
tool for embedded payloads.

Body hashes are computed *after* redaction. A SHA-256 of a 16-digit card number
would be brute-forceable, so the hash has to be of the redacted bytes.

### `hrp scan` is the safety net

Redaction is configured; scanning is not. That asymmetry is deliberate — the last
line of defence has to work with no config at all.

```
$ hrp scan ./cassettes/payment.yaml
FOUND ./cassettes/payment.yaml — 1 suspected secret(s)

  INTERACTION   LOCATION                          DETECTOR  EXCERPT
  4965e53f3991  request.headers.x-vendor-session  jwt       eyJhbG****VP
```

Excerpts are masked: a report gets pasted into issues and CI logs, so it must not
become a second copy of the secret. Exit status is non-zero when anything is
found.

Built-in detectors are high precision — Stripe, GitHub, AWS, Google and Slack key
shapes, JWTs, private-key headers, bearer tokens, and card numbers confirmed by a
Luhn checksum. A scanner that cries wolf gets switched off, so shapes that cannot
be told apart from ordinary data (a 12-digit national ID, a phone number) are
*not* built in. Declare those in `hrp.yaml`; `hrp scan --config hrp.yaml` adds
every `redact.patterns` entry as an extra detector.

## Fault injection

Exercise retry and circuit-breaker paths without asking a vendor to break.

```yaml
fault:
  enabled: true
  latency: 200ms       # added to every request
  error_rate: 0.5      # probability of answering error_status instead
  error_status: 503
  hang_rate: 0         # probability of never answering, to hit client timeouts
  seed: 42             # fixes the sequence
```

The seed matters: a test that fails on the third retry has to fail on the third
retry again. With a fixed seed the same run produces the same sequence of
failures, verified across process restarts. Injected responses carry
`X-Hrp-Fault: error`, so a confusing 503 can be traced back to configuration.

See [hrp.yaml](hrp.yaml) for the whole schema. Unknown keys are rejected — a
misspelled redact rule that silently does nothing is exactly what that file
exists to prevent.

## Development

```sh
make ci      # everything CI runs, in the same order
make race    # go test -race ./...   <- the one that matters
make lint    # golangci-lint run
make golden  # regenerate golden files, then read the diff
make scan     # hrp scan its own committed cassettes
```

Two golden files guard output that unit tests would not notice drifting: the
recorded cassette format, and the text of a replay miss report. Both regenerate
with `-update` — read the resulting diff rather than committing it blind.

CI also runs `hrp scan` over every cassette committed under `testdata/`. The
tool's promise is that a committed cassette carries no secrets, so this
repository is held to it too.

## License

[MIT](LICENSE)
