# hrp — HTTP record & replay proxy

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
- [ ] Body redaction (JSON field paths, regex) and `hrp scan`
- [ ] Fault injection: latency, error rate, forced timeout
- [ ] MITM forward proxy, so `HTTPS_PROXY=localhost:8080` is all you need

> **Cassettes are not yet safe to commit to git.** Only headers are redacted so
> far. A secret inside a request or response body — a card number, a token
> echoed back by the vendor — is still written to disk verbatim. Body redaction
> and a `hrp scan` pre-commit check are the next milestone.

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
| `hrp inspect FILE` | List a cassette's interactions as a table |

Shared flags: `-l/--listen` (default `:8080`), `-u/--upstream`, `-c/--cassette`,
`--name`. `replay` and `auto` also take `--ignore-query` for the timestamps and
nonces that change on every call.

Matching is on method, path, query and body. Headers take no part: they differ
per HTTP client, and the ones carrying secrets are redacted on both sides anyway.

## Development

```sh
make test    # go test ./...
make race    # go test -race ./...   <- the one that matters
make lint    # golangci-lint run
```

Design notes, roadmap and the reasoning behind the tricky parts (single-read
request bodies, cassette concurrency, determinism, explainable match failures)
live in [a.md](a.md).

## License

Not yet chosen — all rights reserved for now.
