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
- [ ] Replay + matching engine, with a readable diff explaining every miss
- [ ] `auto` mode: replay what is known, record what is not
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
./bin/hrp -listen :8080 -upstream https://sandbox.payment-vendor.com \
          -cassette ./cassettes/payment.yaml

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

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:8080` | Address to listen on |
| `-upstream` | — | Upstream base URL (required) |
| `-cassette` | — | Record to this file; omit for plain pass-through |
| `-name` | file base name | Cassette name |

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
