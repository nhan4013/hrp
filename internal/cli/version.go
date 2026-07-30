package cli

// version is stamped by goreleaser via -ldflags at build time, e.g. v1.2.3. A
// plain `go build` or `go run` — the common case for this project's own tests
// and its Makefile — leaves it at "dev".
var version = "dev"
