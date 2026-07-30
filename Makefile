BINARY := hrp
# make run UPSTREAM=https://sandbox.vendor.com
UPSTREAM ?=

.PHONY: build test race lint fmt golden scan ci run clean

build:
	go build -o bin/$(BINARY) ./cmd/hrp

test:
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	go fmt ./...

# Regenerate the golden files, then read the diff before committing it.
golden:
	go test ./... -update

# The tool's promise is that a committed cassette carries no secrets. Hold this
# repository to it. Needs bash for mapfile; make may default to sh.
scan: build
	@bash -c 'mapfile -t c < <(find . -path "*/testdata/*" -name "*.yaml"); \
	  if [ $${#c[@]} -eq 0 ]; then echo "no committed cassettes to scan"; exit 0; fi; \
	  ./bin/$(BINARY) scan --config hrp.yaml "$${c[@]}"'

# Everything CI runs, in the same order, so a red pipeline can be reproduced
# locally without pushing.
ci:
	@u=$$(gofmt -l .); if [ -n "$$u" ]; then echo "needs gofmt:"; echo "$$u"; exit 1; fi
	go vet ./...
	go build ./...
	go test -race -count=1 ./...
	golangci-lint run
	$(MAKE) scan

run: build
	./bin/$(BINARY) proxy --upstream $(UPSTREAM)

clean:
	rm -rf bin
