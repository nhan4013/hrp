BINARY := hrp
# make run UPSTREAM=https://sandbox.vendor.com
UPSTREAM ?=

.PHONY: build test race lint fmt run clean

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

run: build
	./bin/$(BINARY) -upstream $(UPSTREAM)

clean:
	rm -rf bin
