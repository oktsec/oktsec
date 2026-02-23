BINARY := oktsec
PKG := github.com/oktsec/oktsec
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-s -w -X $(PKG)/cmd/oktsec/commands.version=$(VERSION) -X $(PKG)/cmd/oktsec/commands.commit=$(COMMIT)"

.PHONY: build test integration-test lint run clean fmt vet bench

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/oktsec

test:
	go test -race -count=1 ./...

integration-test:
	go test -race -count=1 -tags=integration ./internal/proxy/ -v -timeout 120s

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

run:
	go run ./cmd/oktsec $(ARGS)

bench:
	go run ./cmd/bench

clean:
	rm -f $(BINARY)
