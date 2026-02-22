BINARY := oktsec
PKG := github.com/oktsec/oktsec
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -ldflags "-s -w -X $(PKG)/cmd/oktsec/commands.version=$(VERSION) -X $(PKG)/cmd/oktsec/commands.commit=$(COMMIT)"

.PHONY: build test lint run clean fmt vet bench

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/oktsec

test:
	go test -race -count=1 ./...

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
