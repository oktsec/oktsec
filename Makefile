.PHONY: build test lint clean

BINARY := oktsec
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X github.com/oktsec/oktsec/cmd/oktsec/commands.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/oktsec

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY)

install: build
	cp $(BINARY) $(GOPATH)/bin/$(BINARY)
