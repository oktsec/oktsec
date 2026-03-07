# Contributing

## Development setup

```bash
git clone https://github.com/oktsec/oktsec.git
cd oktsec
make build
make test
```

Requirements: Go 1.23+.

## Build commands

```bash
make build          # Build binary with version injection
make test           # All tests, race detector enabled
make lint           # golangci-lint
make vet            # go vet
make fmt            # gofmt
```

Run a single package:

```bash
go test -race -count=1 ./internal/proxy/
go test -v -race -count=1 ./internal/audit/
```

## Pre-PR checklist

```bash
make build && make test && make lint && make vet
```

## Adding detection rules

1. Add rules to `rules/default.yaml` following the Aguara YAML schema
2. Use `IAP-` prefix for inter-agent rules
3. Include `true_positive` and `false_positive` examples
4. Run `make test` to verify

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`)
- No CGO — all dependencies must be pure Go
- Keep the security pipeline order (cheapest checks first)
- Tests use `testify/assert` and `testify/require`

## Reporting security vulnerabilities

See [SECURITY.md](https://github.com/oktsec/oktsec/blob/main/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](https://github.com/oktsec/oktsec/blob/main/LICENSE).
