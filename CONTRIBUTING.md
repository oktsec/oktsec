# Contributing to Oktsec

Contributions are welcome. Here's how to get started.

## Development Setup

```bash
git clone https://github.com/oktsec/oktsec.git
cd oktsec
make build
make test
```

Requirements:
- Go 1.25+
- No CGO (pure Go dependencies only)

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build the binary with version injection |
| `make test` | Run all tests with race detector |
| `make lint` | Run golangci-lint |
| `make vet` | Run go vet |
| `make fmt` | Format all Go files |
| `make bench` | Run the scaling benchmark |
| `make clean` | Remove the binary |
| `make run ARGS="serve"` | Run with arguments |

## Project Structure

```
cmd/
  oktsec/commands/   CLI commands (cobra)
  bench/             Scaling benchmark
internal/
  audit/             SQLite audit trail, quarantine queue
  config/            YAML config loader + validator
  dashboard/         Web UI (handlers, templates, auth)
  discover/          MCP server auto-discovery
  engine/            Aguara scanner integration
  identity/          Ed25519 keypairs, signing, verification
  mcp/               MCP tool server
  policy/            YAML-based ACL evaluator
  proxy/             HTTP proxy, stdio wrapper
rules/               Inter-agent protocol detection rules
```

## Adding Detection Rules

If you're adding rules to `rules/default.yaml`:

- Follow the existing YAML format (same schema as [Aguara](https://github.com/garagon/aguara) rules)
- Use the `IAP-` prefix for inter-agent protocol rules
- Include `true_positive` and `false_positive` examples for self-testing
- Test your patterns: `make test`

## Running Tests

```bash
# Full suite with race detector
make test

# Single package
go test -race -count=1 ./internal/audit/

# Verbose output
go test -v -race ./internal/proxy/
```

## Pull Request Process

1. Open an issue first to discuss the change
2. Fork the repo and branch from `main`
3. Write tests for your changes
4. Ensure all checks pass:
   ```bash
   make build && make test && make lint && make vet
   ```
5. Update `CHANGELOG.md` under `[Unreleased]` if it's a user-facing change
6. Submit a PR with a clear description

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] No lint issues (`make lint`)
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] No breaking changes (or clearly documented)

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions small and focused
- No CGO dependencies — the project must cross-compile cleanly
- Templates use server-rendered HTML with HTMX for interactivity

## Reporting Issues

- [Bug reports](https://github.com/oktsec/oktsec/issues/new?template=bug_report.yml)
- [Feature requests](https://github.com/oktsec/oktsec/issues/new?template=feature_request.yml)
- Security vulnerabilities: see [SECURITY.md](SECURITY.md)
