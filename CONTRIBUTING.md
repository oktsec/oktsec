# Contributing to Oktsec

Contributions are welcome. Here's how to get started.

## Development

```bash
git clone https://github.com/oktsec/oktsec.git
cd oktsec
make build
make test
```

Requirements:
- Go 1.23+
- No CGO (pure Go dependencies only)

## Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Write tests for your changes
4. Run `make test` and `make lint`
5. Commit with a clear message
6. Open a PR against `main`

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions small and focused
- Add tests for new functionality
- No CGO dependencies — the project must cross-compile cleanly

## Rules

If you're adding detection rules to `rules/default.yaml`:

- Follow the existing YAML format (same as Aguara rules)
- Include `true_positive` and `false_positive` examples
- Use the `IAP-` prefix for inter-agent protocol rules
- Test your patterns against both true and false positives

## Issues

- Use GitHub Issues for bugs and feature requests
- Include reproduction steps for bugs
- Check existing issues before opening a new one
