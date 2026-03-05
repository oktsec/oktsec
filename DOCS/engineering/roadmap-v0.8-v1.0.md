# Roadmap v0.8 → v1.0

**Date**: 2026-03-05
**Baseline**: v0.8.0 — 28K LOC, 21 packages, 36 PRs merged, 175 detection rules

## Phase 1: Python SDK

**Goal**: `pip install oktsec` — HTTP client for Python ecosystem

- HTTP client for `/v1/message`, `/health`, `/v1/quarantine/{id}`
- Ed25519 signing (PyNaCl or `cryptography` lib)
- Sync + async (httpx) support
- Publish to PyPI as `oktsec`
- Scope: ~300 lines + tests
- Location: `sdk/python/`

**Why first**: MCP ecosystem is majority Python/TS. Without this, Python users do raw HTTP.

## Phase 2: Release v0.8.0

**Goal**: Tagged release with downloadable binaries

- Tag v0.8.0 from current main
- goreleaser config (linux/darwin/windows, amd64/arm64)
- Verify `install.sh` works end-to-end with the new release
- GitHub Release with changelog notes
- Optional: Homebrew tap via goreleaser

**Why second**: Makes `curl | bash` install actually work with all the new features.

## Phase 3: Integration Tests E2E

**Goal**: Validate the full happy path automatically

- Test: `setup` in tmpdir → `serve` → send messages via proxy → verify audit entries
- Test: `wrap` + `unwrap` roundtrip on mock client config
- Test: `gateway` with mock MCP backend → tool call interception
- Tag: `-tags=integration`, separate from unit tests
- CI: run on PR merge to main

**Why third**: Protects the onboarding flow against regressions. Current unit tests cover pieces but not the assembled pipeline.

## Phase 4: Framework Integration Examples

**Goal**: Concrete demos showing oktsec with popular AI frameworks

- `examples/langchain-oktsec/` — LangChain agent using MCP tools through oktsec proxy
- `examples/crewai-oktsec/` — Multi-agent CrewAI setup with message interception
- `examples/python-sdk/` — Minimal Python script using the SDK
- Each example: README + working code + expected output

**Why fourth**: These become the marketing content. Developers adopt what they can copy-paste.

## Phase 5: Observability

**Goal**: Enterprise-ready metrics and log export

- Prometheus `/metrics` endpoint: messages/s, latency p50/p95/p99, blocks, quarantine pending, rules triggered by category
- Structured log output (JSON mode for log aggregators)
- Optional: OTLP trace export for distributed tracing
- Optional: Syslog forwarding

**Why fifth**: Without this, oktsec is invisible to SREs. Blocks enterprise adoption.

## Phase 6: Dashboard Agent CRUD

**Goal**: Add/edit/delete agents from the dashboard UI

- Form to create new agent (name, can_message, risk_level, blocked_content)
- Edit existing agent config
- Writes back to `oktsec.yaml`
- Requires config hot-reload on save

**Why last**: Smallest user group benefits from this. CLI/YAML editing works fine for now.

---

## Post-Implementation: Full Quality Audit

After all 6 phases, run a comprehensive battery:

### Performance
- Benchmark: messages/sec throughput at 1, 10, 100 concurrent connections
- Latency: p50/p95/p99 under load (existing `cmd/bench`)
- Memory: profile under sustained traffic, check for leaks
- SQLite: write throughput with WAL mode under contention
- Startup time: cold start to first request served

### Security
- OWASP Top 10 for Agentic Applications — verify coverage of all 10 categories
- Input fuzzing: malformed JSON, oversized payloads, unicode edge cases
- SSRF validation: confirm safefile hardening blocks path traversal and symlinks
- Auth: dashboard access code brute-force resistance, timing attacks
- TLS: verify no plaintext secrets in logs or error messages
- Dependency audit: `govulncheck`, license scan

### Open Source Quality
- README completeness: install, quick-start, all modes documented, badges
- CONTRIBUTING.md: how to add rules, run tests, submit PRs
- LICENSE: Apache 2.0 confirmed
- CI: build + test + lint + vet on every PR
- Code coverage: target >70% across all packages
- godoc: exported types and functions documented
- CHANGELOG: complete for all versions
- Release artifacts: signed binaries, checksums
- Issue templates: bug report, feature request
- Security policy: SECURITY.md with disclosure process

---

## Success Criteria for v1.0

- [ ] Python SDK published on PyPI
- [ ] Tagged release with working install script
- [ ] E2E integration tests in CI
- [ ] At least 2 framework examples with working code
- [ ] Prometheus metrics endpoint
- [ ] Full quality audit passed (performance, security, OSS)
- [ ] All 175+ detection rules with true/false positive examples
- [ ] Zero known security issues
