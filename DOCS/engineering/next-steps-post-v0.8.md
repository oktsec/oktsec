# Next Steps - Post v0.8.0

## Completed (v0.8.0 session)

### P0 - Must fix before v1.0
- [x] Tag release v0.8.0
- [x] SEC-1/SEC-2: Sanitize `err.Error()` in HTTP responses (3 locations)

### P1 - Should fix
- [x] Increase proxy coverage to >65%
- [x] Increase engine coverage to >65%
- [x] Increase identity coverage to >70%
- [x] Increase dashboard coverage to >55%

### P2 - Nice to have
- [x] Fix Content-Security-Policy header (remove stale external domains)
- [x] Add CODEOWNERS file

---

## Current Sprint (v0.8.1)

### P1 - In progress
- [x] **Increase gateway coverage to >65%** - 56.1% -> 69.4%. Added tests for NewGateway, Port, Shutdown, listenAutoPort, isAddrInUse, NewBackend, toolError, unknown/empty agent paths.
- [ ] **Publish Python SDK to PyPI** - `pyproject.toml` ready. Needs PyPI credentials.

### P2 - In progress
- [x] **Speed up dashboard tests** - 158s -> 21s (8.5x speedup). Shared scanner via TestMain instead of recompiling 175 rules per test.
- [x] **Add benchmark regression gate to CI** - Added `make bench` step to `.github/workflows/ci.yml`.

### Road to v1.0
- [x] **Automated release workflow** - Already exists at `.github/workflows/release.yml` with goreleaser, multi-arch Docker, GHCR push, checksums.
- [x] **CHANGELOG automation** - goreleaser generates changelog from commit messages on release.
- [x] **Zero known vulnerabilities** - `govulncheck` clean.

---

## Road to v1.0 (backlog)

### Agent CRUD API
- REST endpoints for agent create/update/delete
- Key rotation workflow
- Agent status dashboard improvements

### Documentation Site
- Hosted docs (GitHub Pages or Docusaurus)
- API reference generated from code
- Tutorial: "Securing your first agent pipeline"

### Advanced Features
- Per-agent egress control (design in `DOCS/strategy/egress-control-plan.md`)
- Multi-tenant support (per-org isolation)
- Custom rule IDE (YAML editor in dashboard)
- Webhook retry with exponential backoff
- Rule testing sandbox in dashboard (partially implemented)

### Quality Gates for v1.0
- [ ] Total test coverage >60%
- [x] Zero known vulnerabilities (govulncheck) - verified 2026-03-05
- [x] All OWASP agentic categories covered
- [ ] Load test: >50K msgs/sec sustained
- [ ] Python SDK published to PyPI
- [ ] At least one external contributor or user
