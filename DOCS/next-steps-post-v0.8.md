# Next Steps — Post v0.8.0

## Completed (v0.8.0 session)

### P0 — Must fix before v1.0
- [x] Tag release v0.8.0
- [x] SEC-1/SEC-2: Sanitize `err.Error()` in HTTP responses (3 locations)

### P1 — Should fix
- [x] Increase proxy coverage to >65% (55.9% → 70.5%)
- [x] Increase engine coverage to >65% (48.9% → 87.0%)
- [x] Increase identity coverage to >70% (56.4% → 91.5%)
- [x] Increase dashboard coverage to >55% (47.1% → 56.2%)

### P2 — Nice to have
- [x] Fix Content-Security-Policy header (remove stale external domains)
- [x] Add CODEOWNERS file

---

## Remaining Items

### P1 — Should fix
- [ ] **Increase gateway coverage to >65%** — Currently 56.1%. Remaining gap is lifecycle functions (NewGateway, Start, Shutdown, createSession) that require real MCP connections. Consider adding an integration test.
- [ ] **Publish Python SDK to PyPI** — `pyproject.toml` ready. Steps:
  ```bash
  cd sdk/python
  python -m build
  twine upload dist/*
  ```

### P2 — Nice to have
- [ ] **Profile and speed up dashboard tests** — 155s with race detector. Likely re-parsing templates per test. Consider caching template compilation in test helpers.
- [ ] **Add benchmark regression gate to CI** — `cmd/bench` exists, add to CI workflow as a check that fails if throughput drops below threshold (e.g., 10K msgs/sec).

---

## Road to v1.0

### Agent CRUD API
- REST endpoints for agent create/update/delete
- Key rotation workflow
- Agent status dashboard improvements

### Documentation Site
- Hosted docs (e.g., GitHub Pages or Docusaurus)
- API reference generated from code
- Tutorial: "Securing your first agent pipeline"

### Release Process
- Automated CHANGELOG generation from PRs
- GitHub Actions release workflow with goreleaser
- Docker image published to GHCR

### Advanced Features
- Multi-tenant support (per-org isolation)
- Custom rule IDE (YAML editor in dashboard)
- Agent-to-agent authorization graph visualization improvements
- Webhook retry with exponential backoff
- Rule testing sandbox in dashboard (partially implemented)

### Quality Gates for v1.0
- [ ] Total test coverage >60%
- [ ] Zero known vulnerabilities (govulncheck)
- [ ] All OWASP agentic categories covered (already done)
- [ ] Load test: >50K msgs/sec sustained
- [ ] Python SDK published to PyPI
- [ ] At least one external contributor or user
