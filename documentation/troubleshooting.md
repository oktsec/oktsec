# Troubleshooting

Fixes for the issues operators hit most often in the first hour. If your problem isn't here, open a [GitHub issue](https://github.com/oktsec/oktsec/issues) with the output of `oktsec doctor` attached.

## Quick first step

Before anything else:

```bash
oktsec doctor
```

This runs a self-check (config validity, keys, DB permissions, MCP client discovery, open ports). Most first-install problems show up here with an exact fix.

---

## 1. Port 8080 already in use

**Symptom**: `oktsec run` exits with `bind: address already in use` or `listen tcp 127.0.0.1:8080: bind`.

**Cause**: another process owns the port. Common culprits: a prior `oktsec` instance that didn't shut down cleanly, Jenkins, a local dev server.

**Fix**:

```bash
# Find the process
lsof -iTCP:8080 -sTCP:LISTEN
# or
ss -ltnp | grep 8080

# Either kill it, or run oktsec on a different port:
oktsec serve --port 8181
```

To make the port change persistent, edit `server.port` in `oktsec.yaml`.

---

## 2. `signature verification failed` on every message

**Symptom**: every `POST /v1/message` returns 403 with `"policy_decision": "identity_rejected"` even though the client is signing.

**Causes** (in order of frequency):

1. The client is signing with a key that doesn't match the public key in `keys/<agent>.pub`.
2. Agent config uses a `key_version` that the client isn't echoing in the `X-Oktsec-Key-Version` header.
3. The `timestamp` field in the signed payload doesn't match what the server receives (clock skew > 5 minutes).

**Fix**:

```bash
# Fingerprint comparison
oktsec keys list | grep <agent-name>           # server-side fingerprint
# Compare against the client-side fingerprint in your SDK logs.

# If you rotated keys recently, restart the server to reload them:
kill -HUP $(pgrep -f "oktsec serve")
```

If you rotated with `oktsec keys rotate`, the agent's `key_version` increments. Clients must send `X-Oktsec-Key-Version: <new-version>` or they'll keep hitting the old key.

---

## 3. Dashboard access code lost

**Symptom**: closed the terminal, can't find the 8-digit code.

**Fix**: codes are generated fresh on each server start and **not persisted**. Restart the server:

```bash
kill $(lsof -iTCP:8080 -sTCP:LISTEN | grep oktsec | awk '{print $2}')
oktsec run
```

The new code will print. If you need a stable code for a demo, set one explicitly in `oktsec.yaml`:

```yaml
dashboard:
  access_code: "12345678"       # 8 digits recommended
```

---

## 4. `database is locked` errors

**Symptom**: audit writes fail intermittently with `database is locked`.

**Cause**: two processes writing to the same SQLite file. Most commonly a leftover `oktsec proxy` subprocess from a previous run, or an `oktsec serve` + a manual `sqlite3` editor session.

**Fix**:

```bash
ps aux | grep oktsec            # find all oktsec processes
# Kill the stragglers (usually oktsec proxy instances with --config)
```

SQLite uses WAL mode by default in oktsec, so multiple readers are fine — but only one writer. For production with many writers, switch to Postgres:

```yaml
db_backend: postgres
db_dsn: postgres://user:pass@host:5432/oktsec?sslmode=require
```

---

## 5. MCP client not discovered by `oktsec discover`

**Symptom**: you have Claude Desktop / Cursor / Cline installed, but `oktsec discover` returns an empty list.

**Causes**:

1. The client hasn't been launched at least once (no config file exists yet).
2. Non-standard install path (snap, flatpak, custom prefix).
3. Config file is at a path oktsec doesn't scan.

**Fix**:

```bash
oktsec discover --verbose           # shows every path oktsec checks
```

If your client's config is in an unusual place, point oktsec at it explicitly. Example for a Claude Desktop config at a non-standard path:

```bash
OKTSEC_CLAUDE_CONFIG=/custom/path/claude_desktop_config.json oktsec discover
```

---

## 6. `oktsec run` starts but dashboard is empty

**Symptom**: dashboard loads but shows no events, no agents, no activity — even after sending test messages.

**Causes**:

1. The MCP clients weren't restarted after `oktsec wrap`, so they're still talking directly to the MCP servers.
2. Your proxy and `oktsec serve` are writing to different audit DBs.
3. You're in `observe` mode and nothing has triggered a rule yet (this is normal).

**Fix**:

```bash
# Confirm both paths point at the same DB
grep db_path oktsec.yaml
oktsec status | grep Config

# Restart MCP clients after any `wrap` change:
# macOS Claude Desktop: Cmd-Q and reopen
# Cursor: full quit and reopen

# Send a test message directly to confirm the pipeline:
curl -X POST http://localhost:8080/v1/message \
  -H "Content-Type: application/json" \
  -d '{"from":"test","to":"echo","content":"hello","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'
```

---

## 7. `docker pull ghcr.io/oktsec/oktsec:latest` returns 401 unauthorized

**Symptom**: Docker pull fails with `unauthorized` or `denied: authentication required`.

**Cause**: GHCR treats packages as private by default. The public flip is pending.

**Fix (today)**: use the install script or Go install path while we make the image public:

```bash
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
# or
go install github.com/oktsec/oktsec/cmd/oktsec@latest
```

Tracking issue: [#TBD](https://github.com/oktsec/oktsec/issues).

---

## 8. `go install` fails with `package requires newer Go version`

**Symptom**: `go install github.com/oktsec/oktsec/cmd/oktsec@latest` exits with a `go.mod requires go >= 1.25` error.

**Cause**: your Go toolchain is older than the minimum required version.

**Fix**:

```bash
go version                         # must be 1.25+
```

Upgrade via your package manager, via [official download](https://go.dev/dl/), or via `goenv`/`asdf`. Alternatively, use the pre-built binary (install script or release page) and skip `go install` entirely.

---

## 9. Audit chain verification reports BROKEN

**Symptom**: `oktsec audit verify-chain` exits with `Chain: BROKEN at entry N`.

**Causes**:

1. Legacy v1-hashed rows are mixed with v2 (happens once after upgrading from pre-v0.15.0).
2. A row was modified directly via `sqlite3` (tampering or manual fix).
3. Backfill migration updated chain-covered columns without rebuilding.

**Fix**:

Case 1 — legacy data after upgrade. Let the server rebuild on next start (it runs `repairChainIfBroken` during init):

```bash
kill $(lsof -iTCP:8080 -sTCP:LISTEN | grep oktsec | awk '{print $2}')
oktsec serve
```

Case 2 — real tamper detected. That's the feature working as intended: the broken entry ID points at the row that was modified. Investigate with `oktsec audit query --id <broken-id>`.

Case 3 — after a schema migration: run `oktsec serve` once to trigger the rebuild, then verify again. If the rebuild doesn't clear it, archive and start fresh:

```bash
oktsec audit archive --before=$(date -u +%Y-%m-%d) --output=archive.jsonl.gz
oktsec audit prune --before=$(date -u +%Y-%m-%d) --yes
```

---

## 10. LLM analysis fails with `401 Unauthorized`

**Symptom**: enabling LLM analysis in `oktsec.yaml` produces 401s in the server logs.

**Causes**:

1. API key not set (env var empty or wrong name).
2. Key has wrong permissions for the model you configured.
3. Key was rotated upstream but `oktsec.yaml` still has the old one.

**Fix**:

```bash
# Confirm the key is present in the environment oktsec sees:
grep api_key_env oktsec.yaml           # e.g. OPENAI_API_KEY
echo $OPENAI_API_KEY | head -c 10      # should print the prefix

# Or pass it inline (for local dev only — don't commit):
# llm:
#   api_key: sk-...
```

If you prefer no LLM at all, set `llm.enabled: false` — oktsec runs the full pipeline (rate limit, identity, ACL, scan, audit) without it.

---

## Still stuck?

- Check `oktsec doctor` output and attach it to any issue.
- Logs: the server logs to stderr. Redirect to a file and grep for `ERROR` / `WARN`.
- Metrics: `http://localhost:8080/metrics` exposes Prometheus counters. `oktsec_rate_limit_hits_total` and `oktsec_llm_budget_exhausted_total` are the most useful debugging signals.
- Email: `gus@oktsec.com` for enterprise-shaped questions.
- GitHub: [issues](https://github.com/oktsec/oktsec/issues).
