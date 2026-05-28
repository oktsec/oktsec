# Startup / Team Baseline Evidence Bundle

A local-only harness that turns one Oktsec install into a single redacted
evidence bundle a small team can review and share by hand. It is the technical
artifact behind the Startup / Team package:

```
one local install -> shared baseline -> evidence report -> repeatable setup
```

It is **not** a SaaS workspace. It creates no accounts, aggregates nothing
across machines, collects nothing remotely, and never mutates your local Oktsec
config or services. The output is operational evidence, not a compliance
certification.

## Usage

```bash
# From a directory where `oktsec` is installed (or build ./oktsec first):
./run.sh --output ./my-team-baseline

# Point at a specific config:
./run.sh --config /etc/oktsec/oktsec.yaml --output ./my-team-baseline

# Overwrite an existing non-empty directory:
./run.sh --output ./my-team-baseline --force
```

The binary is resolved from `$OKTSEC_BIN`, then `./oktsec`, then `oktsec` on
your `PATH`.

If `--output` is omitted, the bundle is written to
`./oktsec-startup-team-baseline-<timestamp>/`.

## What it produces

A directory containing:

| File | Source | Notes |
|------|--------|-------|
| `README.md` | generated | Boundary language + file guide |
| `manifest.json` | generated | Schema, version, host os/arch, SHA-256 of each file |
| `audit.json` | `oktsec audit --json` | Deployment security findings |
| `audit.sarif` | `oktsec audit --sarif` | Same findings, SARIF v2.1.0 |
| `status.txt` | `oktsec status` | Runtime status summary (text) |
| `node-status.json` | `oktsec node status --json` | Local node identity status |
| `node-snapshot.json` | `oktsec node snapshot --json` | Read-only coverage/evidence snapshot |
| `redactions.json` | generated | What was omitted + any missing/partial files |

`manifest.json` uses the stable schema `oktsec_startup_team_baseline.v1`.

## Safety guarantees

The harness:

- writes only into the explicit output directory, created `0700`;
- refuses to write through a symlink or into a non-empty directory without
  `--force`;
- runs without network access;
- never copies the raw audit database, private keys, `.env`, API keys, raw
  prompts/tool payloads, or the full `oktsec.yaml`;
- masks identifying filesystem paths (config directory, working directory,
  user home) as `<CONFIG_DIR>`, `<PWD>`, `<HOME>`;
- self-scans the collected data files for known secret patterns and exits
  non-zero (without presenting the bundle as safe) if any are found;
- exits non-zero if a required collection step fails, and records missing or
  partial files in `redactions.json` rather than failing silently.

`oktsec node status` / `node snapshot` are best-effort: on a fresh install with
no node identity they are recorded as missing rather than failing the bundle.

Always inspect the bundle before sharing it.

## Verification

```bash
make baseline-bundle-smoke
```

This builds the binary into a temp dir, runs the harness against a hermetic
`HOME` and config, and asserts the bundle contract (files present, manifest
hashes match, boundary language present, no secrets, no `.env`/`*.key`/`*.db`).
The same checks live in
`cmd/oktsec/commands/baseline_bundle_example_test.go` behind the `examples`
build tag.
