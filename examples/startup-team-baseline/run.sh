#!/usr/bin/env bash
#
# Oktsec Startup / Team Baseline Evidence Bundle (Order 8B.1)
#
# Local-only harness. It orchestrates existing read-only oktsec commands into a
# single redacted bundle a small team can review by hand and share manually
# during a guided Startup / Team onboarding.
#
# It is NOT a SaaS workspace. It does not create accounts, aggregate across
# machines, collect remotely, phone home, or mutate the local oktsec config or
# services. The output is operational evidence, not a compliance certification.
#
# Usage:
#   ./run.sh [--output <dir>] [--config <path>] [--force]
#
# Binary resolution: $OKTSEC_BIN, then ./oktsec, then `oktsec` on PATH.
#
set -euo pipefail

SCHEMA="oktsec_startup_team_baseline.v1"
PROG="$(basename "$0")"

# Files this harness is allowed to place in a bundle. Anything else present at
# finish (e.g. a stale secret left in an existing dir reused with --force) makes
# the bundle fail closed.
EXPECTED_FILES="README.md manifest.json redactions.json audit.json audit.sarif status.txt node-status.json node-snapshot.json"
# Generated files that intentionally describe what was omitted; excluded from
# the secret scan so their disclosure text is not a false positive.
DISCLOSURE_FILES="README.md manifest.json redactions.json"

# SECRET_PAT is the canonical secret-value scan (grep -E). It targets token
# *values* (key headers, provider token shapes, NAME=value assignments), not
# bare env-var names, so a finding that merely reports the existence of a secret
# env var is not flagged while a leaked value is. The smoke test extracts this
# exact line, so keep it a single-quoted one-liner named SECRET_PAT.
SECRET_PAT='BEGIN [A-Z0-9 ]*PRIVATE KEY|[A-Z0-9_]{2,}(_API_KEY|_TOKEN|_SECRET|_PASSWORD|_PRIVATE_KEY)=[^[:space:]"]|sk-(ant-|proj-)?[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gh[ousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|hooks\.slack\.com'

usage() {
	cat <<EOF
$PROG - produce a redacted Startup / Team baseline evidence bundle

Usage:
  $PROG [--output <dir>] [--config <path>] [--force]

Options:
  --output <dir>   Bundle directory to create.
                   Default: ./oktsec-startup-team-baseline-<timestamp>
  --config <path>  oktsec config file (passed through to oktsec commands).
                   Default: oktsec's normal cascading resolution.
  --force          Allow writing into an existing non-empty output directory.
  -h, --help       Show this help.

The bundle contains: README.md, manifest.json, audit.json, audit.sarif,
status.txt, node-status.json, node-snapshot.json, redactions.json.

Never included: raw prompts, tool payloads, private keys, API keys, .env,
the full oktsec.yaml, or the raw audit database. Filesystem paths under the
user home are masked as <HOME>.
EOF
}

# --- arguments ---------------------------------------------------------------
OUTPUT=""
CONFIG=""
FORCE=0
while [ $# -gt 0 ]; do
	case "$1" in
	--output)
		OUTPUT="${2:?--output needs a value}"
		shift 2
		;;
	--output=*)
		OUTPUT="${1#*=}"
		shift
		;;
	--config)
		CONFIG="${2:?--config needs a value}"
		shift 2
		;;
	--config=*)
		CONFIG="${1#*=}"
		shift
		;;
	--force)
		FORCE=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "$PROG: unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

# --- binary ------------------------------------------------------------------
BIN="${OKTSEC_BIN:-}"
if [ -z "$BIN" ]; then
	if [ -x "./oktsec" ]; then
		BIN="./oktsec"
	elif command -v oktsec >/dev/null 2>&1; then
		BIN="oktsec"
	else
		echo "$PROG: oktsec binary not found. Set OKTSEC_BIN, add oktsec to PATH, or build ./oktsec." >&2
		exit 2
	fi
fi

# --- sha256 tool -------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
	SHACMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	SHACMD="shasum -a 256"
else
	echo "$PROG: no sha256 tool found (need sha256sum or shasum)." >&2
	exit 2
fi

# --- output directory --------------------------------------------------------
TS_COMPACT="$(date -u +%Y%m%dT%H%M%SZ)"
TS_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ -z "$OUTPUT" ]; then
	OUTPUT="./oktsec-startup-team-baseline-${TS_COMPACT}"
fi

if [ -L "$OUTPUT" ]; then
	echo "$PROG: refusing to write through a symlink: $OUTPUT" >&2
	exit 2
fi
if [ -e "$OUTPUT" ] && [ ! -d "$OUTPUT" ]; then
	echo "$PROG: output path exists and is not a directory: $OUTPUT" >&2
	exit 2
fi
if [ -d "$OUTPUT" ] && [ -n "$(ls -A "$OUTPUT" 2>/dev/null)" ] && [ "$FORCE" -ne 1 ]; then
	echo "$PROG: refusing to overwrite non-empty directory: $OUTPUT (use --force)" >&2
	exit 2
fi

mkdir -p "$OUTPUT"
chmod 700 "$OUTPUT" 2>/dev/null || true

# Remove this harness's own prior outputs so a --force re-run cannot leave a
# stale file from a previous run (e.g. a node-snapshot.json that fails to
# regenerate this time). Files we do not own are left untouched and are caught
# by the unexpected-file check at the end.
for _f in $EXPECTED_FILES; do
	rm -f "$OUTPUT/$_f"
done

# --- helpers -----------------------------------------------------------------
REQUIRED_FAIL=0
MISSING_TSV="$OUTPUT/.missing.tsv"

# run_oktsec wraps the binary so --config is applied consistently and exactly
# once. Persistent flags must precede the subcommand.
run_oktsec() {
	if [ -n "$CONFIG" ]; then
		"$BIN" --config "$CONFIG" "$@"
	else
		"$BIN" "$@"
	fi
}

# scrub masks identifying filesystem roots (the username vector) in any
# captured text: the config directory and the working directory first (more
# specific), then the user home. Each root is regex-escaped and `|` is the sed
# delimiter. SED_ARGS may legitimately be empty, hence the count-guarded
# expansion (safe under `set -u`, including bash 3.2).
SED_ARGS=()
add_mask() {
	local p="$1" label="$2" esc
	# Never mask empty or dangerously short roots ("." would replace every dot
	# in the text, "/" every slash).
	case "$p" in "" | "." | "./" | "/") return 0 ;; esac
	esc="$(printf '%s' "$p" | sed 's/[][\.*^$/|]/\\&/g')"
	SED_ARGS+=(-e "s|$esc|$label|g")
}
if [ -n "$CONFIG" ]; then
	# Mask both the canonical absolute config dir (when it exists) and the
	# literal dirname as given. oktsec echoes an explicit --config path verbatim
	# in errors, and that path may point at a directory that does not exist, in
	# which case the canonical form is empty — so the literal form is what
	# masks the path in a failure reason.
	add_mask "$(cd "$(dirname "$CONFIG")" 2>/dev/null && pwd || true)" "<CONFIG_DIR>"
	add_mask "$(dirname "$CONFIG")" "<CONFIG_DIR>"
fi
add_mask "$(pwd)" "<PWD>"
add_mask "${HOME:-}" "<HOME>"
scrub() {
	if [ "${#SED_ARGS[@]}" -gt 0 ]; then
		sed "${SED_ARGS[@]}"
	else
		cat
	fi
}

# collect runs an oktsec command, scrubs its stdout into a bundle file, and
# records failures. It never aborts the harness; the final exit code is decided
# after all collection completes.
#   collect <required|optional> <outfile> <oktsec args...>
collect() {
	local kind="$1" out="$2"
	shift 2
	local errf="$OUTPUT/.collect.err"
	if run_oktsec "$@" 2>"$errf" | scrub >"$OUTPUT/$out"; then
		rm -f "$errf"
		echo "  ok        $out"
		return 0
	fi
	local reason
	# Scrub identifying paths out of the failure reason (stderr is free text
	# that often contains the config path) before recording it. Scrub before
	# truncating so a full root still matches.
	reason="$(tr '\n' ' ' <"$errf" 2>/dev/null | scrub | cut -c1-200)"
	rm -f "$errf" "$OUTPUT/$out"
	printf '%s\t%s\n' "$out" "$reason" >>"$MISSING_TSV"
	if [ "$kind" = required ]; then
		REQUIRED_FAIL=1
		echo "  FAIL req   $out: $reason" >&2
	else
		echo "  skip opt   $out: $reason" >&2
	fi
	return 0
}

compute_sha() { $SHACMD "$1" | awk '{print $1}'; }

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'; }

# --- collection --------------------------------------------------------------
echo "Collecting Startup / Team baseline into $OUTPUT"

# Required: deployment posture. `audit --json`/`--sarif` exit 0 even with
# high/critical findings, so a non-zero exit here means a real failure
# (e.g. config could not be loaded).
collect required audit.json audit --json
collect required audit.sarif audit --sarif

# Recommended but best-effort: node identity may be absent on a fresh install.
# Per spec, that is recorded, not treated as a bundle failure. These are
# read-only and collected before `status` so the snapshot reflects the node's
# state independent of any other command.
collect optional node-status.json node status --json
collect optional node-snapshot.json node snapshot --json

# `status` is read-only and does not create the audit DB, so ordering it last
# is belt-and-suspenders against any future side effect bleeding into the
# read-only snapshots above.
collect required status.txt status

# --- redactions.json ---------------------------------------------------------
{
	printf '{\n'
	printf '  "schema": "%s",\n' "$SCHEMA"
	printf '  "redactions": [\n'
	printf '    "raw prompts and tool payloads omitted (source commands do not emit them)",\n'
	printf '    "private keys omitted",\n'
	printf '    "API keys and secrets omitted",\n'
	printf '    ".env files omitted",\n'
	printf '    "full oktsec.yaml omitted",\n'
	printf '    "raw audit database omitted",\n'
	printf '    "identifying filesystem paths (config dir, working dir, user home) masked",\n'
	printf '    "hostnames and usernames omitted (node identity uses hashed fingerprints)"\n'
	printf '  ],\n'
	printf '  "missing_or_partial": ['
	if [ -f "$MISSING_TSV" ]; then
		first=1
		printf '\n'
		while IFS="$(printf '\t')" read -r file reason; do
			[ -n "$file" ] || continue
			if [ $first -eq 1 ]; then first=0; else printf ',\n'; fi
			printf '    { "file": "%s", "reason": "%s" }' "$(json_escape "$file")" "$(json_escape "$reason")"
		done <"$MISSING_TSV"
		printf '\n  '
	fi
	printf ']\n'
	printf '}\n'
} >"$OUTPUT/redactions.json"
rm -f "$MISSING_TSV"

# --- README.md (in-bundle, business-readable) --------------------------------
cat >"$OUTPUT/README.md" <<'EOF'
# Oktsec Startup / Team Baseline Bundle

This bundle summarizes one local Oktsec runtime for Startup / Team onboarding.
It is operational evidence, not a compliance certification.
Only routed/configured surfaces are represented.
Raw prompts, private keys, secrets and raw audit databases are omitted.

## Files

- `README.md` - this file.
- `manifest.json` - schema, generation time, oktsec version, host os/arch, and
  a SHA-256 for every other file in the bundle.
- `audit.json` - deployment security audit findings (machine-readable).
- `audit.sarif` - the same audit findings in SARIF v2.1.0.
- `status.txt` - a human-readable runtime status summary (mode, agents,
  message counts, health score, top issues).
- `node-status.json` - local node identity status (hashed fingerprint only;
  may report "absent" on a fresh install).
- `node-snapshot.json` - read-only snapshot of what this node sees, controls
  and can prove (coverage, posture, evidence; fingerprints and hashes only).
- `redactions.json` - what was deliberately omitted, plus any missing or
  partial files.

## Safety

This bundle is local-only and was produced without network access. Identifying
filesystem paths (config directory, working directory, user home) are masked as
`<CONFIG_DIR>`, `<PWD>` and `<HOME>`. Inspect every file before sharing.
EOF

# --- manifest.json -----------------------------------------------------------
VER_OUT="$("$BIN" version 2>/dev/null || true)"
VERSION="$(printf '%s\n' "$VER_OUT" | head -1 | awk '{print $2}')"
[ -n "$VERSION" ] || VERSION="unknown"
OSLINE="$(printf '%s\n' "$VER_OUT" | awk -F'os:' 'NF>1{print $2}' | tr -d ' ' | head -1)"
HOST_OS="${OSLINE%%/*}"
HOST_ARCH="${OSLINE##*/}"
[ -n "$HOST_OS" ] || HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
[ -n "$HOST_ARCH" ] || HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"

{
	printf '{\n'
	printf '  "schema": "%s",\n' "$SCHEMA"
	printf '  "generated_at": "%s",\n' "$TS_ISO"
	printf '  "oktsec_version": "%s",\n' "$(json_escape "$VERSION")"
	printf '  "host": {\n'
	printf '    "os": "%s",\n' "$(json_escape "$HOST_OS")"
	printf '    "arch": "%s"\n' "$(json_escape "$HOST_ARCH")"
	printf '  },\n'
	printf '  "files": ['
	first=1
	for f in README.md redactions.json audit.json audit.sarif status.txt node-status.json node-snapshot.json; do
		[ -f "$OUTPUT/$f" ] || continue
		if [ $first -eq 1 ]; then
			first=0
			printf '\n'
		else
			printf ',\n'
		fi
		printf '    { "path": "%s", "sha256": "%s" }' "$f" "$(compute_sha "$OUTPUT/$f")"
	done
	printf '\n  ],\n'
	printf '  "redactions": [\n'
	printf '    "raw prompts omitted",\n'
	printf '    "private keys omitted",\n'
	printf '    "secrets and .env omitted",\n'
	printf '    "full config omitted",\n'
	printf '    "raw audit database omitted",\n'
	printf '    "identifying paths masked"\n'
	printf '  ]\n'
	printf '}\n'
} >"$OUTPUT/manifest.json"

# --- final safety verification ----------------------------------------------
# Scans every entry actually present in the bundle (not a fixed list) so stale
# files reused via --force cannot slip through: rejects unexpected files and
# key/cert/db/env artifacts, and scans data-bearing files for secret values.
# Disclosure files (README/redactions/manifest) name these words on purpose and
# are excluded from the secret scan.
is_listed() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

verify_bundle() {
	local problem=0 entry base
	# Globs cover: normal names, single-dot names (.foo), and double-dot names
	# (..foo). "." and ".." themselves never match .[!.]* or ..?*, so they are
	# not walked. Missing matches stay literal and are skipped by the -e guard.
	for entry in "$OUTPUT"/* "$OUTPUT"/.[!.]* "$OUTPUT"/..?*; do
		[ -e "$entry" ] || continue
		base="$(basename "$entry")"
		if [ ! -f "$entry" ]; then
			echo "  UNEXPECTED non-file entry in bundle: $base" >&2
			problem=1
			continue
		fi
		if ! is_listed "$base" "$EXPECTED_FILES"; then
			echo "  UNEXPECTED file in bundle: $base" >&2
			problem=1
		fi
		case "$base" in
		*.key | *.pem | *.crt | *.db | .env | *.env)
			echo "  FORBIDDEN artifact in bundle: $base" >&2
			problem=1
			;;
		esac
		if ! is_listed "$base" "$DISCLOSURE_FILES"; then
			if grep -Eq "$SECRET_PAT" "$entry"; then
				echo "  LEAK forbidden secret pattern detected in $base" >&2
				problem=1
			fi
		fi
	done
	return "$problem"
}

EXIT=0
if ! verify_bundle; then
	echo "$PROG: ERROR - bundle failed safety verification and is NOT safe to share. Inspect $OUTPUT." >&2
	EXIT=3
fi
if [ "$REQUIRED_FAIL" -eq 1 ]; then
	echo "$PROG: ERROR - one or more required collection steps failed; bundle is incomplete." >&2
	[ "$EXIT" -eq 0 ] && EXIT=1
fi

echo "Bundle written to $OUTPUT"
exit "$EXIT"
