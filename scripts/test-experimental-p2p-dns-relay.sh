#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/test-experimental-p2p-dns-relay.sh [--preflight] [--load] [--keep]

Runs the deterministic scripted four-role topology. The default runs the
network-isolated end-to-end fast tier; --load adds the bounded load scenarios.
--preflight validates fixtures, certificate, Python, and Compose syntax without
requiring Docker daemon access. --keep leaves containers running for debugging.

This command does not claim regtest Urkel/DNSSEC validation. Run
scripts/test-experimental-p2p-dns-relay-full.sh for the real four-hsd tier.
EOF
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
HARNESS_DIR="$REPO_ROOT/tests/experimental-dns-relay"
COMPOSE_FILE="$HARNESS_DIR/compose.yaml"
CERTIFICATE_GENERATOR="$HARNESS_DIR/generate-origin-certificate.sh"
HSD_REPO=${HSD_REPO:-"$(CDPATH= cd -- "$REPO_ROOT/.." && pwd -P)/hsd"}
PYTHON_IMAGE=${PYTHON_IMAGE:-python:3.12-alpine}
RUN_LOAD=0
PREFLIGHT_ONLY=0
KEEP=0

while (($#)); do
  case "$1" in
    --preflight)
      PREFLIGHT_ONLY=1
      ;;
    --load)
      RUN_LOAD=1
      ;;
    --keep)
      KEEP=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

require_command python3
require_command tee
if [[ ! -d "$HSD_REPO" ]]; then
  printf 'HSD_REPO is not a directory: %s\n' "$HSD_REPO" >&2
  exit 1
fi
HSD_REPO=$(CDPATH= cd -- "$HSD_REPO" && pwd -P)
if [[ ! -f "$HSD_REPO/package.json" ]]; then
  printf 'HSD_REPO is not an hsd checkout: %s\n' "$HSD_REPO" >&2
  exit 1
fi

BROWSER_FIXTURES="$REPO_ROOT/fixtures/experimental-dns-relay"
HSD_FIXTURES="$HSD_REPO/fixtures/experimental-dns-relay"
if [[ ! -f "$BROWSER_FIXTURES/manifest.json" || ! -f "$HSD_FIXTURES/manifest.json" ]]; then
  printf 'shared relay fixtures are missing; expected %s and %s\n' "$BROWSER_FIXTURES" "$HSD_FIXTURES" >&2
  exit 1
fi

python3 "$HARNESS_DIR/harness.py" selftest \
  --browser-fixtures "$BROWSER_FIXTURES" \
  --hsd-fixtures "$HSD_FIXTURES"

require_command openssl
if [[ -e "$HARNESS_DIR/certs/origin-cert.pem" \
      || -e "$HARNESS_DIR/certs/origin-key.pem" ]]; then
  printf 'static relay certificate/key fixtures are forbidden\n' >&2
  exit 1
fi
CERTIFICATE_PREFLIGHT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/relay-certificate.XXXXXX")
bash "$CERTIFICATE_GENERATOR" "$CERTIFICATE_PREFLIGHT_DIR"
rm -f -- \
  "$CERTIFICATE_PREFLIGHT_DIR/origin-cert.pem" \
  "$CERTIFICATE_PREFLIGHT_DIR/origin-key.pem"
rmdir "$CERTIFICATE_PREFLIGHT_DIR"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if ! COMPOSE_UP_HELP=$(docker compose up --help 2>&1) || [[ "$COMPOSE_UP_HELP" != *"--wait"* ]]; then
    printf 'Docker Compose is too old: this harness requires support for docker compose up --wait.\n' >&2
    exit 1
  fi
  CONFIG_ARTIFACT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/relay-compose-config.XXXXXX")
  ARTIFACT_DIR="$CONFIG_ARTIFACT_DIR" PYTHON_IMAGE="$PYTHON_IMAGE" \
    docker compose -f "$COMPOSE_FILE" config --quiet
  rmdir "$CONFIG_ARTIFACT_DIR"
elif ((PREFLIGHT_ONLY == 0)); then
  printf 'Docker with the Compose plugin is required for network isolation.\n' >&2
  exit 1
else
  printf 'compose syntax check skipped: Docker Compose is not installed\n' >&2
fi

if ((PREFLIGHT_ONLY)); then
  printf 'experimental DNS-relay preflight passed\n'
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  printf '%s\n' \
    'Docker daemon is unavailable to this user; the network-isolated tier was not run.' \
    'Grant Docker daemon access or run in a Docker-capable CI executor, then retry the same command.' >&2
  exit 1
fi

if ! docker image inspect "$PYTHON_IMAGE" >/dev/null 2>&1; then
  if [[ ${EXPERIMENTAL_RELAY_ALLOW_PULL:-1} == 1 ]]; then
    printf 'pulling missing harness image %s\n' "$PYTHON_IMAGE"
    docker pull "$PYTHON_IMAGE"
  else
    printf 'harness image is not cached: %s (set EXPERIMENTAL_RELAY_ALLOW_PULL=1 to pull it)\n' "$PYTHON_IMAGE" >&2
    exit 1
  fi
fi

ARTIFACT_DIR=${EXPERIMENTAL_RELAY_ARTIFACT_DIR:-"$(mktemp -d "${TMPDIR:-/tmp}/experimental-dns-relay.XXXXXX")"}
mkdir -p "$ARTIFACT_DIR"
if [[ -n "$(find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  printf 'artifact directory must be empty: %s\n' "$ARTIFACT_DIR" >&2
  exit 1
fi
ARTIFACT_DIR_MODE=$(
  python3 -c \
    'import os, stat, sys; print(format(stat.S_IMODE(os.stat(sys.argv[1]).st_mode), "o"))' \
    "$ARTIFACT_DIR"
)
bash "$CERTIFICATE_GENERATOR" "$ARTIFACT_DIR"
# Rootful Docker installations may enable userns-remap, so container root does
# not necessarily map to the host user that owns this directory. The sticky bit
# lets every isolated harness role create its artifacts without letting roles
# remove one another's files. Cleanup restores the caller's original mode.
chmod 1777 "$ARTIFACT_DIR"
# The disposable key must be readable by a remapped container identity. It is
# removed after teardown, or retained only while an explicit --keep topology is
# still using it.
chmod 0644 "$ARTIFACT_DIR/origin-key.pem"
export ARTIFACT_DIR PYTHON_IMAGE
export COMPOSE_PROJECT_NAME="hns-relay-$PPID-$$"
STARTED=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ((STARTED)); then
    docker compose -f "$COMPOSE_FILE" logs --no-color >"$ARTIFACT_DIR/compose.log" 2>&1 || true
    if ((KEEP)); then
      printf 'containers kept: project=%s\n' "$COMPOSE_PROJECT_NAME" >&2
      printf 'artifact directory remains container-writable while the project is running\n' >&2
    else
      docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
  fi
  if ((STARTED == 0 || KEEP == 0)); then
    rm -f -- "$ARTIFACT_DIR/origin-key.pem"
    chmod "$ARTIFACT_DIR_MODE" "$ARTIFACT_DIR" || true
  fi
  printf 'artifacts: %s\n' "$ARTIFACT_DIR" >&2
  exit "$status"
}

signal_exit() {
  local status=$1
  trap - INT TERM
  exit "$status"
}

trap cleanup EXIT
trap 'signal_exit 130' INT
trap 'signal_exit 143' TERM

SERVICES=(
  authoritative-dns
  origin-server
  third-party-sentinel
  hsd-proof
  hsd-relay-good
  hsd-relay-bad
  hsd-legacy
)

STARTED=1
docker compose -f "$COMPOSE_FILE" up -d --wait "${SERVICES[@]}"
docker compose -f "$COMPOSE_FILE" run --rm --no-deps -e HARNESS_MODE=e2e browser-test \
  2>&1 | tee "$ARTIFACT_DIR/browser-e2e.log"

if ((RUN_LOAD)); then
  docker compose -f "$COMPOSE_FILE" run --rm --no-deps -e HARNESS_MODE=load browser-test \
    2>&1 | tee "$ARTIFACT_DIR/browser-load.log"
fi

UNEXPECTED=$(docker compose -f "$COMPOSE_FILE" ps --status exited --services)
if [[ -n "$UNEXPECTED" ]]; then
  printf 'topology service exited unexpectedly:\n%s\n' "$UNEXPECTED" >&2
  exit 1
fi

python3 - "$ARTIFACT_DIR" "$RUN_LOAD" <<'PY'
import json
import pathlib
import sys

artifacts = pathlib.Path(sys.argv[1])
run_load = bool(int(sys.argv[2]))
e2e = json.loads((artifacts / "e2e-result.json").read_text())
sentinel = json.loads((artifacts / "third-party-sentinel.json").read_text())
if e2e["status"] != "pass" or sentinel["contacts"] != 0:
    raise SystemExit("result or zero-contact sentinel assertion failed")
if run_load:
    load = json.loads((artifacts / "load-result.json").read_text())
    if load["status"] != "pass":
        raise SystemExit("load result assertion failed")
print("scripted four-role relay topology passed")
if run_load:
    print("scripted bounded relay load passed")
PY
