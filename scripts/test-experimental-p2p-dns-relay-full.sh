#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/test-experimental-p2p-dns-relay-full.sh [--preflight] [--keep]

Runs the real four-hsd regtest acceptance tier. It creates four independent
blockchain prefixes and identities, mines the complete relaytest name auction,
registers an NS/glue/DS delegation, serves a signed child zone, and runs the
native browser runtime through local Urkel, DNSSEC, TLSA/DANE, and HTTPS checks.

The tier mounts the current host Node executable, its glibc directory, and the
local hsd checkout into the cached Python harness image. It does not download
or build an hsd image. --preflight performs static checks without daemon access.
--keep retains the topology and Android-facing loopback ports 14038 and 18443.
EOF
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
HARNESS_DIR="$REPO_ROOT/tests/experimental-dns-relay"
COMPOSE_FILE="$HARNESS_DIR/full-compose.yaml"
CERTIFICATE_GENERATOR="$HARNESS_DIR/generate-origin-certificate.sh"
HSD_REPO=${HSD_REPO:-"$(CDPATH= cd -- "$REPO_ROOT/.." && pwd -P)/hsd"}
PYTHON_IMAGE=${PYTHON_IMAGE:-python:3.12-alpine}
FULL_TIER_ANDROID_P2P_PORT=${FULL_TIER_ANDROID_P2P_PORT:-14038}
FULL_TIER_ANDROID_ORIGIN_PORT=${FULL_TIER_ANDROID_ORIGIN_PORT:-18443}
PREFLIGHT_ONLY=0
KEEP=0

while (($#)); do
  case "$1" in
    --preflight)
      PREFLIGHT_ONLY=1
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
require_command openssl
require_command node
require_command ldd
require_command readelf
require_command readlink
require_command awk
require_command sed
require_command tee

if [[ ! -d "$HSD_REPO" ]]; then
  printf 'HSD_REPO is not a directory: %s\n' "$HSD_REPO" >&2
  exit 1
fi
HSD_REPO=$(CDPATH= cd -- "$HSD_REPO" && pwd -P)
if [[ ! -f "$HSD_REPO/package.json" || ! -f "$HSD_REPO/bin/hsd" ]]; then
  printf 'HSD_REPO is not an hsd checkout: %s\n' "$HSD_REPO" >&2
  exit 1
fi
if [[ ! -d "$HSD_REPO/node_modules/bns" ]]; then
  printf 'the full tier requires the local hsd runtime dependencies: %s/node_modules/bns\n' "$HSD_REPO" >&2
  exit 1
fi

HOST_NODE=${HOST_NODE:-"$(command -v node)"}
HOST_NODE=$(readlink -f "$HOST_NODE")
HOST_ELF_INTERPRETER=${HOST_ELF_INTERPRETER:-$({
  readelf -l "$HOST_NODE" \
    | sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p'
})}
HOST_LIBC=$({
  ldd "$HOST_NODE" \
    | awk '$1 == "libc.so.6" { print $3; exit }'
})
HOST_MULTIARCH_DIR=${HOST_MULTIARCH_DIR:-"$(dirname -- "$HOST_LIBC")"}

for path in "$HOST_NODE" "$HOST_ELF_INTERPRETER" "$HOST_LIBC"; do
  if [[ ! -f "$path" || "$path" != /* ]]; then
    printf 'unable to derive an absolute host Node/glibc dependency: %s\n' "$path" >&2
    exit 1
  fi
done
if [[ ! -d "$HOST_MULTIARCH_DIR" || "$HOST_MULTIARCH_DIR" != /* ]]; then
  printf 'unable to derive host multiarch library directory: %s\n' "$HOST_MULTIARCH_DIR" >&2
  exit 1
fi

python3 - "$HARNESS_DIR/full-browser-entrypoint.py" "$HARNESS_DIR/full-hsd-entrypoint.py" <<'PY'
import pathlib
import sys

for filename in sys.argv[1:]:
    source = pathlib.Path(filename).read_text(encoding="utf-8")
    compile(source, filename, "exec")
PY
node --check "$HARNESS_DIR/full-zone.js"
node --check "$HARNESS_DIR/full-signed-authority.js"
node --check "$HARNESS_DIR/full-provision.js"

if [[ -e "$HARNESS_DIR/certs/origin-cert.pem" \
      || -e "$HARNESS_DIR/certs/origin-key.pem" ]]; then
  printf 'static relay certificate/key fixtures are forbidden\n' >&2
  exit 1
fi
CERTIFICATE_PREFLIGHT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/relay-full-certificate.XXXXXX")
bash "$CERTIFICATE_GENERATOR" "$CERTIFICATE_PREFLIGHT_DIR"
rm -f -- \
  "$CERTIFICATE_PREFLIGHT_DIR/origin-cert.pem" \
  "$CERTIFICATE_PREFLIGHT_DIR/origin-key.pem"
rmdir "$CERTIFICATE_PREFLIGHT_DIR"

export HSD_REPO PYTHON_IMAGE HOST_NODE HOST_ELF_INTERPRETER HOST_MULTIARCH_DIR
export FULL_TIER_ANDROID_P2P_PORT FULL_TIER_ANDROID_ORIGIN_PORT
CONFIG_CLIENT=${FULL_TIER_CLIENT:-/bin/true}

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  if ! COMPOSE_UP_HELP=$(docker compose up --help 2>&1) || [[ "$COMPOSE_UP_HELP" != *"--wait"* ]]; then
    printf 'Docker Compose is too old: the full tier requires docker compose up --wait.\n' >&2
    exit 1
  fi
  CONFIG_ARTIFACT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/relay-full-compose.XXXXXX")
  ARTIFACT_DIR="$CONFIG_ARTIFACT_DIR" FULL_TIER_CLIENT="$CONFIG_CLIENT" \
    docker compose -f "$COMPOSE_FILE" config --quiet
  rmdir "$CONFIG_ARTIFACT_DIR"
elif ((PREFLIGHT_ONLY == 0)); then
  printf 'Docker with the Compose plugin is required for the full tier.\n' >&2
  exit 1
else
  printf 'compose syntax check skipped: Docker Compose is not installed\n' >&2
fi

if ((PREFLIGHT_ONLY)); then
  printf 'real four-hsd DNS-relay preflight passed\n'
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  printf 'Docker daemon is unavailable to this user; the real-node tier was not run.\n' >&2
  exit 1
fi
if ! docker image inspect "$PYTHON_IMAGE" >/dev/null 2>&1; then
  if [[ ${EXPERIMENTAL_RELAY_ALLOW_PULL:-1} == 1 ]]; then
    printf 'pulling missing harness image %s\n' "$PYTHON_IMAGE"
    docker pull "$PYTHON_IMAGE"
  else
    printf 'harness image is not cached: %s\n' "$PYTHON_IMAGE" >&2
    exit 1
  fi
fi

if [[ -z ${FULL_TIER_CLIENT:-} ]]; then
  require_command cargo
  (
    cd "$REPO_ROOT/rust"
    cargo build -p hns-browser-runtime --bin hns-runtime-full-tier --offline
  )
  FULL_TIER_CLIENT="$REPO_ROOT/rust/target/debug/hns-runtime-full-tier"
fi
if [[ ! -x "$FULL_TIER_CLIENT" || "$FULL_TIER_CLIENT" != /* ]]; then
  printf 'FULL_TIER_CLIENT must be an absolute executable path: %s\n' "$FULL_TIER_CLIENT" >&2
  exit 1
fi
export FULL_TIER_CLIENT

ARTIFACT_DIR=${EXPERIMENTAL_RELAY_FULL_ARTIFACT_DIR:-"$(mktemp -d "${TMPDIR:-/tmp}/experimental-dns-relay-full.XXXXXX")"}
mkdir -p "$ARTIFACT_DIR"
if ! python3 - "$ARTIFACT_DIR" <<'PY'
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
raise SystemExit(0 if not any(directory.iterdir()) else 1)
PY
then
  printf 'artifact directory must be empty: %s\n' "$ARTIFACT_DIR" >&2
  exit 1
fi
ARTIFACT_DIR_MODE=$({
  python3 -c \
    'import os, stat, sys; print(format(stat.S_IMODE(os.stat(sys.argv[1]).st_mode), "o"))' \
    "$ARTIFACT_DIR"
})
bash "$CERTIFICATE_GENERATOR" "$ARTIFACT_DIR"
chmod 1777 "$ARTIFACT_DIR"
# The disposable key must be readable by a remapped container identity. It is
# removed after teardown, or retained only while an explicit --keep topology is
# still using it for the Android-facing HTTPS origin.
chmod 0644 "$ARTIFACT_DIR/origin-key.pem"
export ARTIFACT_DIR
export COMPOSE_PROJECT_NAME="hns-relay-full-$PPID-$$"
STARTED=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ((STARTED)); then
    docker compose -f "$COMPOSE_FILE" logs --no-color >"$ARTIFACT_DIR/full-compose.log" 2>&1 || true
    if ((KEEP)); then
      printf 'containers kept: project=%s\n' "$COMPOSE_PROJECT_NAME" >&2
      printf 'Host P2P endpoint: 127.0.0.1:%s\n' "$FULL_TIER_ANDROID_P2P_PORT" >&2
      printf 'Host HTTPS endpoint: 127.0.0.1:%s\n' "$FULL_TIER_ANDROID_ORIGIN_PORT" >&2
      printf 'adb reverse tcp:14038 tcp:%s\n' \
        "$FULL_TIER_ANDROID_P2P_PORT" >&2
      printf 'adb reverse tcp:18443 tcp:%s\n' \
        "$FULL_TIER_ANDROID_ORIGIN_PORT" >&2
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
  full-signed-authority
  full-device-origin
  full-third-party-sentinel
  hsd-owner-good
  hsd-proof
  hsd-relay-bad
  hsd-legacy
)

assert_loopback_publication() {
  local service=$1
  local container_port=$2
  local host_port=$3
  local expected="127.0.0.1:$host_port"
  local actual

  actual=$(docker compose -f "$COMPOSE_FILE" port "$service" "$container_port")
  if [[ "$actual" != "$expected" ]]; then
    printf '%s port %s was not published on %s (got: %s)\n' \
      "$service" "$container_port" "$expected" "${actual:-none}" >&2
    exit 1
  fi
}

STARTED=1
docker compose -f "$COMPOSE_FILE" up -d --wait "${SERVICES[@]}"
assert_loopback_publication \
  hsd-owner-good 14038 "$FULL_TIER_ANDROID_P2P_PORT"
assert_loopback_publication \
  full-device-origin 18443 "$FULL_TIER_ANDROID_ORIGIN_PORT"
docker compose -f "$COMPOSE_FILE" run --rm --no-deps full-provision \
  2>&1 | tee "$ARTIFACT_DIR/full-provision.log"
docker compose -f "$COMPOSE_FILE" run --rm --no-deps full-browser \
  2>&1 | tee "$ARTIFACT_DIR/full-browser.log"

UNEXPECTED=$(docker compose -f "$COMPOSE_FILE" ps --status exited --services)
if [[ -n "$UNEXPECTED" ]]; then
  printf 'full-tier service exited unexpectedly:\n%s\n' "$UNEXPECTED" >&2
  exit 1
fi

python3 - "$ARTIFACT_DIR" <<'PY'
import hashlib
import json
import pathlib
import ssl
import sys

artifacts = pathlib.Path(sys.argv[1])
result = json.loads((artifacts / "full-tier-result.json").read_text())
state = json.loads((artifacts / "full-regtest-state.json").read_text())
proof = json.loads((artifacts / "full-tier-proof.json").read_text())
sentinel = json.loads((artifacts / "third-party-sentinel.json").read_text())
authority = json.loads((artifacts / "full-authority-metrics.json").read_text())
origin = json.loads((artifacts / "full-browser-origin-metrics.json").read_text())
network = json.loads((artifacts / "full-browser-network.json").read_text())
zone = json.loads((artifacts / "full-zone-evidence.json").read_text())

certificate_pem = (artifacts / "origin-cert.pem").read_text(encoding="ascii")
certificate_der = ssl.PEM_cert_to_DER_cert(certificate_pem)
certificate_sha256 = hashlib.sha256(certificate_der).hexdigest()
provisioned_zone = state.get("zoneEvidence", {})
for source, evidence in (("provisioner", provisioned_zone), ("authority", zone)):
    if evidence.get("certificateSha256") != certificate_sha256:
        raise SystemExit(f"{source} TLSA digest does not match the per-run certificate")
    if (evidence.get("tlsaOwner") != "_18443._tcp.www.relaytest."
            or evidence.get("originPort") != 18443):
        raise SystemExit(f"{source} TLSA owner/port structure is incorrect")

if result.get("status") != "pass" or result.get("nodeCount") != 4:
    raise SystemExit("native full-tier result did not pass with four nodes")
if result.get("urkelProof") != "verified" or result.get("dnssec") != "secure":
    raise SystemExit("Urkel or DNSSEC acceptance evidence is missing")
if result.get("dane") != "verified" or result.get("httpsStatus") != 200:
    raise SystemExit("DANE/HTTPS acceptance evidence is missing")
if not result.get("relayFailover", {}).get("verified"):
    raise SystemExit("real hsd relay failover was not observed")
if result["relayFailover"].get("retryCount", 0) < 1:
    raise SystemExit("real hsd relay failover did not retry")
if state.get("status") != "pass" or not state.get("registered"):
    raise SystemExit("regtest name registration did not pass")
nodes = state.get("nodes", [])
if len(nodes) != 4 or len({(node["height"], node["tip"], node["treeRoot"]) for node in nodes}) != 1:
    raise SystemExit("the four hsd chain/tree tips did not converge")
node_proofs = state.get("nodeProofs", [])
if state.get("postUpdateBlocks") != 17 or state.get("safeRootBlocks") != 12:
    raise SystemExit("the required Urkel commit and safe-root window was not mined")
if len(node_proofs) != 4 or len({item.get("role") for item in node_proofs}) != 4:
    raise SystemExit("per-node Urkel proof evidence is incomplete")
for item in node_proofs:
    if item.get("type") != "TYPE_EXISTS" or not item.get("registered"):
        raise SystemExit(f'{item.get("role")} did not return an inclusion proof')
    if item.get("height") != state.get("targetHeight"):
        raise SystemExit(f'{item.get("role")} proof height is not current')
    if item.get("tip") != state.get("tip") or item.get("root") != state.get("treeRoot"):
        raise SystemExit(f'{item.get("role")} proof is not anchored to the shared tip')
    if item.get("proofValueBytes", 0) <= 0 or item.get("resourceBytes", 0) <= 0:
        raise SystemExit(f'{item.get("role")} proof has no resource value')
    if item.get("resourceRecords", 0) < 3 or not item.get("resourceMatchesDelegation"):
        raise SystemExit(f'{item.get("role")} proof resource does not match the delegation')
if (not state.get("proofRootMatchesTip")
        or proof.get("hnsProof") != "verified"
        or proof.get("treeRoot") != state.get("treeRoot")
        or proof.get("blockHeight") != state.get("targetHeight")):
    raise SystemExit("current-tip Urkel inclusion proof evidence is missing")
if (sentinel.get("contacts") != 0
        or sentinel.get("request_headers_logged") != 0
        or sentinel.get("request_paths_logged") != 0
        or result.get("legacyDohContact") is not False):
    raise SystemExit("legacy DoH zero-contact assertion failed")
if (authority.get("queries", 0) == 0
        or authority.get("qnamesLogged") != 0
        or authority.get("rawDnsLogged") != 0):
    raise SystemExit("signed authority was unused or logged qnames")
if (origin.get("requests", 0) < 1
        or origin.get("request_headers_logged") != 0
        or origin.get("request_paths_logged") != 0):
    raise SystemExit("loopback DANE origin did not receive HTTPS")
for destination in ("authoritative_dns", "external_dns"):
    if not all(network.get(destination, {}).values()):
        raise SystemExit(f"browser port-53 isolation failed for {destination}")

print("real four-hsd regtest Urkel/DNSSEC/DANE relay topology passed")
PY
