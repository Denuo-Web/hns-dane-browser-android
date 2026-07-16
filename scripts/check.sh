#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_CARGO_DENY_VERSION="${HNS_CARGO_DENY_VERSION:-0.19.9}"
RUST_TOOLCHAIN="1.92.0"
CARGO=(cargo "+$RUST_TOOLCHAIN")

"$ROOT_DIR/scripts/verify-supply-chain.sh"
python3 "$ROOT_DIR/scripts/generate-third-party-notices.py" --check
"$ROOT_DIR/scripts/check-version-consistency.sh"
"$ROOT_DIR/scripts/check-runtime-boundaries.sh"
"${CARGO[@]}" fmt --manifest-path "$ROOT_DIR/rust/Cargo.toml" --all -- --check
"${CARGO[@]}" clippy --locked --manifest-path "$ROOT_DIR/rust/Cargo.toml" --workspace --all-targets -- -D warnings
"$ROOT_DIR/scripts/check-ios-abi.sh"
if ! "${CARGO[@]}" deny --version >/dev/null 2>&1; then
  echo "ERROR: cargo-deny is required. Install with: cargo install cargo-deny --version $EXPECTED_CARGO_DENY_VERSION --locked" >&2
  exit 2
fi
installed_cargo_deny_version="$("${CARGO[@]}" deny --version | awk '{print $2}')"
if [[ "$installed_cargo_deny_version" != "$EXPECTED_CARGO_DENY_VERSION" ]]; then
  echo "ERROR: cargo-deny $EXPECTED_CARGO_DENY_VERSION is required; found $installed_cargo_deny_version." >&2
  exit 2
fi
"${CARGO[@]}" deny --locked --manifest-path "$ROOT_DIR/rust/Cargo.toml" check --config "$ROOT_DIR/rust/deny.toml"
"${CARGO[@]}" test --locked --manifest-path "$ROOT_DIR/rust/Cargo.toml" --workspace
"$ROOT_DIR/scripts/fuzz-smoke.sh"
"${CARGO[@]}" deny --locked --manifest-path "$ROOT_DIR/rust/fuzz/Cargo.toml" check --config "$ROOT_DIR/rust/deny.toml"

TOOL_MANIFEST="$ROOT_DIR/tools/hns-header-snapshot-exporter/Cargo.toml"
"${CARGO[@]}" fmt --manifest-path "$TOOL_MANIFEST" --all -- --check
"${CARGO[@]}" clippy --locked --manifest-path "$TOOL_MANIFEST" --all-targets -- -D warnings
"${CARGO[@]}" test --locked --manifest-path "$TOOL_MANIFEST"
"${CARGO[@]}" deny --locked --manifest-path "$TOOL_MANIFEST" check --config "$ROOT_DIR/rust/deny.toml"
