#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/scripts/check-version-consistency.sh"
cargo fmt --manifest-path "$ROOT_DIR/rust/Cargo.toml" --all -- --check
cargo clippy --manifest-path "$ROOT_DIR/rust/Cargo.toml" --workspace --all-targets -- -D warnings
if ! cargo deny --version >/dev/null 2>&1; then
  echo "ERROR: cargo-deny is required. Install with: cargo install cargo-deny --locked" >&2
  exit 2
fi
cargo deny --manifest-path "$ROOT_DIR/rust/Cargo.toml" check --config "$ROOT_DIR/rust/deny.toml"
cargo test --manifest-path "$ROOT_DIR/rust/Cargo.toml" --workspace
"$ROOT_DIR/scripts/fuzz-smoke.sh"
