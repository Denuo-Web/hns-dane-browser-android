#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_TOOLCHAIN="1.92.0"
MANIFEST="$ROOT_DIR/rust/Cargo.toml"
CRATE_DIR="$ROOT_DIR/rust/crates/ios-ffi"
HEADER="$CRATE_DIR/include/hns_browser.h"
SOURCE="$CRATE_DIR/src/lib.rs"
TARGET_DIR="${HNS_IOS_ABI_TARGET_DIR:-${CARGO_TARGET_DIR:-$ROOT_DIR/rust/target}}"
CC_BIN="${CC:-cc}"
CXX_BIN="${CXX:-c++}"
NM_BIN="${NM:-nm}"

export CARGO_INCREMENTAL=0

for command in cargo "$CC_BIN" "$CXX_BIN" "$NM_BIN" comm sed sort; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "ERROR: required iOS ABI check command is unavailable: $command" >&2
    exit 2
  fi
done

CARGO_TARGET_DIR="$TARGET_DIR" \
  cargo "+$RUST_TOOLCHAIN" test --locked --manifest-path "$MANIFEST" --package ios-ffi
CARGO_TARGET_DIR="$TARGET_DIR" \
  cargo "+$RUST_TOOLCHAIN" build --locked --manifest-path "$MANIFEST" --package ios-ffi

include_flag="-I$CRATE_DIR/include"
"$CC_BIN" -std=c11 -Wall -Wextra -Wpedantic -Werror \
  "$include_flag" -fsyntax-only "$CRATE_DIR/tests/header_smoke.c"
"$CXX_BIN" -std=c++17 -Wall -Wextra -Wpedantic -Werror \
  "$include_flag" -fsyntax-only "$CRATE_DIR/tests/header_smoke.cc"

archive="$TARGET_DIR/debug/libhns_browser_ios.a"
if [[ ! -s "$archive" ]]; then
  echo "ERROR: ios-ffi did not produce the expected host archive: $archive" >&2
  exit 1
fi

header_symbols="$({
  sed -nE \
    's/^(HnsBrowserResult|uint32_t)[[:space:]]+(hns_browser_[a-z0-9_]+).*/\2/p' \
    "$HEADER"
} | sort -u)"
source_symbols="$({
  sed -nE \
    's/^pub[[:space:]]+(unsafe[[:space:]]+)?extern[[:space:]]+"C"[[:space:]]+fn[[:space:]]+(hns_browser_[a-z0-9_]+).*/\2/p' \
    "$SOURCE"
} | sort -u)"

if [[ -z "$header_symbols" || -z "$source_symbols" ]]; then
  echo "ERROR: unable to enumerate iOS C ABI symbols." >&2
  exit 1
fi

symbol_difference="$({
  comm -3 \
    <(printf '%s\n' "$header_symbols") \
    <(printf '%s\n' "$source_symbols")
} || true)"
if [[ -n "$symbol_difference" ]]; then
  echo "ERROR: ios-ffi header and Rust export sets differ:" >&2
  printf '%s\n' "$symbol_difference" >&2
  exit 1
fi

archive_symbols="$({
  "$NM_BIN" -g "$archive" 2>/dev/null || "$NM_BIN" "$archive"
} | sed -nE 's/.*[[:space:]]_?(hns_browser_[a-z0-9_]+)$/\1/p' | sort -u)"

while IFS= read -r symbol; do
  if ! grep -Fxq "$symbol" <<<"$archive_symbols"; then
    echo "ERROR: host static archive is missing C ABI symbol: $symbol" >&2
    exit 1
  fi
done <<<"$header_symbols"

echo "iOS C ABI checks passed"
