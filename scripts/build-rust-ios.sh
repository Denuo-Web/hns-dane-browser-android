#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_TOOLCHAIN="1.92.0"
PROFILE="${HNS_RUST_IOS_PROFILE:-ios-release}"
OUT_DIR="${1:-$ROOT_DIR/build/apple}"
TARGET_DIR="$OUT_DIR/target"
FRAMEWORK_PATH="$OUT_DIR/HnsBrowserRuntime.xcframework"
INCLUDE_DIR="$ROOT_DIR/rust/crates/ios-ffi/include"
HEADER="$INCLUDE_DIR/hns_browser.h"
LIBRARY_NAME="libhns_browser_ios.a"
CLEAN_TARGET="${HNS_RUST_IOS_CLEAN_TARGET:-0}"
PLIST_BUDDY="/usr/libexec/PlistBuddy"
TARGETS=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
)

export CARGO_INCREMENTAL=0

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: Apple Rust libraries require macOS and the Apple SDKs." >&2
  exit 2
fi

case "$PROFILE" in
  dev|release|ios-release) ;;
  *)
    echo "ERROR: HNS_RUST_IOS_PROFILE must be dev, release, or ios-release." >&2
    exit 2
    ;;
esac

case "$CLEAN_TARGET" in
  0|1) ;;
  *)
    echo "ERROR: HNS_RUST_IOS_CLEAN_TARGET must be 0 or 1." >&2
    exit 2
    ;;
esac

case "$OUT_DIR" in
  "$ROOT_DIR"/build/*) ;;
  *)
    echo "ERROR: refusing to write Apple build output outside $ROOT_DIR/build: $OUT_DIR" >&2
    exit 2
    ;;
esac

for command in cargo comm rustc rustup sed sort xcodebuild xcrun; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "ERROR: required command is unavailable: $command" >&2
    exit 2
  fi
done

if [[ ! -x "$PLIST_BUDDY" ]]; then
  echo "ERROR: required property-list reader is unavailable: $PLIST_BUDDY" >&2
  exit 2
fi
for xcode_tool in lipo nm; do
  if ! xcrun --find "$xcode_tool" >/dev/null 2>&1; then
    echo "ERROR: required Xcode tool is unavailable: $xcode_tool" >&2
    exit 2
  fi
done

configured_toolchain="$(
  sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$ROOT_DIR/rust/rust-toolchain.toml"
)"
if [[ "$configured_toolchain" != "$RUST_TOOLCHAIN" ]]; then
  echo "ERROR: rust/rust-toolchain.toml must pin Rust $RUST_TOOLCHAIN." >&2
  exit 2
fi

installed_cargo_version="$(cargo "+$RUST_TOOLCHAIN" --version 2>/dev/null || true)"
installed_rustc_version="$(rustc "+$RUST_TOOLCHAIN" --version 2>/dev/null || true)"
if [[ "$installed_cargo_version" != "cargo $RUST_TOOLCHAIN "* ]] || \
  [[ "$installed_rustc_version" != "rustc $RUST_TOOLCHAIN "* ]]; then
  echo "ERROR: cargo and rustc $RUST_TOOLCHAIN are required." >&2
  exit 2
fi

if [[ ! -s "$HEADER" ]] || [[ ! -s "$INCLUDE_DIR/module.modulemap" ]]; then
  echo "ERROR: the committed C header and module map are required in $INCLUDE_DIR." >&2
  exit 2
fi

header_symbols="$({
  sed -nE \
    's/^(HnsBrowserResult|uint32_t)[[:space:]]+(hns_browser_[a-z0-9_]+).*/\2/p' \
    "$HEADER"
} | sort -u)"
if [[ -z "$header_symbols" ]]; then
  echo "ERROR: unable to enumerate the committed iOS C ABI." >&2
  exit 1
fi

require_exact_architectures() {
  local library="$1"
  shift
  local architectures expected actual_count
  local -a actual_architectures

  architectures="$(xcrun lipo -archs "$library")"
  read -r -a actual_architectures <<<"$architectures"
  actual_count="${#actual_architectures[@]}"
  if [[ "$actual_count" -ne "$#" ]]; then
    echo "ERROR: unexpected architectures in $library: $architectures" >&2
    exit 1
  fi
  for expected in "$@"; do
    case " $architectures " in
      *" $expected "*) ;;
      *)
        echo "ERROR: $library is missing architecture $expected: $architectures" >&2
        exit 1
        ;;
    esac
  done
}

verify_archive_abi() {
  local archive="$1"
  local archive_symbols symbol_difference

  archive_symbols="$({
    xcrun nm -gU "$archive" 2>/dev/null
  } | sed -nE 's/.*[[:space:]]_?(hns_browser_[a-z0-9_]+)$/\1/p' | sort -u)"
  if [[ -z "$archive_symbols" ]]; then
    echo "ERROR: Apple archive contains no exported HNS browser ABI: $archive" >&2
    exit 1
  fi

  symbol_difference="$({
    comm -3 \
      <(printf '%s\n' "$header_symbols") \
      <(printf '%s\n' "$archive_symbols")
  } || true)"
  if [[ -n "$symbol_difference" ]]; then
    echo "ERROR: Apple archive and committed C ABI differ: $archive" >&2
    printf '%s\n' "$symbol_difference" >&2
    exit 1
  fi
}

verify_xcframework() {
  local info_plist="$FRAMEWORK_PATH/Info.plist"
  local entry_index=0
  local device_count=0
  local simulator_count=0
  local identifier platform variant library_path headers_path packaged_library
  local arch_index architecture
  local -a architectures

  if [[ ! -s "$info_plist" ]]; then
    echo "ERROR: XCFramework metadata is missing: $info_plist" >&2
    exit 1
  fi

  while identifier="$(
    "$PLIST_BUDDY" \
      -c "Print :AvailableLibraries:$entry_index:LibraryIdentifier" \
      "$info_plist" 2>/dev/null
  )"; do
    platform="$(
      "$PLIST_BUDDY" \
        -c "Print :AvailableLibraries:$entry_index:SupportedPlatform" \
        "$info_plist"
    )"
    variant="$(
      "$PLIST_BUDDY" \
        -c "Print :AvailableLibraries:$entry_index:SupportedPlatformVariant" \
        "$info_plist" 2>/dev/null || true
    )"
    library_path="$(
      "$PLIST_BUDDY" \
        -c "Print :AvailableLibraries:$entry_index:LibraryPath" \
        "$info_plist"
    )"
    headers_path="$(
      "$PLIST_BUDDY" \
        -c "Print :AvailableLibraries:$entry_index:HeadersPath" \
        "$info_plist"
    )"

    if [[ "$platform" != "ios" ]] || [[ "$library_path" != "$LIBRARY_NAME" ]] || \
      [[ "$headers_path" != "Headers" ]]; then
      echo "ERROR: malformed XCFramework library entry: $identifier" >&2
      exit 1
    fi

    architectures=()
    arch_index=0
    while architecture="$(
      "$PLIST_BUDDY" \
        -c "Print :AvailableLibraries:$entry_index:SupportedArchitectures:$arch_index" \
        "$info_plist" 2>/dev/null
    )"; do
      architectures+=("$architecture")
      arch_index=$((arch_index + 1))
    done

    packaged_library="$FRAMEWORK_PATH/$identifier/$library_path"
    if [[ ! -s "$packaged_library" ]] || \
      [[ ! -s "$FRAMEWORK_PATH/$identifier/$headers_path/hns_browser.h" ]] || \
      [[ ! -s "$FRAMEWORK_PATH/$identifier/$headers_path/module.modulemap" ]]; then
      echo "ERROR: XCFramework entry is incomplete: $identifier" >&2
      exit 1
    fi

    case "$variant" in
      "")
        if [[ "${#architectures[@]}" -ne 1 ]] || [[ "${architectures[0]}" != "arm64" ]]; then
          echo "ERROR: malformed iOS device XCFramework entry: $identifier" >&2
          exit 1
        fi
        require_exact_architectures "$packaged_library" arm64
        device_count=$((device_count + 1))
        ;;
      simulator)
        if [[ "${#architectures[@]}" -ne 2 ]]; then
          echo "ERROR: malformed iOS simulator XCFramework entry: $identifier" >&2
          exit 1
        fi
        case " ${architectures[*]} " in
          *" arm64 "*) ;;
          *)
            echo "ERROR: simulator XCFramework metadata omits arm64: $identifier" >&2
            exit 1
            ;;
        esac
        case " ${architectures[*]} " in
          *" x86_64 "*) ;;
          *)
            echo "ERROR: simulator XCFramework metadata omits x86_64: $identifier" >&2
            exit 1
            ;;
        esac
        require_exact_architectures "$packaged_library" arm64 x86_64
        simulator_count=$((simulator_count + 1))
        ;;
      *)
        echo "ERROR: unexpected XCFramework platform variant '$variant': $identifier" >&2
        exit 1
        ;;
    esac

    entry_index=$((entry_index + 1))
  done

  if [[ "$entry_index" -ne 2 ]] || [[ "$device_count" -ne 1 ]] || \
    [[ "$simulator_count" -ne 1 ]]; then
    echo "ERROR: XCFramework must contain exactly one iOS device and one simulator entry." >&2
    exit 1
  fi
}

installed_targets="$(rustup target list --toolchain "$RUST_TOOLCHAIN" --installed)"
for target in "${TARGETS[@]}"; do
  if ! grep -Fxq "$target" <<<"$installed_targets"; then
    echo "ERROR: missing Rust target $target; install it with rustup target add --toolchain $RUST_TOOLCHAIN $target" >&2
    exit 2
  fi
done

rm -rf -- "$OUT_DIR/device" "$OUT_DIR/simulator" "$FRAMEWORK_PATH"
mkdir -p -- "$OUT_DIR/device" "$OUT_DIR/simulator" "$TARGET_DIR"

profile_args=()
if [[ "$PROFILE" != "dev" ]]; then
  profile_args=(--profile "$PROFILE")
fi

for target in "${TARGETS[@]}"; do
  IPHONEOS_DEPLOYMENT_TARGET=17.0 \
    CARGO_TARGET_DIR="$TARGET_DIR" \
    cargo "+$RUST_TOOLCHAIN" build \
      --locked \
      --manifest-path "$ROOT_DIR/rust/Cargo.toml" \
      --package ios-ffi \
      --target "$target" \
      "${profile_args[@]}"
done

profile_dir="$PROFILE"
if [[ "$PROFILE" == "dev" ]]; then
  profile_dir="debug"
fi

device_library="$TARGET_DIR/aarch64-apple-ios/$profile_dir/$LIBRARY_NAME"
simulator_arm_library="$TARGET_DIR/aarch64-apple-ios-sim/$profile_dir/$LIBRARY_NAME"
simulator_x86_library="$TARGET_DIR/x86_64-apple-ios/$profile_dir/$LIBRARY_NAME"
for library in "$device_library" "$simulator_arm_library" "$simulator_x86_library"; do
  if [[ ! -s "$library" ]]; then
    echo "ERROR: Rust did not produce the expected Apple static library: $library" >&2
    exit 1
  fi
done

require_exact_architectures "$device_library" arm64
require_exact_architectures "$simulator_arm_library" arm64
require_exact_architectures "$simulator_x86_library" x86_64
verify_archive_abi "$device_library"
verify_archive_abi "$simulator_arm_library"
verify_archive_abi "$simulator_x86_library"

cp -- "$device_library" "$OUT_DIR/device/$LIBRARY_NAME"
xcrun lipo -create \
  "$simulator_arm_library" \
  "$simulator_x86_library" \
  -output "$OUT_DIR/simulator/$LIBRARY_NAME"

require_exact_architectures "$OUT_DIR/device/$LIBRARY_NAME" arm64
require_exact_architectures "$OUT_DIR/simulator/$LIBRARY_NAME" arm64 x86_64

xcodebuild -create-xcframework \
  -library "$OUT_DIR/device/$LIBRARY_NAME" \
  -headers "$INCLUDE_DIR" \
  -library "$OUT_DIR/simulator/$LIBRARY_NAME" \
  -headers "$INCLUDE_DIR" \
  -output "$FRAMEWORK_PATH"

if [[ ! -d "$FRAMEWORK_PATH" ]]; then
  echo "ERROR: xcodebuild did not create $FRAMEWORK_PATH" >&2
  exit 1
fi

verify_xcframework

if [[ "$CLEAN_TARGET" == "1" ]]; then
  rm -rf -- "$TARGET_DIR"
fi

echo "Created $FRAMEWORK_PATH"
