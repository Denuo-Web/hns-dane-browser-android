#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${HNS_IOS_CONFIGURATION:-Debug}"
DESTINATION="${HNS_IOS_DESTINATION:-generic/platform=iOS Simulator}"
ACTION="${HNS_IOS_ACTION:-build-for-testing}"
REUSE_XCFRAMEWORK="${HNS_IOS_REUSE_XCFRAMEWORK:-0}"
FRAMEWORK_PATH="$ROOT_DIR/build/apple/HnsBrowserRuntime.xcframework"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: the iOS application requires macOS and Xcode." >&2
  exit 2
fi

case "$ACTION" in
  build|build-for-testing|test) ;;
  *)
    echo "ERROR: HNS_IOS_ACTION must be build, build-for-testing, or test." >&2
    exit 2
    ;;
esac

case "$REUSE_XCFRAMEWORK" in
  0|1) ;;
  *)
    echo "ERROR: HNS_IOS_REUSE_XCFRAMEWORK must be 0 or 1." >&2
    exit 2
    ;;
esac

if [[ "$ACTION" == "test" && "$DESTINATION" == generic/* ]]; then
  echo "ERROR: HNS_IOS_ACTION=test requires a concrete simulator destination." >&2
  exit 2
fi

if [[ "$REUSE_XCFRAMEWORK" == "1" ]]; then
  if [[ ! -s "$FRAMEWORK_PATH/Info.plist" ]]; then
    echo "ERROR: the existing XCFramework is unavailable: $FRAMEWORK_PATH" >&2
    exit 1
  fi
else
  "$ROOT_DIR/scripts/build-rust-ios.sh"
fi

xcodebuild \
  -project "$ROOT_DIR/ios/HnsDaneBrowser.xcodeproj" \
  -scheme HnsDaneBrowser \
  -configuration "$CONFIGURATION" \
  -destination "$DESTINATION" \
  CODE_SIGNING_ALLOWED=NO \
  "$ACTION"
