#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS_SDK_VERSION="26.5"
EXPECTED_WIDTH=1284
EXPECTED_HEIGHT=2778
SCENE_KEY="HNS_APP_STORE_SCREENSHOT_SCENE"
OUTPUT_REQUESTED="${1:-$ROOT_DIR/build/app-store-live-screenshots}"
DIAGNOSTICS_DIR="$ROOT_DIR/build/ios-screenshot-diagnostics"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || fail "screenshot generation requires macOS and Xcode."
[[ -z "${HNS_APP_STORE_SCREENSHOT_SCENE+x}" ]] ||
  fail "$SCENE_KEY must be unset for a live App Store capture."
for command in git grep python3 sips strings xcode-select xcodebuild xcrun; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done
[[ -s "$ROOT_DIR/build/apple/HnsBrowserRuntime.xcframework/Info.plist" ]] ||
  fail "build/apple/HnsBrowserRuntime.xcframework is missing; run the iOS gate first."

if [[ "$OUTPUT_REQUESTED" != /* ]]; then
  OUTPUT_REQUESTED="$ROOT_DIR/$OUTPUT_REQUESTED"
fi
mkdir -p -- "$OUTPUT_REQUESTED"
OUTPUT_DIR="$(cd "$OUTPUT_REQUESTED" && pwd -P)"
case "$OUTPUT_DIR" in
  "$ROOT_DIR"/build/*) ;;
  *) fail "output must remain below $ROOT_DIR/build" ;;
esac
rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR"
rm -rf -- "$DIAGNOSTICS_DIR"

if [[ -n "${HNS_XCODE_DEVELOPER_DIR:-}" ]]; then
  xcode_candidates=("$HNS_XCODE_DEVELOPER_DIR")
else
  xcode_candidates=("$(xcode-select --print-path)")
  shopt -s nullglob
  for xcode_app in \
    /Applications/Xcode_26.6.app \
    /Applications/Xcode_26.6*.app \
    /Applications/Xcode_26.5.app \
    /Applications/Xcode_26.5*.app; do
    xcode_candidates+=("$xcode_app/Contents/Developer")
  done
  shopt -u nullglob
fi

developer_dir=""
for candidate in "${xcode_candidates[@]}"; do
  [[ -x "$candidate/usr/bin/xcodebuild" ]] || continue
  candidate_version="$(
    DEVELOPER_DIR="$candidate" xcodebuild -version | sed -n '1s/^Xcode //p'
  )"
  case "$candidate_version" in
    26.5|26.5.*|26.6|26.6.*) ;;
    *) continue ;;
  esac
  candidate_sdk="$(
    DEVELOPER_DIR="$candidate" xcrun --sdk iphonesimulator --show-sdk-version
  )"
  if [[ "$candidate_sdk" == "$IOS_SDK_VERSION" ]]; then
    developer_dir="$candidate"
    break
  fi
done
[[ -n "$developer_dir" ]] ||
  fail "no installed Xcode 26.5/26.6 provides the iOS $IOS_SDK_VERSION simulator SDK."
export DEVELOPER_DIR="$developer_dir"

WORK_DIR="$(mktemp -d "$ROOT_DIR/build/ios-screenshot-work.XXXXXX")"
SIMULATOR_ID=""
cleanup() {
  if [[ -n "$SIMULATOR_ID" ]]; then
    xcrun simctl shutdown "$SIMULATOR_ID" >/dev/null 2>&1 || true
    xcrun simctl delete "$SIMULATOR_ID" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT INT TERM

xcrun simctl list runtimes --json >"$WORK_DIR/runtimes.json"
xcrun simctl list devicetypes --json >"$WORK_DIR/devicetypes.json"
RUNTIME_ID="$(
  python3 "$ROOT_DIR/scripts/ios_screenshot_tools.py" select-runtime \
    --runtime "$IOS_SDK_VERSION" --input "$WORK_DIR/runtimes.json"
)"
DEVICE_SELECTION="$(
  python3 "$ROOT_DIR/scripts/ios_screenshot_tools.py" select-device-type \
    --input "$WORK_DIR/devicetypes.json"
)"
IFS=$'\t' read -r DEVICE_TYPE_ID DEVICE_NAME <<<"$DEVICE_SELECTION"
[[ -n "$DEVICE_TYPE_ID" && -n "$DEVICE_NAME" ]] || fail "device type selection failed."

SIMULATOR_ID="$(
  xcrun simctl create "HNS App Store Screenshots $$" "$DEVICE_TYPE_ID" "$RUNTIME_ID"
)"
xcrun simctl boot "$SIMULATOR_ID"
xcrun simctl bootstatus "$SIMULATOR_ID" -b
xcrun simctl ui "$SIMULATOR_ID" appearance light
xcrun simctl status_bar "$SIMULATOR_ID" override \
  --time 9:41 \
  --dataNetwork wifi \
  --wifiMode active \
  --wifiBars 3 \
  --cellularMode active \
  --cellularBars 4 \
  --operatorName Denuo \
  --batteryState charged \
  --batteryLevel 100

RESULT_BUNDLE="$WORK_DIR/Screenshots.xcresult"
DERIVED_DATA="$WORK_DIR/DerivedData"
if ! xcodebuild \
  -project "$ROOT_DIR/ios/HnsDaneBrowser.xcodeproj" \
  -scheme HnsDaneBrowserScreenshots \
  -configuration Release \
  -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
  -derivedDataPath "$DERIVED_DATA" \
  -resultBundlePath "$RESULT_BUNDLE" \
  -parallel-testing-enabled NO \
  -maximum-parallel-testing-workers 1 \
  -only-testing:HnsDaneBrowserScreenshotTests/LiveAppStoreScreenshotTests/testLiveSubmissionScreenshots \
  CODE_SIGNING_ALLOWED=NO \
  test; then
  mkdir -p -- "$DIAGNOSTICS_DIR"
  if [[ -d "$RESULT_BUNDLE" ]]; then
    cp -R -- "$RESULT_BUNDLE" "$DIAGNOSTICS_DIR/Screenshots.xcresult"
  else
    printf 'xcodebuild failed before producing %s\n' "$RESULT_BUNDLE" \
      >"$DIAGNOSTICS_DIR/xcodebuild-failure.txt"
  fi
  fail "live Release screenshot test failed; preserved the result bundle for review."
fi

ATTACHMENTS_DIR="$WORK_DIR/attachments"
xcrun xcresulttool export attachments \
  --path "$RESULT_BUNDLE" \
  --output-path "$ATTACHMENTS_DIR"
[[ -s "$ATTACHMENTS_DIR/manifest.json" ]] || fail "xcresult attachment manifest is missing."

RAW_DIR="$WORK_DIR/raw"
RUNTIME_PROVENANCE="$WORK_DIR/live-runtime-provenance.json"
python3 "$ROOT_DIR/scripts/ios_screenshot_tools.py" collect \
  --manifest "$ATTACHMENTS_DIR/manifest.json" \
  --attachments-dir "$ATTACHMENTS_DIR" \
  --output-dir "$RAW_DIR" \
  --profile live \
  --provenance-output "$RUNTIME_PROVENANCE"

for source in "$RAW_DIR"/*.png; do
  basename="$(basename "$source" .png)"
  destination="$OUTPUT_DIR/$basename.jpg"
  sips -s format jpeg -s formatOptions best "$source" --out "$destination" >/dev/null
  has_alpha="$(sips -g hasAlpha "$destination" | awk '/hasAlpha:/{print $2}')"
  [[ "$has_alpha" == "no" ]] || fail "$destination unexpectedly contains an alpha channel."
done

RELEASE_BINARY="$DERIVED_DATA/Build/Products/Release-iphonesimulator/HnsDaneBrowser.app/HnsDaneBrowser"
[[ -x "$RELEASE_BINARY" ]] || fail "Release simulator binary was not produced."
strings "$RELEASE_BINARY" >"$WORK_DIR/release-strings.txt"
if grep -Fq "$SCENE_KEY" "$WORK_DIR/release-strings.txt"; then
  fail "the screenshot fixture key is present in the Release binary."
fi

XCODE_VERSION="$(xcodebuild -version | paste -sd ' ' -)"
COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
python3 "$ROOT_DIR/scripts/ios_screenshot_tools.py" manifest \
  --directory "$OUTPUT_DIR" \
  --width "$EXPECTED_WIDTH" \
  --height "$EXPECTED_HEIGHT" \
  --commit "$COMMIT" \
  --xcode "$XCODE_VERSION" \
  --sdk "$IOS_SDK_VERSION" \
  --device "$DEVICE_NAME" \
  --configuration Release \
  --runtime-provenance "$RUNTIME_PROVENANCE"

python3 "$ROOT_DIR/scripts/ios_screenshot_tools.py" verify-live \
  --directory "$OUTPUT_DIR"

printf 'Created four live Release App Store screenshots and provenance in %s\n' "$OUTPUT_DIR"
