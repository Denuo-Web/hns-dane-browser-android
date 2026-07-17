#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEAM_ID="${HNS_IOS_TEAM_ID:-45NQQK3G3S}"
API_KEY_ID="${HNS_ASC_API_KEY_ID:-}"
API_KEY_ISSUER_ID="${HNS_ASC_API_KEY_ISSUER_ID:-}"
API_KEY_PATH="${HNS_ASC_API_KEY_PATH:-}"
IOS_SDK_VERSION="26.5"
FRAMEWORK_PATH="$ROOT_DIR/build/apple/HnsBrowserRuntime.xcframework"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] ||
  fail "the signed iOS archive and upload require macOS and Xcode."
[[ "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] ||
  fail "HNS_IOS_TEAM_ID must be a 10-character Apple Team ID."
[[ "$API_KEY_ID" =~ ^[A-Z0-9]{10}$ ]] ||
  fail "HNS_ASC_API_KEY_ID must be a 10-character App Store Connect API key ID."
[[ "$API_KEY_ISSUER_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] ||
  fail "HNS_ASC_API_KEY_ISSUER_ID must be an App Store Connect issuer UUID."
[[ -f "$API_KEY_PATH" && -s "$API_KEY_PATH" ]] ||
  fail "HNS_ASC_API_KEY_PATH must point to the downloaded App Store Connect .p8 key."
private_key_header="-----BEGIN PRIVATE"" KEY-----"
private_key_footer="-----END PRIVATE"" KEY-----"
grep -Fq -- "$private_key_header" "$API_KEY_PATH" ||
  fail "the App Store Connect key does not contain a private-key header."
grep -Fq -- "$private_key_footer" "$API_KEY_PATH" ||
  fail "the App Store Connect key does not contain a private-key footer."

for command in plutil rustup xcode-select xcodebuild xcrun; do
  command -v "$command" >/dev/null 2>&1 ||
    fail "required command is unavailable: $command"
done

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
  candidate_iphoneos_sdk="$(
    DEVELOPER_DIR="$candidate" xcrun --sdk iphoneos --show-sdk-version
  )"
  if [[ "$candidate_iphoneos_sdk" == "$IOS_SDK_VERSION" ]]; then
    developer_dir="$candidate"
    break
  fi
done

[[ -n "$developer_dir" ]] ||
  fail "no installed Xcode 26.5/26.6 provides the iOS $IOS_SDK_VERSION SDK."
export DEVELOPER_DIR="$developer_dir"

cd "$ROOT_DIR"
./scripts/check-version-consistency.sh

if [[ ! -s "$FRAMEWORK_PATH/Info.plist" ]]; then
  ./scripts/build-rust-ios.sh
fi

release_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hns-ios-release.XXXXXX")"
archive_path="$release_dir/HnsDaneBrowser.xcarchive"
export_path="$release_dir/export"
export_options="$release_dir/ExportOptions.plist"
cleanup() {
  rm -rf -- "$release_dir"
}
trap cleanup EXIT

cat >"$export_options" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>destination</key>
  <string>upload</string>
  <key>manageAppVersionAndBuildNumber</key>
  <false/>
  <key>method</key>
  <string>app-store-connect</string>
  <key>signingStyle</key>
  <string>automatic</string>
  <key>stripSwiftSymbols</key>
  <true/>
  <key>teamID</key>
  <string>$TEAM_ID</string>
  <key>uploadSymbols</key>
  <true/>
</dict>
</plist>
PLIST
plutil -lint "$export_options"

authentication_args=(
  -authenticationKeyPath "$API_KEY_PATH"
  -authenticationKeyID "$API_KEY_ID"
  -authenticationKeyIssuerID "$API_KEY_ISSUER_ID"
)

xcodebuild \
  -project "$ROOT_DIR/ios/HnsDaneBrowser.xcodeproj" \
  -scheme HnsDaneBrowser \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -archivePath "$archive_path" \
  -allowProvisioningUpdates \
  "${authentication_args[@]}" \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_STYLE=Automatic \
  archive

[[ -s "$archive_path/Info.plist" ]] ||
  fail "xcodebuild did not create the expected archive."

xcodebuild \
  -exportArchive \
  -archivePath "$archive_path" \
  -exportPath "$export_path" \
  -exportOptionsPlist "$export_options" \
  -allowProvisioningUpdates \
  "${authentication_args[@]}"

version="$(sed -n 's/^[[:space:]]*MARKETING_VERSION: \([^[:space:]]*\).*/\1/p' ios/project.yml)"
build="$(sed -n 's/^[[:space:]]*CURRENT_PROJECT_VERSION: \([0-9][0-9]*\).*/\1/p' ios/project.yml)"
echo "Uploaded HNS DANE Browser $version ($build) to App Store Connect."
