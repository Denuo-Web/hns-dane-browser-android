#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEAM_ID="${HNS_IOS_TEAM_ID:-45NQQK3G3S}"
BUNDLE_ID="com.denuoweb.hnsdane.ios"
API_KEY_ID="${HNS_ASC_API_KEY_ID:-}"
API_KEY_ISSUER_ID="${HNS_ASC_API_KEY_ISSUER_ID:-}"
API_KEY_PATH="${HNS_ASC_API_KEY_PATH:-}"
DISTRIBUTION_P12_PATH="${HNS_IOS_DISTRIBUTION_P12_PATH:-}"
DISTRIBUTION_P12_PASSWORD="${HNS_IOS_DISTRIBUTION_P12_PASSWORD:-}"
APP_STORE_PROFILE_PATH="${HNS_IOS_APP_STORE_PROFILE_PATH:-}"
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
[[ -f "$DISTRIBUTION_P12_PATH" && -s "$DISTRIBUTION_P12_PATH" ]] ||
  fail "HNS_IOS_DISTRIBUTION_P12_PATH must point to the Apple Distribution .p12 file."
[[ -n "$DISTRIBUTION_P12_PASSWORD" ]] ||
  fail "HNS_IOS_DISTRIBUTION_P12_PASSWORD must contain the .p12 password."
[[ -f "$APP_STORE_PROFILE_PATH" && -s "$APP_STORE_PROFILE_PATH" ]] ||
  fail "HNS_IOS_APP_STORE_PROFILE_PATH must point to the App Store provisioning profile."
private_key_header="-----BEGIN PRIVATE"" KEY-----"
private_key_footer="-----END PRIVATE"" KEY-----"
grep -Fq -- "$private_key_header" "$API_KEY_PATH" ||
  fail "the App Store Connect key does not contain a private-key header."
grep -Fq -- "$private_key_footer" "$API_KEY_PATH" ||
  fail "the App Store Connect key does not contain a private-key footer."

for command in openssl plutil python3 rustup security xcode-select xcodebuild xcrun; do
  command -v "$command" >/dev/null 2>&1 ||
    fail "required command is unavailable: $command"
done
[[ -x /usr/libexec/PlistBuddy ]] ||
  fail "required command is unavailable: /usr/libexec/PlistBuddy"

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
python3 ./dist/app-store/validate.py --metadata-only

version="$(sed -n 's/^[[:space:]]*MARKETING_VERSION: \([^[:space:]]*\).*/\1/p' ios/project.yml)"
build="$(sed -n 's/^[[:space:]]*CURRENT_PROJECT_VERSION: \([0-9][0-9]*\).*/\1/p' ios/project.yml)"
[[ -n "$version" && -n "$build" ]] ||
  fail "the expected iOS version and build could not be read from ios/project.yml."

if [[ ! -s "$FRAMEWORK_PATH/Info.plist" ]]; then
  ./scripts/build-rust-ios.sh
fi

release_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hns-ios-release.XXXXXX")"
archive_path="$release_dir/HnsDaneBrowser.xcarchive"
export_path="$release_dir/export"
export_options="$release_dir/ExportOptions.plist"
profile_plist="$release_dir/AppStoreProfile.plist"
p12_leaf_cert="$release_dir/AppleDistribution.cer"
keychain_path="$release_dir/signing.keychain-db"
installed_profile_path=""
keychain_created=false
keychain_search_list_modified=false
original_keychains=()
cleanup() {
  set +e
  if [[ "$keychain_search_list_modified" == true ]]; then
    if (( ${#original_keychains[@]} > 0 )); then
      security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1
    else
      security list-keychains -d user -s >/dev/null 2>&1
    fi
  fi
  if [[ "$keychain_created" == true ]]; then
    security delete-keychain "$keychain_path" >/dev/null 2>&1
  fi
  if [[ -n "$installed_profile_path" ]]; then
    rm -f -- "$installed_profile_path"
  fi
  rm -rf -- "$release_dir"
}
trap cleanup EXIT

security cms -D -i "$APP_STORE_PROFILE_PATH" >"$profile_plist"
plutil -lint "$profile_plist" >/dev/null
profile_uuid="$(/usr/libexec/PlistBuddy -c 'Print :UUID' "$profile_plist")"
profile_team_id="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$profile_plist")"
profile_app_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$profile_plist")"
profile_get_task_allow="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:get-task-allow' "$profile_plist")"
profile_beta_reports_active="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:beta-reports-active' "$profile_plist")"
[[ "$profile_uuid" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] ||
  fail "the provisioning profile has an invalid UUID."
[[ "$profile_team_id" == "$TEAM_ID" ]] ||
  fail "the provisioning profile belongs to a different Apple team."
[[ "$profile_app_id" == "$TEAM_ID.$BUNDLE_ID" ]] ||
  fail "the provisioning profile does not match $BUNDLE_ID."
[[ "$profile_get_task_allow" == false ]] ||
  fail "the provisioning profile is not an App Store distribution profile."
[[ "$profile_beta_reports_active" == true ]] ||
  fail "the provisioning profile is not enabled for App Store beta distribution."
if /usr/libexec/PlistBuddy -c 'Print :ProvisionedDevices' "$profile_plist" >/dev/null 2>&1; then
  fail "the provisioning profile is device-bound instead of App Store distribution."
fi
if profile_all_devices="$(
  /usr/libexec/PlistBuddy -c 'Print :ProvisionsAllDevices' "$profile_plist" 2>/dev/null
)"; then
  [[ "$profile_all_devices" == false ]] ||
    fail "the provisioning profile is an enterprise profile, not App Store distribution."
fi

if ! python3 -c '
from datetime import datetime, timezone
import plistlib
import sys

with open(sys.argv[1], "rb") as profile_file:
    expiration = plistlib.load(profile_file).get("ExpirationDate")
if not isinstance(expiration, datetime):
    raise SystemExit(1)
if expiration.tzinfo is None:
    expiration = expiration.replace(tzinfo=timezone.utc)
if expiration <= datetime.now(timezone.utc):
    raise SystemExit(1)
' "$profile_plist"; then
  fail "the provisioning profile has expired."
fi

if ! openssl pkcs12 \
  -in "$DISTRIBUTION_P12_PATH" \
  -passin env:HNS_IOS_DISTRIBUTION_P12_PASSWORD \
  -clcerts \
  -nokeys 2>/dev/null |
  openssl x509 -outform DER -out "$p12_leaf_cert"; then
  fail "the .p12 password is incorrect or the signing identity is invalid."
fi
p12_subject="$(openssl x509 -inform DER -in "$p12_leaf_cert" -noout -subject)"
[[ "$p12_subject" == *'Apple Distribution:'* && "$p12_subject" == *"$TEAM_ID"* ]] ||
  fail "the .p12 does not contain this team's Apple Distribution certificate."
openssl x509 -inform DER -in "$p12_leaf_cert" -checkend 0 -noout >/dev/null ||
  fail "the Apple Distribution certificate has expired."
if ! python3 -c '
import plistlib
import sys

with open(sys.argv[1], "rb") as profile_file:
    profile_certificates = plistlib.load(profile_file).get("DeveloperCertificates", [])
with open(sys.argv[2], "rb") as certificate_file:
    distribution_certificate = certificate_file.read()
if distribution_certificate not in profile_certificates:
    raise SystemExit(1)
' "$profile_plist" "$p12_leaf_cert"; then
  fail "the App Store profile does not include the .p12 signing certificate."
fi

profiles_dir="${HOME}/Library/Developer/Xcode/UserData/Provisioning Profiles"
mkdir -p "$profiles_dir"
profile_install_target="$profiles_dir/$profile_uuid.mobileprovision"
[[ ! -e "$profile_install_target" ]] ||
  fail "a provisioning profile with UUID $profile_uuid is already installed."
installed_profile_path="$profile_install_target"
cp "$APP_STORE_PROFILE_PATH" "$installed_profile_path"

while IFS= read -r existing_keychain; do
  [[ -n "$existing_keychain" ]] && original_keychains+=("$existing_keychain")
done < <(
  security list-keychains -d user |
    sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//'
)
keychain_password="$(openssl rand -hex 32)"
security create-keychain -p "$keychain_password" "$keychain_path"
keychain_created=true
security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$keychain_password" "$keychain_path"
security import "$DISTRIBUTION_P12_PATH" \
  -k "$keychain_path" \
  -P "$DISTRIBUTION_P12_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security >/dev/null
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$keychain_password" \
  "$keychain_path" >/dev/null
keychain_search_list_modified=true
if (( ${#original_keychains[@]} > 0 )); then
  security list-keychains -d user -s "$keychain_path" "${original_keychains[@]}"
else
  security list-keychains -d user -s "$keychain_path"
fi
signing_identities="$(security find-identity -v -p codesigning "$keychain_path")"
[[ "$signing_identities" == *'Apple Distribution:'* && "$signing_identities" == *"$TEAM_ID"* ]] ||
  fail "the temporary keychain does not contain the expected signing identity."
unset DISTRIBUTION_P12_PASSWORD HNS_IOS_DISTRIBUTION_P12_PASSWORD keychain_password

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
  <string>manual</string>
  <key>signingCertificate</key>
  <string>Apple Distribution</string>
  <key>provisioningProfiles</key>
  <dict>
    <key>$BUNDLE_ID</key>
    <string>$profile_uuid</string>
  </dict>
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
  DEVELOPMENT_TEAM="$TEAM_ID" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="Apple Distribution" \
  PROVISIONING_PROFILE_SPECIFIER="$profile_uuid" \
  archive

[[ -s "$archive_path/Info.plist" ]] ||
  fail "xcodebuild did not create the expected archive."

archived_app="$archive_path/Products/Applications/HnsDaneBrowser.app"
archived_info="$archived_app/Info.plist"
[[ -s "$archived_info" ]] ||
  fail "the archive does not contain HnsDaneBrowser.app/Info.plist."
archived_bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$archived_info")"
archived_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$archived_info")"
archived_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$archived_info")"
archived_icon_name="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIcons:CFBundlePrimaryIcon:CFBundleIconName' "$archived_info")"
archived_encryption="$(/usr/libexec/PlistBuddy -c 'Print :ITSAppUsesNonExemptEncryption' "$archived_info")"
[[ "$archived_bundle_id" == "$BUNDLE_ID" ]] ||
  fail "the archived bundle ID is $archived_bundle_id; expected $BUNDLE_ID."
[[ "$archived_version" == "$version" ]] ||
  fail "the archived version is $archived_version; expected $version."
[[ "$archived_build" == "$build" ]] ||
  fail "the archived build is $archived_build; expected $build."
[[ "$archived_icon_name" == AppIcon ]] ||
  fail "the archived primary icon is $archived_icon_name; expected AppIcon."
[[ "$archived_encryption" == false ]] ||
  fail "the archived export-compliance declaration is not the reviewed false value."
[[ -s "$archived_app/Assets.car" ]] ||
  fail "the archive does not contain the compiled AppIcon asset catalog."
printf 'Verified archived app: %s %s (%s), icon %s.\n' \
  "$archived_bundle_id" "$archived_version" "$archived_build" "$archived_icon_name"

xcodebuild \
  -exportArchive \
  -archivePath "$archive_path" \
  -exportPath "$export_path" \
  -exportOptionsPlist "$export_options" \
  -allowProvisioningUpdates \
  "${authentication_args[@]}"

echo "Uploaded HNS DANE Browser $version ($build) to App Store Connect."
