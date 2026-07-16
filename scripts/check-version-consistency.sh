#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

android_gradle="android/app/build.gradle.kts"
rust_manifest="rust/Cargo.toml"
ios_project_definition="ios/project.yml"
ios_info_plist="ios/HnsDaneBrowser/Support/Info.plist"
ios_xcode_project="ios/HnsDaneBrowser.xcodeproj/project.pbxproj"

version_name="$(sed -n 's/^[[:space:]]*versionName = "\([^"]*\)".*/\1/p' "$android_gradle")"
version_code="$(sed -n 's/^[[:space:]]*versionCode = \([0-9][0-9]*\).*/\1/p' "$android_gradle")"
rust_version="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$rust_manifest" | head -n 1)"

if [[ -z "$version_name" || -z "$version_code" || -z "$rust_version" ]]; then
  echo "Could not read Android or Rust version values." >&2
  exit 1
fi

if [[ "$rust_version" != "$version_name" ]]; then
  echo "Rust workspace version ($rust_version) does not match Android versionName ($version_name)." >&2
  exit 1
fi

expected_files=(
  "$android_gradle"
  "$rust_manifest"
  "$ios_project_definition"
  "$ios_info_plist"
  "$ios_xcode_project"
  "CHANGELOG.md"
  "scripts/play-upload-closed-testing.sh"
  "dist/play-store/metadata/README.md"
  "dist/play-store/metadata/en-US/release-notes.txt"
  "docs/play-store-readiness.md"
  "docs/production-readiness-audit.md"
  "android/app/src/test/java/com/denuoweb/hnsdane/ui/DiagnosticReportTest.kt"
)

missing=0
for file in "${expected_files[@]}"; do
  if ! grep -q "$version_name" "$file"; then
    echo "Missing versionName $version_name in $file" >&2
    missing=1
  fi
done

artifact="hns-dane-browser-v${version_name}-play-upload-signed.aab"
diagnostic_test="android/app/src/test/java/com/denuoweb/hnsdane/ui/DiagnosticReportTest.kt"

exact_checks=(
  "${android_gradle}:versionCode = ${version_code}"
  "${android_gradle}:versionName = \"${version_name}\""
  "${rust_manifest}:version = \"${version_name}\""
  "${ios_project_definition}:MARKETING_VERSION: ${version_name}"
  "${ios_project_definition}:CURRENT_PROJECT_VERSION: ${version_code}"
  "${ios_info_plist}:<string>${version_name}</string>"
  "${ios_info_plist}:<string>${version_code}</string>"
  "${ios_xcode_project}:MARKETING_VERSION = ${version_name};"
  "${ios_xcode_project}:CURRENT_PROJECT_VERSION = ${version_code};"
  "CHANGELOG.md:## ${version_name} -"
  "scripts/play-upload-closed-testing.sh:${artifact}"
  "scripts/play-upload-closed-testing.sh:HNS DANE Browser ${version_name}"
  "dist/play-store/metadata/README.md:${version_name} release notes"
  "dist/play-store/metadata/README.md:${artifact}"
  "dist/play-store/metadata/en-US/release-notes.txt:${version_name} "
  "${diagnostic_test}:debug ${version_name} (${version_code})"
  "${diagnostic_test}:hns-dane-browser-rust-core/${version_name}"
)

for check in "${exact_checks[@]}"; do
  file="${check%%:*}"
  pattern="${check#*:}"
  if ! grep -Fq "$pattern" "$file"; then
    echo "Missing expected version pattern in $file: $pattern" >&2
    missing=1
  fi
done

current_only_files=(
  "scripts/play-upload-closed-testing.sh"
  "dist/play-store/metadata/README.md"
  "dist/play-store/metadata/en-US/release-notes.txt"
  "$diagnostic_test"
  "$ios_project_definition"
  "$ios_info_plist"
  "$ios_xcode_project"
)

# Audit documents intentionally compare the candidate with an older live Play
# release. They must mention the current candidate (checked above), but unlike
# executable upload metadata they may also contain historical version numbers.

for file in "${current_only_files[@]}"; do
  while IFS= read -r found_version; do
    if [[ "$found_version" != "$version_name" ]]; then
      echo "Unexpected app release version $found_version in $file; expected $version_name." >&2
      missing=1
    fi
  done < <(grep -Eo '0\.[0-9]+\.[0-9]+' "$file" | sort -u)
done

if ! grep -Fq "version = \"${version_name}\"" rust/Cargo.lock; then
  echo "Rust Cargo.lock does not contain workspace package version $version_name." >&2
  missing=1
fi

if ! grep -Fq "version = \"${version_name}\"" rust/fuzz/Cargo.lock; then
  echo "Rust fuzz Cargo.lock does not contain workspace package version $version_name." >&2
  missing=1
fi

if ! grep -Fq "version = \"${version_name}\"" tools/hns-header-snapshot-exporter/Cargo.lock; then
  echo "Header snapshot exporter Cargo.lock does not contain workspace package version $version_name." >&2
  missing=1
fi

exit "$missing"
