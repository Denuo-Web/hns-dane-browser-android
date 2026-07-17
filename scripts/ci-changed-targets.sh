#!/usr/bin/env bash
set -euo pipefail

# Classify a change set by the expensive CI targets that can be affected.
#
# The normal mode derives the complete change set for GitHub pull_request and
# push events. Manual dispatches deliberately run every target. Tests and local
# callers can pass paths directly with `--classify`.

rust=false
android=false
ios=false
changed_count=0
reason=""

set_all_targets() {
  rust=true
  android=true
  ios=true
}

classify_path() {
  local path="$1"
  changed_count=$((changed_count + 1))

  case "$path" in
    # CI policy and cross-platform boundary logic can change which checks are
    # trusted, so validate every target when any of these files changes.
    .github/workflows/ci.yml | \
      scripts/ci-changed-targets.sh | \
      tests/test_ci_changed_targets.py | \
      scripts/check.sh | \
      scripts/check-runtime-boundaries.sh | \
      scripts/check-version-consistency.sh | \
      scripts/verify-supply-chain.sh)
      set_all_targets
      ;;

    # Apple release/capture workflows and their helpers cannot affect the
    # Android package or shared Rust behavior.
    .github/workflows/ios-*.yml | \
      scripts/generate-ios-app-store-screenshots.sh | \
      scripts/ios_screenshot_tools.py | \
      scripts/stage-ios-app-store-screenshots.sh | \
      tests/test_ios_screenshot_tools.py)
      ios=true
      ;;

    # Any other workflow remains conservative until it has an explicit owner.
    .github/workflows/*)
      set_all_targets
      ;;

    # This bootstrap snapshot ships in both apps and is interpreted by the
    # shared runtime. Its Android directory location is only historical.
    android/app/src/main/assets/hns_headers_300000.snapshot.gzip)
      set_all_targets
      ;;

    # The generated third-party notice is packaged by both application shells.
    android/app/src/main/assets/third_party_notices.txt | \
      scripts/generate-third-party-notices.py | \
      scripts/third-party-notices.sha256)
      android=true
      ios=true
      ;;

    # Workspace-wide Rust inputs and shared runtime crates feed both native
    # adapters. The global lockfile is intentionally treated conservatively.
    rust/Cargo.toml | \
      rust/Cargo.lock | \
      rust/rust-toolchain.toml | \
      rust/crates/hns-*)
      set_all_targets
      ;;

    # Platform FFI adapters still receive the full Rust gate, but do not force
    # an unrelated application shell to build.
    rust/crates/android-ffi/*)
      rust=true
      android=true
      ;;
    rust/crates/ios-ffi/*)
      rust=true
      ios=true
      ;;

    # Rust-only developer tooling and fuzz inputs do not ship in either app.
    rust/fuzz/* | \
      rust/.config/* | \
      rust/deny.toml | \
      tools/* | \
      scripts/build-rust.sh | \
      scripts/fuzz-smoke.sh)
      rust=true
      ;;

    # Any future, unclassified Rust path is shared by default.
    rust/*)
      set_all_targets
      ;;

    # Android sources, build inputs, release helpers, and Android-specific
    # notice generation do not require the Apple runner.
    android/* | \
      gradle/* | \
      scripts/build-android.sh | \
      scripts/build-rust-android.sh | \
      scripts/play-upload-closed-testing.sh | \
      scripts/with-local-signing.sh)
      android=true
      ;;

    # The ABI checker is also exercised by the Rust gate. Other Apple helpers
    # are fully covered by the complete iOS gate.
    scripts/check-ios-abi.sh)
      rust=true
      ios=true
      ;;
    ios/* | \
      scripts/build-ios.sh | \
      scripts/build-rust-ios.sh | \
      scripts/run-ios-gate.sh | \
      scripts/upload-ios-testflight.sh | \
      scripts/select_ios_simulator.py | \
      scripts/test_select_ios_simulator.py)
      ios=true
      ;;

    # These files are covered by the lightweight repository-policy checks in
    # the scope job and do not need a native application build by themselves.
    .github/FUNDING.yml | \
      .github/dependabot.yml | \
      .gitignore | \
      CHANGELOG.md | \
      LICENSE | \
      README.md | \
      docs/* | \
      dist/* | \
      fixtures/*.md | \
      scripts/audit-versions.sh)
      ;;

    # Unknown paths force all gates. New repository areas therefore cost an
    # extra run until classified instead of silently escaping validation.
    *)
      set_all_targets
      ;;
  esac
}

valid_commit() {
  local revision="$1"
  [[ "$revision" =~ ^[0-9a-fA-F]{40}$ ]] &&
    git cat-file -e "${revision}^{commit}" 2>/dev/null
}

classify_diff() {
  local base="$1"
  local head="$2"
  local changed_file

  if ! valid_commit "$base" || ! valid_commit "$head"; then
    set_all_targets
    reason="missing or invalid comparison commit; all targets selected"
    return
  fi

  changed_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hns-ci-paths.XXXXXX")"
  if ! git diff --no-renames --name-only -z "$base" "$head" >"$changed_file"; then
    rm -f -- "$changed_file"
    set_all_targets
    reason="git diff failed; all targets selected"
    return
  fi

  while IFS= read -r -d '' path; do
    classify_path "$path"
  done <"$changed_file"
  rm -f -- "$changed_file"
  reason="classified $changed_count changed path(s)"
}

classify_root_commit() {
  local head="$1"
  local changed_file

  if ! valid_commit "$head"; then
    set_all_targets
    reason="missing or invalid initial-push commit; all targets selected"
    return
  fi

  changed_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hns-ci-paths.XXXXXX")"
  if ! git diff-tree --root --no-commit-id --name-only -r -z "$head" >"$changed_file"; then
    rm -f -- "$changed_file"
    set_all_targets
    reason="initial-push diff failed; all targets selected"
    return
  fi

  while IFS= read -r -d '' path; do
    classify_path "$path"
  done <"$changed_file"
  rm -f -- "$changed_file"
  reason="classified $changed_count path(s) from the initial push"
}

emit_outputs() {
  local destination="${GITHUB_OUTPUT:-/dev/stdout}"
  {
    printf 'rust=%s\n' "$rust"
    printf 'android=%s\n' "$android"
    printf 'ios=%s\n' "$ios"
  } >>"$destination"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      printf '### CI target selection\n\n'
      printf -- '- Rust: `%s`\n' "$rust"
      printf -- '- Android: `%s`\n' "$android"
      printf -- '- iOS: `%s`\n' "$ios"
      printf -- '- Reason: %s\n' "$reason"
    } >>"$GITHUB_STEP_SUMMARY"
  fi
}

if [[ "${1:-}" == "--classify" ]]; then
  shift
  for path in "$@"; do
    classify_path "$path"
  done
  reason="classified $changed_count supplied path(s)"
  emit_outputs
  exit 0
fi

if [[ "$#" -ne 0 ]]; then
  echo "Usage: $0 [--classify PATH ...]" >&2
  exit 2
fi

event_name="${CI_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
case "$event_name" in
  workflow_dispatch)
    set_all_targets
    reason="manual workflow dispatch; all targets selected"
    ;;
  pull_request)
    classify_diff "${CI_PR_BASE_SHA:-}" "${CI_PR_HEAD_SHA:-}"
    ;;
  push)
    push_head="${CI_CURRENT_SHA:-${GITHUB_SHA:-}}"
    push_before="${CI_BEFORE_SHA:-}"
    if [[ "$push_before" =~ ^0{40}$ ]]; then
      classify_root_commit "$push_head"
    else
      classify_diff "$push_before" "$push_head"
    fi
    ;;
  *)
    set_all_targets
    reason="unsupported or missing event '$event_name'; all targets selected"
    ;;
esac

printf 'CI target selection: rust=%s android=%s ios=%s (%s)\n' \
  "$rust" "$android" "$ios" "$reason"
emit_outputs
