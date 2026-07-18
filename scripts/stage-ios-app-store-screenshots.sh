#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_REQUESTED="${1:-$ROOT_DIR/build/app-store-live-screenshots}"
SCREENSHOT_ROOT="$ROOT_DIR/dist/app-store/screenshots"
DESTINATION="$SCREENSHOT_ROOT/en-US"
MANIFEST_DESTINATION="$SCREENSHOT_ROOT/manifest.json"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

if [[ "$SOURCE_REQUESTED" != /* ]]; then
  SOURCE_REQUESTED="$ROOT_DIR/$SOURCE_REQUESTED"
fi
[[ -d "$SOURCE_REQUESTED" ]] || fail "live screenshot directory is missing: $SOURCE_REQUESTED"
SOURCE="$(cd "$SOURCE_REQUESTED" && pwd -P)"
case "$SOURCE" in
  "$ROOT_DIR"/build/*) ;;
  *) fail "source must remain below $ROOT_DIR/build" ;;
esac

python3 "$ROOT_DIR/scripts/ios_screenshot_tools.py" verify-live \
  --directory "$SOURCE"

STAGING="$SCREENSHOT_ROOT/.live-stage.$$"
cleanup() {
  rm -rf -- "$STAGING"
}
trap cleanup EXIT INT TERM
mkdir -p -- "$STAGING/en-US"
cp -- "$SOURCE"/*.jpg "$STAGING/en-US/"
cp -- "$SOURCE/manifest.json" "$STAGING/manifest.json"

# This replacement is intentionally gated by verify-live: fixture images and
# hand-renamed files cannot reach the distribution directory through this path.
rm -rf -- "$DESTINATION"
mv -- "$STAGING/en-US" "$DESTINATION"
mv -- "$STAGING/manifest.json" "$MANIFEST_DESTINATION"
rm -rf -- "$STAGING"
trap - EXIT INT TERM

printf 'Staged verified live App Store screenshots and provenance in %s\n' "$SCREENSHOT_ROOT"
