#!/usr/bin/env bash
# Run a command with the ignored project-local Android signing configuration.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
signing_dir="${HNS_DANE_BROWSER_SIGNING_DIR:-$repo_root/.local/signing}"
env_file="$signing_dir/env.sh"
keystore_file="$signing_dir/upload-keystore.jks"

if [[ ! -f "$env_file" || ! -f "$keystore_file" ]]; then
  printf 'Missing local signing files under %s\n' "$signing_dir" >&2
  exit 1
fi

# The ignored file contains the passwords and alias. Keep its values confined to
# the command launched below; the keystore path is always project-local.
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a
export HNS_DANE_BROWSER_UPLOAD_STORE_FILE="$keystore_file"

exec "$@"
