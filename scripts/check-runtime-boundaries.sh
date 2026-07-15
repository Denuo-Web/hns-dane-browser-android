#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_TOOLCHAIN="1.92.0"

for shared_crate in hns-browser-runtime hns-loopback-proxy; do
  shared_dir="$ROOT_DIR/rust/crates/$shared_crate"
  dependency_tree="$(cargo "+$RUST_TOOLCHAIN" tree --locked \
    --manifest-path "$ROOT_DIR/rust/Cargo.toml" \
    --package "$shared_crate" \
    --prefix none)"

  if grep -Eq '^(android-ffi|jni(-sys)?) v[0-9]' <<<"$dependency_tree"; then
    echo "ERROR: $shared_crate must not depend on Android JNI crates." >&2
    grep -E '^(android-ffi|jni(-sys)?) v[0-9]' <<<"$dependency_tree" >&2
    exit 1
  fi

  if matches="$(grep -RInE \
    --include='Cargo.toml' \
    --include='*.rs' \
    '(^|[^[:alnum:]_])(jni::|JNIEnv|JNIEXPORT|JNICALL|JClass|JObject|JString|JValue|jboolean|jbyteArray|jint|jlong)([^[:alnum:]_]|$)|extern[[:space:]]+"system"|Java_[[:alnum:]_]+' \
    "$shared_dir")"; then
    echo "ERROR: $shared_crate contains JNI-specific source or symbols." >&2
    printf '%s\n' "$matches" >&2
    exit 1
  fi
done

legacy_android_protocol_pattern='KotlinFallbackBrowserProxy|LoopbackProxyServer|LocalTlsHnsConnectTerminator|HnsLocalCertificateRegistry|KotlinFallbackHnsLocalCertificateVerifier|nativeLocalTlsCertificate|local_tls_certificate_bundle|HnsWebSocketBridge|HnsWebSocketFrameCodec|HnsWebSocketRequestPolicy|HnsWebSocketShim|nativeGatewayHttpUpgradeTunnel|httpUpgradeTunnel'
if matches="$(grep -RInE \
  --include='*.kt' \
  --include='*.rs' \
  "$legacy_android_protocol_pattern" \
  "$ROOT_DIR/android/app/src" \
  "$ROOT_DIR/rust/crates/android-ffi" \
  "$ROOT_DIR/rust/crates/hns-browser-runtime" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: obsolete Android protocol or compatibility bridge code is present." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

echo "Shared runtime and proxy boundary checks passed"
