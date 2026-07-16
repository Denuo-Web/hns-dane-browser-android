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

android_ffi_dir="$ROOT_DIR/rust/crates/android-ffi"
if matches="$(grep -RInE \
  --include='Cargo.toml' \
  --include='*.rs' \
  'gateway_lock|runtime_gateway_from_handle|with_configured_runtime_gateway|[.]set_policy[[:space:]]*\(|Java_com_denuoweb_hnsdane_net_NativeBridge_native(SyncOnce|SyncStatus|ClearResolverCache|InstallHeaderSnapshot|ResetHeadersFromPeers|HnsProofDetails)|hns_(resolver|loopback_proxy|gateway|transport)::|hns-(resolver|loopback-proxy|gateway|transport)[[:space:]]*=' \
  "$android_ffi_dir" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: android-ffi contains runtime orchestration or legacy JNI entry points." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

if matches="$(grep -RInE \
  --include='*.kt' \
  'HNS_GATEWAY_(STRICT_MODE|DOH_RESOLVER|STATELESS_DANE|NETWORK)_HEADER|X-HNS-Browser-(Strict-Mode|DoH-Resolver|Stateless-DANE|Network)' \
  "$ROOT_DIR/android/app/src/main" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: the Android shell must pass runtime policy as typed fields, not request headers." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

ios_ffi_dir="$ROOT_DIR/rust/crates/ios-ffi"
if [[ ! -s "$ios_ffi_dir/include/hns_browser.h" ]] || \
  [[ ! -s "$ios_ffi_dir/include/module.modulemap" ]]; then
  echo "ERROR: ios-ffi must expose a committed C header and Clang module map." >&2
  exit 1
fi

if matches="$(grep -RInE \
  --include='Cargo.toml' \
  --include='*.rs' \
  '(^|[^[:alnum:]_])(jni::|JNIEnv|Java_[[:alnum:]_]+|hns_(resolver|loopback_proxy|gateway|transport)::)([^[:alnum:]_]|$)|hns-(resolver|loopback-proxy|gateway|transport)[[:space:]]*=' \
  "$ios_ffi_dir" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: ios-ffi must depend only on the shared browser-runtime boundary." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

ios_dir="$ROOT_DIR/ios"
if matches="$(grep -RInE \
  --include='*.swift' \
  'URLSession[[:space:]]*\(|URLSession\.(shared|configuration)|NW(Connection|Listener|Browser)|CF(Stream|Socket)|CFSocket|DNSService|SecTrustEvaluate|SecTrustSetAnchorCertificates|SecPolicyCreate' \
  "$ios_dir" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: the iOS shell contains a direct network or independent trust implementation." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

if matches="$(grep -RInE \
  --include='*.swift' \
  'proxyConfigurations[[:space:]]*=[[:space:]]*\[\]|allowFailover[[:space:]]*=[[:space:]]*true' \
  "$ios_dir" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: the iOS WebKit proxy must never be cleared to a direct route or allow failover." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

if ! grep -Fq 'panic = "unwind"' "$ROOT_DIR/rust/Cargo.toml"; then
  echo "ERROR: Apple FFI artifacts require the panic-contained ios-release profile." >&2
  exit 1
fi

for script in build-rust-ios.sh build-ios.sh check-ios-abi.sh run-ios-gate.sh; do
  if [[ ! -x "$ROOT_DIR/scripts/$script" ]]; then
    echo "ERROR: Apple validation helper is missing or not executable: scripts/$script" >&2
    exit 1
  fi
done

echo "Shared runtime, proxy, and platform-adapter boundary checks passed"
