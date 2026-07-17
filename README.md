# HNS DANE Browser

Cross-platform Handshake-first browser core with local HNS proofs, authoritative DNS, an experimental HNS P2P DNS relay, RFC 8484 DoH transport, DNSSEC, and DANE diagnostics. Android is the validated shipping baseline; the repository also contains the native iOS 17.0-or-later shell and Apple ABI/build integration. The Apple build and simulator gate uses the stable iOS 26.5 SDK with Xcode 26.5 or 26.6; a signed external-TestFlight device pass is the recommended final iOS release gate and has not been completed.

## Layout

- `rust/`: Cargo workspace for consensus primitives, header chain, Urkel proof interfaces, resolver, DNSSEC, DANE, transport, gateway, cache, the shared browser runtime, the platform-neutral loopback proxy, Android JNI, and the stable Apple C ABI.
- `rust/fuzz/`: `cargo-fuzz` parser harnesses for DNS, HNS resource values, P2P frames, Urkel proofs, TLSA records, and X.509 SPKI extraction.
- `android/`: Kotlin Android browser shell with WebView, URL classification, scoped proxy admission, lifecycle integration, and a thin JNI bridge.
- `ios/`: Swift/UIKit WKWebView shell with whole-data-store proxy admission, lifecycle/certificate integration, and a generated Xcode project definition.
- `fixtures/`: Header, Urkel, and DNS fixture slots for HSD/HNSD comparison data.
- `docs/`: Architecture, security model, version audit, and milestone notes.
- `docs/sync-audit.md`: first-run sync path, progress UI, and remaining sync-speed bottlenecks.
- `docs/supply-chain-audit.md`: pinned build inputs, CI/release gates, and residual reproducibility risks.
- `scripts/`: Local validation helpers.

## Current Scope

- Parses and serializes Handshake block headers.
- Computes Handshake mainnet genesis PoW hash using the HSD header algorithm.
- Validates Handshake TLD syntax and derives HSD-compatible SHA3-256 name hashes.
- Provides typed hash, height, target, and chainwork primitives.
- Stores headers behind an injectable trait with in-memory and SQLite implementations, persists a canonical `hash_by_height` index for reorg-aware best-chain lookups, appends canonical tip updates for normal chain growth, validates the exact mainnet genesis header, enforces HSD-compatible mainnet difficulty retarget bits, and rejects non-genesis headers that fail proof-of-work.
- Parses and synthesizes bounded DNS messages, questions, names, resource records, and RFC 9460 SVCB/HTTPS RDATA.
- Decodes HSD name resource values into DNS-style DS, NS, in-zone glue A/AAAA, synthetic glue A/AAAA, and TXT records; delegated nameserver DoH transport is bootstrapped from proof-anchored `hnsdns=1` metadata when present or discovered from RFC 9461 DNS-server SVCB records in authoritative DNS.
- Parses DNSSEC DNSKEY/DS/RRSIG/NSEC/NSEC3 records, computes RFC 4034 key tags, verifies SHA-1, SHA-256, and SHA-384 DS-to-DNSKEY delegation links, builds canonical RRSIG signed data including canonical RDATA names for CNAME, NS, SOA, SRV, and SVCB/HTTPS TargetName, verifies RSA/SHA-1 compatibility, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, and Ed25519 RRset signatures, and composes those checks into fail-closed signed-RRset, delegated-chain, NSEC no-data, NSEC name-range, NSEC name-error, and RFC 5155 NSEC3 denial validators.
- Encodes and decodes the HSD packet subset needed for header sync and proof requests, including HSD-compatible 9-byte wire framing, 88-byte HSD network addresses in version and addr packets, version/verack ordering tolerance, advisory/unknown packet tolerance during sync waits, transient-failure peer recovery with bounded malformed-peer bans, and a blocking TCP peer connection for getaddr, getheaders, and getproof flows.
- Adds an experimental HNS P2P recursive-DNS transport after local proof validation and authoritative DNS attempts. Android new installs enable this relay path and the independent legacy third-party HNS DoH fallback by default; explicit existing preferences are preserved. Relayed answers remain untrusted input to local DNSSEC, HTTPS/SVCB, TLSA, and DANE validation. Settings accepts manual relay peers only as IP-literal `IPv4:port` or `[IPv6]:port` endpoints, and persists one only after a live HSD handshake confirms the current relay capability. The companion `hsd` responder remains an explicit operator opt-in.
- Adds parser fuzz smoke targets for DNS messages/names/SVCB, HNS resource values, P2P frames/payloads, Urkel proofs, TLSA records, and bounded X.509 SPKI extraction.
- Provides sync coordinators for version/verack, getaddr/addr peer discovery, getheaders/headers ingestion with duplicate-header tolerance, locator construction, remote-height-aware no-op sync when peers are not ahead of the local best header, bounded multi-batch header sync across selected peers with persisted peer outcomes, same-run getaddr discovery rotation toward the peer-table target, Android first-run catch-up status that stays `syncing` while the known or estimated target is ahead of local best height, DNS seed refresh while the peer table is below target, tracked getproof/proof flow control, upstream-compatible Urkel proof verification, verified HSD `NameState.data` value handoff, and proof scheduling into the resolver resource-value store.
- Implements DANE TLSA matching, bounded X.509 certificate SPKI extraction, chain-aware EE/TA TLSA policy, and fail-closed HNS/WebPKI TLS decisions.
- Adds an off-by-default experimental stateless DANE certificate-evidence path for HNS names. When enabled in Settings, native HNS HTTPS requests carry a private gateway flag, the Rust TLS verifier can parse experimental HIP-0017-style x509 Urkel-proof and RFC 9102 DNSSEC-chain extensions, verify direct-zone Urkel/DNSSEC/TLSA evidence against recent local tree roots, and fall back to the existing live proof/resolver path when no supported certificate evidence is present. HIP-0017 extension OIDs remain TBD, so this path uses project-local experimental OIDs and is not a final interop commitment.
- Provides peer scoring, banning, static peer seeding, HSD-compatible DNS seed discovery, bounded rotating getaddr peer discovery, SQLite peer-state persistence, address-group-aware outbound peer selection, LRU-bounded TTL resolver positive and verified-negative caching primitives, in-memory and SQLite verified resource-value providers, resource-cache byte accounting, chain-root/height anchoring, current-tip cache invalidation, active cap enforcement, clear-cache support, a proof-provider-backed HNS resolver boundary that can extract verified HSD resource values, distinguishes verified non-inclusion from existing names with no origin address, extracts final-label HNS roots for dotted HNS hosts, hydrates out-of-zone HNS nameserver addresses from their own verified root proofs, filters proven DNS-style records fail-closed, bootstraps RFC 8484 authoritative DoH from proof-anchored `hnsdns=1` transport metadata or RFC 9461 `_dns.<nameserver>` SVCB discovery, detects confirmed transparent port 53 interception with a bounded TEST-NET sentinel probe, and a DNSSEC-gated delegation boundary for HNS roots with NS/DS records backed by authoritative DoH or UDP DNS with TCP fallback, signed positive RRset validation, bounded CNAME-chain validation, signed child-referral validation with child CNAME-chain handling, parent/child NSEC/NSEC3 no-data validation, and delegated NXDOMAIN name-error validation.
- Provides bounded HTTP/1.1 origin transport over TCP or rustls TLS with same-origin keep-alive pooling, HTTPS rustls session resumption scoped to the active DANE/WebPKI policy, safe same-port Alt-Svc promotion to HTTP/2 or HTTP/3, HTTPS HTTP/2 origin transport over Tokio/Rustls, and HTTPS HTTP/3 origin transport over Quinn/h3 with DANE validation bound to the QUIC TLS handshake, with gateway routing only from owner-matching secure A/AAAA answers or validated CNAME-chain terminal A/AAAA answers to transport connect addresses, delegated origin A/AAAA lookup when Android starts from all root records, exact `_port._tcp.host` DNSSEC-secure TLSA lookup for DANE policy, strict and compatibility HNS HTTPS policy modes, HTTPS/SVCB ALPN and service-port policy selection constrained to implemented origin protocols, HTTP/1.1 default fallback when SVCB permits it, fail-closed origin response framing for unsupported transfer codings or ambiguous lengths, stream-to-writer decoded response bodies, and actionable fail-closed handling when HNS resolution lacks an origin address or delegated nameserver responses are invalid.
- Adds gateway-time live proof fetching on verified-resource cache miss from peers at or above the local anchor height, storing Urkel-verified values anchored to the current best header before origin routing, an Android-only AD-gated HNS DoH compatibility fallback for delegated nameserver failures after the proof-backed root path has run, and native HNS WebSocket/HTTP Upgrade stream tunneling after HNS resolution, HTTPS/SVCB policy, and DANE validation; remaining DNSSEC algorithms and remaining gateway boundaries stay fail-closed or future work.
- Packages the Rust FFI core into the APK for `arm64-v8a` and `x86_64`.
- Adds an Android WebView shell with HNS-aware omnibox classification that defaults bare HNS names to HTTPS, keeps dotted hosts under the vendored current IANA TLD set and reserved special-use suffixes on the normal path, reports main-frame HNS gateway failures plus DANE/WebPKI and resolver compatibility policy in the left-side toolbar security state, and uses a shared reserved-name host policy and sync-aware security-label policy. An application-foreground scheduler owns repeated native sync while an app screen is open, including automatic first-run catch-up, live block-height progress, explicit peer-failure outcomes, diagnostics, cache controls, and actionable HNS proof, name, nameserver, DNSSEC, DANE, transport, and origin-address error pages.
- Gates every HNS main-frame navigation through `BrowserProxyCoordinator`. The latest load waits until the process-global AndroidX proxy override is owned and an immutable exact root/subdomain-scoped endpoint is started and applied; scope transitions, suspension, or ownership loss immediately withdraw routing, authentication, certificate trust, and typed status publication. Active in-scope WebView and Service Worker requests use the same proxy/compatibility/block routing snapshot; because Android WebView does not expose a Service Worker TLS challenge to the page client, admitted worker requests execute through the shared Rust runtime gateway instead of the local CONNECT certificate path.
- Selects the platform-neutral Rust proxy exclusively. It exposes a fresh authenticated loopback HTTP/CONNECT endpoint, routes HNS requests through the shared persistent runtime, terminates CONNECT with Rust-owned per-host local TLS identities, forwards validated native WebSocket/HTTP Upgrade streams, and supplies bounded typed main-frame security status. Android proceeds past the expected local TLS error only when the full certificate DER matches the exact host and live proxy generation.
- Falls back only to the exact-scope compatibility interceptor if the Rust proxy cannot start. A document-start policy leaves allowed WebSockets on Chromium's native implementation while rejecting cross-scope HNS targets; all HTTP parsing, CONNECT termination, certificate generation, and Upgrade tunneling remain in Rust.
- Provides a second, fail-closed whole-browser proxy mode for WebKit data stores that cannot express Android's reverse-bypass scope. The Rust proxy routes the admitted HNS root through the shared HNS/DNSSEC/DANE backend, forwards ICANN HTTP and opaque CONNECT only to explicit public addresses obtained through bounded WebPKI-authenticated DoH, blocks reserved/private destinations and unsafe ports before dialing, and never uses the system resolver for a browser target.
- Exposes the shared runtime through a versioned `ios-ffi` C ABI with opaque monotonic handles, Rust-owned result buffers, bounded status mailboxes, one active proxy per runtime, immediate lifecycle revocation, and live generation/host/certificate matching. Apple device and simulator slices are packaged as `HnsBrowserRuntime.xcframework`.
- Adds an iOS 17.0-or-later UIKit/WKWebView shell using one persistent website-data-store profile and an authenticated, no-failover whole-browser proxy configuration. The deployment floor retains support for the iOS 17 and iOS 18 generations, while Apple builds use the stable iOS 26.5 SDK with Xcode 26.5 or 26.6. Swift owns navigation admission, WebView reconstruction, downloads, UI, and server-trust challenge integration; HNS classification, sync, resolution, DNSSEC, DANE, HTTP parsing, proxying, and TLS termination remain in Rust.

## Platform Migration Status

Android has completed its Rust-only proxy cutover: `MainActivity` uses the shared Rust runtime and proxy, while Kotlin owns only platform UI, WebView admission, lifecycle, and JNI conversion. The Apple C ABI, XCFramework build, and native iOS shell are implemented against the same runtime and proxy. Linux validates the Rust, ABI, header, and architecture boundaries; macOS compilation and simulator tests against the iOS 26.5 SDK form the Apple build gate. The signed physical-device matrix in `docs/ios-device-validation.md` is a recommended final release gate for WebKit behavior that simulator success cannot establish.

## Validate

```sh
./scripts/check.sh
./scripts/fuzz-smoke.sh
```

Android builds on ARM64 host use APK Workbench:

```sh
APK_WORKBENCH="$HOME/APK_Workbench"
GRADLE="$APK_WORKBENCH/scripts/dev/apkw-gradle.sh"

./scripts/build-android.sh

"$GRADLE" --project-dir "$PWD/android" testDebugUnitTest

"$GRADLE" \
  --project-dir "$PWD/android" \
  connectedDebugAndroidTest
```

The debug APK is written to `android/app/build/outputs/apk/debug/app-debug.apk`.

On macOS with Xcode 26.5 or 26.6, the stable iOS 26.5 SDK, and the configured Apple Rust targets:

```sh
./scripts/run-ios-gate.sh
```

The gate verifies the selected Xcode and exact SDK, installs the pinned Rust toolchain and Apple targets, checks the ABI and platform boundaries, creates `build/apple/HnsBrowserRuntime.xcframework`, selects an iOS 26.5 iPhone simulator, executes the test target, and links an unsigned Release build against the arm64 device slice. This validates the Apple build, linkage, and simulator tests only; see `docs/ios-device-validation.md` for the recommended signed physical-device matrix before final App Review.

Debug/demo builds are unsigned beyond the default Android debug key and are intended for testing only. The diagnostics screen identifies Denuo Web, LLC as publisher, shows the build channel and license, and states that donations are optional and unlock no app features.

The Android build runs `scripts/build-rust-android.sh` through Gradle and builds `android-ffi` with pinned `cargo-ndk`. Release JNI outputs retain line-table debug information long enough for the Android Gradle Plugin to strip the shipping libraries and package native symbols; the libraries ship under `lib/<abi>/libhns_dane_browser_ffi.so`.

## Support

Donations are optional and do not unlock any app features.

- HNS donation address: `hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

## License

This repository is source-available under the PolyForm Noncommercial License 1.0.0. Noncommercial use, study, modification, and redistribution are allowed under the license. Commercial use requires separate written permission from Denuo Web, LLC.

Source code: https://github.com/Denuo-Web/hns-dane-browser
