# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

## 0.2.9 - 2026-07-06

### Added

- Replaced `hnsdns=1` HNS TXT discovery with RFC 9461 `_dns.<nameserver>` SVCB discovery for RFC 8484 authoritative DoH endpoints on delegated nameservers, used after direct UDP/TCP 53 and validated against the HNS-proven DS chain.
- Added resolver trace and Android diagnostics labels for authoritative DoH attempts and malformed RFC 9461 DoH discovery records.

### Changed

- Rebranded the unreleased Android app to HNS DANE Browser with launcher label HNS DANE, package ID `com.denuoweb.hnsdane`, and GitHub package references under `Denuo-Web/hns-dane-browser-android`.
- Replaced the launcher, Play icon, feature graphic, and in-app brand assets with the centered HNS DANE mark.

## 0.2.8 - 2026-07-04

### Added

- Added a configurable compatibility DoH resolver setting for portable HNS resolution across arbitrary networks.

### Fixed

- Validated delegated HNS DNSSEC over DoH transport locally against HNS DS records instead of relying on resolver AD bits.
- Accepted DoH responses with compressed RRSIG signer names.
- Validated inline child-zone signed answers and no-data proofs for delegated HNS zones.
- Kept optional HTTPS/SVCB policy lookup failures from blocking secure A/TLSA/DANE validation.

## 0.2.7 - 2026-06-30

### Changed

- Updated the bundled HNS directory homepage organization and footer copy.

## 0.2.6 - 2026-06-30

### Fixed

- Kept refreshed HNS WebSocket pages from receiving stale native events from the previous page instance.

## 0.2.5 - 2026-06-30

### Fixed

- Bridged HNS WebSockets through the native HNS gateway so single-label HNS pages can open `wss://` connections with resolver, HTTPS service, and DANE validation instead of relying on Android WebView's WebSocket TLS stack.

## 0.2.4 - 2026-06-30

### Changed

- Audited the bundled HNS homepage with resolver trace, HNS proof, TLSA, and DANE checks; removed non-working entries and added Denuo Web as a core direct-authoritative HNS site.
- Updated Denuo Web infrastructure to advertise HTTP/3 through DNS HTTPS records and showcase HTTP/3 plus WebSocket echo support.

### Fixed

- Kept regular origin HTTP reads on the normal response timeout instead of the shorter tunnel idle timeout.
- Avoided stale DoH transport promotion state across Android resolver fallback queries.
- Submitted omnibox Enter on key-down and forced focus back to WebView so the keyboard closes reliably.

## 0.2.3 - 2026-06-30

### Security

- Hardened Android WebView startup, optional WebKit feature usage, Service Worker interception, renderer recovery, and non-HTTP(S) navigation handling.
- Hardened the Android loopback gateway so it refuses broad WebView proxy fallback when host-scoped reverse-bypass support is unavailable.
- Restricted loopback gateway handling to active HNS host/subdomain scope and rejected non-HNS proxy traffic with fail-closed responses.
- Removed release stack-trace printing from the loopback accept path and kept diagnostics bounded through the gateway event log.

### Changed

- Updated `androidx.activity:activity-ktx` from `1.12.0-alpha05` to stable `1.13.0`.
- Updated production-readiness and security-model documentation for the stricter loopback proxy posture.

### Fixed

- Made the Android FFI live-proof cache-miss test deterministic by persisting the synthetic peer height before selection.
- Addressed the current Rust clippy warning in the Android FFI fallback marker.
