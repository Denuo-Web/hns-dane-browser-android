# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

## 0.3.13 - 2026-07-14

### Added

- Added in-app third-party software notices generated deterministically from the locked Android release runtime and shipping Rust dependency closure, with complete license text and integrity checking.
- Added a release-bundle gate for exact native ABI inventory, 16 KiB bundle/ELF alignment, ELF hardening and bounds, stripped shipping libraries, matching FULL native debug symbols and Build IDs, path sanitization, R8 mapping, notices, and upload-certificate signing.

### Security

- Hardened the native release build against caller-supplied compiler, linker, and Cargo profile overrides; pinned NDK r28c; remapped local checkout, tool-home, and NDK paths; and made AGP responsible for stripping while retaining Play Console symbols.

### Fixed

- Added proof-anchored `hnsdns=1` authoritative DoH bootstrap metadata so delegated HNS names can reach their RFC 8484 endpoint without first relying on interceptable UDP/TCP port 53; origin answers still require delegated DNSSEC validation against the HNS-proven DS.
- Added a bounded TEST-NET DNS sentinel probe and resolver-trace field that can positively identify transparent port 53 interception without treating a timeout as proof that the network is clean.
- Allowed RFC 9461 DNS-server SVCB records to use a distinct WebPKI-authenticated target name while retaining the HNS-proven nameserver glue address for the connection.
- Expanded the deletion controls to clear WebView origin storage with cookies and to clear the persisted gateway diagnostic log, with updated in-app privacy disclosure.
- Replaced the automatically loaded remote default homepage with a bundled start page that contains no network resources; user-configured homepages remain supported.
- Moved adaptive launcher icons to the API-compatible resource directory and removed obsolete notification, service, privacy, resolver-trace, and cookie-only localized strings.

### Changed

- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.13 release.

## 0.3.12 - 2026-07-13

### Fixed

- Retried delegated authoritative DNS over TCP when UDP answers fail DNSSEC validation, preserving fail-closed DNSSEC behavior while recovering from UDP-only DNS path corruption.
- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.12 release.

## 0.3.11 - 2026-07-12

### Fixed

- Kept automatic HNS header sync alive while navigating between browser, settings, diagnostics, and sync screens; it now stops only when the whole app leaves the foreground, and the HNS Sync screen follows automatic status updates live.
- Added the missing localized cleartext-HTTP warning in every declared app language so the warning bar no longer fails Android lint or falls back to English.

### Changed

- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.11 release.

## 0.3.10 - 2026-07-12

### Security

- Removed the insecure HNS DNS result opt-in. HNS gateway resolution requires verified HNS/DNSSEC data again; cleartext `http://` remains a transport choice only after secure name resolution.
- Added a persistent yellow warning bar for `http://` pages to make cleartext transport visible separately from HNS resolution status.

### Fixed

- Stabilized HNS gateway page loads by falling back from failed Alt-Svc promotion, avoiding unsafe DoH POST promotion, preserving identity-encoded WebView gateway assets, and normalizing root main-frame URL status matching.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.10 release.

## 0.3.9 - 2026-07-12

### Fixed

- Restricted insecure HNS resolution opt-in to cleartext HNS origins; HTTPS and WSS HNS origins still fail closed on unsigned HNS address, HTTPS/SVCB, or TLSA/DANE resolution.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.9 release.

## 0.3.8 - 2026-07-12

### Security

- Blocked native origin, authoritative DNS/DoH, and advertised P2P connections to non-public endpoints on mainnet/testnet, enforced the browser unsafe-port policy, and kept explicit regtest-only development exceptions.
- Authenticated the randomized loopback proxy, limited it to the active HNS origin, blocked alternate loopback literals, made exported launcher input extra-blind, and required a user gesture before external-scheme intents.
- Enforced same-origin redirect following, strict WebSocket handshake/frame/close validation, bounded WebSocket sessions and queues, bounded response/download/cache stores, and fail-closed Service Worker behavior when proxy authentication is unavailable.
- Pinned and verified Rust, Gradle, Android, CI Action, dependency, and release-signing inputs; added read-only CI, Dependabot coverage, secret checks, strict lockfiles, and cryptographic AAB signer verification.

### Fixed

- Fixed native WebSocket upgrade headers and clean-close handling, HTTP/1 informational/framing/trailer parsing, HTTP/2 and HTTP/3 body/header limits and timeouts, unsafe pooled-request replay, and caller header normalization.
- Fixed unchecked header-height arithmetic, JNI request/read length validation, stale or unbounded transport state, delegated DNS source validation, and complete current IANA/special-use name classification including `.internal`.
- Fixed Android lifecycle leaks and sync/cache races, unbounded browser history/download fields, staged-file cleanup, oversized header-snapshot extraction, and release lint failures for experimental API opt-in and locale plural resources.

### Changed

- Removed the ICANN DANE TXT-shadow compatibility fallback. The hardcoded ICANN DANE test host now uses native DNSSEC TLSA only, while delegated HNS authoritative DoH continues to use RFC 9461 `_dns.<nameserver>` SVCB discovery.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.8 release.

## 0.3.7 - 2026-07-08

### Changed

- Disabled spellcheck, suggestions, and personalized learning for the browser omnibar so Android keyboards treat it as a URI/search field instead of prose.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.7 release.

## 0.3.6 - 2026-07-08

### Changed

- Kept HNS sync active only while the app is open, removed the persistent phone sync notification, hid completed sync progress until header resync, enlarged the browser menu, aligned the main toolbar with the top of the app, and moved header resync into HNS Sync settings.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.6 release.

## 0.3.5 - 2026-07-08

### Added

- Added Android locale resources for English, Spanish, French, German, Portuguese, Japanese, Arabic, Persian, and Hebrew.
- Added Android per-app language configuration and a Settings entry for Android's system app-language picker.

### Changed

- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.5 release.

## 0.3.4 - 2026-07-07

### Added

- Added an off-by-default experimental Settings flag for stateless HNS DANE certificate evidence using certificate-carried Urkel proof and RFC 9102 DNSSEC-chain extensions against recent local tree roots.

## 0.3.1 - 2026-07-06

### Changed

- Set the default Android homepage to `https://denuoweb/homepage` and removed the bundled static homepage asset.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.1 release.

## 0.3.0 - 2026-07-06

### Changed

- Bumped the Android app, Rust core, network user-agent strings, and Play upload defaults for the 0.3.0 release.

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
