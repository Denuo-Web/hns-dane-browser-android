# Branding Audit

Audited: 2026-07-06

## Recommendation

Use **HNS DANE Browser** as the public Play title and **HNS DANE** as the Android launcher label.

This is the strongest near-term adoption name because it keeps the product HNS-first while making the differentiator clear: DNSSEC/DANE/TLSA validation for names that have a secure DNS path. RFC 8484 DNS-over-HTTPS should be described as a standards-based transport layer, not as the trust anchor itself. The trust story is HNS proofs plus DNSSEC/DANE; DoH is the interoperable HTTPS transport used when direct DNS transport is unavailable or when a trusted ICANN diagnostic path is selected.

Recommended copy:

- Play title: `HNS DANE Browser`
- Android launcher label: `HNS DANE`
- Short description: `Browse HNS names with local proofs, RFC 8484 DoH, DNSSEC, and DANE.`
- Longer positioning line: `A Handshake-first browser with local HNS proofs, delegated authoritative DoH, and DNSSEC/DANE diagnostics for selected ICANN domains.`

Do not use `CA-free browser` as the product promise. The app still has WebPKI paths and compatibility modes, so that wording overpromises and may create policy or trust problems. Use wording such as `DANE-capable`, `DNSSEC-validated`, or `CA-bypass capable for validated DANE paths` only where the UI can show the exact validation path.

## Brand Positioning

The brand hierarchy should be:

1. HNS primary.
2. DANE/TLSA as the security differentiator.
3. RFC 8484 DoH as the standards-based transport bridge.
4. ICANN interoperability as selected diagnostic and compatibility support.

This avoids implying that the app is a general-purpose ICANN DANE browser. The product should instead read as a Handshake-native browser that uses standard DNS mechanisms where they strengthen HNS resolution or provide useful comparison diagnostics.

The clean user-facing distinction:

- HNS names use local HNS proofs as the root of authority.
- Delegated HNS names may use authoritative DNS over UDP/TCP 53, then RFC 9461-discovered RFC 8484 authoritative DoH if port 53 is unavailable.
- ICANN names stay on the normal ICANN path but also fall back to RFC 8484.

## Package / Application ID

Decision rule:

- Change the install identity from `com.handshake.browser` to `com.denuoweb.hnsdane`.

Implementation note: changing only `applicationId` is a smaller Play identity change; changing `namespace` and Kotlin package names is a larger refactor because the Rust JNI exports currently use `Java_com_handshake_browser_net_NativeBridge_*` names.

## Current Brand Surface

- App label: `HNS Browser` in `android/app/src/main/res/values/strings.xml`.
- Android identity: `namespace = "com.handshake.browser"` and `applicationId = "com.handshake.browser"` in `android/app/build.gradle.kts`.
- Legal/app info copy still uses both `HNS Browser` and `Handshake Browser`.
- Store-readiness docs describe the app as HNS-first with DNSSEC/DANE diagnostics.
- Current Play icon is readable but literal: a browser-window mark with `HNS`, which does not communicate DANE/TLSA, HNS proofs, or RFC 8484 transport.

That means the name should not imply generalized ICANN DANE browsing until routing, UX, and docs support it beyond selected test hosts.

## Language Rules

Use:

- `Handshake-first`
- `HNS proofs`
- `DNSSEC/DANE`
- `TLSA validation`
- `RFC 8484 DoH transport`
- `authoritative DoH for delegated HNS names`
- `selected ICANN DNSSEC/DANE diagnostics`

Avoid:

- `CA-free browser`
- `ICANN DANE browser`
- `DoH-secured DANE`
- `trustless HTTPS`
- `replaces certificate authorities`
- `private DNS` unless referring to Android's specific Private DNS feature

## Sources

- Android application IDs: https://developer.android.com/build/configure-app-module
- Google Play metadata policy and 30-character title limit: https://support.google.com/googleplay/android-developer/answer/9898842
- Google Play store listing best practices: https://support.google.com/googleplay/android-developer/answer/13393723
- DANE/TLSA RFC 6698: https://www.rfc-editor.org/rfc/rfc6698.html
- DANE operational guidance RFC 7671: https://www.rfc-editor.org/rfc/rfc7671.html
- DNS Queries over HTTPS RFC 8484: https://www.rfc-editor.org/rfc/rfc8484.html
- Existing HNS/DANE browser precedent, Beacon: https://impervious.com/beacon
- Existing HNS resolver/DANE positioning, Easy HNS FAQ: https://easyhns.com/faq/
