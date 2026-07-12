# Production Readiness Audit

Last audited: 2026-07-12

This audit treats the app as a Play Store closed-testing candidate and checks the shipped Android surface from the outside in: manifest, WebView behavior, release build configuration, network/privacy declarations, diagnostic UI, and release automation.

## Release Candidate Findings

| Area | Status | Finding |
| --- | --- | --- |
| Android release build | Ready | Release builds are non-debuggable, minified, resource-shrunk, upload-signed when Play signing env vars are present, cryptographically verified entry-by-entry against the expected upload-certificate SHA-256 fingerprint, and checked for required 64-bit native libraries. |
| Manifest exposure | Ready | Only `LauncherActivity` is exported. The browser and all settings, diagnostics, HNS inspector, history, and download activities are non-exported; no Android service is declared. |
| Backup / transfer | Ready | App backup and device-transfer extraction are disabled for local browsing, cookies-adjacent prefs, downloads records, diagnostics, resolver cache, and HNS sync/cache state. |
| Cleartext policy | Ready | Cleartext is disabled globally with a loopback-only exception for the local gateway. |
| WebView hardening | Ready | Mixed content is blocked, Safe Browsing is enabled, file/content access is disabled, native JavaScript bridges are removed, WebView debugging follows `BuildConfig.DEBUG`, and loopback proxying is limited to active HNS host/subdomain scope. |
| Dependency maturity | Ready | Runtime AndroidX dependencies are stable release versions; no alpha runtime dependency is used for the Play build. |
| Build supply chain | Ready for CI | The Rust toolchain, cargo-deny, cargo-ndk, Cargo lockfiles, Gradle dependencies, the Gradle distribution, and wrapper JAR are pinned or checksum-verified. CI actions use immutable commit SHAs and run without write permissions or release secrets. |
| Data collection posture | Ready for declaration | No ads, analytics SDKs, developer accounts, location, contacts, SMS, camera, microphone, or advertising ID access were found in app code. Browser requests, HNS peer traffic, DNS, and optional compatibility DoH remain user-visible app functionality. |
| HNS diagnostics | Ready | Resolver trace, HNS proof details, TLSA/DANE inspector, gateway event log, and diagnostic bundle export are present. |
| Production UI | Improved | Main menu now keeps user browsing controls and HNS page-specific inspectors; full app diagnostics live under Settings. Toolbar status text is bounded so it does not crowd the omnibar on small screens. |
| Google Play closed testing | Externally blocked | Build packaging reaches `bundleRelease`, but `verifyPlayReleaseBundle` fails until Play upload signing environment variables are configured. Manual Play Console upload remains valid after a verified signed AAB exists. |

## Applied Cleanup

- Removed the general Diagnostics shortcut from the main hamburger menu so Diagnostics remains a Settings tool instead of a primary browsing action.
- Constrained the toolbar security label and sync summary text to avoid layout crowding on small devices.
- Hardened the loopback gateway so WebView proxy override is refused without reverse-bypass host scoping, non-HNS proxy traffic fails closed, and active HNS host/subdomain scope is enforced at the server.
- Updated `androidx.activity:activity-ktx` from an alpha build to stable `1.13.0`.
- Clarified Strict HNS mode wording: compatibility DoH fallback is described as available only after local HNS proof path verification and direct delegated resolution failure.
- Added `scripts/play-upload-closed-testing.sh` for closed testing upload once Play API credentials are available.
- Documented that the standard Play closed-testing API track is `alpha` unless the Play Console app uses a custom closed track.
- Added CI for the shipping Rust workspace, fuzz workspace, snapshot exporter, Android unit/lint/debug/release builds, and dependency/license checks; pinned the Gradle wrapper distribution and artifact verification metadata.
- Corrected the release documentation to match activity-scoped sync and the absence of notification/foreground-service permissions.

## Remaining Non-Code Work

- Build and upload a fresh `dist/play-store/hns-dane-browser-v0.3.8-play-upload-signed.aab` to the closed testing track in Play Console for package `com.denuoweb.hnsdane`.
- In Play Console, declare that the current build uses no foreground service types; remove any stale `dataSync` declaration from earlier drafts.
- Complete Data safety, App access, Content rating, Target audience, Ads, and Privacy policy declarations using `docs/play-store-readiness.md`.
- Add at least 12 opted-in testers and keep closed testing active for the required period if Google applies the new personal-account production-access rule.

## Watch Items

- Sync runs only while `MainActivity` is started and stops in `onStop`; test background/foreground interruption and catch-up resume because there is no background service or notification.
- Release AAB signing and Play upload remain manual, secret-dependent external gates. CI intentionally builds an unsigned release bundle and receives no signing or Play credentials.
- General-purpose browsing can reach arbitrary third-party web content; keep target audience and content rating conservative.
- HNS WebSocket / HTTP Upgrade for HNS origins now uses native stream tunneling after HNS resolution, HTTPS/SVCB policy, and DANE validation with bounded bridge messages, handshake buffering, and outbound native write queues; keep regression coverage around bridge-unavailable and validation-failure fail-closed behavior.
- Parallel/ranged header sync remains bounded by Handshake header-chain validation order and peer/protocol pacing; performance work should avoid weakening canonical-header validation.
