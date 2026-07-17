# Production Readiness Audit

Last audited: 2026-07-16

This audit treats the repository as a candidate update to an existing public Google Play app, not as a first closed-testing launch. The live listing observed during the prior audit served version `0.3.1` (`versionCode 22`), while the current repository release candidate declares Android `0.5.0` (`versionCode 40`) with shared Rust engine `0.5.0`. Local and signed-artifact verification is complete; hosted CI and exact-build release-device verification remain pending. Results and hashes retained for `0.4.1` are explicitly historical and do not establish readiness for `0.5.0`.

## Release Candidate Findings

| Area | Status | Finding |
| --- | --- | --- |
| Android release build | Locally verified for `0.5.0` | The clean committed-tree code 40 APK and AAB are non-debuggable, minified, resource-shrunk, and upload-signed. The APK SHA-256 is `bff5ba468b0c5ad2d134603127f089ad6fdc9e9b5ceab921825e570cfefd60fb`; the AAB SHA-256 is `96c5926c559881ba74e380eea062dce3de6cefaf91d3753882e528cccc96e1d0`. |
| Public Play listing | Reconciliation required | Google Play already has a production listing at `0.3.1` (`versionCode 22`). Before the next update, reconcile the live privacy-policy field, Data safety answers, listing text, screenshots, and release notes with current behavior and the eventual release version. |
| Privacy policy | Repository updated; hosted update pending | The repository policy now discloses the default P2P DNS relay, relay-visible queried names/types and network address, manual peer endpoints, local DNSSEC/DANE validation, and the independent legacy DoH fallback. Publish this revision at the canonical `https://denuoweb.com/work/hns-dane-browser/privacy` URL before submitting `0.5.0`; the previously accepted hosted copy applies only to the historical audit. |
| Manifest exposure | Ready | The only app-defined exported entry point is `LauncherActivity`. Browser, settings, diagnostics, HNS inspector, history, download, and other app activities are non-exported, and the app declares no service. Merged dependency components remain subject to their own signature/permission guards. |
| Backup / transfer | Ready | App backup and device-transfer extraction are disabled for local browsing data, WebView state, download records, diagnostics, resolver cache, and HNS sync/cache state. |
| Cleartext policy | Ready | Cleartext is disabled globally with a loopback-only exception for the local gateway. User-selected HTTP and direct DNS/HNS traffic are accurately disclosed, but ordinary open-web and user-initiated transfers are outside Google Play's Data safety collection/sharing scope. |
| WebView hardening | Ready | Mixed content is blocked, Safe Browsing is enabled, file/content access is disabled, native JavaScript bridges are removed, WebView debugging follows `BuildConfig.DEBUG`, and loopback proxying is limited to active HNS host/subdomain scope. |
| Privacy controls | Improved | Settings can clear cookies plus WebView origin storage, and the diagnostics UI can clear the bounded gateway event log. The repository and in-app disclosures now describe WebView-provider Safe Browsing and these local retention controls. |
| Build supply chain | Local gates pass; hosted gates pending | `scripts/check.sh`, 192 Android unit tests, debug/release lint, clean signed builds, and the relay fast/load/full acceptance tiers pass. Hosted path-policy, Rust, cold-cache Android, Apple, and required-result jobs remain pending for the exact candidate commits. |
| 16 KiB / native symbols | Ready locally for `0.5.0` | Both rebuilt JNI libraries passed PT_LOAD alignment, hardening, stripping, Build ID, matching FULL debug metadata, and path-sanitization checks; the signed APK also passed `zipalign -c -P 16 4`. |
| Release-device acceptance | Pending for `0.5.0` | Install the exact signed code 40 APK and exercise cold launch, upgrade, first-run relay-on behavior, verified manual-peer persistence, relay failure to legacy DoH fallback, and ordinary HNS/DNSSEC/DANE browsing. Historical only: the signed `0.4.1` APK upgraded and cold-launched successfully on the Pixel 9 after its shared-runtime device matrix passed. |
| Data collection posture | Repository review updated; live-form reconciliation required | No ads, analytics SDKs, developer accounts, sensitive permissions, advertising ID access, or developer telemetry endpoint was found. The policy now records that a relay peer receives the DNS name/type and source network address needed for the request. Retain the live `No collected / No shared` posture only after reconciling the current Play definitions and WebView-provider Safe Browsing guidance. |

## Applied Cleanup

- Added user-facing deletion of both cookies and WebView origin storage instead of clearing cookies alone.
- Replaced the automatic developer-hosted default homepage request with a bundled, Content-Security-Policy-restricted start page that contains no network resources and does not contact a Denuo Web server; configured remote homepages remain user-controlled.
- Added a Diagnostics control that clears the bounded, sanitized gateway event log.
- Updated the repository privacy policy to disclose WebView-provider Safe Browsing, WebView origin storage, and gateway-diagnostic retention/deletion.
- Corrected the Data safety draft to apply Google's explicit open-web, on-device, and user-initiated-transfer exclusions instead of treating ordinary browser networking as developer collection or sharing.
- Removed stale localized overrides for recently changed privacy and resolver-trace copy so affected locales fall back to the current, accurate source strings until translations are refreshed.
- Added deterministic in-app notices for the complete locked Android release-runtime and shipping Rust dependency inventories, with full license text and a CI-safe integrity check.
- Reworked release native packaging so AGP strips the installed libraries and embeds matching FULL debug metadata, while deterministic prefix maps keep checkout, home, Cargo, Rustup, and NDK paths out of both artifacts.
- Added an automated release-bundle gate for exact ABI inventory, 16 KiB bundle and ELF alignment, ELF architecture/type/bounds, native hardening, stripping, matching Build IDs and symbols, local-path rejection, R8 mapping, third-party notices, and upload signing.
- Hardened the loopback gateway so WebView proxy override is refused without reverse-bypass host scoping, non-HNS proxy traffic fails closed, and active HNS host/subdomain scope is enforced at the server.
- Added proof-pinned authoritative DoH bootstrap for single-label HNS endpoint names, with authoritative DoH preferred when declared, direct authoritative UDP/TCP 53 next, and the configured third-party HNS DoH resolver as the compatibility fallback. The browser now exposes the successful path explicitly in the status bar and strips its internal provenance header before content reaches Chromium or the page.
- Added an untrusted HNS P2P DNS relay after local proof and authoritative transport attempts. Android new installs enable the relay and the independent legacy DoH fallback by default; relayed answers still pass local DNSSEC, TLSA, and DANE validation.
- Added manual relay-peer configuration restricted to IP-literal endpoints. The runtime completes a live HSD handshake and verifies the current relay capability before persisting an endpoint; the `hsd` responder remains an explicit operator opt-in.
- Updated repository privacy and store disclosures for relay-visible queried names/types and client network address. The hosted privacy page must be updated before release.
- Updated `androidx.activity:activity-ktx` from an alpha build to stable `1.13.0`.
- Added local dependency, test, lint, bundle-signing, and supply-chain verification, with immutable Action references in the checked-in workflow.

## Remaining Release Gates

1. Run the hosted path-policy, Rust, cold-cache Android, Apple, and required-result jobs on the exact candidate commit. If future merges should require CI, leave GitHub Actions enabled and add appropriate protection or a ruleset for `main`.
2. Compare upload certificate SHA-256 `D2:2F:F3:25:17:53:11:EB:E6:D6:E9:3D:A3:FD:F5:1D:84:89:22:A1:B8:1A:CB:B3:2F:22:39:CC:F9:4A:51:14` with the upload certificate shown in Play Console.
3. Run the critical first-run, sync-resume, default relay, verified manual-peer, legacy fallback, HNS browsing, download, website-data deletion, and gateway-log deletion flows on a physical supported Android device using the exact signed `0.5.0` build.
4. Publish the revised privacy policy and reconcile the existing live Play listing: update its privacy-policy field, Data safety/app-access/content/ads answers, listing copy, release notes, and stale screenshots before submitting the verified AAB.

## Candidate Verification Status

- `0.5.0` / code 40 local checks: passed.
- `0.5.0` hosted CI checks: pending.
- `0.5.0` signed APK/AAB verification and hashes: passed and recorded above.
- `0.5.0` exact signed-build physical-device acceptance: pending because the Pixel 9 physically disconnected before installation.

## Historical `0.4.1` Evidence

- `./scripts/check.sh` passed on 2026-07-15 for Android `0.4.1` with shared Rust engine `0.4.0`, including supply-chain/version checks, formatting, warning-denied Clippy, all three cargo-deny scopes, the complete Rust test matrix, fuzz-target compilation, and the snapshot exporter.
- The final signed Android build passed with Gradle 9.6.1 / AGP 9.2.1, compile/target SDK 37, NDK `28.2.13676358`, and build-tools AAPT2 36.1.0; the clean gate completed 97 actionable tasks in 11m 13s after compiling both native ABIs.
- Android tests and lint reported 187 unit tests passed and no debug or release lint errors.
- Both packaged libraries reported NDK r28c, Android API 34, stripped status, 16 KiB PT_LOAD alignment, GNU_RELRO, non-executable GNU_STACK, BIND_NOW/NOW, and matching unstripped debug-symbol Build IDs. The signed release APK also passed `zipalign -c -P 16 4`.
- The final signed `0.4.1` / code 39 AAB SHA-256 was `4b2cc8b1da7700675eedb1ed2319ccafd9541acc7114abff9bd60eb6399b4267`. The signed GitHub APK SHA-256 was `a5a9d50d5b19302af488f7f5e6c68281364070edc7edcb14e16dbb1e1a5d61a2`; it matched the established release signer and passed APK Signature Scheme v2 plus 16 KiB ZIP-alignment verification.

## Watch Items

- Sync runs while any app activity is started and stops when the entire app backgrounds; verify cross-screen continuity, interruption, and catch-up resume on the release device.
- Release AAB signing and Play upload remain secret-dependent external operations. CI should build and structurally verify an unsigned release bundle without receiving signing or Play credentials.
- General-purpose browsing can reach arbitrary third-party content; keep target audience and content rating conservative and consistent with the live listing.
- Re-review the accepted hosted policy, repository policy, in-app privacy copy, and live Data safety answers whenever a material networking, storage, diagnostics, or third-party-service behavior changes.
- The hosted policy accepted for the historical release is now materially less complete than the `0.5.0` repository disclosure and must be updated before submission.
