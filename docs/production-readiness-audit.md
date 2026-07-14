# Production Readiness Audit

Last audited: 2026-07-14

This audit treats the repository as a candidate update to an existing public Google Play app, not as a first closed-testing launch. The live listing observed during the audit serves version `0.3.1` (`versionCode 22`), while the repository release candidate declares `0.3.14` (`versionCode 35`).

## Release Candidate Findings

| Area | Status | Finding |
| --- | --- | --- |
| Android release build | Ready locally | The clean final `0.3.14` build produced a non-debuggable, minified, resource-shrunk, upload-signed AAB, and its structural and entry-by-entry signer checks passed. |
| Public Play listing | Reconciliation required | Google Play already has a production listing at `0.3.1` (`versionCode 22`). Before the next update, reconcile the live privacy-policy field, Data safety answers, listing text, screenshots, and release notes with current behavior and the eventual release version. |
| Privacy policy | Ready | The canonical URL `https://denuoweb.com/work/hns-dane-browser/privacy` renders the HNS DANE Browser Privacy Policy after the site application loads. The supplied hosted policy covers local data, browser/HNS network requests, sharing, security, retention/deletion, children, and a privacy contact mechanism; it is accepted unchanged for this release audit. |
| Manifest exposure | Ready | The only app-defined exported entry point is `LauncherActivity`. Browser, settings, diagnostics, HNS inspector, history, download, and other app activities are non-exported, and the app declares no service. Merged dependency components remain subject to their own signature/permission guards. |
| Backup / transfer | Ready | App backup and device-transfer extraction are disabled for local browsing data, WebView state, download records, diagnostics, resolver cache, and HNS sync/cache state. |
| Cleartext policy | Ready | Cleartext is disabled globally with a loopback-only exception for the local gateway. User-selected HTTP and direct DNS/HNS traffic are accurately disclosed, but ordinary open-web and user-initiated transfers are outside Google Play's Data safety collection/sharing scope. |
| WebView hardening | Ready | Mixed content is blocked, Safe Browsing is enabled, file/content access is disabled, native JavaScript bridges are removed, WebView debugging follows `BuildConfig.DEBUG`, and loopback proxying is limited to active HNS host/subdomain scope. |
| Privacy controls | Improved | Settings can clear cookies plus WebView origin storage, and the diagnostics UI can clear the bounded gateway event log. The repository and in-app disclosures now describe WebView-provider Safe Browsing and these local retention controls. |
| Build supply chain | Local gates pass; remote enforcement blocked | Local Rust, dependency, Android unit, lint, and signed-bundle checks passed during the audit. The checked-in GitHub Actions workflow has no runs because Actions is disabled for the repository; `main` also has no branch protection or ruleset. |
| 16 KiB / native symbols | Local gate passed | The clean bundle uses `PAGE_ALIGNMENT_16K`; both stripped JNI libraries have 16 KiB PT_LOAD alignment, RELRO, non-executable stacks, immediate binding, no text relocations, and matching unstripped FULL debug metadata with SHA-1 Build IDs. |
| Device instrumentation | External verification pending | The Android unit suite passed, but no physical Android device was attached, so `HnsConnectInstrumentationTest` and live browser flows were not rerun during this audit. |
| Data collection posture | Ready for live-form reconciliation | No ads, analytics SDKs, developer accounts, sensitive permissions, advertising ID access, or developer telemetry endpoint was found. Google's current guidance excludes open-web WebView navigation, on-device processing, and reasonably expected user-initiated transfers; retain the live `No collected / No shared` posture unless the current WebView Safe Browsing provider guidance requires a declaration. |

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
- Updated `androidx.activity:activity-ktx` from an alpha build to stable `1.13.0`.
- Added local dependency, test, lint, bundle-signing, and supply-chain verification, with immutable Action references in the checked-in workflow.

## Remaining Release Gates

1. Compare upload certificate SHA-256 `D2:2F:F3:25:17:53:11:EB:E6:D6:E9:3D:A3:FD:F5:1D:84:89:22:A1:B8:1A:CB:B3:2F:22:39:CC:F9:4A:51:14` with the upload certificate shown in Play Console.
2. Enable GitHub Actions and add appropriate protection or a ruleset for `main`, then obtain a successful run of the release workflow. These are repository-hosting changes and cannot be proven by the checked-in workflow alone.
3. Run `HnsConnectInstrumentationTest` and the critical first-run, sync-resume, HNS browsing, download, website-data deletion, and gateway-log deletion flows on a physical supported Android device using that final-version build.
4. Reconcile the existing live Play listing: point its privacy-policy field to the accepted canonical URL, update Data safety/app-access/content/ads answers, refresh listing copy and release notes, and replace stale screenshots before submitting the verified AAB.

## Local Verification Evidence

- `./scripts/check.sh`: passed supply-chain/version checks, formatting, warning-denied Clippy, all three cargo-deny scopes, 398 Rust tests, fuzz-target compilation, and the snapshot exporter.
- Clean Android build: passed with Gradle 9.6.1 / AGP 9.2.1, compile/target SDK 37, NDK `28.2.13676358`, and build-tools AAPT2 36.1.0; 97 actionable tasks completed in 13m 44s.
- Android tests and lint: 193 unit tests passed; debug and release lint each reported 0 errors and 110 warnings.
- Candidate artifact inspection: both packaged libraries report NDK r28c, Android API 34, stripped status, 16 KiB PT_LOAD alignment, GNU_RELRO, non-executable GNU_STACK, BIND_NOW/NOW, and matching unstripped debug-symbol Build IDs. The debug APK also passes `zipalign -c -P 16 4`.
- Final signed `0.3.14` / code 35 AAB: SHA-256 `85b1d843d0afc5b50990b75866a8ced0e13e1cfb98dc05b193c531df908e3b7e`. The signed GitHub APK is SHA-256 `fefd14aebdcb7a0796cacff0e4dd3b60a01d5f4a399ea0c931d8523b159b74d3` and passes APK signature plus 16 KiB ZIP-alignment verification.

## Watch Items

- Sync runs while any app activity is started and stops when the entire app backgrounds; verify cross-screen continuity, interruption, and catch-up resume on the release device.
- Release AAB signing and Play upload remain secret-dependent external operations. CI should build and structurally verify an unsigned release bundle without receiving signing or Play credentials.
- General-purpose browsing can reach arbitrary third-party content; keep target audience and content rating conservative and consistent with the live listing.
- Re-review the accepted hosted policy, repository policy, in-app privacy copy, and live Data safety answers whenever a material networking, storage, diagnostics, or third-party-service behavior changes.
- The accepted hosted policy is intentionally less granular than the repository and in-app disclosures for this release; that difference is recorded as an explicit release decision, not evidence that the texts are identical.
