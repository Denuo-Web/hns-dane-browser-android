# Google Play Readiness Checklist

Last audited: 2026-07-14

This checklist maps HNS DANE Browser to current Google Play update requirements and identifies the Play Console fields that must be reconciled outside the repository. The app is already public: the live production listing observed during this audit serves `0.3.1` (`versionCode 22`). The repository release candidate declares `0.3.13` (`versionCode 34`).

## Current Repo Status

| Area | Status | Evidence / Action |
| --- | --- | --- |
| Target API level | Ready | `targetSdk = 37`, above the current Google Play requirement of Android 15 / API 35 for new apps and updates. |
| Android App Bundle | Final build required | Package identity is `com.denuoweb.hnsdane`. A clean upload-signed audit AAB passed the structural and signer gates before the version increment; build and verify the final `0.3.13` artifact before upload. |
| 64-bit / 16 KiB native code | Ready locally | The audit bundle contains exactly `arm64-v8a` and `x86_64`; both stripped NDK r28c libraries and their matching FULL debug metadata passed 16 KiB alignment, ELF hardening, Build ID, symbol, and path-sanitization checks. |
| Restricted permissions | Ready | Manifest does not request location, contacts, SMS, call logs, camera, microphone, all-files, package visibility, or account permissions. |
| Foreground service | Not used | Sync is owned by the application while at least one app screen is started and stops when the whole app backgrounds. The manifest declares no service and requests none of `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE`, or `FOREGROUND_SERVICE_DATA_SYNC`; mark foreground-service use as not applicable and remove stale `dataSync` drafts. |
| Privacy policy | Ready | Keep `https://denuoweb.com/work/hns-dane-browser/privacy` as the canonical URL. It renders the supplied HNS DANE Browser policy through the Denuo Web site application and is accepted unchanged for this release audit. |
| Data safety form | Live reconciliation required | The current `No data collected / No data shared` posture is consistent with Google's open-web, on-device, and user-initiated-transfer exclusions. Confirm current WebView-provider Safe Browsing guidance before resubmission. |
| Ads declaration | Ready | Declare “No ads.” Donations do not unlock features. |
| Account deletion | Not applicable | The app does not create developer-operated accounts. |
| App category | Recommended: Tools or Communication | Avoid Finance classification; the app is not a wallet, exchange, lender, or financial service. |
| Target audience | Live reconciliation required | Use `18 and over` because the app is a general-purpose browser and is not child-directed; confirm the existing public listing already uses that answer. |
| Release track | Existing production app | This is an update to a public listing, not a first closed-test launch. An internal or closed track remains useful for release-candidate validation but is not the launch precondition described by the new-personal-account rule. |
| Store assets | Reconciliation required | Local icon, feature graphic, screenshots, and listing text exist in `dist/play-store/`, but they must be compared with the live listing. Recapture stale screenshots, including the diagnostic image showing an older version, after the final version increment. |

## Release Signing

Google Play requires an upload-signed Android App Bundle. Do not commit keystores or passwords.

Set these environment variables before creating a Play upload bundle:

```sh
export HNS_DANE_BROWSER_UPLOAD_STORE_FILE=/absolute/path/to/upload-keystore.jks
export HNS_DANE_BROWSER_UPLOAD_STORE_PASSWORD='...'
export HNS_DANE_BROWSER_UPLOAD_KEY_ALIAS='...'
export HNS_DANE_BROWSER_UPLOAD_KEY_PASSWORD='...'
export HNS_DANE_BROWSER_UPLOAD_CERTIFICATE_SHA256='AA:BB:...'
```

The certificate fingerprint is not secret. Obtain it from the upload keystore without putting the password on the command line:

```sh
keytool -list -v \
  -keystore "$HNS_DANE_BROWSER_UPLOAD_STORE_FILE" \
  -alias "$HNS_DANE_BROWSER_UPLOAD_KEY_ALIAS"
```

Copy the `SHA256` certificate fingerprint into `HNS_DANE_BROWSER_UPLOAD_CERTIFICATE_SHA256`; colon-separated or plain hexadecimal is accepted.

Then run:

```sh
"$HOME/APK_Workbench/scripts/dev/apkw-gradle.sh" \
  --project-dir "$HOME/path/to/handshake/Browser/android" \
  :app:verifyPlayReleaseBundle
```

`verifyPlayReleaseBundle` builds `android/app/build/outputs/bundle/release/app-release.aab`, first runs the unsigned structural gate, then reads every non-signature-metadata entry so Java cryptographically verifies its digest. It rejects an unexpected ABI/library inventory, non-16 KiB bundle or ELF alignment, malformed or weakly hardened ELF files, unstripped shipping libraries, missing/mismatched FULL debug symbols and Build IDs, local build paths, missing R8 mapping or notices, unsigned or mixed-signer content, and a signer that differs from the expected fingerprint. Regenerate third-party notices after version changes, rerun this gate, and copy the verified output to `dist/play-store/hns-dane-browser-v<release-version>-play-upload-signed.aab` before uploading.

## Google Play Developer API

The Play Developer API is optional for this update. It can automate upload and track promotion for the existing Play Console app.

To use the API:

1. Create or select a Google Cloud project.
2. Enable the Google Play Android Developer API.
3. Create a service account.
4. Link that service account in Play Console and grant the minimum release-management role needed.
5. Store the service-account JSON outside the repo; `service-account*.json` is ignored by `.gitignore`.

Closed testing upload helper:

```sh
RELEASE_VERSION='set-after-final-version-increment'
PLAY_TRACK=alpha \
  scripts/play-upload-closed-testing.sh \
  "dist/play-store/hns-dane-browser-v${RELEASE_VERSION}-play-upload-signed.aab"
```

`alpha` is the default Play API track used for the standard closed testing track. If the Play Console app uses a custom closed testing track, set `PLAY_TRACK` to that track ID from Play Console. On 2026-07-06, the local `gcloud` user token could not upload because it lacked the `https://www.googleapis.com/auth/androidpublisher` OAuth scope. Fix that by using a Play-linked service account, setting `PLAY_ACCESS_TOKEN` from a correctly scoped token, or re-authenticating gcloud with the Android Publisher scope.

## Play Console Declarations

Use these values to reconcile the existing live production listing. Re-check the current saved answers and Console UI labels before submission because Google can rename form fields without changing app behavior.

### Foreground Services

The repository candidate does not declare an Android service or request notification/foreground-service permissions. Header sync starts when the first app activity starts, publishes progress in-process across app screens, and stops when the last activity stops. In Play Console, answer that the candidate does not use foreground service types. A foreground-service declaration, notification demo, or `dataSync` reviewer note would describe a removed implementation and must not be submitted for this build.

### Data Safety Draft

Use the Play Console definitions and answer conservatively. These are repository draft answers, not proof that the existing live form is current; compare every saved Console answer before submission:

- Data collected: `No` under the current Play definitions. There are no developer-operated accounts, analytics/ads/crash-upload SDKs, or backend telemetry endpoints. Google explicitly excludes on-device-only processing and data from a WebView in which users navigate the open web.
- Data shared: `No` under the current Play definitions. Google explicitly excludes open-web WebView navigation and transfers based on a specific user-initiated action where sharing is reasonably expected. User-entered website/HNS navigation and its necessary resolution requests fit those exclusions; protocol-only background header sync does not transmit a listed user data type.
- Web browsing: do not declare URLs or browsing history solely because the browser contacts a user-selected site. Continue to disclose those network effects in the privacy policy even though Play excludes them from the Data safety form.
- Default start page: the app loads a bundled `appassets.androidplatform.net` asset with a restrictive Content Security Policy and no network resources; it does not contact a developer server. A remote homepage is loaded only after the user configures one.
- Safe Browsing: the installed Android WebView provider may check URLs through its Safe Browsing service. Confirm the provider's current Data safety guidance before submission. If it requires declaring a listed data type for this integration, update the form for that flow; do not imply that Denuo Web operates the service.
- App activity: browsing history, diagnostics, download records, settings, resolver cache, HNS sync/cache state, and cookies-adjacent WebView state are stored locally on device.
- Files/docs: user-initiated downloads are saved to public Downloads. Normal WebPKI downloads use Android DownloadManager; HNS downloads are fetched through the native gateway and saved through Android MediaStore.
- Device or other IDs: `No` unless a future SDK adds one. Current app code does not read advertising ID, IMEI, contacts, installed apps, or account identifiers.
- Encryption in transit: not applicable when the form correctly remains `No collected / No shared`. If WebView-provider guidance causes a data type to be declared, answer this question for the declared flow rather than for excluded open-web traffic.
- Data deletion: no developer-held data or app account exists to delete. Separately, users can clear cookies and WebView origin storage, history, download records, gateway diagnostics, resolver cache, or all local app data through Settings / Android system settings.

### Privacy Policy URL

Use an active, publicly accessible, non-PDF URL. Current hosted URL:

<https://denuoweb.com/work/hns-dane-browser/privacy>

On 2026-07-14 the route rendered the supplied HNS DANE Browser Privacy Policy after the site application loaded. Leave that hosted page unchanged for this release. Change the existing Play listing from its older `/hns-dane-browser/privacy/` URL to this canonical route, and keep the live Data safety answers consistent with the accepted policy and actual app behavior.

### Content Rating

Use a conservative general-purpose browser posture:

- App type/category in Play: retain or reconcile as `Tools` for the production update.
- Questionnaire category: choose the closest non-game utility/browser category offered by Play Console.
- Target audience and content: not designed for children; use `18 and over` and reconcile this with the saved live answer.
- User-generated content: the app does not host UGC or operate a social feed, but it can browse arbitrary third-party web content. Answer any unrestricted web access question as `Yes`.
- Violence, sexual content, gambling, controlled substances, hate, financial trading, medical, government, and news: `No` for app-provided content/features.
- Ads: `No ads`.
- In-app purchases: `No`; donations are external/optional and do not unlock features.

### Existing Production Listing and Test Track

The app is already public at `0.3.1` (`versionCode 22`), so closed-testing eligibility is not a first-launch gate. Use an internal or closed track when useful to validate the candidate, then promote or submit the verified update:

1. Regenerate the third-party notices and release notes after any version or dependency change.
2. Build and verify `dist/play-store/hns-dane-browser-v0.3.13-play-upload-signed.aab` with the exact release toolchain; the automated gate covers 16 KiB alignment, required ABIs, native hardening/symbols, R8 mapping, notices, and upload signing.
3. Compare the configured upload-certificate fingerprint with Play Console and complete the physical-device test pass on the final-version build.
4. Upload to an internal/closed track for validation if desired. For API upload, use the Console's actual track ID; `alpha` is the standard closed-testing API track.
5. Reconcile the live privacy policy, Data safety answers, listing copy, screenshots, and release notes, then submit the update to production.

## Store Listing Draft

The repository draft copy lives under `dist/play-store/metadata/en-US/`. Compare it field-by-field with the existing public listing before treating it as Console-ready, and regenerate release notes after the deferred version increment.

Short description, 80 characters max:

> Browse HNS names with local proofs, RFC 8484 DoH, DNSSEC, and DANE.

Full description draft:

> HNS DANE Browser is a Handshake-first browser with local HNS proofs, delegated authoritative DoH, and DNSSEC/DANE diagnostics for selected ICANN domains. It syncs Handshake headers, verifies HNS proofs, resolves delegated names, and shows clear security labels for local HNS, DANE, WebPKI, and compatibility fallback paths.
>
> Features:
> - HNS-aware omnibar for names such as `example/` and `name.tld/`
> - Local Handshake proof verification and resolver cache
> - DNSSEC and TLSA/DANE diagnostics for HTTPS HNS sites
> - Strict HNS mode to disable third-party HNS DoH fallback
> - Resolver trace, HNS proof viewer, and TLSA inspector
> - Local controls for cookies, history, downloads, and resolver cache
>
> This app is for browsing and diagnostics. It is not a wallet, exchange, financial service, or investment product. Donations are optional and do not unlock features.

## Store Asset Checklist

- App icon: 512×512 PNG for Play Console: `dist/play-store/hns-dane-browser-play-icon-512.png`.
- Feature graphic: 1024×500 PNG24, no alpha: `dist/play-store/hns-dane-browser-feature-graphic-1024x500.png`.
- Phone screenshots: compare the local set with the live listing and recapture first-run sync, a successful HNS page, resolver trace, privacy/deletion controls, and diagnostics after the final version increment. The current diagnostics screenshot visibly reports an older app version and must not ship unchanged.
- Tablet screenshots: recommended if tablet distribution remains enabled.
- Privacy policy URL: ready; point the existing Play listing to the accepted canonical route without changing the hosted page.
- Content rating questionnaire: reconcile the saved live answers as a general-purpose browser that is not child-directed.

## References

- Target API level: <https://support.google.com/googleplay/android-developer/answer/11926878>
- 64-bit native code: <https://developer.android.com/google/play/requirements/64-bit>
- 16 KiB page-size support: <https://developer.android.com/guide/practices/page-sizes>
- Native debug symbols: <https://developer.android.com/build/include-native-symbols>
- Data safety form: <https://support.google.com/googleplay/android-developer/answer/10787469>
- User data and privacy policy: <https://support.google.com/googleplay/android-developer/answer/10144311>
- Closed testing for new personal accounts: <https://support.google.com/googleplay/android-developer/answer/14151465>
- Store listing preview assets: <https://support.google.com/googleplay/android-developer/answer/9866151>
