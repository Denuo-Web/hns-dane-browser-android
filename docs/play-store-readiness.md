# Google Play Readiness Checklist

Last audited: 2026-07-07

This checklist maps HNS DANE Browser to current Google Play release requirements and identifies the Play Console fields that must be completed outside the repository.

## Current Repo Status

| Area | Status | Evidence / Action |
| --- | --- | --- |
| Target API level | Ready | `targetSdk = 37`, above the current Google Play requirement of Android 15 / API 35 for new apps and updates. |
| Android App Bundle | Rebuild required | Package identity is `com.denuoweb.hnsdane`; create a new upload AAB such as `dist/play-store/hns-dane-browser-v0.3.7-play-upload-signed.aab`. |
| 64-bit native code | Gate ready | `verifyPlayReleaseBundle` checks `arm64-v8a` and `x86_64` `libhns_dane_browser_ffi.so`; no 32-bit ABI is shipped. |
| Restricted permissions | Ready | Manifest does not request location, contacts, SMS, call logs, camera, microphone, all-files, package visibility, or account permissions. |
| Foreground service | Console copy ready | App uses `dataSync` foreground service for visible HNS header/proof sync. Use the declaration text and demo script below. |
| Privacy policy | Console URL ready | Use `https://denuoweb.com/work/hns-dane-browser/privacy`; verify the hosted static HTML page is live immediately before Play submission. |
| Data safety form | Console copy ready | No ads/analytics/accounts. Disclose user-requested browsing/HNS network sharing and local browsing/download records. |
| Ads declaration | Ready | Declare “No ads.” Donations do not unlock features. |
| Account deletion | Not applicable | The app does not create developer-operated accounts. |
| App category | Recommended: Tools or Communication | Avoid Finance classification; the app is not a wallet, exchange, lender, or financial service. |
| Target audience | Console answer ready | Use `18 and over` for the first production request because the app is a general-purpose browser and is not child-directed. |
| Testing track | Console/API action ready | Use the standard closed testing track (`alpha` API track) unless Play Console shows a custom closed track. New personal Play accounts may need 12 opted-in testers for 14 continuous days before production access. |
| Store assets | Mostly ready | Play icon, feature graphic, phone screenshots, and listing text are in `dist/play-store/`; use the content rating answers below. |

## Release Signing

Google Play requires an upload-signed Android App Bundle. Do not commit keystores or passwords.

Set these environment variables before creating a Play upload bundle:

```sh
export HNS_DANE_BROWSER_UPLOAD_STORE_FILE=/absolute/path/to/upload-keystore.jks
export HNS_DANE_BROWSER_UPLOAD_STORE_PASSWORD='...'
export HNS_DANE_BROWSER_UPLOAD_KEY_ALIAS='...'
export HNS_DANE_BROWSER_UPLOAD_KEY_PASSWORD='...'
```

Then run:

```sh
"$HOME/APK_Workbench/scripts/dev/apkw-gradle.sh" \
  --project-dir "$HOME/path/to/handshake/Browser/android" \
  :app:verifyPlayReleaseBundle
```

`verifyPlayReleaseBundle` builds `android/app/build/outputs/bundle/release/app-release.aab`, verifies that upload signing is configured, verifies the bundle has a jar signature, and checks required 64-bit native libraries. Copy the verified output to `dist/play-store/hns-dane-browser-v0.3.7-play-upload-signed.aab` before uploading.

## Google Play Developer API

The Play Developer API is optional for launch. It is useful for automating upload and track promotion after a Play Console app exists.

Do not create a Google Cloud project solely for this repo until the Play Console app is created. To use the API later:

1. Create or select a Google Cloud project.
2. Enable the Google Play Android Developer API.
3. Create a service account.
4. Link that service account in Play Console and grant the minimum release-management role needed.
5. Store the service-account JSON outside the repo; `service-account*.json` is ignored by `.gitignore`.

Closed testing upload helper:

```sh
PLAY_TRACK=alpha \
  scripts/play-upload-closed-testing.sh \
  dist/play-store/hns-dane-browser-v0.3.7-play-upload-signed.aab
```

`alpha` is the default Play API track used for the standard closed testing track. If the Play Console app uses a custom closed testing track, set `PLAY_TRACK` to that track ID from Play Console. On 2026-07-06, the local `gcloud` user token could not upload because it lacked the `https://www.googleapis.com/auth/androidpublisher` OAuth scope. Fix that by using a Play-linked service account, setting `PLAY_ACCESS_TOKEN` from a correctly scoped token, or re-authenticating gcloud with the Android Publisher scope.

## Play Console Declarations

Use these exact values for the first production-track readiness pass. Re-check the Console UI labels before submission because Google can rename form fields without changing app behavior.

### Foreground Service Declaration

Type: `dataSync`

Use case: `Network transfer: Upload or download` or the closest available `dataSync` network-transfer option.

Suggested feature description:

> HNS DANE Browser uses a visible foreground data sync service to keep Handshake block headers, peer state, and proof cache data current while the user is using the browser. This enables local HNS proof verification and reduces resolver failures during browsing.

Suggested user impact if deferred/interrupted:

> If sync is deferred or interrupted, HNS names may fail closed or use stale local proof data until the app can catch up. The browser remains usable for normal WebPKI sites, but HNS verification quality is reduced.

Suggested demo video content:

1. Launch HNS DANE Browser.
2. Show the sync notification and main-page sync progress.
3. Open Diagnostics and show `bestHeight`, `bestPeerHeight`, and sync status.
4. Stop/restart sync from the visible notification or app flow if needed.

Reviewer note:

> The foreground service starts only while the browser is in use so HNS headers, peer state, and proof cache state stay current for local HNS resolution. The notification is visible and includes a stop action.

### Data Safety Draft

Use the Play Console definitions and answer conservatively:

- Data collected by developer: `No`. There are no developer-operated accounts, analytics SDKs, ads SDKs, crash upload SDKs, or backend telemetry endpoints in app code.
- Data shared with third parties: `Yes`, only for app functionality. User-requested browsing and HNS resolution send requests to websites, HNS peers, DNS seeds, authoritative DNS servers, RFC 9461-discovered authoritative DoH endpoints, and the optional compatibility HNS DoH resolver after local/direct resolution fails.
- Web browsing: disclose URLs/hostnames and website interaction data as shared for app functionality. Do not mark as developer-collected unless Play's current wording treats user-requested browser traffic as collection.
- App activity: browsing history, diagnostics, download records, settings, resolver cache, HNS sync/cache state, and cookies-adjacent WebView state are stored locally on device.
- Files/docs: user-initiated downloads are saved to public Downloads. Normal WebPKI downloads use Android DownloadManager; HNS downloads are fetched through the native gateway and saved through Android MediaStore.
- Device or other IDs: `No` unless a future SDK adds one. Current app code does not read advertising ID, IMEI, contacts, installed apps, or account identifiers.
- Encryption in transit: `Yes` for HTTPS, DoH, and DANE-validated HNS HTTPS paths. User-selected cleartext HTTP sites remain possible browser functionality and are disclosed in the privacy policy.
- Data deletion: Users can clear cookies, history, download records, resolver cache, or all app data through Settings / Android system settings.

### Privacy Policy URL

Use an active, publicly accessible, non-PDF URL. Current hosted URL:

<https://denuoweb.com/work/hns-dane-browser/privacy>

This route should be deployed from the Denuo Web site checkout at `web/public/work/hns-dane-browser/privacy/index.html` so it is readable without JavaScript. Keep the website policy, app copy, and repo copy synchronized when the app behavior changes.

### Content Rating

Use a conservative general-purpose browser posture:

- App type/category in Play: `Tools` for the first submission.
- Questionnaire category: choose the closest non-game utility/browser category offered by Play Console.
- Target audience and content: not designed for children; choose `18 and over` for the first production request.
- User-generated content: the app does not host UGC or operate a social feed, but it can browse arbitrary third-party web content. Answer any unrestricted web access question as `Yes`.
- Violence, sexual content, gambling, controlled substances, hate, financial trading, medical, government, and news: `No` for app-provided content/features.
- Ads: `No ads`.
- In-app purchases: `No`; donations are external/optional and do not unlock features.

### Closed Testing Track

Use this sequence when the Play Console app record exists:

1. Build and verify `dist/play-store/hns-dane-browser-v0.3.7-play-upload-signed.aab`.
2. Upload to the standard closed testing track. For API upload, use `PLAY_TRACK=alpha` unless the Console app has a custom closed testing track ID.
3. Add at least 12 opted-in testers if the account is subject to the personal-account production-access rule.
4. Keep closed testing active for 14 continuous days before requesting production access.
5. Use tester feedback to verify first-run sync, HNS browsing, HNS downloads, notification-denied behavior, and Diagnostics export.

## Store Listing Draft

The Play Console-ready copy lives under `dist/play-store/metadata/en-US/`.

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
- Phone screenshots: capture first run sync, the Denuo Web HNS homepage, a successful HNS page, resolver trace, Settings privacy controls.
- Tablet screenshots: recommended if tablet distribution remains enabled.
- Privacy policy URL: required.
- Content rating questionnaire: answer as a general-purpose browser, not child-directed.

## References

- Target API level: <https://support.google.com/googleplay/android-developer/answer/11926878>
- 64-bit native code: <https://developer.android.com/google/play/requirements/64-bit>
- Data safety form: <https://support.google.com/googleplay/android-developer/answer/10787469>
- User data and privacy policy: <https://support.google.com/googleplay/android-developer/answer/17105854>
- Foreground service declarations: <https://support.google.com/googleplay/android-developer/answer/13392821>
- Closed testing for new personal accounts: <https://support.google.com/googleplay/android-developer/answer/14151465>
- Store listing preview assets: <https://support.google.com/googleplay/android-developer/answer/9866151>
