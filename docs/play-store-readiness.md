# Google Play Readiness Checklist

Last audited: 2026-07-06

This checklist maps HNS DANE Browser to current Google Play release requirements and identifies the Play Console fields that must be completed outside the repository.

## Current Repo Status

| Area | Status | Evidence / Action |
| --- | --- | --- |
| Target API level | Ready | `targetSdk = 37`, above the current Google Play requirement of Android 15 / API 35 for new apps and updates. |
| Android App Bundle | Rebuild required | Package identity changed to `com.denuoweb.hnsdane`; create a new upload AAB such as `dist/play-store/hns-dane-browser-v0.3.0-play-upload-signed.aab`. |
| 64-bit native code | Ready | Release bundle includes `arm64-v8a` and `x86_64` `libhns_dane_browser_ffi.so`; no 32-bit ABI is shipped. |
| Restricted permissions | Ready | Manifest does not request location, contacts, SMS, call logs, camera, microphone, all-files, package visibility, or account permissions. |
| Foreground service | Play Console declaration required | App uses `dataSync` foreground service for visible HNS header/proof sync. Complete the Foreground service declaration and provide a short demo video. |
| Privacy policy | Ready after website sync | Use `https://denuoweb.com/work/hns-dane-browser/privacy`; host the static HTML copy before Play submission and keep it mirrored in-app. |
| Data safety form | Draft below | No ads/analytics/accounts. Disclose local browsing data and network sharing needed for browser/HNS function. |
| Ads declaration | Ready | Declare “No ads.” Donations do not unlock features. |
| Account deletion | Not applicable | The app does not create developer-operated accounts. |
| App category | Recommended: Tools or Communication | Avoid Finance classification; the app is not a wallet, exchange, lender, or financial service. |
| Target audience | Recommended: 13+ or 18+ | General-purpose browser can access arbitrary third-party web content; not designed for children. |
| Testing track | Console/API action | New personal Play accounts may need a closed test with at least 12 opted-in testers for 14 continuous days before production access. Use the closed testing track, not internal testing, when satisfying this requirement. |
| Store assets | Partially ready | Play icon and feature graphic are in `dist/play-store/`; screenshots and content rating questionnaire still need Console work. |

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

`verifyPlayReleaseBundle` builds `android/app/build/outputs/bundle/release/app-release.aab`, verifies that upload signing is configured, verifies the bundle has a jar signature, and checks required 64-bit native libraries. Copy the verified output to a new `dist/play-store/hns-dane-browser-...` artifact before uploading.

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
  dist/play-store/hns-dane-browser-v0.3.0-play-upload-signed.aab
```

`alpha` is the default Play API track used for the standard closed testing track. If the Play Console app uses a custom closed testing track, set `PLAY_TRACK` to that track ID from Play Console. On 2026-06-29, the local `gcloud` user token could not upload because it lacked the `https://www.googleapis.com/auth/androidpublisher` OAuth scope. Fix that by using a Play-linked service account, setting `PLAY_ACCESS_TOKEN` from a correctly scoped token, or re-authenticating gcloud with the Android Publisher scope.

## Play Console Declarations

### Foreground Service Declaration

Type: `dataSync`

Suggested feature description:

> HNS DANE Browser uses a visible foreground data sync service to keep Handshake block headers, peer state, and proof cache data current while the user is using the browser. This enables local HNS proof verification and reduces resolver failures during browsing.

Suggested user impact if deferred/interrupted:

> If sync is deferred or interrupted, HNS names may fail closed or use stale local proof data until the app can catch up. The browser remains usable for normal WebPKI sites, but HNS verification quality is reduced.

Suggested demo video content:

1. Launch HNS DANE Browser.
2. Show the sync notification and main-page sync progress.
3. Open Diagnostics and show `bestHeight`, `bestPeerHeight`, and sync status.
4. Stop/restart sync from the visible notification or app flow if needed.

### Data Safety Draft

Use the Play Console definitions and answer conservatively. Suggested basis for the current app:

- Data collected by developer: No developer-operated analytics, ads, or account data collection.
- Data shared with third parties: Yes, for app functionality, because user-requested browsing and HNS resolution send requests to websites, HNS peers, DNS seeds, authoritative DNS servers, and optional HNS DoH fallback.
- Data types to review for disclosure:
  - Web browsing: URLs/hostnames and website interaction data sent to user-selected sites and resolver infrastructure.
  - App activity: browsing history and diagnostics stored locally on device.
  - Files/docs: downloads initiated by the user through Android DownloadManager.
  - Device or other IDs: avoid declaring unless a dependency or WebView behavior requires it; no app code currently reads advertising ID, IMEI, contacts, or installed apps.
- Encryption in transit: Yes for HTTPS/DoH paths; user-selected cleartext HTTP sites are possible and should be described in the privacy policy.
- Data deletion: Users can clear cookies, history, download records, resolver cache, or all app data through Android settings.

### Privacy Policy URL

Use an active, publicly accessible, non-PDF URL. Current hosted URL:

<https://denuoweb.com/work/hns-dane-browser/privacy>

This route should be deployed from the Denuo Web site checkout at `web/public/work/hns-dane-browser/privacy/index.html` so it is readable without JavaScript. Keep the website policy, app copy, and repo copy synchronized when the app behavior changes.

## Store Listing Draft

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
- Phone screenshots: capture first run sync, HNS directory, a successful HNS page, resolver trace, Settings privacy controls.
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
