# HNS DANE Browser Privacy Policy

Last updated: 2026-07-06

HNS DANE Browser is published by Denuo Web, LLC. For privacy questions or deletion requests, use the project issue tracker at <https://github.com/Denuo-Web/hns-dane-browser-android/issues> or the contact method listed by the developer in Google Play Console.

## Summary

HNS DANE Browser is a Handshake-first browser for local HNS proofs, RFC 8484 DoH transport, DNSSEC, and DANE diagnostics. The app does not include advertising SDKs, analytics SDKs, developer-operated accounts, or paid feature unlocks. Donations are optional and do not unlock app functionality.

The app stores browser data locally on the device and sends network requests needed to load sites and keep HNS resolution data current.

## Data Stored Locally

The app may store the following data on the device:

- Browsing history: page URLs, page titles, and visit times.
- Website data: cookies and other WebView-managed site storage.
- Download records: URL, file name, MIME type, Android DownloadManager ID, and queued time for downloads started by the browser.
- HNS data: synced headers, peer records, verified resource values, resolver cache, and resolver diagnostics.
- Settings: homepage, cookie preference, Strict HNS mode, and related app preferences.

This local data is used only to provide browser functionality, diagnostics, and HNS resolution. It is not sold. It is not sent to a Denuo Web analytics or advertising service.

## Network Requests

To provide browser functionality, HNS DANE Browser may connect to:

- Websites and web services that you choose to open.
- Handshake peers and DNS seed hosts for header sync, peer discovery, and proof retrieval.
- Authoritative DNS nameservers for delegated HNS names.
- RFC 9461-discovered RFC 8484 authoritative DoH endpoints for delegated HNS names when direct DNS transport is unavailable or invalid.
- The configured HNS DNS-over-HTTPS compatibility resolver when compatibility mode is enabled and local or direct delegated resolution fails.
- Android DownloadManager destinations when you choose to download a file.

These network endpoints may receive technical information that is normal for network communication, such as your IP address, the requested host or URL, protocol metadata, and any data you submit to websites. Strict HNS mode disables the third-party HNS DNS-over-HTTPS compatibility fallback.

HTTPS, DNSSEC, and DANE are used where applicable. If you intentionally open a cleartext `http://` site, that site connection is not encrypted by HTTPS.

## Cookies and Website Data

Websites may set cookies or use WebView storage. HNS DANE Browser provides Settings controls to block third-party cookies and delete cookies. Websites are responsible for their own privacy practices.

## Data Sharing

Denuo Web does not sell personal or sensitive user data. HNS DANE Browser shares data only as necessary for user-requested browser functionality, such as loading a website, syncing HNS data, resolving a name, or downloading a file.

## Retention and Deletion

Local browser data remains on the device until you clear it or uninstall the app. The app provides Settings controls for clearing cookies, browsing history, download records, and the HNS resolver cache. Android system settings can also clear all app storage.

HNS DANE Browser does not create developer-operated user accounts, so there is no app account deletion flow.

## Children

HNS DANE Browser is not directed to children. Because it is a general-purpose browser, websites opened by users may contain third-party content outside Denuo Web's control.

## Changes

This policy may be updated as the app changes. Material privacy changes should be reflected in this file, the in-app privacy text, and the Google Play Data safety form.
