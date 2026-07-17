# HNS DANE Browser Privacy Policy

Last updated: 2026-07-16

HNS DANE Browser is published by Denuo Web, LLC. For privacy questions or deletion requests, email <info@denuoweb.com> or use the contact method listed by the developer in Google Play Console. Do not post personal information to the public project issue tracker.

## Summary

HNS DANE Browser is a Handshake-first browser for local HNS proofs, authoritative DNS, an HNS P2P DNS relay, RFC 8484 DoH transport, DNSSEC, and DANE diagnostics. The app does not include advertising SDKs, analytics SDKs, developer-operated accounts, or paid feature unlocks. Donations are optional and do not unlock app functionality.

The app stores browser data locally on the device and sends network requests needed to load sites and keep HNS resolution data current.

## Data Stored Locally

The app may store the following data on the device:

- Browsing history: page URLs, page titles, and visit times.
- Website data: cookies and other WebView-managed site storage.
- Download records: URL, file name, MIME type, Android DownloadManager ID, and queued time for downloads started by the browser.
- HNS data: synced headers, peer records (including manually added relay-peer IP endpoints), verified resource values, resolver cache, and resolver diagnostics.
- Settings: homepage, cookie preference, HNS P2P DNS relay and legacy DoH fallback preferences, Strict HNS mode, and related app preferences.

This local data is used only to provide browser functionality, diagnostics, and HNS resolution. It is not sold. It is not sent to a Denuo Web analytics or advertising service.

## Network Requests

To provide browser functionality, HNS DANE Browser may connect to:

- Websites and web services that you choose to open.
- Handshake peers and DNS seed hosts for header sync, peer discovery, and proof retrieval.
- Relay-capable Handshake peers for recursive HNS DNS queries after local proof validation and authoritative DNS attempts fail. Android new installs enable this path by default. A manual relay peer must be entered as an IP-literal endpoint and is stored only after its live HSD handshake advertises the relay capability.
- Authoritative DNS nameservers for delegated HNS names.
- Proof-bootstrapped or RFC 9461-discovered RFC 8484 authoritative DoH endpoints for delegated HNS names.
- Safe Browsing services exposed by the installed Android WebView provider. The provider may check URLs and apply its own privacy policy when Safe Browsing is supported; HNS DANE Browser does not operate that service.
- The non-routable `192.0.2.1` TEST-NET DNS sentinel after delegated DNS failure; a matching reply confirms transparent outbound port 53 interception, while no reply is reported only as not detected.
- The configured HNS DNS-over-HTTPS compatibility resolver when compatibility mode is enabled and local or direct delegated resolution fails.
- Android DownloadManager destinations when you choose to download a file.

These network endpoints may receive technical information that is normal for network communication, such as your IP address, the requested host or URL, protocol metadata, and any data you submit to websites. In particular, an HNS relay peer can observe the queried DNS name and record type together with your P2P connection and network address. An ordinary Handshake TCP connection is not query-confidential; encrypted peer transport should be preferred where available. The relay response is still validated locally through the app's Handshake proof, DNSSEC, TLSA, and DANE checks, and the peer's DNS authenticated-data bit is not trusted.

The legacy third-party HNS DNS-over-HTTPS compatibility fallback is independently enabled by default on Android new installs and remains available after the P2P relay path fails. Strict HNS mode disables that third-party fallback. Both relay and legacy fallback controls can be changed in Settings.

HTTPS, DNSSEC, and DANE are used where applicable. If you intentionally open a cleartext `http://` site, that site connection is not encrypted by HTTPS.

## Cookies and Website Data

Websites may set cookies or use WebView storage. HNS DANE Browser provides Settings controls to block third-party cookies and delete cookies plus WebView origin storage. Websites are responsible for their own privacy practices.

## Data Sharing

Denuo Web does not sell personal or sensitive user data. HNS DANE Browser shares data only as necessary for user-requested browser functionality, such as loading a website, syncing HNS data, resolving a name, or downloading a file.

## Retention and Deletion

Local browser data remains on the device until you clear it or uninstall the app. The app provides Settings controls for clearing cookies and WebView origin storage, browsing history, download records, gateway diagnostics, and the HNS resolver cache. Android system settings can also clear all app storage.

HNS DANE Browser does not create developer-operated user accounts, so there is no app account deletion flow.

## Children

HNS DANE Browser is not directed to children. Because it is a general-purpose browser, websites opened by users may contain third-party content outside Denuo Web's control.

## Changes

This policy may be updated as the app changes. Material privacy changes should be reflected in this file, the in-app privacy text, and the Google Play Data safety form.
