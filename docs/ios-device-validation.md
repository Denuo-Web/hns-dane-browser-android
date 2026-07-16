# iOS Device Validation

The iOS shell has an iOS 17.0 deployment floor, retaining support for the iOS 17 and iOS 18 generations. That minimum supported runtime is independent of the build SDK: Apple builds use the stable iOS 26.5 SDK with Xcode 26.5 or 26.6.

The Rust and C boundaries can be validated on Linux. The Apple slices, Swift shell, and unit tests can then be compiled and exercised in a macOS simulator gate. An optional signed physical-device pass can add evidence about WebKit's out-of-process networking that simulator success cannot provide; it has not been completed.

## macOS Build and Simulator Gate

Run with the repository-pinned Rust toolchain, Xcode 26.5 or 26.6, and the iOS 26.5 device and simulator SDKs selected:

```sh
./scripts/check.sh
./scripts/build-rust-ios.sh
./scripts/build-ios.sh
```

The gate must produce device arm64 and universal arm64/x86_64 simulator slices, create `HnsBrowserRuntime.xcframework`, compile the C header smoke test, link the iOS application and test target without undefined FFI symbols, and execute the unit tests on an iPhone simulator. Completion establishes build, linkage, and simulator behavior only; it is not evidence that the signed physical-device matrix passed.

## Signed Physical Device Gate — Pending

No physical-device pass is currently claimed. If a device or external TestFlight tester becomes available, use a signed build on iOS 17.0 or later and capture device traffic from a controlled Wi-Fi network while running the optional matrix.

### Proxy isolation

- Confirm the WebKit profile has one authenticated proxy configuration, `allowFailover` is false, and both domain lists are empty.
- Confirm ordinary ICANN HTTPS uses an opaque Rust CONNECT tunnel and retains WebKit WebPKI.
- Confirm ordinary ICANN HTTP uses Rust's bounded direct forwarder.
- Confirm the active HNS root and its subdomains use Rust HNS resolution, DNSSEC, DANE, and local CONNECT termination.
- Confirm another HNS root, malformed host, special-use name, loopback/private/link-local address, and browser-blocked port fail before any system resolver or outbound socket is called.
- Confirm an absent, stopped, or authentication-rejecting loopback proxy never causes WebKit to connect directly.
- Confirm no HNS DNS, HTTP/3, QUIC, or fallback traffic leaves the device outside the Rust-selected transports.
- Confirm proxy credentials never appear in origin request headers, logs, diagnostic JSON, or crash reports.

### Certificate challenges

For each case below, record that WebKit delivered the server-trust challenge, the Swift shell extracted the full leaf DER, and Rust authorized only the exact host and live proxy generation:

- main-frame HNS HTTPS;
- CSS, image, script, iframe, XHR, and `fetch` subresources;
- a new subdomain that requires a separate generated local certificate;
- Service Worker install, activation, controlled fetch, and fetch after rotation;
- `wss://` and HTTP Upgrade;
- same-origin and rejected cross-scope redirects;
- back-forward cache restoration;
- renderer and WebKit network-process restart.

Presenting an unrelated certificate, another host's certificate, or a stopped generation must be canceled. ICANN trust challenges must remain under WebKit's default handling.

### Lifecycle and ownership

- Background the app during a main-frame load, subresource load, WebSocket, Service Worker fetch, and download.
- Verify the visible WebView is disabled first, proxy credentials and certificate authorization are revoked immediately, and all Rust listener/client workers join off the main thread.
- Resume and confirm a fresh generation, credentials, port, proxy configuration, and WebView are created before navigation restarts.
- Terminate the renderer/network process and verify the same fail-closed rebuild.
- Confirm stale delegate callbacks cannot authorize, publish status, navigate, or clear a newer generation.
- Confirm cookies and profile data persist across safe WebView reconstruction without sharing proxy ownership across multiple scenes.

### Browser behavior

- Repeat the Android parity cases for GET, POST, uploads, range requests, redirects, cookies, JavaScript fetch/XHR, Service Workers, WebSockets, downloads, HTTP/1.1, HTTP/2, HTTP/3 origin transport, IPv4, and IPv6.
- Exercise `https://denuoweb/` for authoritative DoH and `https://aboutlife/` for the compatibility resolver path; compare security labels and bounded traces with Android.
- Verify strict mode, compatibility mode, configured HNS DoH, stateless DANE, sync progress, cache clearing, proof details, download handoff, sharing, accessibility labels, and Dynamic Type.

## Apple References

- https://developer.apple.com/documentation/network/proxyconfiguration
- https://developer.apple.com/documentation/webkit/wkwebsitedatastore/proxyconfigurations-cdc1
- https://developer.apple.com/documentation/webkit/wknavigationdelegate/webview%28_%3Adidreceive%3Acompletionhandler%3A%29
- https://developer.apple.com/documentation/security/sectrustcopycertificatechain%28_%3A%29
- https://developer.apple.com/documentation/uikit/managing-your-app-s-life-cycle
- https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle
