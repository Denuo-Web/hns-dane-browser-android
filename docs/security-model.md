# Security Model

## Trust

The app verifies header chainwork, checkpoint ancestry, proof-of-work difficulty, Urkel proofs against header tree roots, DNSSEC chains below HNS delegations, TLSA records, DANE certificate or SPKI matches, and transport downgrade policy.

The default proof-backed path does not trust a single peer, external HNS resolvers, unsigned DNS answers for HNS names, TLSA answers without a valid proof chain, stale caches, or origin certificates that fail active DANE policy. Configured compatibility mode may query the selected HNS DoH resolver only after the local HNS proof/delegation path has established the root name and then failed at delegated nameserver transport/validation; those fallback answers are treated as secure only when the DNS response carries authenticated-data.

## Failure Policy

- HNS proof failure: fail closed.
- DNSSEC validation failure: fail closed.
- TLSA exists but DANE validation fails: fail closed.
- Experimental stateless DANE certificate evidence is off by default. When enabled, certificate evidence can only supply HNS TLSA policy after its Urkel proof matches a recent locally synced tree root and its direct-zone DNSSEC chain validates from the HNS-proven DS RRset. Missing certificate evidence falls back to the normal live proof/resolver path; malformed or invalid supported certificate evidence fails closed when it is used.
- Sync stale: block HNS secure state and show a sync-specific browser error.
- Sync attempts that make no progress must distinguish up-to-date peers from all-peer failure.
- Sync catch-up must continue while persisted `bestPeerHeight` or the estimated mainnet tip is greater than local `bestHeight`, regardless of whether the latest native tick accepted headers.
- HNS browser state must not show verified unless the proxy is active, the native sync status is `synced` or `up_to_date`, and the current main-frame HNS gateway response has not failed.
- Main-frame HNS gateway 4xx/5xx responses must override ready sync state and show validation failed.
- No-network sync status reads may report `up_to_date` only when stored peer heights are not ahead of a non-genesis local best header.
- Gateway exposure beyond loopback: configuration error.
- Browser-visible HNS gateway errors must identify the failing stage without exposing private request bodies.
- Gateway diagnostics must persist only bounded, sanitized stage/host/status/reason events in app-private storage; paths, query strings, request headers, and response/request bodies stay out of default logs.
- Verified HNS non-inclusion must surface as name-not-found instead of origin-address-missing.
- Proof-anchored `hnsdns=1` metadata and RFC 9461 `_dns.<nameserver>` SVCB records may add only RFC 8484 authoritative DoH transport endpoints for HNS-proven nameservers. They do not synthesize origin A/AAAA, HTTPS, or TLSA answers; malformed matching declarations fail closed, and all resulting DNS answers still validate against the HNS-proven DS.
- A whole-browser proxy target must authenticate before host classification, DNS, or dialing. ICANN forwarding accepts only canonical public IP literals or public A/AAAA addresses returned by the runtime's bounded, explicit-bootstrap, WebPKI-authenticated DoH client. NXDOMAIN, truncated, wrong-class, unrelated-owner, ambiguous CNAME, private/special address, and unsafe-port results fail before an origin socket is opened.

## Hardened WebView Profile

The Android WebView shell follows a hardened browser profile derived from Android WebView platform security guidance, OWASP MASVS/MASTG WebView controls, RFC 6454 origin semantics, and the applicable W3C web-platform security standards.

Applied WebView controls:

- JavaScript is enabled for the main browser WebView because general web compatibility requires it, but no JavaScript/native bridge is exposed to untrusted content and default bridge names are removed.
- Local file access, file-origin cross-access, universal file-origin access, and content-provider access are disabled.
- Mixed active/passive content is blocked with `WebSettings.MIXED_CONTENT_NEVER_ALLOW`.
- Safe Browsing is explicitly enabled where supported by the platform WebView.
- AndroidX WebKit feature checks gate optional WebView, Service Worker, proxy, renderer-process, WebAuthn, Safe Browsing, and speculative-loading APIs before use.
- WebView asynchronous startup is initiated from `Application.onCreate` through AndroidX WebKit so startup work can run before the first browser `WebView` is constructed.
- JavaScript pop-up windows and multiple WebView windows are disabled.
- WebView debugging is tied to `BuildConfig.DEBUG`, so production release builds do not enable WebView remote debugging.
- Main-frame navigation allows only HTTP(S) in WebView plus `about:blank`; recognized external schemes are opened through Android `ACTION_VIEW`, and unsupported schemes are blocked before they can mutate browser state.
- Service Worker interception uses the same native HNS gateway policy as normal WebView request interception, with Service Worker file/content access disabled where supported.
- Renderer hangs and renderer-process exits are handled explicitly so a bad page can be terminated or closed without crashing the whole browser process.
- Cleartext network policy is denied except for the explicit loopback gateway allowance in Android Network Security Config; the gateway binds only to randomized `127.0.0.1` ports while an HNS page needs proxy support, refuses WebView proxy override when host-scoped reverse-bypass support is unavailable, rejects non-HNS proxy traffic, enforces the active HNS host/subdomain scope, closes when the main browser activity leaves the foreground, and applies bounded active-client and HNS request admission limits.
- App asset loads should use HTTPS-style app-asset origins or native interception instead of broad `file://` access.

## Android Platform Checklist

The app follows the Android security checklist as a platform baseline:

- Manifest permissions are limited to `INTERNET` and `ACCESS_NETWORK_STATE`. The app does not request notification, foreground-service, contacts, location, SMS, camera, microphone, account, package-visibility, or broad file permissions.
- Only `LauncherActivity` is exported. The browser, settings, diagnostics, history, downloads, proof/TLSA views, and resolver trace activities are explicitly non-exported, and no Android service is declared.
- App backup and device-transfer extraction are disabled for files, databases, shared preferences, root storage, and external app data. Browser history, download records, diagnostics, resolver cache, and sync/cache state remain app-local unless the user explicitly exports or shares data.
- Normal browsing does not enable `file://` or `content://` WebView access. User-initiated downloads use Android DownloadManager into public Downloads, but the system-visible download description does not include the full URL.
- Network Security Config denies cleartext by default and allows cleartext only for the loopback gateway. The gateway binds randomized `127.0.0.1` ports only while scoped HNS proxy support is needed.
- WebView JavaScript is enabled for browser compatibility, but no `addJavascriptInterface` or `WebMessageListener` bridge is exposed to untrusted content. Allowed WebSockets remain Chromium-native and traverse the scoped Rust proxy; a document-start policy rejects cross-scope HNS targets before network admission.
- Gateway diagnostic persistence is bounded and stores sanitized stage, host, status, and reason fields only; URL paths, query strings, headers, and bodies are not persisted in default diagnostics.
- Release builds are non-debuggable, minified, resource-shrunk, and require upload-signing configuration before Play release bundle verification can pass.

## Android Privacy Checklist

The app follows the Android privacy checklist as a platform baseline:

- The app requests no dangerous runtime permissions. Sync is scoped to the application foreground, so there is no notification permission prompt or foreground-service notification.
- The app does not request location, nearby device, camera, microphone, contacts, SMS, call log, account, advertising ID, all-files storage, or package-visibility permissions.
- The app does not use background location, location foreground services, device serial numbers, IMEI, SSAID, Advertising ID, or an app-generated cross-install tracking identifier.
- External storage use is limited to user-initiated downloads through Android DownloadManager into public Downloads; app metadata stays in private shared preferences or app-private files and is excluded from backup and device transfer.
- Sensitive app-to-app sharing uses explicit user actions such as Android share/copy flows or DownloadManager. Sync snapshots stay in-process and internal diagnostic activities are non-exported.
- Production Logcat output avoids browsing URLs, user-entered content, request/response bodies, and resolver secrets; default persisted diagnostics remain bounded and sanitized.
- The Google Play Data safety and privacy policy drafts disclose local browsing data, user-initiated downloads, HNS peer/DNS/web requests, optional compatibility DoH, and local deletion controls.

## iOS WebKit Profile

The iOS shell uses one persistent identified `WKWebsiteDataStore` with one authenticated HTTP CONNECT proxy configuration. `allowFailover` is false and the match/exclusion lists are empty, so ordinary ICANN and HNS WebKit traffic share the Rust admission boundary. An absent, stopped, or rejecting proxy is an error; Swift has no route that clears the profile to direct networking.

- Main-frame classification and HNS-root extraction come from Rust. Crossing between ICANN and HNS or between HNS roots revokes the current WebView, credentials, status, and certificate authority before the old proxy is stopped and joined; only then is a fresh immutable generation installed.
- Subframes and subresources do not rotate or widen the admitted HNS scope. An out-of-scope HNS request is rejected inside Rust before HNS resolution or any origin dial.
- ICANN HTTPS remains an opaque CONNECT tunnel after explicit-address resolution, leaving server WebPKI validation to WebKit. ICANN HTTP and WebSocket Upgrade use the bounded Rust forwarder. HNS HTTPS CONNECT terminates only in Rust and reaches the shared HNS/DNSSEC/DANE backend.
- Swift may answer proxy authentication only for the exact live proxy handle, endpoint, and realm. It may accept the expected local HNS server-trust challenge only after Rust separately confirms the exact live generation, canonical host, and complete leaf certificate DER. ICANN trust challenges use WebKit's default handling.
- Proxy credentials, certificate state, trace data, and Rust-owned buffers are memory-only and bounded. Lifecycle revocation becomes visible before any blocking worker join.
- Swift contains no independent HNS resolver, socket transport, HTTP proxy parser, DANE validator, certificate generator, or TLS terminator.
- The committed privacy manifest declares the platform reason APIs used for preferences and file timestamps. Optional physical-device traffic/challenge testing remains unverified.

## Review Checklist

- Parsers are bounded and return structured errors.
- Parser fuzz smoke targets cover DNS messages/names/SVCB, HNS resource values, P2P frames/payloads, Urkel proofs, TLSA records, and X.509 SPKI extraction.
- P2P frames reject wrong network magic and payloads above the 8 MB HSD message limit.
- P2P sockets must use bounded frame decoding, connection timeouts, and session-state checks before accepting headers or proofs.
- Header sync must not request additional headers from a peer whose advertised height is not ahead of the local best header.
- Android first-run header sync should use active polling and high-batch native runs while behind, then fall back to idle polling only after stored peer heights are not ahead.
- Transient peer failures must not permanently exhaust the outbound peer pool; malformed consensus data is still scored and cooldown-banned.
- Peer-gossip addresses are advisory only; addr packets are bounded, deduplicated, service-filtered, and still subject to outbound peer scoring before any header or proof data is accepted.
- Version packets use HSD's 88-byte network address format rather than Bitcoin's shorter address encoding.
- Version/verack ordering is accepted in either HSD-observed order before the session enters ready state.
- Advisory or unknown P2P packets are ignored while waiting for required sync packets; they do not advance header/proof state.
- Duplicate headers in peer batches are ignored as idempotent sync input; full duplicate-only pages stop the bounded multi-batch loop so a stale peer cannot spin the sync runner, while invalid difficulty bits, invalid proof-of-work, and unknown-parent headers still fail closed.
- No panics on malformed network data.
- No unbounded memory growth from attacker-controlled lengths.
- No Urkel proof request key should be derived from a name that fails Handshake TLD validation.
- No Urkel proof should be accepted unless its BLAKE2b-256 path recomputes the expected tree root for the requested name hash.
- No verified Urkel value should be exposed as resolver records unless its HSD resource payload decodes within bounded type and record limits.
- No HSD Urkel inclusion value should be cached as resolver data until its serialized `NameState` name matches the requested root and only its bounded `data` field is extracted.
- No TCP proof response should be stored for resolver use unless it matches a tracked getproof request and passes Urkel verification.
- No cached verified resource value should be served unless its root label and name hash match the resolver request.
- No chain-anchored cached verified resource value should be served unless its proof tree root and height match the current local best header; sync ticks prune values that are unanchored or not anchored to that current tip.
- No persisted verified resource value should be stored or returned unless its root label and name hash are normalized and matched.
- No proven HNS answer should be returned if the proof name hash or root name mismatches the request.
- No verified HNS non-inclusion should be treated as an existing name with an empty record set.
- No HNS origin connect address should be selected from NS glue or another owner name unless that owner is reached through a DNSSEC-validated CNAME chain from the requested origin owner.
- No HNS origin connect address should be inferred from GLUE, SYNTH, `hnsdns=1`, or DNS-server SVCB data. These records only bootstrap nameserver transport; origin A/AAAA selection still requires DNSSEC-secure delegated answers.
- No HNS origin request that starts from root delegation records should be treated as complete until a secure delegated A/AAAA lookup has been attempted.
- No dotted HNS host should be routed to Chromium DNS when its final label is treated as an HNS root by browser policy.
- No out-of-zone HNS nameserver address should be used unless it comes from a separate verified HNS root proof for that nameserver owner.
- No HNS gateway request should fall back to origin-host system DNS when secure resolution produces no A/AAAA connect address.
- No reserved non-HNS single-label name should be routed into the HNS proxy path or shown as HNS browser state.
- No DNS leak for HNS names.
- No DNSSEC delegation should be treated as secure unless at least one DS digest matches a child DNSKEY.
- No HTTPS/SVCB ALPN or service-port binding should be honored unless the binding is parsed, in service mode, owner-scoped, and limited to supported mandatory keys.
- No address-only HNS answer should skip a separate secure HTTPS/SVCB lookup before TLSA service-owner selection.
- No unsupported DS digest type should be treated as a secure delegation match.
- No RRSIG should be evaluated against non-canonical RRset bytes or outside its validity window.
- No RRset should be treated as DNSSEC-secure unless the delegation link and a covering RRSIG both validate.
- No delegated HNS DNS answer should be treated as secure unless it comes from HNS-proven nameserver glue or synth addresses and validates against the HNS-proven DS RRset.
- No authoritative DoH endpoint should be used unless its declaration identifies an HNS-proven NS address and the endpoint uses RFC 8484 HTTPS transport with DNS wire messages. A distinct SVCB/URI target name is authenticated by WebPKI while the connection remains pinned to HNS-proven glue.
- No delegated NXDOMAIN response should be treated as malformed solely because its RCODE is NXDOMAIN; it must either validate as secure NSEC/NSEC3 name-error denial or fail closed.
- No empty delegated HNS DNS answer should be treated as secure unless an NSEC or NSEC3 no-data proof validates under the delegated zone DNSKEY.
- No delegated CNAME chain should be followed outside the HNS-proven delegated zone or beyond the bounded CNAME-chain limit.
- No child referral below a delegated HNS zone should be followed as secure unless the HNS-proven parent DS validates the parent DNSKEY, the child DS RRset validates under that parent DNSKEY, and the child answer validates under a DS-matched self-signed child DNSKEY.
- No empty child-zone answer below a delegated HNS zone should be treated as secure unless the parent DNSKEY chain, child DS RRset, child DNSKEY RRset, and child NSEC/NSEC3 no-data proof all validate.
- No DNSSEC signature should depend on mixed-case RDATA owner names or signer names.
- No SVCB/HTTPS RRset should be signed or trusted using compressed or non-canonical TargetName bytes.
- No delegated child DNSKEY RRset should be trusted unless its DS RRset is signed by the parent and the child DNSKEY RRset is self-signed.
- No unsupported DNSSEC signature algorithm should be treated as validated.
- No malformed DNSSEC public key should be treated as validated.
- No malformed ECDSA or Ed25519 DNSSEC public key or signature should be treated as validated.
- No HTTPS/SVCB ALPN value should cause the gateway to select an origin protocol that the configured transport does not support; if SVCB disables default ALPN and no supported protocol remains, fail closed.
- No NSEC denial proof should be accepted unless the NSEC RRset signature validates first.
- No NSEC name error should be accepted unless the queried name is covered and the applicable wildcard under the closest encloser is also denied.
- No NSEC3 denial proof should be accepted unless every participating NSEC3 RRset signature validates first.
- No NSEC3 name error should be accepted unless the closest encloser matches, the next closer is covered, and the applicable wildcard is also denied.
- No NSEC3 opt-out proof should set a secure-denial outcome; it is surfaced only as an insecure-delegation outcome.
- No NSEC3 hash algorithm other than SHA-1 should be accepted until a safe transition mechanism is implemented.
- No TLSA downgrade without an explicit policy event.
- No TLSA record should influence HTTPS trust unless its exact `_port._tcp.host` resolver result is DNSSEC-secure.
- No HNS-strict HTTPS connection should proceed without a DNSSEC-secure TLSA match.
- No HNS compatibility-mode HTTPS connection should be labeled as DANE verified when it used WebPKI fallback; the Android toolbar must show the explicit mixed `HNS + WebPKI` state.
- No HNS DoH compatibility fallback answer should be treated as secure unless the response matches the query tuple and carries the DNS authenticated-data bit.
- No page resolved through the HNS DoH compatibility fallback should be labeled as plain local `DANE verified` or `HNS verified`; the toolbar must show an explicit `via DoH` compatibility state.
- No unbounded or panic-prone X.509 parsing for DANE SPKI selector matching.
- No QUIC downgrade without an explicit policy event.
- No local gateway listener beyond loopback and no fixed browser proxy port in normal app startup. Android must not apply a broad proxy when WebView cannot scope it to the active HNS host; iOS intentionally proxies the whole data store and therefore must not enable failover or any direct WebKit route. Neither platform keeps a browser proxy listener after its owning foreground browser lifecycle is revoked.
- No dotted host under the vendored IANA root-zone TLD snapshot should be routed into HNS resolution; normal ICANN destinations such as `discord.gg` must stay on the WebView/ICANN path.
- No origin fetch unless the gateway resolution name matches the requested origin host.
- No intercepted HNS redirect should be followed unless the target has the same scheme, host, and effective port and the redirect chain stays under the configured bound.
- No main-frame HNS gateway 4xx/5xx response should leave the toolbar in verified state.
- No local gateway request flood should create unbounded worker tasks, HNS resolution calls, or per-host limiter state; excess requests fail closed with `429 Too Many Requests`.
- No gateway diagnostic event should persist URL paths, query strings, request headers, request bodies, or response bodies; the app-private event store remains bounded to recent sanitized failures.
- No HNS origin connect attempt should use origin-host system DNS when secure resolution has not produced an explicit connect address.
- No insecure resolver result when gateway secure-resolution mode is enabled.
- No proxy request body should be forwarded or dropped unless HTTP/1.1 framing is unambiguous and supported.
- No origin HTTP response body should be accepted unless HTTP/1.1 framing is unambiguous and supported.
- No whole-browser ICANN request should invoke system hostname resolution, connect to an address not returned by the explicit runtime address boundary, follow an invalid/ambiguous DoH CNAME chain, accept a non-IN answer, or dial a private/special address or unsafe port.
- No decoded chunked origin response should be exposed to WebView with stale `Transfer-Encoding` or mismatched `Content-Length` framing; native gateway file-backed bodies are returned with fixed decoded lengths.
- No WebView SSL error should call `proceed()` unless the requested URL is an HNS HTTPS URL and the presented certificate's full DER bytes match the exact host and currently published Rust proxy generation.
- No HNS WebSocket or HTTP Upgrade request should be silently downgraded to a normal GET by stripping hop-by-hop Upgrade headers; these requests must enter the native stream tunnel after HNS resolution, HTTPS/SVCB policy, and DANE validation, and fail closed if the native tunnel path is unavailable or validation fails.
- No WebView JavaScript/native bridge should be exposed to untrusted web content; browser UI/native operations must remain outside page script reachability.
- No WebView `file://` or `content://` access should be enabled for normal browsing; app assets must use safe app-asset origins or native response interception.
- No main-frame non-HTTP(S) URL should be passed through to WebView except `about:blank`; external schemes require explicit Android intent handling and unsupported schemes are blocked.
- No mixed-content downgrade should be allowed inside the WebView.
- No production build should enable WebView debugging.
- Browser proxy listeners bind randomized `127.0.0.1` ports only while their owning browser lifecycle is active. Android applies an exact HNS reverse-bypass scope and rejects non-HNS proxy traffic. iOS applies a no-failover whole-data-store proxy: the optional immutable HNS scope reaches the native persistent-runtime gateway and all other HNS roots fail closed, while ICANN traffic can use only the explicit public-address forward path. Both modes enforce authentication, bounded concurrency/framing, header sanitization, streamed responses, exact live certificate authorization, and joined teardown.
