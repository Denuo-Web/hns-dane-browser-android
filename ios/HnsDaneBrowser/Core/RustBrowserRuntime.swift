import Foundation
import HnsBrowserRuntime

private enum RustBridgeError: LocalizedError {
    case incompatibleABI(actual: UInt32)
    case callFailed(operation: String, code: UInt32, detail: String)
    case invalidOutput(String)

    var errorDescription: String? {
        switch self {
        case .incompatibleABI(let actual):
            return "Rust ABI version \(actual) is incompatible with this app."
        case .callFailed(let operation, let code, let detail):
            return "\(operation) failed (\(code)): \(detail)"
        case .invalidOutput(let detail):
            return "The Rust bridge returned invalid output: \(detail)"
        }
    }
}

final class RustBrowserRuntime: BrowserRuntime {
    private let handleLock = NSLock()
    private var runtimeHandle: HnsBrowserRuntimeHandle

    init(_ dataDirectory: String) throws {
        let actualABI = hns_browser_abi_version()
        guard actualABI == HNS_BROWSER_ABI_VERSION else {
            throw RustBridgeError.incompatibleABI(actual: actualABI)
        }

        var options = HnsBrowserRuntimeOptions()
        try RustBridge.check(
            hns_browser_runtime_options_default(&options),
            operation: "runtime options"
        )
        var handle: HnsBrowserRuntimeHandle = 0
        let result = RustBridge.withUTF8Slice(dataDirectory) { dataDirectorySlice in
            options.data_dir = dataDirectorySlice
            options.network = HNS_BROWSER_NETWORK_MAINNET
            options.resolution_mode = HNS_BROWSER_RESOLUTION_COMPATIBILITY
            return hns_browser_runtime_create(&options, &handle)
        }
        try RustBridge.check(result, operation: "runtime create")
        guard handle != 0 else {
            throw RustBridgeError.invalidOutput("runtime handle is zero")
        }
        runtimeHandle = handle
    }

    func classifyNavigation(_ rawValue: String) throws -> BrowserDestination {
        try BrowserNavigationParser(
            canonicalizeHost: rustCanonicalHost,
            classifyCanonicalHost: classifyName,
            hnsRootForCanonicalHost: hnsRoot
        ).parse(rawValue)
    }

    func classifyHost(_ host: String) -> BrowserHostKind {
        guard let canonical = try? rustCanonicalHost(host) else { return .search }
        return (try? classifyName(canonical)) ?? .search
    }

    func canonicalHost(_ host: String) -> String? {
        try? rustCanonicalHost(host)
    }

    func startWholeWebKitProxy(hnsScopeRoot: String?) throws -> BrowserProxySession {
        let handle = try liveHandle()
        var proxyHandle: HnsBrowserProxyHandle = 0
        let result: HnsBrowserResult
        if let hnsScopeRoot {
            result = RustBridge.withUTF8Slice(hnsScopeRoot) { scope in
                hns_browser_proxy_start(handle, scope, &proxyHandle)
            }
        } else {
            result = hns_browser_proxy_start(
                handle,
                HnsBrowserSlice(ptr: nil, len: 0),
                &proxyHandle
            )
        }
        try RustBridge.check(result, operation: "proxy start")
        guard proxyHandle != 0 else {
            throw RustBridgeError.invalidOutput("proxy handle is zero")
        }

        do {
            return try RustBrowserProxySession(handle: proxyHandle)
        } catch {
            _ = hns_browser_proxy_request_stop(proxyHandle)
            _ = hns_browser_proxy_destroy(proxyHandle)
            throw error
        }
    }

    func installHeaderSnapshot(at path: String) throws {
        let handle = try liveHandle()
        var output = HnsBrowserBuffer()
        let result = RustBridge.withUTF8Slice(path) { pathSlice in
            hns_browser_runtime_install_header_snapshot(handle, pathSlice, &output)
        }
        defer { RustBridge.free(output) }
        try RustBridge.check(result, operation: "header snapshot install")
        _ = try RustBridge.data(copying: output)
    }

    @discardableResult
    func updatePolicy(_ policy: BrowserRuntimePolicy) throws -> UInt64 {
        let handle = try liveHandle()
        var nativePolicy = HnsBrowserPolicy()
        try RustBridge.check(
            hns_browser_policy_default(&nativePolicy),
            operation: "policy defaults"
        )
        switch policy.resolutionMode {
        case .compatibility:
            nativePolicy.resolution_mode = HNS_BROWSER_RESOLUTION_COMPATIBILITY
        case .strict:
            nativePolicy.resolution_mode = HNS_BROWSER_RESOLUTION_STRICT
        }
        nativePolicy.stateless_dane_certificates = policy.statelessDANECertificates ? 1 : 0

        var revision: UInt64 = 0
        let result: HnsBrowserResult
        if let endpoint = policy.hnsDohResolver {
            result = RustBridge.withUTF8Slice(endpoint) { endpointSlice in
                nativePolicy.hns_doh_resolver = endpointSlice
                return hns_browser_runtime_set_policy(handle, &nativePolicy, &revision)
            }
        } else {
            result = hns_browser_runtime_set_policy(handle, &nativePolicy, &revision)
        }
        try RustBridge.check(result, operation: "runtime policy update")
        guard revision != 0 else {
            throw RustBridgeError.invalidOutput("policy revision is zero")
        }
        return revision
    }

    func syncOnce() throws -> BrowserSyncSummary {
        let object = try runtimeJSONObject(operation: "header sync") { handle, output in
            hns_browser_runtime_sync_once(handle, output)
        }
        return try Self.syncSummary(from: object)
    }

    func syncSummary() -> BrowserSyncSummary {
        guard let object = try? runtimeJSONObject(operation: "sync status", invoke: {
            handle, output in
            hns_browser_runtime_sync_status(handle, output)
        }) else { return .unavailable }
        return (try? Self.syncSummary(from: object)) ?? .unavailable
    }

    func clearResolverCache() throws -> BrowserSyncSummary {
        let object = try runtimeJSONObject(operation: "resolver cache clear") { handle, output in
            hns_browser_runtime_clear_resolver_cache(handle, output)
        }
        return try Self.syncSummary(from: object)
    }

    func proofDetails(for hostOrURL: String) throws -> BrowserProofDetails {
        let object = try RustBridge.withUTF8Slice(hostOrURL) { input in
            try runtimeJSONObject(operation: "proof details") { handle, output in
                hns_browser_runtime_proof_details(handle, input, output)
            }
        }
        return try Self.proofDetails(from: object, fallbackHost: hostOrURL)
    }

    static func proofDetails(
        from object: [String: Any],
        fallbackHost: String
    ) throws -> BrowserProofDetails {
        let formattedData = try JSONSerialization.data(
            withJSONObject: object,
            options: [.prettyPrinted, .sortedKeys]
        )
        guard let formattedJSON = String(data: formattedData, encoding: .utf8) else {
            throw RustBridgeError.invalidOutput("proof details are not UTF-8")
        }

        let host = Self.string(in: object, key: "host") ?? fallbackHost
        let proofStatus = Self.string(in: object, key: "proofStatus") ?? "unknown"
        let hnsProof = Self.string(in: object, key: "hnsProof") ?? proofStatus
        let cacheStatus = Self.string(in: object, key: "cacheStatus") ?? "unknown"
        let error = Self.string(in: object, key: "error")
        let headline: String
        switch proofStatus {
        case "verified": headline = "Handshake proof verified"
        case "not_found": headline = "Handshake name not found"
        case "unavailable": headline = "Handshake proof unavailable"
        case "failed", "error", "invalid_resource": headline = "Handshake proof failed"
        default: headline = "Handshake proof \(proofStatus.replacingOccurrences(of: "_", with: " "))"
        }
        var detailParts = [host, "cache \(cacheStatus.replacingOccurrences(of: "_", with: " "))"]
        if let error { detailParts.append(error) }

        return BrowserProofDetails(
            headline: headline,
            detail: detailParts.joined(separator: " · "),
            host: host,
            name: Self.string(in: object, key: "name"),
            network: Self.string(in: object, key: "network"),
            nameHash: Self.string(in: object, key: "nameHash"),
            hnsProof: hnsProof,
            proofStatus: proofStatus,
            secure: (object["secure"] as? NSNumber)?.boolValue,
            exists: (object["exists"] as? NSNumber)?.boolValue,
            treeRoot: Self.string(in: object, key: "treeRoot"),
            blockHeight: (object["blockHeight"] as? NSNumber)?.uint64Value,
            cacheStatus: cacheStatus,
            recordTypes: object["recordTypes"] as? [String] ?? [],
            error: error,
            formattedJSON: formattedJSON
        )
    }

    func close() {
        handleLock.lock()
        let handle = runtimeHandle
        runtimeHandle = 0
        handleLock.unlock()
        if handle != 0 {
            _ = hns_browser_runtime_destroy(handle)
        }
    }

    deinit {
        close()
    }

    private func classifyName(_ input: String) throws -> BrowserHostKind {
        var nameClass: HnsBrowserNameClass = HNS_BROWSER_NAME_SEARCH
        let result = RustBridge.withUTF8Slice(input) { slice in
            hns_browser_classify_name(slice, &nameClass)
        }
        try RustBridge.check(result, operation: "name classification")
        switch nameClass {
        case HNS_BROWSER_NAME_HNS: return .handshake
        case HNS_BROWSER_NAME_ICANN: return .icann
        case HNS_BROWSER_NAME_SEARCH: return .search
        default: throw RustBridgeError.invalidOutput("unknown name class \(nameClass)")
        }
    }

    private func hnsRoot(_ host: String) throws -> String {
        var output = HnsBrowserBuffer()
        let result = RustBridge.withUTF8Slice(host) { slice in
            hns_browser_hns_root(slice, &output)
        }
        defer { RustBridge.free(output) }
        try RustBridge.check(result, operation: "HNS root derivation")
        return try RustBridge.string(copying: output)
    }

    private func rustCanonicalHost(_ host: String) throws -> String {
        var output = HnsBrowserBuffer()
        let result = RustBridge.withUTF8Slice(host) { slice in
            hns_browser_canonical_host(slice, &output)
        }
        defer { RustBridge.free(output) }
        try RustBridge.check(result, operation: "host canonicalization")
        return try RustBridge.string(copying: output)
    }

    private func liveHandle() throws -> HnsBrowserRuntimeHandle {
        guard let handle = currentHandle() else {
            throw BrowserCoreError.runtimeUnavailable("runtime handle is closed")
        }
        return handle
    }

    private func currentHandle() -> HnsBrowserRuntimeHandle? {
        handleLock.lock()
        defer { handleLock.unlock() }
        return runtimeHandle == 0 ? nil : runtimeHandle
    }

    private func runtimeJSONObject(
        operation: String,
        invoke: (HnsBrowserRuntimeHandle, UnsafeMutablePointer<HnsBrowserBuffer>) -> HnsBrowserResult
    ) throws -> [String: Any] {
        let handle = try liveHandle()
        var output = HnsBrowserBuffer()
        let result = withUnsafeMutablePointer(to: &output) { outputPointer in
            invoke(handle, outputPointer)
        }
        defer { RustBridge.free(output) }
        try RustBridge.check(result, operation: operation)
        let data = try RustBridge.data(copying: output)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RustBridgeError.invalidOutput("\(operation) did not return a JSON object")
        }
        return object
    }

    static func syncSummary(from object: [String: Any]) throws -> BrowserSyncSummary {
        guard let status = string(in: object, key: "status"), !status.isEmpty else {
            throw RustBridgeError.invalidOutput("sync status is missing")
        }
        let error = string(in: object, key: "error")
        let bestHeight = (object["bestHeight"] as? NSNumber)?.uint64Value
        let peerHeight = (object["bestPeerHeight"] as? NSNumber)?.uint64Value
        let estimatedTipHeight = (object["estimatedTipHeight"] as? NSNumber)?.uint64Value
        let attempted = (object["attempted"] as? NSNumber)?.intValue ?? 0
        let successful = (object["successful"] as? NSNumber)?.intValue ?? 0
        let accepted = (object["accepted"] as? NSNumber)?.intValue ?? 0
        let failed = (object["failed"] as? NSNumber)?.intValue ?? 0
        let cacheEntries = (object["resourceCacheEntries"] as? NSNumber)?.intValue ?? 0
        let cacheBytes = (object["resourceCacheBytes"] as? NSNumber)?.uint64Value ?? 0
        let cacheEvicted = (object["resourceCacheEvicted"] as? NSNumber)?.intValue ?? 0

        let headline: String
        switch status {
        case "up_to_date": headline = "Handshake headers current"
        case "syncing": headline = "Syncing Handshake headers"
        case "cleared": headline = "Resolver cache cleared"
        case "idle": headline = "Handshake sync idle"
        case "error", "peer_failed", "seed_failed": headline = "Header sync needs attention"
        default: headline = "Handshake sync \(status.replacingOccurrences(of: "_", with: " "))"
        }

        let detail: String
        if let error {
            detail = error
        } else if status == "cleared" {
            detail = "The runtime resolver cache now contains \(cacheEntries) entries."
        } else {
            let best = bestHeight.map(String.init) ?? "unknown"
            let peer = peerHeight.map(String.init) ?? "unknown"
            detail = "Local height \(best) · peer height \(peer) · accepted \(accepted)/\(attempted)"
        }

        return BrowserSyncSummary(
            headline: headline,
            detail: detail,
            status: status,
            network: string(in: object, key: "network"),
            attempted: attempted,
            successful: successful,
            accepted: accepted,
            failed: failed,
            peerCount: (object["peerCount"] as? NSNumber)?.intValue ?? 0,
            peerGroups: (object["peerGroups"] as? NSNumber)?.intValue ?? 0,
            bestHeight: bestHeight,
            bestPeerHeight: peerHeight,
            estimatedTipHeight: estimatedTipHeight,
            resourceCacheEntries: cacheEntries,
            resourceCacheBytes: cacheBytes,
            resourceCacheEvicted: cacheEvicted,
            error: error
        )
    }

    private static func string(in object: [String: Any], key: String) -> String? {
        guard let value = object[key] as? String, !value.isEmpty else { return nil }
        return value
    }

}

private final class RustBrowserProxySession: BrowserProxySession {
    let endpoint: BrowserProxyEndpoint

    private let handleLock = NSLock()
    private var proxyHandle: HnsBrowserProxyHandle
    private let generation: UInt64
    private let sessionID: String

    init(handle: HnsBrowserProxyHandle) throws {
        var nativeEndpoint = HnsBrowserProxyEndpoint()
        let result = hns_browser_proxy_endpoint(handle, &nativeEndpoint)
        defer {
            RustBridge.free(nativeEndpoint.session_id)
            RustBridge.free(nativeEndpoint.realm)
            RustBridge.free(nativeEndpoint.username)
            RustBridge.free(nativeEndpoint.password)
        }
        try RustBridge.check(result, operation: "proxy endpoint")

        let sessionID = try RustBridge.string(copying: nativeEndpoint.session_id)
        let realm = try RustBridge.string(copying: nativeEndpoint.realm)
        let username = try RustBridge.string(copying: nativeEndpoint.username)
        let password = try RustBridge.string(copying: nativeEndpoint.password)
        guard nativeEndpoint.port != 0,
              nativeEndpoint.generation != 0,
              !sessionID.isEmpty,
              !realm.isEmpty,
              !username.isEmpty,
              !password.isEmpty else {
            throw RustBridgeError.invalidOutput("proxy endpoint is incomplete")
        }

        proxyHandle = handle
        generation = nativeEndpoint.generation
        self.sessionID = sessionID
        endpoint = BrowserProxyEndpoint(
            host: "127.0.0.1",
            port: nativeEndpoint.port,
            realm: realm,
            username: username,
            password: password
        )
    }

    func requestStop() {
        guard let handle = currentHandle() else { return }
        _ = hns_browser_proxy_request_stop(handle)
    }

    func joinAndDestroy() {
        handleLock.lock()
        let handle = proxyHandle
        proxyHandle = 0
        handleLock.unlock()
        if handle != 0 {
            _ = hns_browser_proxy_destroy(handle)
        }
    }

    func acceptsProxyChallenge(
        host: String,
        port: Int,
        realm: String?,
        authenticationMethod: String
    ) -> Bool {
        guard authenticationMethod == NSURLAuthenticationMethodHTTPBasic,
              let handle = currentHandle(),
              let port = UInt16(exactly: port),
              let realm,
              !realm.isEmpty else {
            return false
        }
        var matches: UInt8 = 0
        let result = RustBridge.withUTF8Slice(host) { hostSlice in
            RustBridge.withUTF8Slice(realm) { realmSlice in
                hns_browser_proxy_matches_authentication_challenge(
                    handle,
                    hostSlice,
                    port,
                    realmSlice,
                    &matches
                )
            }
        }
        return result == HNS_BROWSER_RESULT_OK && matches == 1
    }

    func matchesLocalCertificate(host: String, leafCertificateDER: Data) -> Bool {
        guard let handle = currentHandle(), !leafCertificateDER.isEmpty else { return false }
        var matches: UInt8 = 0
        let result = RustBridge.withUTF8Slice(host) { hostSlice in
            RustBridge.withDataSlice(leafCertificateDER) { certificateSlice in
                hns_browser_proxy_matches_local_certificate(
                    handle,
                    hostSlice,
                    certificateSlice,
                    &matches
                )
            }
        }
        return result == HNS_BROWSER_RESULT_OK && matches == 1
    }

    func takeMainFrameSecurityStatus(host: String) -> BrowserSecuritySummary? {
        guard let handle = currentHandle() else { return nil }
        var status = HnsBrowserProxyStatus()
        let result = RustBridge.withUTF8Slice(host) { hostSlice in
            hns_browser_proxy_take_main_frame_status(handle, hostSlice, &status)
        }
        defer {
            RustBridge.free(status.host)
            RustBridge.free(status.resolution_trace_json)
        }
        guard result == HNS_BROWSER_RESULT_OK,
              status.generation == generation,
              let returnedHost = try? RustBridge.string(copying: status.host),
              returnedHost == host else {
            return nil
        }

        if status.http_status >= 400 {
            return BrowserSecuritySummary(
                level: .blocked,
                detail: "The Rust proxy rejected the HNS response"
            )
        }
        if status.tls_policy == HNS_BROWSER_TLS_POLICY_UNKNOWN,
           status.security_path != HNS_BROWSER_SECURITY_PATH_UNKNOWN {
            return BrowserSecuritySummary(
                level: .insecure,
                detail: "Rust HNS resolution · \(Self.securityPathLabel(status.security_path)) · plain HTTP"
            )
        }
        if status.tls_policy == HNS_BROWSER_TLS_POLICY_DANE {
            return BrowserSecuritySummary(
                level: .handshakeDANE,
                detail: "DANE verified · \(Self.securityPathLabel(status.security_path))"
            )
        }
        if status.tls_policy == HNS_BROWSER_TLS_POLICY_WEBPKI_FALLBACK {
            return BrowserSecuritySummary(
                level: .handshakeFallback,
                detail: "HNS resolved · system WebPKI fallback"
            )
        }
        return BrowserSecuritySummary(
            level: .blocked,
            detail: "Unknown HNS transport policy"
        )
    }

    deinit {
        handleLock.lock()
        let handle = proxyHandle
        proxyHandle = 0
        handleLock.unlock()
        guard handle != 0 else { return }
        _ = hns_browser_proxy_request_stop(handle)
        DispatchQueue.global(qos: .utility).async {
            _ = hns_browser_proxy_destroy(handle)
        }
    }

    private func currentHandle() -> HnsBrowserProxyHandle? {
        handleLock.lock()
        defer { handleLock.unlock() }
        return proxyHandle == 0 ? nil : proxyHandle
    }

    private static func securityPathLabel(_ path: HnsBrowserSecurityPath) -> String {
        switch path {
        case HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DOH:
            return "authoritative DoH"
        case HNS_BROWSER_SECURITY_PATH_DANE_AUTHORITATIVE_DNS53:
            return "authoritative DNS"
        case HNS_BROWSER_SECURITY_PATH_DANE_THIRD_PARTY_DOH:
            return "configured DoH"
        case HNS_BROWSER_SECURITY_PATH_STATELESS_DANE:
            return "stateless DANE"
        case HNS_BROWSER_SECURITY_PATH_DANE_ICANN_DOH:
            return "ICANN DoH"
        case HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DOH:
            return "HNS authoritative DoH"
        case HNS_BROWSER_SECURITY_PATH_HNS_AUTHORITATIVE_DNS53:
            return "HNS authoritative DNS"
        case HNS_BROWSER_SECURITY_PATH_HNS_THIRD_PARTY_DOH:
            return "HNS configured DoH"
        default:
            return "verified Rust path"
        }
    }
}

private enum RustBridge {
    static func withUTF8Slice<T>(
        _ value: String,
        body: (HnsBrowserSlice) throws -> T
    ) rethrows -> T {
        let bytes = Array(value.utf8)
        return try bytes.withUnsafeBufferPointer { buffer in
            try body(
                HnsBrowserSlice(
                    ptr: buffer.baseAddress,
                    len: UInt64(buffer.count)
                )
            )
        }
    }

    static func withDataSlice<T>(_ value: Data, body: (HnsBrowserSlice) -> T) -> T {
        value.withUnsafeBytes { bytes in
            body(
                HnsBrowserSlice(
                    ptr: bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    len: UInt64(bytes.count)
                )
            )
        }
    }

    static func data(copying buffer: HnsBrowserBuffer) throws -> Data {
        guard buffer.len <= UInt64(Int.max) else {
            throw RustBridgeError.invalidOutput("buffer length is unsupported")
        }
        if buffer.len == 0 {
            guard buffer.ptr == nil, buffer.allocation_id == 0 else {
                throw RustBridgeError.invalidOutput("empty buffer token is malformed")
            }
            return Data()
        }
        guard let pointer = buffer.ptr, buffer.allocation_id != 0 else {
            throw RustBridgeError.invalidOutput("nonempty buffer is malformed")
        }
        return Data(bytes: pointer, count: Int(buffer.len))
    }

    static func string(copying buffer: HnsBrowserBuffer) throws -> String {
        let data = try data(copying: buffer)
        guard let value = String(data: data, encoding: .utf8) else {
            throw RustBridgeError.invalidOutput("buffer is not UTF-8")
        }
        return value
    }

    static func free(_ buffer: HnsBrowserBuffer) {
        _ = hns_browser_buffer_free(buffer)
    }

    static func check(_ result: HnsBrowserResult, operation: String) throws {
        guard result != HNS_BROWSER_RESULT_OK else { return }
        var errorBuffer = HnsBrowserBuffer()
        let errorResult = hns_browser_last_error(&errorBuffer)
        defer { free(errorBuffer) }
        let detail: String
        if errorResult == HNS_BROWSER_RESULT_OK,
           let message = try? string(copying: errorBuffer),
           !message.isEmpty {
            detail = message
        } else {
            detail = "no native error detail"
        }
        throw RustBridgeError.callFailed(
            operation: operation,
            code: result,
            detail: detail
        )
    }
}
