import Foundation

enum BrowserCoreError: LocalizedError, Equatable {
    case runtimeUnavailable(String)
    case invalidAddress(String)
    case unsupportedAddress
    case proxyStartFailed(String)
    case invalidProxyEndpoint

    var errorDescription: String? {
        switch self {
        case .runtimeUnavailable(let message):
            return "The Handshake runtime is unavailable: \(message)"
        case .invalidAddress(let message):
            return message
        case .unsupportedAddress:
            return "Only HTTP and HTTPS addresses can be opened."
        case .proxyStartFailed(let message):
            return "The secure browser proxy could not start: \(message)"
        case .invalidProxyEndpoint:
            return "The secure browser proxy returned an invalid loopback endpoint."
        }
    }
}

enum BrowserHostKind: Equatable, Sendable {
    case handshake
    case icann
    case search
}

enum BrowserProxyScope: Equatable, Sendable {
    case icann
    case handshakeRoot(String)
}

struct BrowserDestination: Equatable, Sendable {
    let url: URL
    let canonicalHost: String
    let hostKind: BrowserHostKind
    let proxyScope: BrowserProxyScope

    var isHandshake: Bool { hostKind == .handshake }
}

struct BrowserProxyEndpoint: Equatable, Sendable {
    let host: String
    let port: UInt16
    let realm: String
    let username: String
    let password: String

    var isNumericIPv4Loopback: Bool { host == "127.0.0.1" }
}

enum BrowserSecurityLevel: Equatable, Sendable {
    case pending
    case webPKI
    case insecure
    case handshakeDANE
    case handshakeFallback
    case blocked
}

enum MainFrameAdmissionDecision: Equatable {
    case allow
    case rotateProxy
    case blockNonIdempotentReplay
}

struct MainFrameAdmissionPolicy {
    func evaluate(
        activeScope: BrowserProxyScope?,
        destinationScope: BrowserProxyScope,
        httpMethod: String
    ) -> MainFrameAdmissionDecision {
        if activeScope == destinationScope { return .allow }
        let method = httpMethod.uppercased()
        return (method == "GET" || method == "HEAD")
            ? .rotateProxy
            : .blockNonIdempotentReplay
    }
}

struct NavigationReplayPolicy {
    func allowsAutomaticReplay(httpMethod: String?) -> Bool {
        let method = httpMethod?.uppercased() ?? "GET"
        return method == "GET" || method == "HEAD"
    }
}

struct BrowserSecuritySummary: Equatable, Sendable {
    let level: BrowserSecurityLevel
    let detail: String

    static let pending = BrowserSecuritySummary(
        level: .pending,
        detail: "Waiting for a verified response"
    )
}

struct BrowserSyncSummary: Equatable, Sendable {
    let headline: String
    let detail: String
    let status: String
    let network: String?
    let attempted: Int
    let successful: Int
    let accepted: Int
    let failed: Int
    let peerCount: Int
    let peerGroups: Int
    let bestHeight: UInt64?
    let bestPeerHeight: UInt64?
    let estimatedTipHeight: UInt64?
    let resourceCacheEntries: Int
    let resourceCacheBytes: UInt64
    let resourceCacheEvicted: Int
    let error: String?

    init(
        headline: String,
        detail: String,
        status: String = "unavailable",
        network: String? = nil,
        attempted: Int = 0,
        successful: Int = 0,
        accepted: Int = 0,
        failed: Int = 0,
        peerCount: Int = 0,
        peerGroups: Int = 0,
        bestHeight: UInt64? = nil,
        bestPeerHeight: UInt64? = nil,
        estimatedTipHeight: UInt64? = nil,
        resourceCacheEntries: Int = 0,
        resourceCacheBytes: UInt64 = 0,
        resourceCacheEvicted: Int = 0,
        error: String? = nil
    ) {
        self.headline = headline
        self.detail = detail
        self.status = status
        self.network = network
        self.attempted = attempted
        self.successful = successful
        self.accepted = accepted
        self.failed = failed
        self.peerCount = peerCount
        self.peerGroups = peerGroups
        self.bestHeight = bestHeight
        self.bestPeerHeight = bestPeerHeight
        self.estimatedTipHeight = estimatedTipHeight
        self.resourceCacheEntries = resourceCacheEntries
        self.resourceCacheBytes = resourceCacheBytes
        self.resourceCacheEvicted = resourceCacheEvicted
        self.error = error
    }

    var requiresRetry: Bool {
        error != nil || ["error", "peer_failed", "seed_failed"].contains(status)
    }

    var isCaughtUp: Bool { status == "up_to_date" }

    static let unavailable = BrowserSyncSummary(
        headline: "Sync unavailable",
        detail: "The Handshake runtime did not return sync status."
    )

    static func failure(_ error: Error) -> BrowserSyncSummary {
        BrowserSyncSummary(
            headline: "Header sync needs attention",
            detail: error.localizedDescription,
            status: "error",
            error: error.localizedDescription
        )
    }
}

struct BrowserProofDetails: Equatable, Sendable {
    let headline: String
    let detail: String
    let host: String
    let name: String?
    let network: String?
    let nameHash: String?
    let hnsProof: String
    let proofStatus: String
    let secure: Bool?
    let exists: Bool?
    let treeRoot: String?
    let blockHeight: UInt64?
    let cacheStatus: String
    let recordTypes: [String]
    let error: String?
    let formattedJSON: String
}

protocol BrowserProxySession: AnyObject {
    var endpoint: BrowserProxyEndpoint { get }

    /// Must be nonblocking and safe to call repeatedly from the main actor.
    func requestStop()

    /// Blocks until the listener and connection workers exit, then releases the native handle.
    func joinAndDestroy()

    func acceptsProxyChallenge(
        host: String,
        port: Int,
        realm: String?,
        authenticationMethod: String
    ) -> Bool

    func matchesLocalCertificate(host: String, leafCertificateDER: Data) -> Bool

    func takeMainFrameSecurityStatus(host: String) -> BrowserSecuritySummary?
}

protocol BrowserRuntime: AnyObject {
    /// Parses user input or an absolute WebKit URL and classifies its host in the Rust policy.
    func classifyNavigation(_ rawValue: String) throws -> BrowserDestination

    /// Classifies a protection-space host in Rust without a duplicated platform TLD list.
    func classifyHost(_ host: String) -> BrowserHostKind

    func canonicalHost(_ host: String) -> String?

    /// Starts a whole-WebKit proxy. This can block and must run off the main actor.
    func startWholeWebKitProxy(hnsScopeRoot: String?) throws -> BrowserProxySession

    /// Imports the bounded, uncompressed mainnet bootstrap snapshot at a private file path.
    func installHeaderSnapshot(at path: String) throws

    /// Publishes a live resolver policy. Native code revokes every older proxy generation.
    @discardableResult
    func updatePolicy(_ policy: BrowserRuntimePolicy) throws -> UInt64

    func syncOnce() throws -> BrowserSyncSummary

    func syncSummary() -> BrowserSyncSummary

    func clearResolverCache() throws -> BrowserSyncSummary

    func proofDetails(for hostOrURL: String) throws -> BrowserProofDetails

    func close()
}
