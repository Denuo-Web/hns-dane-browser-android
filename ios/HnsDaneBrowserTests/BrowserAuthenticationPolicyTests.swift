import Foundation
import XCTest
@testable import HnsDaneBrowser

final class BrowserAuthenticationPolicyTests: XCTestCase {
    private let policy = BrowserAuthenticationPolicy()

    func testIcannTrustAlwaysUsesWebKitDefault() {
        let runtime = FakeRuntime(hostKind: .icann)
        let context = BrowserAuthenticationContext(
            kind: .serverTrust(leafCertificateDER: Data([1, 2, 3])),
            host: "example.com",
            port: 443,
            realm: nil
        )

        XCTAssertEqual(
            policy.evaluate(context, runtime: runtime, liveProxy: nil, activeScope: nil),
            .performDefaultHandling
        )
    }

    func testExactHnsLeafUsesLiveGenerationTrust() {
        let runtime = FakeRuntime(hostKind: .handshake)
        let proxy = FakeProxy()
        proxy.certificateMatches = true
        let context = BrowserAuthenticationContext(
            kind: .serverTrust(leafCertificateDER: Data([1, 2, 3])),
            host: "nathan.woodburn",
            port: 443,
            realm: nil
        )

        XCTAssertEqual(
            policy.evaluate(
                context,
                runtime: runtime,
                liveProxy: proxy,
                activeScope: .handshakeRoot("woodburn")
            ),
            .useServerTrust
        )
    }

    func testMismatchedHnsLeafCancels() {
        let runtime = FakeRuntime(hostKind: .handshake)
        let proxy = FakeProxy()
        let context = BrowserAuthenticationContext(
            kind: .serverTrust(leafCertificateDER: Data([9])),
            host: "nathan.woodburn",
            port: 443,
            realm: nil
        )

        XCTAssertEqual(
            policy.evaluate(
                context,
                runtime: runtime,
                liveProxy: proxy,
                activeScope: .handshakeRoot("woodburn")
            ),
            .cancel
        )
    }

    func testProxyCredentialRequiresExactNativeChallenge() {
        let runtime = FakeRuntime(hostKind: .icann)
        let proxy = FakeProxy()
        proxy.authenticationMatches = true
        let context = BrowserAuthenticationContext(
            kind: .proxy(authenticationMethod: NSURLAuthenticationMethodHTTPBasic),
            host: "127.0.0.1",
            port: 47_123,
            realm: "hns-browser"
        )

        XCTAssertEqual(
            policy.evaluate(
                context,
                runtime: runtime,
                liveProxy: proxy,
                activeScope: .icann
            ),
            .useProxyCredential(username: "user", password: "password")
        )
    }

    func testOriginAuthenticationNeverReceivesProxyCredential() {
        let runtime = FakeRuntime(hostKind: .handshake)
        let proxy = FakeProxy()
        proxy.authenticationMatches = true
        let context = BrowserAuthenticationContext(
            kind: .origin(authenticationMethod: NSURLAuthenticationMethodHTTPBasic),
            host: "nathan.woodburn",
            port: 443,
            realm: "origin"
        )

        XCTAssertEqual(
            policy.evaluate(
                context,
                runtime: runtime,
                liveProxy: proxy,
                activeScope: .handshakeRoot("woodburn")
            ),
            .performDefaultHandling
        )
    }
}

final class FakeRuntime: BrowserRuntime {
    var hostKind: BrowserHostKind
    var installedSnapshotPath: String?
    var runtimePolicy = BrowserRuntimePolicy.default

    init(hostKind: BrowserHostKind) {
        self.hostKind = hostKind
    }

    func classifyNavigation(_ rawValue: String) throws -> BrowserDestination {
        throw BrowserCoreError.invalidAddress("unused fake")
    }

    func classifyHost(_ host: String) -> BrowserHostKind { hostKind }

    func canonicalHost(_ host: String) -> String? { host.lowercased() }

    func startWholeWebKitProxy(hnsScopeRoot: String?) throws -> BrowserProxySession {
        FakeProxy()
    }

    func installHeaderSnapshot(at path: String) throws {
        installedSnapshotPath = path
    }

    func updatePolicy(_ policy: BrowserRuntimePolicy) throws -> UInt64 {
        runtimePolicy = policy
        return 1
    }

    func syncOnce() throws -> BrowserSyncSummary { .unavailable }
    func syncSummary() -> BrowserSyncSummary { .unavailable }
    func clearResolverCache() throws -> BrowserSyncSummary { .unavailable }
    func proofDetails(for hostOrURL: String) throws -> BrowserProofDetails {
        BrowserProofDetails(
            headline: "Unused fake proof",
            detail: hostOrURL,
            host: hostOrURL,
            name: nil,
            network: nil,
            nameHash: nil,
            hnsProof: "unavailable",
            proofStatus: "unavailable",
            secure: nil,
            exists: nil,
            treeRoot: nil,
            blockHeight: nil,
            cacheStatus: "unused",
            recordTypes: [],
            error: nil,
            formattedJSON: "{}"
        )
    }
    func close() {}
}

final class FakeProxy: BrowserProxySession {
    let endpoint = BrowserProxyEndpoint(
        host: "127.0.0.1",
        port: 47_123,
        realm: "hns-browser",
        username: "user",
        password: "password"
    )
    var authenticationMatches = false
    var certificateMatches = false

    func requestStop() {}
    func joinAndDestroy() {}

    func acceptsProxyChallenge(
        host: String,
        port: Int,
        realm: String?,
        authenticationMethod: String
    ) -> Bool {
        authenticationMatches
    }

    func matchesLocalCertificate(host: String, leafCertificateDER: Data) -> Bool {
        certificateMatches
    }

    func takeMainFrameSecurityStatus(host: String) -> BrowserSecuritySummary? { nil }
}
