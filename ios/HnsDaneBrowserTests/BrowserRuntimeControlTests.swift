import Foundation
import XCTest
@testable import HnsDaneBrowser

final class BrowserRuntimeControlTests: XCTestCase {
    private var defaults: UserDefaults!
    private var suiteName: String!

    override func setUp() {
        super.setUp()
        suiteName = "BrowserRuntimeControlTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suiteName)
        defaults = nil
        suiteName = nil
        super.tearDown()
    }

    func testPolicyNormalizesEmptyResolverEndpoint() {
        let policy = BrowserRuntimePolicy(hnsDohResolver: "  \n ")
        XCTAssertNil(policy.hnsDohResolver)

        let configured = BrowserRuntimePolicy(
            resolutionMode: .strict,
            hnsDohResolver: "  https://resolver.example/dns-query  ",
            statelessDANECertificates: true,
            experimentalP2PDNSRelay: true,
            legacyHNSDoHCompatibility: false
        )
        XCTAssertEqual(configured.hnsDohResolver, "https://resolver.example/dns-query")
    }

    func testPolicyStoreRoundTripsNonSensitiveSettings() {
        let store = BrowserRuntimePolicyStore(defaults: defaults)
        let expected = BrowserRuntimePolicy(
            resolutionMode: .strict,
            hnsDohResolver: "https://resolver.example/dns-query",
            statelessDANECertificates: true,
            experimentalP2PDNSRelay: true,
            legacyHNSDoHCompatibility: false
        )

        store.save(expected)

        XCTAssertEqual(store.load(), expected)
    }

    func testPolicyDefaultsKeepExperimentOffAndLegacyCompatibilityOn() {
        let policy = BrowserRuntimePolicyStore(defaults: defaults).load()

        XCTAssertFalse(policy.experimentalP2PDNSRelay)
        XCTAssertTrue(policy.legacyHNSDoHCompatibility)
    }

    func testPolicyStoreFallsBackForUnknownResolutionMode() {
        defaults.set(
            "future-mode",
            forKey: "hnsBrowser.runtimePolicy.resolutionMode"
        )

        XCTAssertEqual(
            BrowserRuntimePolicyStore(defaults: defaults).load().resolutionMode,
            .compatibility
        )
    }

    func testSyncSchedulingUsesBoundedFailureBackoff() {
        let policy = BrowserSyncSchedulingPolicy(
            progressInterval: 30,
            caughtUpInterval: 300,
            failureBackoff: [5, 15, 60]
        )

        XCTAssertEqual(policy.delay(after: nil, consecutiveFailures: 1), 5)
        XCTAssertEqual(policy.delay(after: nil, consecutiveFailures: 2), 15)
        XCTAssertEqual(policy.delay(after: nil, consecutiveFailures: 3), 60)
        XCTAssertEqual(policy.delay(after: nil, consecutiveFailures: 20), 60)
    }

    func testSyncSchedulingSlowsDownWhenCaughtUp() {
        let policy = BrowserSyncSchedulingPolicy()
        let caughtUp = BrowserSyncSummary(
            headline: "Current",
            detail: "Current",
            status: "up_to_date"
        )
        let syncing = BrowserSyncSummary(
            headline: "Syncing",
            detail: "Syncing",
            status: "syncing"
        )

        XCTAssertEqual(policy.delay(after: caughtUp, consecutiveFailures: 0), 300)
        XCTAssertEqual(policy.delay(after: syncing, consecutiveFailures: 0), 30)
        XCTAssertTrue(
            BrowserSyncSummary(
                headline: "Attention",
                detail: "Peer failed",
                status: "peer_failed"
            ).requiresRetry
        )
    }

    func testNativeSyncSummaryPreservesUsefulRuntimeResults() throws {
        let summary = try RustBrowserRuntime.syncSummary(from: [
            "network": "mainnet",
            "status": "up_to_date",
            "attempted": 4,
            "successful": 3,
            "accepted": 2,
            "failed": 1,
            "peerCount": 8,
            "peerGroups": 3,
            "bestHeight": 250_000,
            "bestPeerHeight": 250_000,
            "estimatedTipHeight": 250_000,
            "resourceCacheEntries": 14,
            "resourceCacheBytes": 4_096,
            "resourceCacheEvicted": 2,
            "error": NSNull(),
            "failures": [],
        ])

        XCTAssertEqual(summary.network, "mainnet")
        XCTAssertEqual(summary.status, "up_to_date")
        XCTAssertEqual(summary.attempted, 4)
        XCTAssertEqual(summary.successful, 3)
        XCTAssertEqual(summary.accepted, 2)
        XCTAssertEqual(summary.failed, 1)
        XCTAssertEqual(summary.peerCount, 8)
        XCTAssertEqual(summary.peerGroups, 3)
        XCTAssertEqual(summary.bestHeight, 250_000)
        XCTAssertEqual(summary.bestPeerHeight, 250_000)
        XCTAssertEqual(summary.estimatedTipHeight, 250_000)
        XCTAssertEqual(summary.resourceCacheEntries, 14)
        XCTAssertEqual(summary.resourceCacheBytes, 4_096)
        XCTAssertEqual(summary.resourceCacheEvicted, 2)
        XCTAssertFalse(summary.requiresRetry)
    }

    func testNativeProofDetailsRemainViewableAndExportable() throws {
        let details = try RustBrowserRuntime.proofDetails(
            from: [
                "host": "alice",
                "name": "alice",
                "network": "mainnet",
                "nameHash": "001122",
                "hnsProof": "verified",
                "proofStatus": "verified",
                "secure": true,
                "exists": true,
                "treeRoot": "aabbcc",
                "blockHeight": 250_000,
                "cacheStatus": "anchored_to_current_tip",
                "resourceValueHex": "00",
                "recordTypes": ["A", "TLSA"],
                "resourceRecords": [],
                "currentTip": ["height": 250_000],
                "error": NSNull(),
            ],
            fallbackHost: "fallback"
        )

        XCTAssertEqual(details.headline, "Handshake proof verified")
        XCTAssertEqual(details.host, "alice")
        XCTAssertEqual(details.proofStatus, "verified")
        XCTAssertEqual(details.secure, true)
        XCTAssertEqual(details.exists, true)
        XCTAssertEqual(details.blockHeight, 250_000)
        XCTAssertEqual(details.recordTypes, ["A", "TLSA"])
        XCTAssertTrue(details.formattedJSON.contains("\"proofStatus\" : \"verified\""))
    }
}
