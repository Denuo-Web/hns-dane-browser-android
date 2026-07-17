import Foundation
import UIKit
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

        XCTAssertFalse(policy.statelessDANECertificates)
        XCTAssertFalse(policy.experimentalP2PDNSRelay)
        XCTAssertTrue(policy.legacyHNSDoHCompatibility)
    }

    @MainActor
    func testIOSSettingsKeepBackedHNSControlsInAndroidRelativeOrder() {
        let rows = BrowserSettingsViewController.rows(in: .hnsResolution)

        XCTAssertEqual(
            rows,
            [
                .strictHNSMode,
                .statelessDANECertificates,
                .experimentalP2PDNSRelay,
                .legacyHNSDoHCompatibility,
                .compatibilityDoHResolver,
                .clearResolverCache,
                .hnsSync,
            ]
        )
        XCTAssertEqual(rows.map(\.title), [
            "Strict HNS mode",
            "Experimental stateless DANE certificates",
            "Experimental P2P DNS relay",
            "Legacy HNS DoH compatibility",
            "Compatibility DoH resolver",
            "Clear resolver cache",
            "HNS sync",
        ])
    }

    @MainActor
    func testStatelessDANEIsAToggleWithAndroidExplanations() throws {
        let settings = BrowserSettingsViewController(
            policy: .default,
            runtimeControlsAreAvailable: true
        )
        settings.loadViewIfNeeded()
        let indexPath = IndexPath(row: 1, section: 0)

        var cell = settings.tableView(settings.tableView, cellForRowAt: indexPath)
        var content = try XCTUnwrap(cell.contentConfiguration as? UIListContentConfiguration)
        let toggle = try XCTUnwrap(cell.accessoryView as? UISwitch)
        XCTAssertEqual(cell.accessibilityIdentifier, "settings.hns-resolution.stateless-dane-certificates")
        XCTAssertEqual(content.text, "Experimental stateless DANE certificates")
        XCTAssertEqual(
            content.secondaryText,
            "Off. HNS proof and TLSA evidence use the live resolver path."
        )
        XCTAssertFalse(toggle.isOn)

        settings.update(
            policy: BrowserRuntimePolicy(statelessDANECertificates: true),
            runtimeControlsAreAvailable: true,
            isOperationInFlight: false
        )
        cell = settings.tableView(settings.tableView, cellForRowAt: indexPath)
        content = try XCTUnwrap(cell.contentConfiguration as? UIListContentConfiguration)
        XCTAssertEqual(
            content.secondaryText,
            "On. Certificate-carried HNS proof evidence may satisfy DANE when valid."
        )
        XCTAssertTrue(try XCTUnwrap(cell.accessoryView as? UISwitch).isOn)
    }

    @MainActor
    func testHNSSyncRowNavigatesBeforeAnExplicitRun() throws {
        let initialSummary = BrowserSyncSummary(
            headline: "Handshake sync idle",
            detail: "Local height 300000 · peer height 300100 · accepted 0/0",
            status: "idle",
            network: "mainnet",
            peerCount: 4,
            peerGroups: 2,
            bestHeight: 300_000,
            bestPeerHeight: 300_100
        )
        let settings = BrowserSettingsViewController(
            policy: .default,
            runtimeControlsAreAvailable: true,
            syncSummary: initialSummary
        )
        let delegate = BrowserSettingsDelegateSpy()
        settings.delegate = delegate
        let navigation = UINavigationController(rootViewController: settings)
        navigation.loadViewIfNeeded()
        settings.loadViewIfNeeded()

        let settingsIndexPath = IndexPath(row: 6, section: 0)
        let settingsCell = settings.tableView(
            settings.tableView,
            cellForRowAt: settingsIndexPath
        )
        let settingsContent = try XCTUnwrap(
            settingsCell.contentConfiguration as? UIListContentConfiguration
        )
        XCTAssertEqual(
            settingsContent.secondaryText,
            "View sync status and run a manual sync."
        )

        settings.tableView(settings.tableView, didSelectRowAt: settingsIndexPath)

        let sync = try XCTUnwrap(navigation.topViewController as? HNSSyncViewController)
        XCTAssertTrue(delegate.actions.isEmpty)
        sync.loadViewIfNeeded()
        let statusCell = sync.tableView(
            sync.tableView,
            cellForRowAt: IndexPath(row: 0, section: 0)
        )
        let statusContent = try XCTUnwrap(
            statusCell.contentConfiguration as? UIListContentConfiguration
        )
        XCTAssertTrue(statusContent.secondaryText?.contains("Handshake sync idle") == true)
        XCTAssertTrue(statusContent.secondaryText?.contains("Network: mainnet") == true)

        sync.tableView(sync.tableView, didSelectRowAt: IndexPath(row: 1, section: 0))
        XCTAssertEqual(delegate.actions, [.runHNSSync])
    }

    @MainActor
    func testHNSSyncStatusScreenReceivesLiveSummaryUpdates() throws {
        let settings = BrowserSettingsViewController(
            policy: .default,
            runtimeControlsAreAvailable: true,
            syncSummary: .unavailable
        )
        let navigation = UINavigationController(rootViewController: settings)
        navigation.loadViewIfNeeded()
        settings.loadViewIfNeeded()
        settings.tableView(
            settings.tableView,
            didSelectRowAt: IndexPath(row: 6, section: 0)
        )
        let sync = try XCTUnwrap(navigation.topViewController as? HNSSyncViewController)
        sync.loadViewIfNeeded()

        settings.update(
            policy: .default,
            runtimeControlsAreAvailable: true,
            isOperationInFlight: false,
            syncSummary: BrowserSyncSummary(
                headline: "Handshake headers current",
                detail: "Local height 335942 · peer height 335942 · accepted 2/2",
                status: "up_to_date",
                network: "mainnet",
                attempted: 2,
                successful: 2,
                accepted: 2,
                peerCount: 8,
                peerGroups: 3,
                bestHeight: 335_942,
                bestPeerHeight: 335_942
            )
        )

        let statusCell = sync.tableView(
            sync.tableView,
            cellForRowAt: IndexPath(row: 0, section: 0)
        )
        let content = try XCTUnwrap(
            statusCell.contentConfiguration as? UIListContentConfiguration
        )
        XCTAssertTrue(content.secondaryText?.contains("Handshake headers current") == true)
        XCTAssertTrue(content.secondaryText?.contains("Peers: 8 in 3 groups") == true)
    }

    @MainActor
    func testIOSSettingsUseBackedAndroidDefaultsAndActionLabels() throws {
        let settings = BrowserSettingsViewController(
            policy: .default,
            runtimeControlsAreAvailable: true
        )
        settings.loadViewIfNeeded()

        let doh = settings.tableView(
            settings.tableView,
            cellForRowAt: IndexPath(row: 4, section: 0)
        )
        XCTAssertEqual(
            try XCTUnwrap(doh.contentConfiguration as? UIListContentConfiguration)
                .secondaryText,
            "https://zorro.hnsdoh.com/dns-query"
        )
        XCTAssertEqual((doh.accessoryView as? UILabel)?.text, "Edit")

        let cache = settings.tableView(
            settings.tableView,
            cellForRowAt: IndexPath(row: 5, section: 0)
        )
        XCTAssertEqual(
            try XCTUnwrap(cache.contentConfiguration as? UIListContentConfiguration)
                .secondaryText,
            "Ready to clear cached resolver values."
        )
        XCTAssertEqual((cache.accessoryView as? UILabel)?.text, "Clear")

        let hnsSync = settings.tableView(
            settings.tableView,
            cellForRowAt: IndexPath(row: 6, section: 0)
        )
        XCTAssertEqual((hnsSync.accessoryView as? UILabel)?.text, "View")

        let proof = settings.tableView(
            settings.tableView,
            cellForRowAt: IndexPath(row: 0, section: 1)
        )
        XCTAssertEqual((proof.accessoryView as? UILabel)?.text, "Open")

        let build = settings.tableView(
            settings.tableView,
            cellForRowAt: IndexPath(row: 0, section: 2)
        )
        let buildText = try XCTUnwrap(
            (build.contentConfiguration as? UIListContentConfiguration)?.secondaryText
        )
        XCTAssertTrue(buildText.hasPrefix("release "))
        XCTAssertTrue(buildText.contains(" ("))
        XCTAssertTrue(buildText.hasSuffix(")"))
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

@MainActor
private final class BrowserSettingsDelegateSpy: BrowserSettingsViewControllerDelegate {
    private(set) var actions: [BrowserSettingsViewController.Action] = []

    func browserSettingsViewController(
        _ controller: BrowserSettingsViewController,
        didRequest action: BrowserSettingsViewController.Action
    ) {
        actions.append(action)
    }
}
