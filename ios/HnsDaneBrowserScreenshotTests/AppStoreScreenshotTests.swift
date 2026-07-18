import Foundation
import XCTest

/// Captures App Store submission candidates from the unmodified shipping
/// runtime. This test deliberately does not set HNS_APP_STORE_SCREENSHOT_SCENE.
/// All four images are captured in one test so Proof Details is guaranteed to
/// describe the same live HNS navigation shown in the first image.
final class LiveAppStoreScreenshotTests: XCTestCase {
    private static let hnsURL = "https://denuoweb/"
    private static let webPKIURL = "https://denuoweb.com/work/hns-dane-browser"

    private var app: XCUIApplication!

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        XCUIDevice.shared.orientation = .portrait
        app = XCUIApplication()
        app.launchArguments += [
            "-AppleLanguages", "(en)",
            "-AppleLocale", "en_US",
            "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryL",
        ]
    }

    override func tearDown() {
        app?.terminate()
        app = nil
        super.tearDown()
    }

    func testLiveSubmissionScreenshots() throws {
        let currentRuntimeStatus = launchShippingRuntime(requireCurrentHeaders: true)
        var hnsEvidence = try navigateAndWait(
            to: Self.hnsURL,
            expectedHost: "denuoweb",
            timeout: 180
        )
        hnsEvidence["runtimeStatusBeforeNavigation"] = currentRuntimeStatus
        capture(named: "LIVE_APPSTORE_SCREENSHOT_01_HNS_PAGE")

        let settingsEvidence = openSettings(timeout: 20)
        capture(named: "LIVE_APPSTORE_SCREENSHOT_02_SETTINGS")

        let proofEvidence = try openProofDetails(timeout: 60)
        capture(named: "LIVE_APPSTORE_SCREENSHOT_03_PROOF_DETAILS")

        app.terminate()
        launchShippingRuntime(requireCurrentHeaders: false)
        let webPKIEvidence = try navigateAndWait(
            to: Self.webPKIURL,
            expectedHost: "denuoweb.com",
            timeout: 90
        )
        capture(named: "LIVE_APPSTORE_SCREENSHOT_04_WEBPKI")

        try attachProvenance(
            hnsEvidence: hnsEvidence,
            settingsEvidence: settingsEvidence,
            proofEvidence: proofEvidence,
            webPKIEvidence: webPKIEvidence
        )
    }

    @discardableResult
    private func launchShippingRuntime(requireCurrentHeaders: Bool) -> String {
        // A Release test run excludes the fixture implementation at compile
        // time. Removing this inherited value also prevents a caller's shell
        // from accidentally requesting a fixture scene.
        app.launchEnvironment.removeValue(forKey: "HNS_APP_STORE_SCREENSHOT_SCENE")
        app.launch()

        let address = app.textFields["app-store-screenshot.address"]
        XCTAssertTrue(address.waitForExistence(timeout: 20), "Address field did not appear")

        let sync = app.staticTexts["app-store-screenshot.sync"]
        XCTAssertTrue(sync.waitForExistence(timeout: 20), "Runtime status did not appear")
        let readinessTimeout: TimeInterval = requireCurrentHeaders ? 1_200 : 120
        var lastRuntimeStatus = ""
        XCTAssertTrue(
            waitUntil(
                description: requireCurrentHeaders
                    ? "current Handshake headers"
                    : "shipping runtime readiness",
                timeout: readinessTimeout,
                timeoutEvidence: { " Last runtime status: \(lastRuntimeStatus)" },
                condition: {
                    let label = sync.label.trimmingCharacters(in: .whitespacesAndNewlines)
                    if label != lastRuntimeStatus {
                        lastRuntimeStatus = label
                        print("Live screenshot runtime status: \(label)")
                    }
                    if requireCurrentHeaders {
                        return label.hasPrefix("Handshake headers current")
                    }
                    return !label.isEmpty && label != "Preparing runtime"
                }
            )
        )
        return sync.label.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func navigateAndWait(
        to requestedURL: String,
        expectedHost: String,
        timeout: TimeInterval
    ) throws -> [String: Any] {
        let address = app.textFields["app-store-screenshot.address"]
        address.tap()
        address.typeText(requestedURL)
        address.typeText("\n")

        XCTAssertTrue(
            waitUntil(
                description: "address update for \(expectedHost)",
                timeout: timeout,
                condition: {
                    guard let value = address.value as? String else { return false }
                    return value.localizedCaseInsensitiveContains(expectedHost)
                }
            )
        )

        let webView = app.webViews.firstMatch
        XCTAssertTrue(
            waitUntil(
                description: "rendered page for \(expectedHost)",
                timeout: timeout,
                condition: {
                    webView.exists
                        && webView.descendants(matching: .staticText).firstMatch.exists
                        && self.app.buttons["Reload"].exists
                }
            )
        )

        let security = app.staticTexts["app-store-screenshot.security"]
        XCTAssertTrue(security.waitForExistence(timeout: 10), "Security status did not appear")
        XCTAssertTrue(
            waitUntil(
                description: "actual security outcome for \(expectedHost)",
                timeout: timeout,
                condition: {
                    let label = security.label.trimmingCharacters(in: .whitespacesAndNewlines)
                    return !label.isEmpty
                        && label != "Security pending"
                        && label != "Waiting for a verified response"
                }
            )
        )
        assertNoNavigationAlert()

        return [
            "requestedURL": requestedURL,
            "finalAddress": (address.value as? String) ?? "",
            // This is evidence, not an assertion. HNS may honestly report DANE,
            // fallback, insecure, or blocked depending on the live response.
            "securityLabel": security.label,
        ]
    }

    private func openSettings(
        timeout: TimeInterval
    ) -> [String: Any] {
        let controls = app.buttons["app-store-screenshot.controls"]
        XCTAssertTrue(controls.waitForExistence(timeout: 10), "Settings control did not appear")
        controls.tap()

        let table = app.tables["settings.table"]
        let statelessRow = app.descendants(matching: .any)[
            "settings.hns-resolution.stateless-dane-certificates"
        ]
        let statelessToggle = app.switches[
            "settings.hns-resolution.stateless-dane-certificates.toggle"
        ]
        XCTAssertTrue(
            waitUntil(
                description: "Android-aligned HNS settings",
                timeout: timeout,
                condition: {
                    table.exists
                        && statelessRow.exists
                        && statelessRow.isHittable
                        && statelessToggle.exists
                        && statelessToggle.isHittable
                }
            )
        )
        assertNoNavigationAlert()
        return [
            "sourceRequestedURL": Self.hnsURL,
            "statelessDANERowIdentifier":
                "settings.hns-resolution.stateless-dane-certificates",
            "statelessDANEToggleIdentifier":
                "settings.hns-resolution.stateless-dane-certificates.toggle",
        ]
    }

    private func openProofDetails(timeout: TimeInterval) throws -> [String: Any] {
        let table = app.tables["settings.table"]
        let proofRow = app.descendants(matching: .any)["browser-settings.proof-details"]
        for _ in 0..<6 where !proofRow.exists || !proofRow.isHittable {
            assertNoNavigationAlert()
            table.swipeUp()
        }
        XCTAssertTrue(
            waitUntil(
                description: "HNS proof details setting",
                timeout: 20,
                condition: { proofRow.exists && proofRow.isHittable }
            )
        )
        proofRow.tap()

        let identifiedContent = app.textViews["browser-proof-details.content"]
        let proofContent = identifiedContent.waitForExistence(timeout: timeout)
            ? identifiedContent
            : app.textViews.firstMatch
        XCTAssertTrue(
            waitUntil(
                description: "live proof details",
                timeout: timeout,
                condition: { proofContent.exists && !proofContent.label.isEmpty }
            )
        )
        assertNoNavigationAlert()

        return [
            "sourceRequestedURL": Self.hnsURL,
            "contentAccessibilityLabel": proofContent.label,
        ]
    }

    @discardableResult
    private func waitUntil(
        description: String,
        timeout: TimeInterval,
        timeoutEvidence: () -> String = { "" },
        condition: () -> Bool
    ) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if app.alerts.firstMatch.exists {
                assertNoNavigationAlert()
                return false
            }
            if condition() { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        } while Date() < deadline
        XCTFail("Timed out waiting for \(description).\(timeoutEvidence())")
        return false
    }

    private func assertNoNavigationAlert() {
        let alert = app.alerts.firstMatch
        guard alert.exists else { return }
        let message = alert.descendants(matching: .staticText).allElementsBoundByIndex
            .map(\.label)
            .filter { !$0.isEmpty }
            .joined(separator: " — ")
        XCTFail("Live capture stopped because the app presented an alert: \(message)")
    }

    private func capture(named name: String) {
        assertNoNavigationAlert()
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func attachProvenance(
        hnsEvidence: [String: Any],
        settingsEvidence: [String: Any],
        proofEvidence: [String: Any],
        webPKIEvidence: [String: Any]
    ) throws {
        let document: [String: Any] = [
            "captureMode": "live-production-runtime",
            "configuration": "Release",
            "fixtureEnvironmentInjected": false,
            "hnsNavigation": hnsEvidence,
            "proofDetails": proofEvidence,
            "schemaVersion": 1,
            "settings": settingsEvidence,
            "webPKINavigation": webPKIEvidence,
        ]
        let data = try JSONSerialization.data(
            withJSONObject: document,
            options: [.prettyPrinted, .sortedKeys]
        )
        let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.json")
        attachment.name = "LIVE_APPSTORE_PROVENANCE"
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}

/// Debug-only fixture coverage for visual regression work. These captures use
/// offline injected content, are not App Store submission candidates, and are
/// intentionally excluded from the live Release capture script.
final class NonSubmissionFixtureScreenshotRegressionTests: XCTestCase {
    private static let sceneEnvironmentKey = "HNS_APP_STORE_SCREENSHOT_SCENE"

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        XCUIDevice.shared.orientation = .portrait
    }

    func testFixtureHNSChrome() {
        let app = launch(scene: "hns-page")
        waitForFixturePage(in: app, scene: "hns-page", title: "Browse beyond traditional DNS")
        XCTAssertEqual(
            app.staticTexts["app-store-screenshot.security"].label,
            "DANE verified · authoritative DoH"
        )
        capture(named: "UI_REGRESSION_FIXTURE_01_HNS")
    }

    func testFixtureProofViewer() {
        let app = launch(scene: "proof-details")
        let proof = app.textViews["app-store-screenshot.ready.proof-details"]
        XCTAssertTrue(proof.waitForExistence(timeout: 15))
        XCTAssertTrue(proof.label.contains("shakeshift"))
        capture(named: "UI_REGRESSION_FIXTURE_02_PROOF_DETAILS")
    }

    func testFixtureWebPKIChrome() {
        let app = launch(scene: "webpki-page")
        waitForFixturePage(
            in: app,
            scene: "webpki-page",
            title: "One browser for Handshake and the open web"
        )
        XCTAssertEqual(
            app.staticTexts["app-store-screenshot.security"].label,
            "System WebPKI · Rust proxy"
        )
        capture(named: "UI_REGRESSION_FIXTURE_03_WEBPKI")
    }

    private func launch(scene: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment[Self.sceneEnvironmentKey] = scene
        app.launchArguments += [
            "-AppleLanguages", "(en)",
            "-AppleLocale", "en_US",
            "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryL",
        ]
        app.launch()
        return app
    }

    private func waitForFixturePage(
        in app: XCUIApplication,
        scene: String,
        title: String
    ) {
        let webView = app.webViews["app-store-screenshot.ready.\(scene)"]
        XCTAssertTrue(webView.waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 15))
    }

    private func capture(named name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
