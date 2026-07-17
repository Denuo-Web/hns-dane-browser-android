import XCTest

final class AppStoreScreenshotTests: XCTestCase {
    private static let sceneEnvironmentKey = "HNS_APP_STORE_SCREENSHOT_SCENE"

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        XCUIDevice.shared.orientation = .portrait
    }

    func test01HandshakeDANEVerified() {
        let app = launch(scene: "hns-page")
        waitForPage(
            in: app,
            scene: "hns-page",
            title: "Browse beyond traditional DNS"
        )
        XCTAssertEqual(
            app.staticTexts["app-store-screenshot.security"].label,
            "DANE verified · authoritative DoH"
        )
        capture(named: "APPSTORE_SCREENSHOT_01_HNS_DANE_VERIFIED")
    }

    func test02BrowserSettings() {
        let app = launch(scene: "hns-page")
        waitForPage(
            in: app,
            scene: "hns-page",
            title: "Browse beyond traditional DNS"
        )

        let controls = app.buttons["app-store-screenshot.controls"]
        XCTAssertTrue(controls.waitForExistence(timeout: 10))
        controls.tap()

        let resolutionMode = app.descendants(matching: .any)["Resolution Mode"]
        XCTAssertTrue(resolutionMode.waitForExistence(timeout: 10))
        capture(named: "APPSTORE_SCREENSHOT_02_BROWSER_SETTINGS")
    }

    func test03ProofDetails() {
        let app = launch(scene: "proof-details")
        let proof = app.textViews["app-store-screenshot.ready.proof-details"]
        XCTAssertTrue(proof.waitForExistence(timeout: 15))
        XCTAssertTrue(proof.label.contains("shakeshift"))
        capture(named: "APPSTORE_SCREENSHOT_03_PROOF_DETAILS")
    }

    func test04WebPKI() {
        let app = launch(scene: "webpki-page")
        waitForPage(
            in: app,
            scene: "webpki-page",
            title: "One browser for Handshake and the open web"
        )
        XCTAssertEqual(
            app.staticTexts["app-store-screenshot.security"].label,
            "System WebPKI · Rust proxy"
        )
        capture(named: "APPSTORE_SCREENSHOT_04_WEBPKI")
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

    private func waitForPage(
        in app: XCUIApplication,
        scene: String,
        title: String
    ) {
        let webView = app.webViews["app-store-screenshot.ready.\(scene)"]
        XCTAssertTrue(webView.waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 15))
        XCTAssertTrue(
            app.textFields["app-store-screenshot.address"].waitForExistence(timeout: 5)
        )
    }

    private func capture(named name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
