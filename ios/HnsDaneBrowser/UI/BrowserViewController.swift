import SafariServices
import UIKit
import WebKit

@MainActor
final class BrowserViewController: UIViewController {
    private static let privacyPolicyURL = URL(
        string: "https://denuoweb.com/work/hns-dane-browser/privacy"
    )!
    private static let supportURL = URL(
        string: "https://denuoweb.com/work/hns-dane-browser"
    )!

#if DEBUG && targetEnvironment(simulator)
    private static let appStoreScreenshotSceneKey = "HNS_APP_STORE_SCREENSHOT_SCENE"

    private enum AppStoreScreenshotScene: String {
        case hnsPage = "hns-page"
        case proofDetails = "proof-details"
        case webPKIPage = "webpki-page"
    }
#endif

    private let process: BrowserProcess

    private let backButton = UIButton(type: .system)
    private let forwardButton = UIButton(type: .system)
    private let reloadButton = UIButton(type: .system)
    private let shareButton = UIButton(type: .system)
    private let controlsButton = UIButton(type: .system)
    private let addressField = UITextField()
    private let securityLabel = UILabel()
    private let syncLabel = UILabel()
    private let progressView = UIProgressView(progressViewStyle: .bar)
    private let webContainer = UIView()
    private let placeholderLabel = UILabel()

    private var coordinator: BrowserProxyCoordinator?
    private var environment: BrowserProcess.Environment?
    private var progressObservation: NSKeyValueObservation?
    private var pendingExternalAddress: String?
    private var isForeground = false
    private var isPreparing = false
    private var isLoading = false
    private var isControlOperationInFlight = false
    private var isDestroyed = false

#if DEBUG && targetEnvironment(simulator)
    private var appStoreScreenshotScene: AppStoreScreenshotScene?
    private var shouldPresentScreenshotProof = false
#endif

    init(process: BrowserProcess) {
        self.process = process
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        configureUI()
#if DEBUG && targetEnvironment(simulator)
        if configureAppStoreScreenshotFixtureIfRequested() { return }
#endif
        prepareRuntime()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
#if DEBUG && targetEnvironment(simulator)
        presentScreenshotProofIfNeeded()
#endif
    }

    func resumeBrowsing() {
        guard !isDestroyed else { return }
        isForeground = true
#if DEBUG && targetEnvironment(simulator)
        if appStoreScreenshotScene != nil { return }
#endif
        coordinator?.resume()
        process.resumeForegroundSync { [weak self] summary in
            self?.updateSyncSummary(summary)
        }
    }

    func suspendBrowsing() {
        guard !isDestroyed else { return }
        isForeground = false
#if DEBUG && targetEnvironment(simulator)
        if appStoreScreenshotScene != nil { return }
#endif
        coordinator?.suspend()
        process.suspendForegroundSync()
        placeholderLabel.text = "Secure browsing paused"
    }

    func destroyBrowsing() {
        guard !isDestroyed else { return }
        isDestroyed = true
        isForeground = false
#if DEBUG && targetEnvironment(simulator)
        if appStoreScreenshotScene != nil { return }
#endif
        process.suspendForegroundSync()
        coordinator?.destroy()
        coordinator = nil
        environment = nil
        progressObservation = nil
    }

    func openExternalURL(_ url: URL) {
        guard !isDestroyed else { return }
        guard url.isFileURL == false else {
            showError(BrowserCoreError.unsupportedAddress)
            return
        }
        if let coordinator {
            coordinator.navigate(rawValue: url.absoluteString)
        } else {
            pendingExternalAddress = url.absoluteString
        }
    }

    private func configureUI() {
        view.backgroundColor = .systemBackground

        configureButton(backButton, symbol: "chevron.backward", label: "Back", action: #selector(goBack))
        configureButton(forwardButton, symbol: "chevron.forward", label: "Forward", action: #selector(goForward))
        configureButton(reloadButton, symbol: "arrow.clockwise", label: "Reload", action: #selector(reloadOrStop))
        configureButton(shareButton, symbol: "square.and.arrow.up", label: "Share", action: #selector(sharePage))
        controlsButton.setImage(UIImage(systemName: "slider.horizontal.3"), for: .normal)
        controlsButton.accessibilityLabel = "Browser settings and information"
        controlsButton.accessibilityIdentifier = "app-store-screenshot.controls"
        controlsButton.showsMenuAsPrimaryAction = true
        backButton.isEnabled = false
        forwardButton.isEnabled = false
        shareButton.isEnabled = false
        controlsButton.isEnabled = true

        addressField.borderStyle = .roundedRect
        addressField.clearButtonMode = .whileEditing
        addressField.keyboardType = .URL
        addressField.returnKeyType = .go
        addressField.autocapitalizationType = .none
        addressField.autocorrectionType = .no
        addressField.spellCheckingType = .no
        addressField.placeholder = "Enter a web or Handshake address"
        addressField.accessibilityLabel = "Address"
        addressField.accessibilityIdentifier = "app-store-screenshot.address"
        addressField.delegate = self

        securityLabel.font = .preferredFont(forTextStyle: .caption1)
        securityLabel.adjustsFontForContentSizeCategory = true
        securityLabel.textColor = .secondaryLabel
        securityLabel.numberOfLines = 1
        securityLabel.text = "Security pending"
        securityLabel.accessibilityIdentifier = "app-store-screenshot.security"

        syncLabel.font = .preferredFont(forTextStyle: .caption2)
        syncLabel.adjustsFontForContentSizeCategory = true
        syncLabel.textColor = .tertiaryLabel
        syncLabel.numberOfLines = 1
        syncLabel.textAlignment = .right
        syncLabel.text = "Preparing runtime"
        syncLabel.accessibilityIdentifier = "app-store-screenshot.sync"

        placeholderLabel.translatesAutoresizingMaskIntoConstraints = false
        placeholderLabel.font = .preferredFont(forTextStyle: .title3)
        placeholderLabel.textColor = .secondaryLabel
        placeholderLabel.textAlignment = .center
        placeholderLabel.numberOfLines = 0
        placeholderLabel.text = "Preparing secure browsing…"

        let addressRow = UIStackView(
            arrangedSubviews: [
                backButton,
                forwardButton,
                addressField,
                reloadButton,
                shareButton,
                controlsButton,
            ]
        )
        addressRow.axis = .horizontal
        addressRow.alignment = .center
        addressRow.spacing = 8
        backButton.widthAnchor.constraint(equalToConstant: 36).isActive = true
        forwardButton.widthAnchor.constraint(equalToConstant: 36).isActive = true
        reloadButton.widthAnchor.constraint(equalToConstant: 36).isActive = true
        shareButton.widthAnchor.constraint(equalToConstant: 36).isActive = true
        controlsButton.widthAnchor.constraint(equalToConstant: 36).isActive = true

        let statusRow = UIStackView(arrangedSubviews: [securityLabel, syncLabel])
        statusRow.axis = .horizontal
        statusRow.alignment = .firstBaseline
        statusRow.distribution = .fill
        statusRow.spacing = 8
        securityLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        syncLabel.setContentCompressionResistancePriority(.required, for: .horizontal)

        let chrome = UIStackView(arrangedSubviews: [addressRow, statusRow, progressView])
        chrome.axis = .vertical
        chrome.spacing = 6
        chrome.isLayoutMarginsRelativeArrangement = true
        chrome.directionalLayoutMargins = NSDirectionalEdgeInsets(top: 8, leading: 10, bottom: 6, trailing: 10)

        webContainer.backgroundColor = .secondarySystemBackground
        webContainer.addSubview(placeholderLabel)
        NSLayoutConstraint.activate([
            placeholderLabel.centerXAnchor.constraint(equalTo: webContainer.centerXAnchor),
            placeholderLabel.centerYAnchor.constraint(equalTo: webContainer.centerYAnchor),
            placeholderLabel.leadingAnchor.constraint(greaterThanOrEqualTo: webContainer.leadingAnchor, constant: 24),
            placeholderLabel.trailingAnchor.constraint(lessThanOrEqualTo: webContainer.trailingAnchor, constant: -24),
        ])

        let root = UIStackView(arrangedSubviews: [chrome, webContainer])
        root.translatesAutoresizingMaskIntoConstraints = false
        root.axis = .vertical
        root.spacing = 0
        view.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            root.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            root.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        rebuildControlsMenu()
    }

    private func configureButton(
        _ button: UIButton,
        symbol: String,
        label: String,
        action: Selector
    ) {
        button.setImage(UIImage(systemName: symbol), for: .normal)
        button.accessibilityLabel = label
        button.addTarget(self, action: action, for: .touchUpInside)
    }

#if DEBUG && targetEnvironment(simulator)
    /// Provides deterministic, offline App Store artwork without shipping a
    /// screenshot-only code path in Release builds. UI tests are the only caller.
    private func configureAppStoreScreenshotFixtureIfRequested() -> Bool {
        guard let rawScene = ProcessInfo.processInfo.environment[
            Self.appStoreScreenshotSceneKey
        ], let scene = AppStoreScreenshotScene(rawValue: rawScene) else {
            return false
        }

        appStoreScreenshotScene = scene
        UIView.setAnimationsEnabled(false)
        addressField.isUserInteractionEnabled = false
        progressView.progress = 0
        progressView.isHidden = true
        placeholderLabel.isHidden = true
        backButton.isEnabled = false
        forwardButton.isEnabled = false
        reloadButton.isEnabled = true
        shareButton.isEnabled = true

        let webView = WKWebView(frame: .zero, configuration: screenshotWebViewConfiguration())
        webView.translatesAutoresizingMaskIntoConstraints = false
        webView.accessibilityIdentifier = "app-store-screenshot.ready.\(scene.rawValue)"
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webContainer.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: webContainer.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: webContainer.trailingAnchor),
            webView.topAnchor.constraint(equalTo: webContainer.topAnchor),
            webView.bottomAnchor.constraint(equalTo: webContainer.bottomAnchor),
        ])

        switch scene {
        case .hnsPage, .proofDetails:
            addressField.text = scene == .proofDetails
                ? "https://shakeshift/"
                : "https://denuoweb/"
            updateSecuritySummary(
                BrowserSecuritySummary(
                    level: .handshakeDANE,
                    detail: "DANE verified · authoritative DoH"
                )
            )
            updateSyncSummary(
                BrowserSyncSummary(
                    headline: "Handshake headers current",
                    detail: "Local height 335942 · peer height 335942 · accepted 0/0",
                    status: "up_to_date",
                    network: "main",
                    bestHeight: 335_942,
                    bestPeerHeight: 335_942,
                    estimatedTipHeight: 335_942
                )
            )
            shouldPresentScreenshotProof = scene == .proofDetails
        case .webPKIPage:
            addressField.text = "https://denuoweb.com/work/hns-dane-browser"
            updateSecuritySummary(
                BrowserSecuritySummary(
                    level: .webPKI,
                    detail: "System WebPKI · Rust proxy"
                )
            )
            updateSyncSummary(
                BrowserSyncSummary(
                    headline: "Handshake headers current",
                    detail: "Local height 335942 · peer height 335942 · accepted 0/0",
                    status: "up_to_date",
                    network: "main",
                    bestHeight: 335_942,
                    bestPeerHeight: 335_942,
                    estimatedTipHeight: 335_942
                )
            )
        }

        rebuildControlsMenu()
        webView.loadHTMLString(appStoreScreenshotHTML(for: scene), baseURL: nil)
        return true
    }

    private func screenshotWebViewConfiguration() -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = false
        return configuration
    }

    private func appStoreScreenshotHTML(for scene: AppStoreScreenshotScene) -> String {
        let isWebPKI = scene == .webPKIPage
        let eyebrow = isWebPKI ? "OPEN WEB" : "HANDSHAKE NATIVE"
        let title = isWebPKI
            ? "One browser for Handshake and the open web"
            : "Browse beyond traditional DNS"
        let summary = isWebPKI
            ? "Ordinary HTTPS stays protected by system WebPKI while traffic moves through the app's bounded Rust proxy."
            : "Resolve Handshake names locally, validate DNSSEC and DANE, and inspect the proof behind each result."
        let badge = isWebPKI ? "System WebPKI" : "DANE certificate verified"
        let badgeIcon = isWebPKI ? "●" : "✓"
        let firstTitle = isWebPKI ? "Normal HTTPS trust" : "Local HNS proofs"
        let firstBody = isWebPKI
            ? "WebKit keeps its native certificate validation for ordinary internet sites."
            : "Name results are anchored to the locally verified Handshake header chain."
        let secondTitle = isWebPKI ? "Private-address blocking" : "DNSSEC + DANE"
        let secondBody = isWebPKI
            ? "The proxy rejects unsafe destinations before an origin connection is opened."
            : "Delegated records and certificate policy are validated before a page is trusted."
        let thirdTitle = isWebPKI ? "Clear security labels" : "Resolver transparency"
        let thirdBody = isWebPKI
            ? "The browser distinguishes WebPKI, DANE, fallback, and insecure paths."
            : "Proof details expose the name hash, tree root, block height, and record types."

        return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
          <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
          <style>
            :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
            * { box-sizing: border-box; }
            body { margin: 0; color: #172039; background: #f5f7fb; }
            main { min-height: 100vh; padding: 36px 24px 42px; background: radial-gradient(circle at top right, #dceeff 0, transparent 38%); }
            .eyebrow { color: #2563a9; font-size: 12px; font-weight: 800; letter-spacing: 1.8px; }
            h1 { max-width: 360px; margin: 12px 0 14px; font-size: 36px; line-height: 1.06; letter-spacing: -1.2px; }
            .summary { margin: 0; max-width: 355px; color: #536078; font-size: 17px; line-height: 1.45; }
            .badge { display: inline-flex; align-items: center; gap: 9px; margin: 24px 0 28px; padding: 10px 14px; color: #12633a; background: #dff5e8; border: 1px solid #b8e8cb; border-radius: 999px; font-size: 14px; font-weight: 700; }
            .badge span { display: inline-grid; width: 22px; height: 22px; place-items: center; color: white; background: #1c8a50; border-radius: 50%; }
            .cards { display: grid; gap: 12px; }
            article { padding: 19px 18px; background: rgba(255,255,255,.94); border: 1px solid #e1e7f0; border-radius: 18px; box-shadow: 0 8px 22px rgba(37,55,89,.06); }
            article h2 { margin: 0 0 7px; font-size: 18px; letter-spacing: -.25px; }
            article p { margin: 0; color: #5e6a7d; font-size: 14px; line-height: 1.42; }
            footer { margin-top: 28px; color: #708098; font-size: 13px; font-weight: 600; }
          </style>
        </head>
        <body>
          <main>
            <div class="eyebrow">\(eyebrow)</div>
            <h1>\(title)</h1>
            <p class="summary">\(summary)</p>
            <div class="badge"><span>\(badgeIcon)</span>\(badge)</div>
            <section class="cards">
              <article><h2>\(firstTitle)</h2><p>\(firstBody)</p></article>
              <article><h2>\(secondTitle)</h2><p>\(secondBody)</p></article>
              <article><h2>\(thirdTitle)</h2><p>\(thirdBody)</p></article>
            </section>
            <footer>HNS DANE Browser · Denuo Web</footer>
          </main>
        </body>
        </html>
        """
    }

    private func presentScreenshotProofIfNeeded() {
        guard shouldPresentScreenshotProof, presentedViewController == nil else { return }
        shouldPresentScreenshotProof = false
        let details = BrowserProofDetails(
            headline: "Handshake proof verified",
            detail: "shakeshift · cache verified",
            host: "shakeshift",
            name: "shakeshift",
            network: "main",
            nameHash: "002ccfdd5297befb2598bed3b71f6e6b05974d6abb0a9afda3e27e6b2ed9f12d",
            hnsProof: "verified",
            proofStatus: "verified",
            secure: true,
            exists: true,
            treeRoot: "dbce83cc6380d528b1df30d4721624dcfedad421a5ef074e7a3fa384d8c40d99",
            blockHeight: 335_942,
            cacheStatus: "verified",
            recordTypes: ["DS", "NS"],
            error: nil,
            formattedJSON: """
            {
              "blockHeight" : 335942,
              "cacheStatus" : "verified",
              "exists" : true,
              "hnsProof" : "verified",
              "host" : "shakeshift",
              "name" : "shakeshift",
              "nameHash" : "002ccfdd5297befb2598bed3b71f6e6b05974d6abb0a9afda3e27e6b2ed9f12d",
              "network" : "main",
              "proofStatus" : "verified",
              "recordTypes" : [ "DS", "NS" ],
              "secure" : true,
              "treeRoot" : "dbce83cc6380d528b1df30d4721624dcfedad421a5ef074e7a3fa384d8c40d99"
            }
            """
        )
        let viewer = ProofDetailsViewController(
            details: details,
            accessibilityIdentifier: "app-store-screenshot.ready.proof-details"
        )
        present(UINavigationController(rootViewController: viewer), animated: false)
    }
#endif

    private func prepareRuntime() {
        guard !isPreparing, coordinator == nil else { return }
        isPreparing = true
        placeholderLabel.text = "Preparing secure browsing…"
        process.prepare { [weak self] result in
            guard let self, !self.isDestroyed else { return }
            self.isPreparing = false
            switch result {
            case .success(let environment):
                self.environment = environment
                let coordinator = self.installCoordinator(environment: environment)
                self.placeholderLabel.text = "Enter an address to begin"
                self.updateSyncSummary(environment.runtime.syncSummary())
                self.controlsButton.isEnabled = true
                self.rebuildControlsMenu()
                if let pending = self.pendingExternalAddress {
                    self.pendingExternalAddress = nil
                    coordinator.navigate(rawValue: pending)
                }
            case .failure(let error):
                self.placeholderLabel.text = "Secure runtime preparation failed"
                self.showPreparationError(error)
            }
        }
    }

    @discardableResult
    private func installCoordinator(
        environment: BrowserProcess.Environment,
        replayAddress: String? = nil
    ) -> BrowserProxyCoordinator {
        let coordinator = BrowserProxyCoordinator(
            runtime: environment.runtime,
            profile: environment.profile
        )
        coordinator.delegate = self
        self.coordinator = coordinator
        if isForeground {
            coordinator.resume()
        }
        if let replayAddress {
            coordinator.navigate(rawValue: replayAddress)
        }
        return coordinator
    }

    private func showPreparationError(_ error: Error) {
        guard presentedViewController == nil else { return }
        let alert = UIAlertController(
            title: "Unable to prepare secure browsing",
            message: error.localizedDescription,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Retry", style: .default) { [weak self] _ in
            self?.prepareRuntime()
        })
        present(alert, animated: true)
    }

    private func showError(_ error: Error) {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain && nsError.code == NSURLErrorCancelled { return }
        placeholderLabel.text = error.localizedDescription
        guard presentedViewController == nil else { return }
        let alert = UIAlertController(
            title: "Navigation failed",
            message: error.localizedDescription,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    @objc private func goBack() {
        coordinator?.goBack()
    }

    @objc private func goForward() {
        coordinator?.goForward()
    }

    @objc private func reloadOrStop() {
        if isLoading {
            coordinator?.stopLoading()
        } else {
            coordinator?.reload()
        }
    }

    @objc private func sharePage() {
        guard let url = coordinator?.currentShareURL else { return }
        presentShareSheet(items: [url], sourceView: shareButton)
    }

    private func rebuildControlsMenu() {
        let policy = process.currentPolicy
        let runtimeDisabled: UIMenuElement.Attributes =
            !runtimeControlsAreAvailable || isControlOperationInFlight ? .disabled : []

        let compatibility = UIAction(
            title: "Compatibility",
            image: UIImage(systemName: "network"),
            attributes: runtimeDisabled,
            state: policy.resolutionMode == .compatibility ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: .compatibility,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        }
        let strict = UIAction(
            title: "Strict Handshake",
            image: UIImage(systemName: "checkmark.shield"),
            attributes: runtimeDisabled,
            state: policy.resolutionMode == .strict ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: .strict,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        }
        let modeMenu = UIMenu(
            title: "Resolution Mode",
            image: UIImage(systemName: "point.3.connected.trianglepath.dotted"),
            children: [compatibility, strict]
        )

        let statelessDANE = UIAction(
            title: "Stateless DANE Certificates",
            image: UIImage(systemName: "lock.shield"),
            attributes: runtimeDisabled,
            state: policy.statelessDANECertificates ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: !policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        }

        let experimentalP2PRelay = UIAction(
            title: "Experimental P2P DNS Relay",
            image: UIImage(systemName: "point.3.filled.connected.trianglepath.dotted"),
            attributes: runtimeDisabled,
            state: policy.experimentalP2PDNSRelay ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: !policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        }
        let legacyDoHCompatibility = UIAction(
            title: "Legacy HNS DoH Compatibility",
            image: UIImage(systemName: "network.badge.shield.half.filled"),
            attributes: runtimeDisabled,
            state: policy.legacyHNSDoHCompatibility ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: !policy.legacyHNSDoHCompatibility
                )
            )
        }
        let resolverPaths = UIMenu(
            title: "Resolver Paths",
            image: UIImage(systemName: "arrow.triangle.branch"),
            children: [experimentalP2PRelay, legacyDoHCompatibility]
        )

        let configureDoH = UIAction(
            title: "Configure DoH Resolver…",
            image: UIImage(systemName: "server.rack"),
            attributes: runtimeDisabled
        ) { [weak self] _ in
            self?.presentDoHConfiguration()
        }
        let clearDoHAttributes: UIMenuElement.Attributes =
            !runtimeControlsAreAvailable || isControlOperationInFlight || policy.hnsDohResolver == nil
                ? .disabled : []
        let clearDoH = UIAction(
            title: "Use Default Resolver",
            image: UIImage(systemName: "arrow.uturn.backward"),
            attributes: clearDoHAttributes
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: nil,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        }
        let dohMenu = UIMenu(
            title: policy.hnsDohResolver == nil ? "Default HNS Resolver" : "Configured HNS DoH",
            image: UIImage(systemName: "globe.desk"),
            children: [configureDoH, clearDoH]
        )

        let syncNow = UIAction(
            title: "Sync Headers Now",
            image: UIImage(systemName: "arrow.triangle.2.circlepath"),
            attributes: runtimeDisabled
        ) { [weak self] _ in
            self?.syncNow()
        }
        let clearCache = UIAction(
            title: "Clear Resolver Cache",
            image: UIImage(systemName: "trash"),
            attributes: runtimeDisabled
        ) { [weak self] _ in
            self?.clearResolverCache()
        }
        let proofDetails = UIAction(
            title: "Proof Details",
            image: UIImage(systemName: "doc.text.magnifyingglass"),
            attributes: runtimeDisabled
        ) { [weak self] _ in
            self?.showProofDetails()
        }
        let maintenance = UIMenu(
            title: "",
            options: .displayInline,
            children: [syncNow, clearCache, proofDetails]
        )

        let privacyPolicy = UIAction(
            title: "Privacy Policy",
            image: UIImage(systemName: "hand.raised")
        ) { [weak self] _ in
            self?.presentStorefrontPage(Self.privacyPolicyURL)
        }
        let support = UIAction(
            title: "Support",
            image: UIImage(systemName: "questionmark.circle")
        ) { [weak self] _ in
            self?.presentStorefrontPage(Self.supportURL)
        }
        let thirdPartyNotices = UIAction(
            title: "Third-Party Notices",
            image: UIImage(systemName: "doc.plaintext")
        ) { [weak self] _ in
            self?.presentThirdPartyNotices()
        }
        let about = UIMenu(
            title: "Information",
            image: UIImage(systemName: "info.circle"),
            children: [privacyPolicy, support, thirdPartyNotices]
        )
        controlsButton.menu = UIMenu(
            title: "Browser Settings",
            children: [modeMenu, statelessDANE, resolverPaths, dohMenu, maintenance, about]
        )
    }

    private func presentStorefrontPage(_ url: URL) {
        guard presentedViewController == nil else { return }
        let browser = SFSafariViewController(url: url)
        browser.dismissButtonStyle = .close
        present(browser, animated: true)
    }

    private func presentThirdPartyNotices() {
        guard presentedViewController == nil else { return }
        guard let url = Bundle.main.url(
            forResource: "third_party_notices",
            withExtension: "txt"
        ), let notices = try? String(contentsOf: url, encoding: .utf8) else {
            showOperationError(
                title: "Third-party notices unavailable",
                error: BrowserCoreError.runtimeUnavailable("The bundled notices could not be read.")
            )
            return
        }
        let viewer = TextDocumentViewController(
            title: "Third-Party Notices",
            text: notices
        )
        present(UINavigationController(rootViewController: viewer), animated: true)
    }

    private var runtimeControlsAreAvailable: Bool {
#if DEBUG && targetEnvironment(simulator)
        environment != nil || appStoreScreenshotScene != nil
#else
        environment != nil
#endif
    }

    private func presentDoHConfiguration() {
        guard !isControlOperationInFlight else { return }
        let policy = process.currentPolicy
        let alert = UIAlertController(
            title: "Configured HNS DoH Resolver",
            message: "Enter an HTTPS DNS-over-HTTPS endpoint. Leave it empty to use the runtime default.",
            preferredStyle: .alert
        )
        alert.addTextField { textField in
            textField.text = policy.hnsDohResolver
            textField.placeholder = "https://resolver.example/dns-query"
            textField.keyboardType = .URL
            textField.autocapitalizationType = .none
            textField.autocorrectionType = .no
            textField.clearButtonMode = .whileEditing
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Use Default", style: .default) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: nil,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        })
        alert.addAction(UIAlertAction(title: "Apply", style: .default) { [weak self, weak alert] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: alert?.textFields?.first?.text,
                    statelessDANECertificates: policy.statelessDANECertificates,
                    experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
                    legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
                )
            )
        })
        present(alert, animated: true)
    }

    private func applyRuntimePolicy(_ policy: BrowserRuntimePolicy) {
        guard !isControlOperationInFlight, let environment else { return }
        guard policy != process.currentPolicy else {
            rebuildControlsMenu()
            return
        }

        let replayAddress = coordinator?.replayableAddressForRuntimeChange()
        if isForeground {
            process.suspendForegroundSync()
        }
        setControlOperationInFlight(true)
        addressField.isEnabled = false
        coordinator?.destroy()
        coordinator = nil
        progressObservation = nil
        placeholderLabel.isHidden = false
        placeholderLabel.text = "Applying runtime policy…"
        syncLabel.text = "Applying policy"

        process.updatePolicy(policy) { [weak self] result in
            guard let self, !self.isDestroyed else { return }
            self.addressField.isEnabled = true
            self.setControlOperationInFlight(false)
            self.installCoordinator(environment: environment, replayAddress: replayAddress)
            if self.isForeground {
                self.process.resumeForegroundSync { [weak self] summary in
                    self?.updateSyncSummary(summary)
                }
            }
            switch result {
            case .success(let revision):
                self.syncLabel.text = "Runtime policy revision \(revision)"
            case .failure(let error):
                self.showOperationError(title: "Policy update failed", error: error)
            }
        }
    }

    private func syncNow() {
        guard beginControlOperation() else { return }
        syncLabel.text = "Syncing Handshake headers…"
        process.syncNow { [weak self] result in
            guard let self, !self.isDestroyed else { return }
            self.setControlOperationInFlight(false)
            switch result {
            case .success(let summary):
                self.updateSyncSummary(summary)
                self.showRuntimeSummary(summary)
            case .failure(let error): self.showOperationError(title: "Header sync failed", error: error)
            }
        }
    }

    private func clearResolverCache() {
        guard beginControlOperation() else { return }
        process.clearResolverCache { [weak self] result in
            guard let self, !self.isDestroyed else { return }
            self.setControlOperationInFlight(false)
            switch result {
            case .success(let summary):
                self.updateSyncSummary(summary)
                self.showRuntimeSummary(summary)
            case .failure(let error): self.showOperationError(title: "Cache clear failed", error: error)
            }
        }
    }

    private func showProofDetails() {
        guard beginControlOperation() else { return }
        let value = coordinator?.currentShareURL?.absoluteString
            ?? addressField.text?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? ""
        guard !value.isEmpty else {
            setControlOperationInFlight(false)
            showOperationError(
                title: "Proof details unavailable",
                error: BrowserCoreError.invalidAddress("Enter a Handshake address first.")
            )
            return
        }

        process.proofDetails(for: value) { [weak self] result in
            guard let self, !self.isDestroyed else { return }
            self.setControlOperationInFlight(false)
            switch result {
            case .success(let details):
                let viewer = ProofDetailsViewController(details: details)
                self.present(UINavigationController(rootViewController: viewer), animated: true)
            case .failure(let error):
                self.showOperationError(title: "Proof details unavailable", error: error)
            }
        }
    }

    private func beginControlOperation() -> Bool {
        guard !isControlOperationInFlight, environment != nil else { return false }
        setControlOperationInFlight(true)
        return true
    }

    private func setControlOperationInFlight(_ value: Bool) {
        isControlOperationInFlight = value
        controlsButton.isEnabled = !isDestroyed && !value
        rebuildControlsMenu()
    }

    private func updateSecuritySummary(_ summary: BrowserSecuritySummary) {
        let symbol: String
        let color: UIColor
        switch summary.level {
        case .pending:
            symbol = "hourglass"
            color = .secondaryLabel
        case .webPKI:
            symbol = "lock.fill"
            color = .systemBlue
        case .insecure:
            symbol = "lock.open.fill"
            color = .systemOrange
        case .handshakeDANE:
            symbol = "checkmark.shield.fill"
            color = .systemGreen
        case .handshakeFallback:
            symbol = "shield.lefthalf.filled"
            color = .systemOrange
        case .blocked:
            symbol = "xmark.shield.fill"
            color = .systemRed
        }
        let attachment = NSTextAttachment()
        attachment.image = UIImage(systemName: symbol)?.withTintColor(color)
        let value = NSMutableAttributedString(attachment: attachment)
        value.append(NSAttributedString(string: " \(summary.detail)"))
        securityLabel.attributedText = value
        securityLabel.accessibilityLabel = summary.detail
    }

    private func updateSyncSummary(_ summary: BrowserSyncSummary) {
        syncLabel.text = summary.headline
        syncLabel.accessibilityLabel = "\(summary.headline). \(summary.detail)"
    }

    private func showOperationError(title: String, error: Error) {
        guard presentedViewController == nil else { return }
        let alert = UIAlertController(
            title: title,
            message: error.localizedDescription,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    private func showRuntimeSummary(_ summary: BrowserSyncSummary) {
        guard presentedViewController == nil else { return }
        let alert = UIAlertController(
            title: summary.headline,
            message: summary.detail,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    private func presentShareSheet(items: [Any], sourceView: UIView) {
        let activity = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let popover = activity.popoverPresentationController {
            popover.sourceView = sourceView
            popover.sourceRect = sourceView.bounds
        }
        present(activity, animated: true)
    }
}

extension BrowserViewController: UITextFieldDelegate {
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        textField.resignFirstResponder()
        guard let value = textField.text else { return false }
        coordinator?.navigate(rawValue: value)
        return true
    }
}

extension BrowserViewController: BrowserProxyCoordinatorDelegate {
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, install webView: WKWebView) {
        progressObservation = webView.observe(\.estimatedProgress, options: [.initial, .new]) { [weak self] webView, _ in
            DispatchQueue.main.async {
                self?.progressView.progress = Float(webView.estimatedProgress)
            }
        }
        webView.translatesAutoresizingMaskIntoConstraints = false
        webContainer.addSubview(webView)
        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: webContainer.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: webContainer.trailingAnchor),
            webView.topAnchor.constraint(equalTo: webContainer.topAnchor),
            webView.bottomAnchor.constraint(equalTo: webContainer.bottomAnchor),
        ])
        placeholderLabel.isHidden = true
    }

    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, remove webView: WKWebView) {
        progressObservation = nil
        placeholderLabel.isHidden = false
        placeholderLabel.text = isForeground ? "Switching secure browsing context…" : "Secure browsing paused"
    }

    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didUpdateAddress address: String) {
        addressField.text = address
        shareButton.isEnabled = true
    }

    func proxyCoordinator(
        _ coordinator: BrowserProxyCoordinator,
        canGoBack: Bool,
        canGoForward: Bool,
        isLoading: Bool
    ) {
        backButton.isEnabled = canGoBack
        forwardButton.isEnabled = canGoForward
        self.isLoading = isLoading
        let symbol = isLoading ? "xmark" : "arrow.clockwise"
        reloadButton.setImage(UIImage(systemName: symbol), for: .normal)
        reloadButton.accessibilityLabel = isLoading ? "Stop" : "Reload"
        if !isLoading { progressView.progress = 0 }
    }

    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didUpdateSecurity summary: BrowserSecuritySummary) {
        updateSecuritySummary(summary)
    }

    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didUpdateSync summary: BrowserSyncSummary) {
        updateSyncSummary(summary)
    }

    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didFail error: Error) {
        showError(error)
    }

    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didFinishDownloadAt url: URL) {
        let alert = UIAlertController(
            title: "Download complete",
            message: url.lastPathComponent,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Share or Save to Files", style: .default) { [weak self] _ in
            guard let self else { return }
            self.presentShareSheet(items: [url], sourceView: self.shareButton)
        })
        alert.addAction(UIAlertAction(title: "Done", style: .cancel))
        present(alert, animated: true)
    }
}

@MainActor
private final class ProofDetailsViewController: UIViewController {
    private let details: BrowserProofDetails
    private let accessibilityIdentifier: String?
    private let textView = UITextView()

    init(details: BrowserProofDetails, accessibilityIdentifier: String? = nil) {
        self.details = details
        self.accessibilityIdentifier = accessibilityIdentifier
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = details.headline

        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .close,
            target: self,
            action: #selector(closeViewer)
        )
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "square.and.arrow.up"),
            style: .plain,
            target: self,
            action: #selector(exportDetails)
        )
        navigationItem.rightBarButtonItem?.accessibilityLabel = "Export proof details"

        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.isEditable = false
        textView.isSelectable = true
        textView.alwaysBounceVertical = true
        textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.text = "\(details.detail)\n\n\(details.formattedJSON)"
        textView.accessibilityLabel = "Handshake proof details for \(details.host)"
        textView.accessibilityIdentifier = accessibilityIdentifier
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            textView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    @objc private func closeViewer() {
        dismiss(animated: true)
    }

    @objc private func exportDetails() {
        let activity = UIActivityViewController(
            activityItems: [details.formattedJSON],
            applicationActivities: nil
        )
        if let popover = activity.popoverPresentationController {
            popover.barButtonItem = navigationItem.rightBarButtonItem
        }
        present(activity, animated: true)
    }
}

@MainActor
private final class TextDocumentViewController: UIViewController {
    private let documentTitle: String
    private let documentText: String
    private let textView = UITextView()

    init(title: String, text: String) {
        documentTitle = title
        documentText = text
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = documentTitle
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .close,
            target: self,
            action: #selector(closeViewer)
        )

        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.isEditable = false
        textView.isSelectable = true
        textView.alwaysBounceVertical = true
        textView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.text = documentText
        textView.accessibilityLabel = documentTitle
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            textView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    @objc private func closeViewer() {
        dismiss(animated: true)
    }
}
