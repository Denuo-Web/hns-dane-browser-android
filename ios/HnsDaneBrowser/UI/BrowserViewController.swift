import UIKit
import WebKit

@MainActor
final class BrowserViewController: UIViewController {
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
        prepareRuntime()
    }

    func resumeBrowsing() {
        guard !isDestroyed else { return }
        isForeground = true
        coordinator?.resume()
        process.resumeForegroundSync { [weak self] summary in
            self?.updateSyncSummary(summary)
        }
    }

    func suspendBrowsing() {
        guard !isDestroyed else { return }
        isForeground = false
        coordinator?.suspend()
        process.suspendForegroundSync()
        placeholderLabel.text = "Secure browsing paused"
    }

    func destroyBrowsing() {
        guard !isDestroyed else { return }
        isDestroyed = true
        isForeground = false
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
        controlsButton.accessibilityLabel = "Handshake runtime controls"
        controlsButton.showsMenuAsPrimaryAction = true
        backButton.isEnabled = false
        forwardButton.isEnabled = false
        shareButton.isEnabled = false
        controlsButton.isEnabled = false

        addressField.borderStyle = .roundedRect
        addressField.clearButtonMode = .whileEditing
        addressField.keyboardType = .URL
        addressField.returnKeyType = .go
        addressField.autocapitalizationType = .none
        addressField.autocorrectionType = .no
        addressField.spellCheckingType = .no
        addressField.placeholder = "Enter a web or Handshake address"
        addressField.accessibilityLabel = "Address"
        addressField.delegate = self

        securityLabel.font = .preferredFont(forTextStyle: .caption1)
        securityLabel.adjustsFontForContentSizeCategory = true
        securityLabel.textColor = .secondaryLabel
        securityLabel.numberOfLines = 1
        securityLabel.text = "Security pending"

        syncLabel.font = .preferredFont(forTextStyle: .caption2)
        syncLabel.adjustsFontForContentSizeCategory = true
        syncLabel.textColor = .tertiaryLabel
        syncLabel.numberOfLines = 1
        syncLabel.textAlignment = .right
        syncLabel.text = "Preparing runtime"

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
        let disabled: UIMenuElement.Attributes = isControlOperationInFlight ? .disabled : []

        let compatibility = UIAction(
            title: "Compatibility",
            image: UIImage(systemName: "network"),
            attributes: disabled,
            state: policy.resolutionMode == .compatibility ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: .compatibility,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: policy.statelessDANECertificates
                )
            )
        }
        let strict = UIAction(
            title: "Strict Handshake",
            image: UIImage(systemName: "checkmark.shield"),
            attributes: disabled,
            state: policy.resolutionMode == .strict ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: .strict,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: policy.statelessDANECertificates
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
            attributes: disabled,
            state: policy.statelessDANECertificates ? .on : .off
        ) { [weak self] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: policy.hnsDohResolver,
                    statelessDANECertificates: !policy.statelessDANECertificates
                )
            )
        }

        let configureDoH = UIAction(
            title: "Configure DoH Resolver…",
            image: UIImage(systemName: "server.rack"),
            attributes: disabled
        ) { [weak self] _ in
            self?.presentDoHConfiguration()
        }
        let clearDoHAttributes: UIMenuElement.Attributes =
            isControlOperationInFlight || policy.hnsDohResolver == nil ? .disabled : []
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
                    statelessDANECertificates: policy.statelessDANECertificates
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
            attributes: disabled
        ) { [weak self] _ in
            self?.syncNow()
        }
        let clearCache = UIAction(
            title: "Clear Resolver Cache",
            image: UIImage(systemName: "trash"),
            attributes: disabled
        ) { [weak self] _ in
            self?.clearResolverCache()
        }
        let proofDetails = UIAction(
            title: "Proof Details",
            image: UIImage(systemName: "doc.text.magnifyingglass"),
            attributes: disabled
        ) { [weak self] _ in
            self?.showProofDetails()
        }
        let maintenance = UIMenu(
            title: "",
            options: .displayInline,
            children: [syncNow, clearCache, proofDetails]
        )
        controlsButton.menu = UIMenu(
            title: "Handshake Runtime",
            children: [modeMenu, statelessDANE, dohMenu, maintenance]
        )
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
                    statelessDANECertificates: policy.statelessDANECertificates
                )
            )
        })
        alert.addAction(UIAlertAction(title: "Apply", style: .default) { [weak self, weak alert] _ in
            guard let self else { return }
            self.applyRuntimePolicy(
                BrowserRuntimePolicy(
                    resolutionMode: policy.resolutionMode,
                    hnsDohResolver: alert?.textFields?.first?.text,
                    statelessDANECertificates: policy.statelessDANECertificates
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
        controlsButton.isEnabled = environment != nil && !value
        rebuildControlsMenu()
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
    private let textView = UITextView()

    init(details: BrowserProofDetails) {
        self.details = details
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
