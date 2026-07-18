import UIKit

@MainActor
protocol BrowserSettingsViewControllerDelegate: AnyObject {
    func browserSettingsViewController(
        _ controller: BrowserSettingsViewController,
        didRequest action: BrowserSettingsViewController.Action
    )
}

/// Native settings UI that follows the Android app's section and row hierarchy
/// while exposing only controls backed by the iOS runtime.
@MainActor
final class BrowserSettingsViewController: UITableViewController {
    enum Action: Equatable {
        case applyRuntimePolicy(BrowserRuntimePolicy)
        case clearResolverCache
        case runHNSSync
        case showHNSProofDetails
        case showPrivacyPolicy
        case showSupport
        case showSourceCode
        case showThirdPartyNotices
    }

    enum Section: Int, CaseIterable {
        case hnsResolution
        case diagnosticsAndTools
        case aboutLegalAndSupport

        var title: String {
            switch self {
            case .hnsResolution: "HNS resolution"
            case .diagnosticsAndTools: "Diagnostics and tools"
            case .aboutLegalAndSupport: "About, legal, and support"
            }
        }

        var accessibilityIdentifier: String {
            switch self {
            case .hnsResolution: "settings.section.hns-resolution"
            case .diagnosticsAndTools: "settings.section.diagnostics-and-tools"
            case .aboutLegalAndSupport: "settings.section.about-legal-and-support"
            }
        }
    }

    enum Row: Int, CaseIterable {
        case strictHNSMode
        case statelessDANECertificates
        case experimentalP2PDNSRelay
        case legacyHNSDoHCompatibility
        case compatibilityDoHResolver
        case clearResolverCache
        case hnsSync
        case hnsProofDetails
        case build
        case privacyPolicy
        case support
        case sourceCode
        case thirdPartyNotices

        var title: String {
            switch self {
            case .strictHNSMode: "Strict HNS mode"
            case .statelessDANECertificates: "Experimental stateless DANE certificates"
            case .experimentalP2PDNSRelay: "Experimental P2P DNS relay"
            case .legacyHNSDoHCompatibility: "Legacy HNS DoH compatibility"
            case .compatibilityDoHResolver: "Compatibility DoH resolver"
            case .clearResolverCache: "Clear resolver cache"
            case .hnsSync: "HNS sync"
            case .hnsProofDetails: "HNS proof details"
            case .build: "Build"
            case .privacyPolicy: "Privacy policy"
            case .support: "Support"
            case .sourceCode: "Source code"
            case .thirdPartyNotices: "Third-party notices"
            }
        }

        var accessibilityIdentifier: String {
            switch self {
            case .strictHNSMode: "settings.hns-resolution.strict-hns-mode"
            case .statelessDANECertificates:
                "settings.hns-resolution.stateless-dane-certificates"
            case .experimentalP2PDNSRelay:
                "settings.hns-resolution.experimental-p2p-dns-relay"
            case .legacyHNSDoHCompatibility:
                "settings.hns-resolution.legacy-hns-doh-compatibility"
            case .compatibilityDoHResolver:
                "settings.hns-resolution.compatibility-doh-resolver"
            case .clearResolverCache: "settings.hns-resolution.clear-resolver-cache"
            case .hnsSync: "settings.hns-resolution.hns-sync"
            case .hnsProofDetails: "browser-settings.proof-details"
            case .build: "settings.about-legal-and-support.build"
            case .privacyPolicy: "settings.about-legal-and-support.privacy-policy"
            case .support: "settings.about-legal-and-support.support"
            case .sourceCode: "settings.about-legal-and-support.source-code"
            case .thirdPartyNotices: "settings.about-legal-and-support.third-party-notices"
            }
        }

        var isRuntimeAction: Bool {
            switch self {
            case .strictHNSMode,
                 .statelessDANECertificates,
                 .experimentalP2PDNSRelay,
                 .legacyHNSDoHCompatibility,
                 .compatibilityDoHResolver,
                 .clearResolverCache,
                 .hnsProofDetails:
                true
            case .hnsSync,
                 .build,
                 .privacyPolicy,
                 .support,
                 .sourceCode,
                 .thirdPartyNotices:
                false
            }
        }

        var isToggle: Bool {
            switch self {
            case .strictHNSMode,
                 .statelessDANECertificates,
                 .experimentalP2PDNSRelay,
                 .legacyHNSDoHCompatibility:
                true
            default:
                false
            }
        }
    }

    static let privacyPolicyURL = "https://denuoweb.com/work/hns-dane-browser/privacy"
    static let supportURL = "https://denuoweb.com/work/hns-dane-browser"
    static let sourceCodeURL = "https://github.com/Denuo-Web/hns-dane-browser"
    static let defaultDoHResolverURL = "https://zorro.hnsdoh.com/dns-query"

    weak var delegate: BrowserSettingsViewControllerDelegate?

    private var policy: BrowserRuntimePolicy
    private var runtimeControlsAreAvailable: Bool
    private var isOperationInFlight: Bool
    private var syncSummary: BrowserSyncSummary
    private var resolverCacheSummary: String
    private weak var hnsSyncViewController: HNSSyncViewController?

    init(
        policy: BrowserRuntimePolicy,
        runtimeControlsAreAvailable: Bool,
        isOperationInFlight: Bool = false,
        syncSummary: BrowserSyncSummary = .unavailable,
        resolverCacheSummary: String = "Ready to clear cached resolver values."
    ) {
        self.policy = policy
        self.runtimeControlsAreAvailable = runtimeControlsAreAvailable
        self.isOperationInFlight = isOperationInFlight
        self.syncSummary = syncSummary
        self.resolverCacheSummary = resolverCacheSummary
        super.init(style: .insetGrouped)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Settings"
        view.backgroundColor = .systemGroupedBackground
        tableView.accessibilityIdentifier = "settings.table"
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 76
        tableView.sectionHeaderHeight = UITableView.automaticDimension
        tableView.estimatedSectionHeaderHeight = 44
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .close,
            target: self,
            action: #selector(closeSettings)
        )
        navigationItem.rightBarButtonItem?.accessibilityLabel = "Close settings"
        navigationItem.rightBarButtonItem?.accessibilityIdentifier = "settings.close"
    }

    /// Refreshes the displayed runtime state after the browser completes an
    /// asynchronous settings action. The controller never writes preferences.
    func update(
        policy: BrowserRuntimePolicy,
        runtimeControlsAreAvailable: Bool,
        isOperationInFlight: Bool,
        syncSummary: BrowserSyncSummary = .unavailable,
        resolverCacheSummary: String? = nil
    ) {
        self.policy = policy
        self.runtimeControlsAreAvailable = runtimeControlsAreAvailable
        self.isOperationInFlight = isOperationInFlight
        self.syncSummary = syncSummary
        if let resolverCacheSummary {
            self.resolverCacheSummary = resolverCacheSummary
        }
        guard isViewLoaded else { return }
        tableView.reloadData()
        hnsSyncViewController?.update(
            summary: syncSummary,
            runtimeControlsAreAvailable: runtimeControlsAreAvailable,
            isOperationInFlight: isOperationInFlight
        )
    }

    static func rows(in section: Section) -> [Row] {
        switch section {
        case .hnsResolution:
            [
                .strictHNSMode,
                .statelessDANECertificates,
                .experimentalP2PDNSRelay,
                .legacyHNSDoHCompatibility,
                .compatibilityDoHResolver,
                .clearResolverCache,
                .hnsSync,
            ]
        case .diagnosticsAndTools:
            [.hnsProofDetails]
        case .aboutLegalAndSupport:
            [.build, .privacyPolicy, .support, .sourceCode, .thirdPartyNotices]
        }
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        Section.allCases.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        guard let section = Section(rawValue: section) else { return 0 }
        return Self.rows(in: section).count
    }

    override func tableView(
        _ tableView: UITableView,
        viewForHeaderInSection sectionIndex: Int
    ) -> UIView? {
        guard let section = Section(rawValue: sectionIndex) else { return nil }
        let header = UITableViewHeaderFooterView(reuseIdentifier: nil)
        var content = UIListContentConfiguration.groupedHeader()
        content.text = section.title
        content.textProperties.font = .preferredFont(forTextStyle: .headline)
        header.contentConfiguration = content
        header.accessibilityIdentifier = section.accessibilityIdentifier
        return header
    }

    override func tableView(
        _ tableView: UITableView,
        cellForRowAt indexPath: IndexPath
    ) -> UITableViewCell {
        guard let row = row(at: indexPath) else { return UITableViewCell() }
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.accessibilityIdentifier = row.accessibilityIdentifier
        cell.backgroundColor = .secondarySystemGroupedBackground

        var content = UIListContentConfiguration.subtitleCell()
        content.text = row.title
        content.secondaryText = summary(for: row)
        content.textProperties.font = .preferredFont(forTextStyle: .body)
        content.textProperties.numberOfLines = 0
        content.secondaryTextProperties.font = .preferredFont(forTextStyle: .footnote)
        content.secondaryTextProperties.color = .secondaryLabel
        content.secondaryTextProperties.numberOfLines = 0
        content.prefersSideBySideTextAndSecondaryText = false
        cell.contentConfiguration = content

        if row.isToggle {
            configureToggleCell(cell, row: row)
        } else {
            configureActionCell(cell, row: row)
        }
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard let row = row(at: indexPath), !row.isToggle else { return }
        guard !row.isRuntimeAction || runtimeActionsAreEnabled else { return }

        switch row {
        case .compatibilityDoHResolver:
            presentDoHConfiguration()
        case .clearResolverCache:
            confirmClearResolverCache()
        case .hnsSync:
            showHNSSync()
        case .hnsProofDetails:
            request(.showHNSProofDetails, marksOperationInFlight: true)
        case .privacyPolicy:
            request(.showPrivacyPolicy)
        case .support:
            request(.showSupport)
        case .sourceCode:
            request(.showSourceCode)
        case .thirdPartyNotices:
            request(.showThirdPartyNotices)
        case .build,
             .strictHNSMode,
             .statelessDANECertificates,
             .experimentalP2PDNSRelay,
             .legacyHNSDoHCompatibility:
            break
        }
    }

    private var runtimeActionsAreEnabled: Bool {
        runtimeControlsAreAvailable && !isOperationInFlight
    }

    private func row(at indexPath: IndexPath) -> Row? {
        guard let section = Section(rawValue: indexPath.section) else { return nil }
        let rows = Self.rows(in: section)
        guard rows.indices.contains(indexPath.row) else { return nil }
        return rows[indexPath.row]
    }

    private func summary(for row: Row) -> String {
        switch row {
        case .strictHNSMode:
            if policy.resolutionMode == .strict {
                return "On. Delegated resolution failures fail closed."
            }
            return "Off. Compatibility fallback may be used after local or direct resolution fails."
        case .statelessDANECertificates:
            if policy.statelessDANECertificates {
                return "On. Certificate-carried HNS proof evidence may satisfy DANE when valid."
            }
            return "Off. HNS proof and TLSA evidence use the live resolver path."
        case .experimentalP2PDNSRelay:
            if policy.experimentalP2PDNSRelay {
                return "On. Delegated DNS may use relay-capable Handshake peers; DNSSEC validation remains local."
            }
            return "Off. Peer DNS relay messages are not used."
        case .legacyHNSDoHCompatibility:
            if policy.legacyHNSDoHCompatibility {
                return "On by default. The configured third-party HNS DoH path remains available as a compatibility fallback."
            }
            return "Off. The legacy third-party HNS DoH compatibility path is disabled independently of P2P relay."
        case .compatibilityDoHResolver:
            return policy.hnsDohResolver ?? Self.defaultDoHResolverURL
        case .clearResolverCache:
            return resolverCacheSummary
        case .hnsSync:
            return "View sync status and run a manual sync."
        case .hnsProofDetails:
            return "Inspect local proof data for an HNS name."
        case .build:
            return Self.buildLabel
        case .privacyPolicy:
            return Self.privacyPolicyURL
        case .support:
            return Self.supportURL
        case .sourceCode:
            return Self.sourceCodeURL
        case .thirdPartyNotices:
            return "Open-source components, licenses, and attribution notices included with this app."
        }
    }

    private func configureToggleCell(_ cell: UITableViewCell, row: Row) {
        let toggle = UISwitch()
        toggle.tag = row.rawValue
        toggle.isOn = toggleValue(for: row)
        toggle.isEnabled = runtimeActionsAreEnabled
        toggle.accessibilityLabel = row.title
        toggle.accessibilityIdentifier = "\(row.accessibilityIdentifier).toggle"
        toggle.addTarget(self, action: #selector(runtimeToggleChanged(_:)), for: .valueChanged)
        cell.accessoryView = toggle
        cell.selectionStyle = .none
        cell.isUserInteractionEnabled = true
        applyEnabledAppearance(runtimeActionsAreEnabled, to: cell)
    }

    private func configureActionCell(_ cell: UITableViewCell, row: Row) {
        let enabled = !row.isRuntimeAction || runtimeActionsAreEnabled
        cell.isUserInteractionEnabled = enabled || row == .build
        applyEnabledAppearance(enabled || row == .build, to: cell)

        switch row {
        case .build:
            cell.selectionStyle = .none
        case .clearResolverCache:
            var content = cell.contentConfiguration as? UIListContentConfiguration
                ?? .subtitleCell()
            content.textProperties.color = enabled ? .systemRed : .tertiaryLabel
            cell.contentConfiguration = content
        default:
            break
        }

        if let actionTitle = actionTitle(for: row) {
            let actionLabel = UILabel()
            actionLabel.text = actionTitle
            actionLabel.font = .preferredFont(forTextStyle: .subheadline)
            actionLabel.adjustsFontForContentSizeCategory = true
            actionLabel.textColor = enabled
                ? (row == .clearResolverCache ? .systemRed : view.tintColor)
                : .tertiaryLabel
            actionLabel.accessibilityElementsHidden = true
            cell.accessoryView = actionLabel
        }
    }

    private func applyEnabledAppearance(_ enabled: Bool, to cell: UITableViewCell) {
        guard var content = cell.contentConfiguration as? UIListContentConfiguration else { return }
        content.textProperties.color = enabled ? .label : .tertiaryLabel
        content.secondaryTextProperties.color = enabled ? .secondaryLabel : .tertiaryLabel
        cell.contentConfiguration = content
    }

    private func actionTitle(for row: Row) -> String? {
        switch row {
        case .compatibilityDoHResolver: "Edit"
        case .clearResolverCache: "Clear"
        case .hnsSync: "View"
        case .hnsProofDetails,
             .privacyPolicy,
             .support,
             .sourceCode,
             .thirdPartyNotices:
            "Open"
        case .build,
             .strictHNSMode,
             .statelessDANECertificates,
             .experimentalP2PDNSRelay,
             .legacyHNSDoHCompatibility:
            nil
        }
    }

    private func toggleValue(for row: Row) -> Bool {
        switch row {
        case .strictHNSMode:
            policy.resolutionMode == .strict
        case .statelessDANECertificates:
            policy.statelessDANECertificates
        case .experimentalP2PDNSRelay:
            policy.experimentalP2PDNSRelay
        case .legacyHNSDoHCompatibility:
            policy.legacyHNSDoHCompatibility
        default:
            false
        }
    }

    @objc private func runtimeToggleChanged(_ sender: UISwitch) {
        guard runtimeActionsAreEnabled, let row = Row(rawValue: sender.tag) else {
            sender.setOn(!sender.isOn, animated: true)
            return
        }

        let updatedPolicy: BrowserRuntimePolicy
        switch row {
        case .strictHNSMode:
            updatedPolicy = policyByReplacingResolutionMode(
                sender.isOn ? .strict : .compatibility
            )
        case .statelessDANECertificates:
            updatedPolicy = policyByReplacingStatelessDANECertificates(sender.isOn)
        case .experimentalP2PDNSRelay:
            updatedPolicy = policyByReplacingExperimentalP2PDNSRelay(sender.isOn)
        case .legacyHNSDoHCompatibility:
            updatedPolicy = policyByReplacingLegacyHNSDoHCompatibility(sender.isOn)
        default:
            return
        }
        requestPolicyUpdate(updatedPolicy)
    }

    private func presentDoHConfiguration() {
        let alert = UIAlertController(
            title: "Edit DoH resolver",
            message: "Enter an HTTPS DNS-over-HTTPS endpoint. Leave blank to use the default.",
            preferredStyle: .alert
        )
        alert.addTextField { [policy = self.policy] textField in
            textField.text = policy.hnsDohResolver ?? Self.defaultDoHResolverURL
            textField.placeholder = "https://resolver.example/dns-query"
            textField.keyboardType = .URL
            textField.autocapitalizationType = .none
            textField.autocorrectionType = .no
            textField.clearButtonMode = .whileEditing
            textField.accessibilityIdentifier =
                "settings.hns-resolution.compatibility-doh-resolver.field"
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Reset", style: .default) { [weak self] _ in
            guard let self else { return }
            self.requestPolicyUpdate(self.policyByReplacingDoHResolver(nil))
        })
        alert.addAction(UIAlertAction(title: "Save", style: .default) { [weak self, weak alert] _ in
            guard let self else { return }
            self.requestPolicyUpdate(
                self.policyByReplacingDoHResolver(alert?.textFields?.first?.text)
            )
        })
        present(alert, animated: true)
    }

    private func confirmClearResolverCache() {
        let alert = UIAlertController(
            title: "Clear resolver cache?",
            message: "The app will keep synced Mainnet headers and peers, but cached HNS resource values for this network will be removed.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Clear", style: .destructive) { [weak self] _ in
            self?.request(.clearResolverCache, marksOperationInFlight: true)
        })
        present(alert, animated: true)
    }

    private func showHNSSync() {
        let controller = HNSSyncViewController(
            summary: syncSummary,
            runtimeControlsAreAvailable: runtimeControlsAreAvailable,
            isOperationInFlight: isOperationInFlight
        )
        controller.onRunSync = { [weak self] in
            self?.request(.runHNSSync, marksOperationInFlight: true)
        }
        hnsSyncViewController = controller
        navigationController?.pushViewController(controller, animated: true)
    }

    private func requestPolicyUpdate(_ updatedPolicy: BrowserRuntimePolicy) {
        guard updatedPolicy != policy else {
            tableView.reloadData()
            return
        }
        policy = updatedPolicy
        request(.applyRuntimePolicy(updatedPolicy), marksOperationInFlight: true)
    }

    private func request(_ action: Action, marksOperationInFlight: Bool = false) {
        if marksOperationInFlight {
            isOperationInFlight = true
            tableView.reloadData()
            hnsSyncViewController?.update(
                summary: syncSummary,
                runtimeControlsAreAvailable: runtimeControlsAreAvailable,
                isOperationInFlight: true
            )
        }
        delegate?.browserSettingsViewController(self, didRequest: action)
    }

    private func policyByReplacingResolutionMode(
        _ mode: BrowserResolutionMode
    ) -> BrowserRuntimePolicy {
        BrowserRuntimePolicy(
            resolutionMode: mode,
            hnsDohResolver: policy.hnsDohResolver,
            statelessDANECertificates: policy.statelessDANECertificates,
            experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
            legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
        )
    }

    private func policyByReplacingDoHResolver(_ resolver: String?) -> BrowserRuntimePolicy {
        BrowserRuntimePolicy(
            resolutionMode: policy.resolutionMode,
            hnsDohResolver: resolver,
            statelessDANECertificates: policy.statelessDANECertificates,
            experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
            legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
        )
    }

    private func policyByReplacingStatelessDANECertificates(
        _ enabled: Bool
    ) -> BrowserRuntimePolicy {
        BrowserRuntimePolicy(
            resolutionMode: policy.resolutionMode,
            hnsDohResolver: policy.hnsDohResolver,
            statelessDANECertificates: enabled,
            experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
            legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
        )
    }

    private func policyByReplacingExperimentalP2PDNSRelay(
        _ enabled: Bool
    ) -> BrowserRuntimePolicy {
        BrowserRuntimePolicy(
            resolutionMode: policy.resolutionMode,
            hnsDohResolver: policy.hnsDohResolver,
            statelessDANECertificates: policy.statelessDANECertificates,
            experimentalP2PDNSRelay: enabled,
            legacyHNSDoHCompatibility: policy.legacyHNSDoHCompatibility
        )
    }

    private func policyByReplacingLegacyHNSDoHCompatibility(
        _ enabled: Bool
    ) -> BrowserRuntimePolicy {
        BrowserRuntimePolicy(
            resolutionMode: policy.resolutionMode,
            hnsDohResolver: policy.hnsDohResolver,
            statelessDANECertificates: policy.statelessDANECertificates,
            experimentalP2PDNSRelay: policy.experimentalP2PDNSRelay,
            legacyHNSDoHCompatibility: enabled
        )
    }

    private static var buildLabel: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString")
            as? String ?? "Unknown"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")
            as? String ?? "Unknown"
        return "release \(version) (\(build))"
    }

    @objc private func closeSettings() {
        dismiss(animated: true)
    }
}

@MainActor
final class HNSSyncViewController: UITableViewController {
    enum Row: Int, CaseIterable {
        case syncStatus
        case runSyncNow
    }

    var onRunSync: (() -> Void)?

    private var summary: BrowserSyncSummary
    private var runtimeControlsAreAvailable: Bool
    private var isOperationInFlight: Bool

    init(
        summary: BrowserSyncSummary,
        runtimeControlsAreAvailable: Bool,
        isOperationInFlight: Bool
    ) {
        self.summary = summary
        self.runtimeControlsAreAvailable = runtimeControlsAreAvailable
        self.isOperationInFlight = isOperationInFlight
        super.init(style: .insetGrouped)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "HNS Sync"
        view.backgroundColor = .systemGroupedBackground
        tableView.accessibilityIdentifier = "hns-sync.table"
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 96
    }

    func update(
        summary: BrowserSyncSummary,
        runtimeControlsAreAvailable: Bool,
        isOperationInFlight: Bool
    ) {
        self.summary = summary
        self.runtimeControlsAreAvailable = runtimeControlsAreAvailable
        self.isOperationInFlight = isOperationInFlight
        guard isViewLoaded else { return }
        tableView.reloadData()
    }

    override func numberOfSections(in tableView: UITableView) -> Int { 1 }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        Row.allCases.count
    }

    override func tableView(
        _ tableView: UITableView,
        titleForHeaderInSection section: Int
    ) -> String? {
        "HNS sync"
    }

    override func tableView(
        _ tableView: UITableView,
        cellForRowAt indexPath: IndexPath
    ) -> UITableViewCell {
        guard let row = Row(rawValue: indexPath.row) else { return UITableViewCell() }
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = .secondarySystemGroupedBackground

        var content = UIListContentConfiguration.subtitleCell()
        content.textProperties.font = .preferredFont(forTextStyle: .body)
        content.secondaryTextProperties.font = .preferredFont(forTextStyle: .footnote)
        content.secondaryTextProperties.color = .secondaryLabel
        content.secondaryTextProperties.numberOfLines = 0
        content.prefersSideBySideTextAndSecondaryText = false

        switch row {
        case .syncStatus:
            content.text = "Sync status"
            content.secondaryText = Self.statusText(
                summary: summary,
                isOperationInFlight: isOperationInFlight
            )
            cell.accessibilityIdentifier = "hns-sync.status"
            cell.selectionStyle = .none
            if isOperationInFlight {
                let spinner = UIActivityIndicatorView(style: .medium)
                spinner.startAnimating()
                spinner.accessibilityLabel = "Sync running"
                cell.accessoryView = spinner
            }
        case .runSyncNow:
            content.text = "Run sync now"
            content.secondaryText =
                "Start a foreground HNS sync and watch the status update here."
            cell.accessibilityIdentifier = "hns-sync.run-now"
            let enabled = runtimeControlsAreAvailable && !isOperationInFlight
            content.textProperties.color = enabled ? .label : .tertiaryLabel
            content.secondaryTextProperties.color = enabled ? .secondaryLabel : .tertiaryLabel
            cell.isUserInteractionEnabled = enabled
            let actionLabel = UILabel()
            actionLabel.text = "Run"
            actionLabel.font = .preferredFont(forTextStyle: .subheadline)
            actionLabel.adjustsFontForContentSizeCategory = true
            actionLabel.textColor = enabled ? view.tintColor : .tertiaryLabel
            actionLabel.accessibilityElementsHidden = true
            cell.accessoryView = actionLabel
        }
        cell.contentConfiguration = content
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard Row(rawValue: indexPath.row) == .runSyncNow,
              runtimeControlsAreAvailable,
              !isOperationInFlight else {
            return
        }
        isOperationInFlight = true
        tableView.reloadData()
        onRunSync?()
    }

    static func statusText(
        summary: BrowserSyncSummary,
        isOperationInFlight: Bool
    ) -> String {
        var lines = [isOperationInFlight ? "Running…" : summary.headline]
        if !summary.detail.isEmpty {
            lines.append(summary.detail)
        }
        if let network = summary.network, !network.isEmpty {
            lines.append("Network: \(network)")
        }
        if summary.peerCount > 0 || summary.peerGroups > 0 {
            lines.append("Peers: \(summary.peerCount) in \(summary.peerGroups) groups")
        }
        if summary.resourceCacheEntries > 0 || summary.resourceCacheBytes > 0 {
            lines.append(
                "Resolver cache: \(summary.resourceCacheEntries) entries, "
                    + "\(summary.resourceCacheBytes) bytes"
            )
        }
        return lines.joined(separator: "\n")
    }
}
