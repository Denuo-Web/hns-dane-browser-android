import Foundation
import Security
import WebKit

@MainActor
protocol BrowserProxyCoordinatorDelegate: AnyObject {
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, install webView: WKWebView)
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, remove webView: WKWebView)
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didUpdateAddress address: String)
    func proxyCoordinator(
        _ coordinator: BrowserProxyCoordinator,
        canGoBack: Bool,
        canGoForward: Bool,
        isLoading: Bool
    )
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didUpdateSecurity summary: BrowserSecuritySummary)
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didUpdateSync summary: BrowserSyncSummary)
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didFail error: Error)
    func proxyCoordinator(_ coordinator: BrowserProxyCoordinator, didFinishDownloadAt url: URL)
}

@MainActor
final class BrowserProxyCoordinator: NSObject {
    private struct PendingNavigation {
        let request: URLRequest
        let destination: BrowserDestination
        let historyTarget: Int?
    }

    private final class CandidateDisposition {
        private let lock = NSLock()
        private var retained = false

        func setRetained(_ value: Bool) {
            lock.lock()
            retained = value
            lock.unlock()
        }

        func isRetained() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return retained
        }
    }

    weak var delegate: BrowserProxyCoordinatorDelegate?

    private let runtime: BrowserRuntime
    private let profile: PersistentWebKitProfile
    private let lifecycleQueue = DispatchQueue(
        label: "com.denuoweb.hnsdane.ios.proxy-lifecycle",
        qos: .userInitiated
    )
    private let statusQueue = DispatchQueue(
        label: "com.denuoweb.hnsdane.ios.runtime-status",
        qos: .utility
    )
    private let authenticationPolicy = BrowserAuthenticationPolicy()
    private let admissionPolicy = MainFrameAdmissionPolicy()
    private let replayPolicy = NavigationReplayPolicy()
    private let downloadController = BrowserDownloadController()

    private var machine = BrowserProxyStateMachine()
    private var activeProxy: BrowserProxySession?
    private var activeScope: BrowserProxyScope?
    private var webView: WKWebView?
    private var pendingNavigation: PendingNavigation?
    private var lastNavigation: PendingNavigation?
    private var history: [String] = []
    private var historyIndex = -1
    private var destroyed = false

    init(runtime: BrowserRuntime, profile: PersistentWebKitProfile) {
        self.runtime = runtime
        self.profile = profile
        super.init()
        downloadController.delegate = self
        downloadController.authenticationHandler = { [weak self] challenge, completion in
            self?.answerAuthenticationChallenge(challenge, completionHandler: completion)
                ?? completion(.cancelAuthenticationChallenge, nil)
        }
    }

    func navigate(rawValue: String) {
        guard !destroyed else { return }
        do {
            let destination = try runtime.classifyNavigation(rawValue)
            enqueue(
                request: URLRequest(url: destination.url),
                destination: destination,
                historyTarget: nil
            )
        } catch {
            delegate?.proxyCoordinator(self, didFail: error)
        }
    }

    func resume() {
        guard !destroyed else { return }
        if pendingNavigation == nil,
           let lastNavigation,
           replayPolicy.allowsAutomaticReplay(httpMethod: lastNavigation.request.httpMethod) {
            pendingNavigation = lastNavigation
        }
        execute(machine.resume())
    }

    func suspend() {
        guard !destroyed else { return }
        discardUnsafePendingReplay()
        if pendingNavigation == nil,
           let lastNavigation,
           replayPolicy.allowsAutomaticReplay(httpMethod: lastNavigation.request.httpMethod) {
            pendingNavigation = lastNavigation
        }
        execute(machine.suspend(retaining: pendingNavigation?.destination.proxyScope))
    }

    func destroy() {
        guard !destroyed else { return }
        destroyed = true
        pendingNavigation = nil
        lastNavigation = nil
        execute(machine.destroy())
        downloadController.authenticationHandler = nil
        delegate = nil
    }

    func goBack() {
        guard historyIndex > 0 else { return }
        navigateToHistory(index: historyIndex - 1)
    }

    func goForward() {
        guard historyIndex >= 0, historyIndex + 1 < history.count else { return }
        navigateToHistory(index: historyIndex + 1)
    }

    func reload() {
        guard replayPolicy.allowsAutomaticReplay(httpMethod: lastNavigation?.request.httpMethod) else {
            delegate?.proxyCoordinator(
                self,
                didFail: BrowserCoreError.invalidAddress(
                    "Reloading this page was blocked to avoid replaying a request body."
                )
            )
            return
        }
        guard let webView else {
            if let lastNavigation { enqueue(lastNavigation) }
            return
        }
        webView.reload()
    }

    func stopLoading() {
        webView?.stopLoading()
        delegate?.proxyCoordinator(
            self,
            canGoBack: historyIndex > 0,
            canGoForward: historyIndex + 1 < history.count,
            isLoading: false
        )
    }

    var currentShareURL: URL? { webView?.url ?? lastNavigation?.destination.url }

    /// Returns only a navigation that can be replayed after a live policy change without
    /// duplicating a request body. The caller must revoke this coordinator before publishing the
    /// new policy so no WebKit request survives under an older native proxy generation.
    func replayableAddressForRuntimeChange() -> String? {
        if let pendingNavigation {
            guard replayPolicy.allowsAutomaticReplay(
                httpMethod: pendingNavigation.request.httpMethod
            ) else { return nil }
            return pendingNavigation.destination.url.absoluteString
        }
        guard let lastNavigation,
              replayPolicy.allowsAutomaticReplay(
                  httpMethod: lastNavigation.request.httpMethod
              ) else { return nil }
        return lastNavigation.destination.url.absoluteString
    }

    private func enqueue(_ navigation: PendingNavigation) {
        enqueue(
            request: navigation.request,
            destination: navigation.destination,
            historyTarget: navigation.historyTarget
        )
    }

    private func enqueue(
        request: URLRequest,
        destination: BrowserDestination,
        historyTarget: Int?
    ) {
        pendingNavigation = PendingNavigation(
            request: request,
            destination: destination,
            historyTarget: historyTarget
        )
        delegate?.proxyCoordinator(self, didUpdateSecurity: .pending)
        execute(machine.queueNavigation(scope: destination.proxyScope))
    }

    private func discardUnsafePendingReplay() {
        guard let pendingNavigation,
              !replayPolicy.allowsAutomaticReplay(
                  httpMethod: pendingNavigation.request.httpMethod
              ) else {
            return
        }
        self.pendingNavigation = nil
    }

    private func navigateToHistory(index: Int) {
        guard history.indices.contains(index) else { return }
        do {
            let destination = try runtime.classifyNavigation(history[index])
            enqueue(
                request: URLRequest(url: destination.url),
                destination: destination,
                historyTarget: index
            )
        } catch {
            delegate?.proxyCoordinator(self, didFail: error)
        }
    }

    private func execute(
        _ actions: [BrowserProxyStateMachine.Action],
        candidate: BrowserProxySession? = nil,
        candidateDisposition: CandidateDisposition? = nil
    ) {
        for action in actions {
            switch action {
            case .revokeWebView:
                revokeWebView()
            case .requestStopActiveProxy:
                retireActiveProxy()
            case .startProxy(let epoch, let scope):
                startProxy(epoch: epoch, scope: scope)
            case .disposeStaleProxy:
                candidateDisposition?.setRetained(false)
            case .disposeStaleProxyThenStart(let epoch, let scope):
                candidateDisposition?.setRetained(false)
                startProxy(epoch: epoch, scope: scope)
            case .publishCandidateAndAdmitWebView(let epoch, let scope):
                guard let candidate else {
                    execute(machine.admissionFailed(epoch: epoch, scope: scope))
                    delegate?.proxyCoordinator(
                        self,
                        didFail: BrowserCoreError.proxyStartFailed(
                            "native proxy candidate was not available for publication"
                        )
                    )
                    continue
                }
                do {
                    try profile.install(proxy: candidate.endpoint)
                    activeProxy = candidate
                    activeScope = scope
                    candidateDisposition?.setRetained(true)
                    admitPendingNavigation(epoch: epoch, scope: scope)
                } catch {
                    candidateDisposition?.setRetained(false)
                    execute(machine.admissionFailed(epoch: epoch, scope: scope))
                    delegate?.proxyCoordinator(self, didFail: error)
                }
            case .admitThroughActiveProxy(let epoch, let scope):
                guard activeProxy != nil, activeScope == scope else {
                    execute(machine.admissionFailed(epoch: epoch, scope: scope))
                    retireActiveProxy()
                    delegate?.proxyCoordinator(
                        self,
                        didFail: BrowserCoreError.proxyStartFailed(
                            "the active proxy generation was unavailable during navigation admission"
                        )
                    )
                    continue
                }
                admitPendingNavigation(epoch: epoch, scope: scope)
            case .showFailure:
                delegate?.proxyCoordinator(
                    self,
                    didFail: BrowserCoreError.proxyStartFailed("native start or admission failed")
                )
            }
        }
    }

    private func startProxy(epoch: UInt64, scope: BrowserProxyScope) {
        let runtime = runtime
        lifecycleQueue.async { [weak self] in
            let result: Result<BrowserProxySession, Error>
            do {
                let hnsRoot: String?
                switch scope {
                case .icann:
                    hnsRoot = nil
                case .handshakeRoot(let root):
                    hnsRoot = root
                }
                result = .success(
                    try runtime.startWholeWebKitProxy(hnsScopeRoot: hnsRoot)
                )
            } catch {
                result = .failure(error)
            }

            switch result {
            case .failure:
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.execute(
                        self.machine.proxyStarted(
                            epoch: epoch,
                            scope: scope,
                            succeeded: false
                        )
                    )
                }
            case .success(let candidate):
                // Keep the lifecycle queue occupied until the main actor either publishes the
                // exact generation or rejects it. A rejected candidate is joined here before any
                // subsequently queued start can run.
                let semaphore = DispatchSemaphore(value: 0)
                let disposition = CandidateDisposition()
                DispatchQueue.main.async { [weak self] in
                    defer { semaphore.signal() }
                    guard let self else { return }
                    let actions = self.machine.proxyStarted(
                        epoch: epoch,
                        scope: scope,
                        succeeded: true
                    )
                    self.execute(
                        actions,
                        candidate: candidate,
                        candidateDisposition: disposition
                    )
                }
                semaphore.wait()
                if !disposition.isRetained() {
                    candidate.requestStop()
                    candidate.joinAndDestroy()
                }
            }
        }
    }

    private func admitPendingNavigation(epoch: UInt64, scope: BrowserProxyScope) {
        guard let activeProxy,
              activeScope == scope,
              let pendingNavigation,
              pendingNavigation.destination.proxyScope == scope else {
            return
        }

        let webView = self.webView ?? makeWebView()
        self.webView = webView
        lastNavigation = pendingNavigation
        self.pendingNavigation = nil
        machine.navigationAdmitted(epoch: epoch, scope: scope)
        delegate?.proxyCoordinator(
            self,
            didUpdateAddress: pendingNavigation.destination.url.absoluteString
        )
        delegate?.proxyCoordinator(
            self,
            canGoBack: historyIndex > 0,
            canGoForward: historyIndex + 1 < history.count,
            isLoading: true
        )
        _ = activeProxy
        webView.load(pendingNavigation.request)
    }

    private func makeWebView() -> WKWebView {
        let webView = WKWebView(frame: .zero, configuration: profile.makeHardenedConfiguration())
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = false
        webView.allowsLinkPreview = true
        webView.isInspectable = false
        delegate?.proxyCoordinator(self, install: webView)
        return webView
    }

    private func revokeWebView() {
        guard let webView else { return }
        webView.stopLoading()
        webView.navigationDelegate = nil
        webView.uiDelegate = nil
        delegate?.proxyCoordinator(self, remove: webView)
        webView.removeFromSuperview()
        self.webView = nil
    }

    private func retireActiveProxy() {
        guard let activeProxy else { return }
        self.activeProxy = nil
        activeScope = nil
        activeProxy.requestStop()
        lifecycleQueue.async {
            activeProxy.joinAndDestroy()
        }
    }

    private func isAdmitted(_ destination: BrowserDestination, in webView: WKWebView) -> Bool {
        guard self.webView === webView,
              activeProxy != nil,
              activeScope == destination.proxyScope else {
            return false
        }
        if case .active(_, let scope) = machine.phase {
            return scope == destination.proxyScope
        }
        return false
    }

    private func commitHistory(url: URL) {
        let value = url.absoluteString
        let historyTarget = lastNavigation?.historyTarget
        if let historyTarget, history.indices.contains(historyTarget) {
            historyIndex = historyTarget
        } else if historyIndex >= 0, history[historyIndex] == value {
            // Reload or duplicate finish callback.
        } else {
            if historyIndex + 1 < history.count {
                history.removeSubrange((historyIndex + 1)..<history.count)
            }
            history.append(value)
            historyIndex = history.count - 1
        }
        delegate?.proxyCoordinator(
            self,
            canGoBack: historyIndex > 0,
            canGoForward: historyIndex + 1 < history.count,
            isLoading: false
        )
    }

    private func updateSecurity(for url: URL) {
        guard let destination = try? runtime.classifyNavigation(url.absoluteString) else { return }
        let host = destination.canonicalHost
        switch destination.hostKind {
        case .icann:
            guard url.scheme?.lowercased() == "https" else {
                delegate?.proxyCoordinator(
                    self,
                    didUpdateSecurity: BrowserSecuritySummary(
                        level: .insecure,
                        detail: "Plain HTTP; no transport encryption"
                    )
                )
                break
            }
            delegate?.proxyCoordinator(
                self,
                didUpdateSecurity: BrowserSecuritySummary(
                    level: .webPKI,
                    detail: "System WebPKI via the Rust whole-browser proxy"
                )
            )
        case .search:
            delegate?.proxyCoordinator(
                self,
                didUpdateSecurity: BrowserSecuritySummary(
                    level: .blocked,
                    detail: "The destination host is invalid"
                )
            )
        case .handshake:
            let summary = activeProxy?.takeMainFrameSecurityStatus(host: host)
                ?? BrowserSecuritySummary(
                    level: .blocked,
                    detail: "No exact Rust proxy security result was available"
                )
            delegate?.proxyCoordinator(self, didUpdateSecurity: summary)
        }

        let runtime = runtime
        statusQueue.async { [weak self] in
            let summary = runtime.syncSummary()
            DispatchQueue.main.async {
                guard let self, !self.destroyed else { return }
                self.delegate?.proxyCoordinator(self, didUpdateSync: summary)
            }
        }
    }

    private func answerAuthenticationChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let protectionSpace = challenge.protectionSpace
        let context: BrowserAuthenticationContext
        if protectionSpace.isProxy() {
            context = BrowserAuthenticationContext(
                kind: .proxy(authenticationMethod: protectionSpace.authenticationMethod),
                host: protectionSpace.host,
                port: protectionSpace.port,
                realm: protectionSpace.realm
            )
        } else if protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            let leafDER: Data?
            if let trust = protectionSpace.serverTrust,
               let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
               let leaf = chain.first {
                leafDER = SecCertificateCopyData(leaf) as Data
            } else {
                leafDER = nil
            }
            context = BrowserAuthenticationContext(
                kind: .serverTrust(leafCertificateDER: leafDER),
                host: protectionSpace.host,
                port: protectionSpace.port,
                realm: protectionSpace.realm
            )
        } else {
            context = BrowserAuthenticationContext(
                kind: .origin(authenticationMethod: protectionSpace.authenticationMethod),
                host: protectionSpace.host,
                port: protectionSpace.port,
                realm: protectionSpace.realm
            )
        }

        switch authenticationPolicy.evaluate(
            context,
            runtime: runtime,
            liveProxy: activeProxy,
            activeScope: activeScope
        ) {
        case .performDefaultHandling:
            completionHandler(.performDefaultHandling, nil)
        case .cancel:
            completionHandler(.cancelAuthenticationChallenge, nil)
        case .useProxyCredential(let username, let password):
            completionHandler(
                .useCredential,
                URLCredential(
                    user: username,
                    password: password,
                    persistence: .forSession
                )
            )
        case .useServerTrust:
            guard let trust = protectionSpace.serverTrust else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        }
    }
}

extension BrowserProxyCoordinator: WKNavigationDelegate {
    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        preferences: WKWebpagePreferences,
        decisionHandler: @escaping (WKNavigationActionPolicy, WKWebpagePreferences) -> Void
    ) {
        guard navigationAction.targetFrame?.isMainFrame != false,
              let url = navigationAction.request.url else {
            decisionHandler(.allow, preferences)
            return
        }

        do {
            let destination = try runtime.classifyNavigation(url.absoluteString)
            if isAdmitted(destination, in: webView) {
                let historyTarget: Int?
                if let lastNavigation,
                   lastNavigation.request.url == navigationAction.request.url,
                   lastNavigation.request.httpMethod == navigationAction.request.httpMethod {
                    historyTarget = lastNavigation.historyTarget
                } else {
                    historyTarget = nil
                }
                lastNavigation = PendingNavigation(
                    request: navigationAction.request,
                    destination: destination,
                    historyTarget: historyTarget
                )
                delegate?.proxyCoordinator(self, didUpdateAddress: destination.url.absoluteString)
                decisionHandler(.allow, preferences)
                return
            }

            let method = navigationAction.request.httpMethod?.uppercased() ?? "GET"
            switch admissionPolicy.evaluate(
                activeScope: activeScope,
                destinationScope: destination.proxyScope,
                httpMethod: method
            ) {
            case .allow:
                // A live exact scope is required in addition to policy equality. Reaching this
                // branch means the generation is being revoked, so fail closed and retry later.
                decisionHandler(.cancel, preferences)
                return
            case .blockNonIdempotentReplay:
                decisionHandler(.cancel, preferences)
                delegate?.proxyCoordinator(
                    self,
                    didFail: BrowserCoreError.invalidAddress(
                        "A cross-scope \(method) navigation was blocked to avoid replaying a request body."
                    )
                )
                return
            case .rotateProxy:
                break
            }
            enqueue(
                request: navigationAction.request,
                destination: destination,
                historyTarget: nil
            )
            decisionHandler(.cancel, preferences)
        } catch {
            decisionHandler(.cancel, preferences)
            delegate?.proxyCoordinator(self, didFail: error)
        }
    }

    func webView(
        _ webView: WKWebView,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        answerAuthenticationChallenge(challenge, completionHandler: completionHandler)
    }

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation?) {
        delegate?.proxyCoordinator(
            self,
            canGoBack: historyIndex > 0,
            canGoForward: historyIndex + 1 < history.count,
            isLoading: true
        )
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation?) {
        guard let url = webView.url else { return }
        delegate?.proxyCoordinator(self, didUpdateAddress: url.absoluteString)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation?) {
        guard self.webView === webView, let url = webView.url else { return }
        commitHistory(url: url)
        updateSecurity(for: url)
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation?,
        withError error: Error
    ) {
        delegate?.proxyCoordinator(
            self,
            canGoBack: historyIndex > 0,
            canGoForward: historyIndex + 1 < history.count,
            isLoading: false
        )
        delegate?.proxyCoordinator(self, didFail: error)
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation?,
        withError error: Error
    ) {
        delegate?.proxyCoordinator(
            self,
            canGoBack: historyIndex > 0,
            canGoForward: historyIndex + 1 < history.count,
            isLoading: false
        )
        delegate?.proxyCoordinator(self, didFail: error)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        guard self.webView === webView else { return }
        discardUnsafePendingReplay()
        if pendingNavigation == nil,
           let lastNavigation,
           replayPolicy.allowsAutomaticReplay(httpMethod: lastNavigation.request.httpMethod) {
            pendingNavigation = lastNavigation
        }
        execute(machine.rendererTerminated(retaining: pendingNavigation?.destination.proxyScope))
    }

    func webView(
        _ webView: WKWebView,
        navigationAction: WKNavigationAction,
        didBecome download: WKDownload
    ) {
        downloadController.attach(download)
    }

    func webView(
        _ webView: WKWebView,
        navigationResponse: WKNavigationResponse,
        didBecome download: WKDownload
    ) {
        downloadController.attach(download)
    }
}

extension BrowserProxyCoordinator: WKUIDelegate {
    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        guard navigationAction.targetFrame == nil,
              let url = navigationAction.request.url else {
            return nil
        }
        do {
            let destination = try runtime.classifyNavigation(url.absoluteString)
            enqueue(
                request: navigationAction.request,
                destination: destination,
                historyTarget: nil
            )
        } catch {
            delegate?.proxyCoordinator(self, didFail: error)
        }
        return nil
    }
}

extension BrowserProxyCoordinator: BrowserDownloadControllerDelegate {
    func downloadController(_ controller: BrowserDownloadController, didFinishAt url: URL) {
        delegate?.proxyCoordinator(self, didFinishDownloadAt: url)
    }

    func downloadController(_ controller: BrowserDownloadController, didFail error: Error) {
        delegate?.proxyCoordinator(self, didFail: error)
    }
}
