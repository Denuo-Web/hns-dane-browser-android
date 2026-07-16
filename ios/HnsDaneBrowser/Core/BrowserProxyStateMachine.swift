import Foundation

/// Pure, scope-bound admission model used by the UIKit coordinator and unit tests.
struct BrowserProxyStateMachine: Equatable {
    enum Phase: Equatable {
        case suspended
        case idle
        case starting(UInt64, BrowserProxyScope)
        case active(UInt64, BrowserProxyScope)
        case failed(UInt64, BrowserProxyScope)
        case destroyed
    }

    enum Action: Equatable {
        case revokeWebView
        case requestStopActiveProxy
        case startProxy(UInt64, BrowserProxyScope)
        case disposeStaleProxy
        case disposeStaleProxyThenStart(UInt64, BrowserProxyScope)
        case publishCandidateAndAdmitWebView(UInt64, BrowserProxyScope)
        case admitThroughActiveProxy(UInt64, BrowserProxyScope)
        case showFailure(UInt64)
    }

    private(set) var phase: Phase = .suspended
    private(set) var epoch: UInt64 = 0
    private(set) var pendingScope: BrowserProxyScope?
    private(set) var isForeground = false

    mutating func queueNavigation(scope: BrowserProxyScope) -> [Action] {
        guard phase != .destroyed else { return [] }
        pendingScope = scope
        guard isForeground else { return [] }

        switch phase {
        case .idle, .failed:
            return beginStart(scope: scope)
        case .active(let generation, let activeScope) where activeScope == scope:
            return [.admitThroughActiveProxy(generation, activeScope)]
        case .active:
            let start = beginStart(scope: scope)
            return [.revokeWebView, .requestStopActiveProxy] + start
        case .starting:
            // The in-flight generation is not published. Its callback will either commit the
            // newest exact scope or dispose it before scheduling the newest scope.
            return []
        case .suspended, .destroyed:
            return []
        }
    }

    mutating func resume() -> [Action] {
        guard phase != .destroyed else { return [] }
        isForeground = true
        if case .suspended = phase {
            phase = .idle
        }
        guard let pendingScope else { return [] }

        switch phase {
        case .idle, .failed:
            return beginStart(scope: pendingScope)
        case .active(let generation, let activeScope) where activeScope == pendingScope:
            return [.admitThroughActiveProxy(generation, activeScope)]
        case .active:
            let start = beginStart(scope: pendingScope)
            return [.revokeWebView, .requestStopActiveProxy] + start
        case .suspended, .starting, .destroyed:
            return []
        }
    }

    mutating func proxyStarted(
        epoch callbackEpoch: UInt64,
        scope callbackScope: BrowserProxyScope,
        succeeded: Bool
    ) -> [Action] {
        guard case .starting(callbackEpoch, callbackScope) = phase, isForeground else {
            // Another transition has already superseded this callback. In particular, a
            // suspend/resume cycle can have a newer start queued on the serialized lifecycle
            // executor while the older native start is still returning. Scheduling yet another
            // start here would make each stale callback chase the next epoch indefinitely.
            // Dispose only the candidate owned by this callback and preserve the newer phase.
            return succeeded ? [.disposeStaleProxy] : []
        }

        guard succeeded else {
            phase = .failed(callbackEpoch, callbackScope)
            if let pendingScope, pendingScope != callbackScope {
                return beginStart(scope: pendingScope)
            }
            return [.showFailure(callbackEpoch)]
        }

        guard pendingScope == callbackScope else {
            phase = .idle
            return restartActionsAfterStaleProxy()
        }

        phase = .active(callbackEpoch, callbackScope)
        return [.publishCandidateAndAdmitWebView(callbackEpoch, callbackScope)]
    }

    mutating func navigationAdmitted(epoch callbackEpoch: UInt64, scope: BrowserProxyScope) {
        guard case .active(callbackEpoch, scope) = phase else { return }
        pendingScope = nil
    }

    mutating func admissionFailed(epoch callbackEpoch: UInt64, scope: BrowserProxyScope) -> [Action] {
        guard case .active(callbackEpoch, scope) = phase else { return [] }
        phase = .failed(callbackEpoch, scope)
        return [.revokeWebView, .showFailure(callbackEpoch)]
    }

    mutating func suspend(retaining scope: BrowserProxyScope?) -> [Action] {
        guard phase != .destroyed else { return [] }
        // The coordinator passes the exact replay-safe navigation it retained. `nil` therefore
        // means an unsafe pending request was discarded and must also clear its native scope.
        pendingScope = scope
        isForeground = false
        epoch = nextEpoch(epoch)

        let hadLiveProxy: Bool
        switch phase {
        case .active:
            hadLiveProxy = true
        default:
            hadLiveProxy = false
        }
        phase = .suspended

        var actions: [Action] = [.revokeWebView]
        if hadLiveProxy {
            actions.append(.requestStopActiveProxy)
        }
        return actions
    }

    mutating func rendererTerminated(retaining scope: BrowserProxyScope?) -> [Action] {
        guard phase != .destroyed else { return [] }
        let hadLiveProxy: Bool
        switch phase {
        case .active:
            hadLiveProxy = true
        default:
            hadLiveProxy = false
        }
        // Mirror suspension semantics: never keep a scope whose navigation cannot safely replay.
        pendingScope = scope
        epoch = nextEpoch(epoch)
        phase = isForeground ? .idle : .suspended

        var actions: [Action] = [.revokeWebView]
        if hadLiveProxy {
            actions.append(.requestStopActiveProxy)
        }
        if isForeground, let pendingScope {
            actions.append(contentsOf: beginStart(scope: pendingScope))
        }
        return actions
    }

    mutating func destroy() -> [Action] {
        guard phase != .destroyed else { return [] }
        let hadLiveProxy: Bool
        switch phase {
        case .active:
            hadLiveProxy = true
        default:
            hadLiveProxy = false
        }
        epoch = nextEpoch(epoch)
        pendingScope = nil
        isForeground = false
        phase = .destroyed

        var actions: [Action] = [.revokeWebView]
        if hadLiveProxy {
            actions.append(.requestStopActiveProxy)
        }
        return actions
    }

    private mutating func beginStart(scope: BrowserProxyScope) -> [Action] {
        epoch = nextEpoch(epoch)
        phase = .starting(epoch, scope)
        return [.startProxy(epoch, scope)]
    }

    private mutating func restartActionsAfterStaleProxy() -> [Action] {
        phase = isForeground ? .idle : .suspended
        guard isForeground, let pendingScope else { return [.disposeStaleProxy] }
        epoch = nextEpoch(epoch)
        phase = .starting(epoch, pendingScope)
        return [.disposeStaleProxyThenStart(epoch, pendingScope)]
    }

    private func nextEpoch(_ value: UInt64) -> UInt64 {
        value == .max ? 1 : value + 1
    }
}
