import Foundation

enum BrowserResolutionMode: String, CaseIterable, Equatable, Sendable {
    case compatibility
    case strict
}

struct BrowserRuntimePolicy: Equatable, Sendable {
    let resolutionMode: BrowserResolutionMode
    let hnsDohResolver: String?
    let statelessDANECertificates: Bool

    init(
        resolutionMode: BrowserResolutionMode = .compatibility,
        hnsDohResolver: String? = nil,
        statelessDANECertificates: Bool = false
    ) {
        self.resolutionMode = resolutionMode
        let endpoint = hnsDohResolver?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.hnsDohResolver = endpoint?.isEmpty == false ? endpoint : nil
        self.statelessDANECertificates = statelessDANECertificates
    }

    static let `default` = BrowserRuntimePolicy()
}

final class BrowserRuntimePolicyStore {
    private enum Key {
        static let resolutionMode = "hnsBrowser.runtimePolicy.resolutionMode"
        static let hnsDohResolver = "hnsBrowser.runtimePolicy.hnsDohResolver"
        static let statelessDANE = "hnsBrowser.runtimePolicy.statelessDANE"
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func load() -> BrowserRuntimePolicy {
        let mode = defaults.string(forKey: Key.resolutionMode)
            .flatMap(BrowserResolutionMode.init(rawValue:)) ?? .compatibility
        return BrowserRuntimePolicy(
            resolutionMode: mode,
            hnsDohResolver: defaults.string(forKey: Key.hnsDohResolver),
            statelessDANECertificates: defaults.bool(forKey: Key.statelessDANE)
        )
    }

    func save(_ policy: BrowserRuntimePolicy) {
        defaults.set(policy.resolutionMode.rawValue, forKey: Key.resolutionMode)
        if let endpoint = policy.hnsDohResolver {
            defaults.set(endpoint, forKey: Key.hnsDohResolver)
        } else {
            defaults.removeObject(forKey: Key.hnsDohResolver)
        }
        defaults.set(policy.statelessDANECertificates, forKey: Key.statelessDANE)
    }
}

struct BrowserSyncSchedulingPolicy: Equatable, Sendable {
    let progressInterval: TimeInterval
    let caughtUpInterval: TimeInterval
    let failureBackoff: [TimeInterval]

    init(
        progressInterval: TimeInterval = 30,
        caughtUpInterval: TimeInterval = 300,
        failureBackoff: [TimeInterval] = [5, 15, 60]
    ) {
        self.progressInterval = progressInterval
        self.caughtUpInterval = caughtUpInterval
        self.failureBackoff = failureBackoff
    }

    func delay(after summary: BrowserSyncSummary?, consecutiveFailures: Int) -> TimeInterval {
        if consecutiveFailures > 0, !failureBackoff.isEmpty {
            return failureBackoff[min(consecutiveFailures - 1, failureBackoff.count - 1)]
        }
        return summary?.isCaughtUp == true ? caughtUpInterval : progressInterval
    }
}
