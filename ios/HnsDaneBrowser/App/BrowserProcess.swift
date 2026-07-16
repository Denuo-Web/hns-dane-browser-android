import Foundation
import WebKit

@MainActor
final class BrowserProcess {
    struct Environment {
        let runtime: BrowserRuntime
        let profile: PersistentWebKitProfile
    }

    private enum State {
        case idle
        case preparing([((Result<Environment, Error>) -> Void)])
        case ready(Environment)
        case failed(Error)
        case closed
    }

    private let preparationQueue = DispatchQueue(
        label: "com.denuoweb.hnsdane.ios.runtime-preparation",
        qos: .userInitiated
    )
    private let runtimeFactory: (String) throws -> BrowserRuntime
    private let bootstrapper: HeaderSnapshotBootstrapper
    private let policyStore: BrowserRuntimePolicyStore
    private let syncSchedulingPolicy: BrowserSyncSchedulingPolicy
    private var state: State = .idle
    private(set) var currentPolicy: BrowserRuntimePolicy
    private var isForegroundSyncEnabled = false
    private var syncObserver: ((BrowserSyncSummary) -> Void)?
    private var syncWorkItem: DispatchWorkItem?
    private var syncScheduleGeneration: UInt64 = 0
    private var syncInFlight = false
    private var syncCompletions: [((Result<BrowserSyncSummary, Error>) -> Void)] = []
    private var consecutiveSyncFailures = 0

    init(
        runtimeFactory: @escaping (String) throws -> BrowserRuntime = { path in
            try RustBrowserRuntime(path)
        },
        bootstrapper: HeaderSnapshotBootstrapper = HeaderSnapshotBootstrapper(),
        policyStore: BrowserRuntimePolicyStore = BrowserRuntimePolicyStore(),
        syncSchedulingPolicy: BrowserSyncSchedulingPolicy = BrowserSyncSchedulingPolicy()
    ) {
        self.runtimeFactory = runtimeFactory
        self.bootstrapper = bootstrapper
        self.policyStore = policyStore
        self.syncSchedulingPolicy = syncSchedulingPolicy
        currentPolicy = policyStore.load()
    }

    func prepare(completion: @escaping (Result<Environment, Error>) -> Void) {
        switch state {
        case .ready(let environment):
            completion(.success(environment))
            return
        case .failed:
            // A first-run bundle/I/O failure remains fail-closed, but a user-initiated retry may
            // recover from transient protected-storage or resource pressure failures.
            state = .preparing([completion])
        case .closed:
            completion(.failure(BrowserCoreError.runtimeUnavailable("process is closed")))
            return
        case .preparing(var callbacks):
            callbacks.append(completion)
            state = .preparing(callbacks)
            return
        case .idle:
            state = .preparing([completion])
        }

        do {
            let dataDirectory = try Self.makeDataDirectory()
            let runtimeFactory = runtimeFactory
            let bootstrapper = bootstrapper
            let policy = currentPolicy
            preparationQueue.async { [weak self] in
                let result: Result<BrowserRuntime, Error>
                do {
                    let runtime = try runtimeFactory(dataDirectory.path)
                    do {
                        try runtime.updatePolicy(policy)
                        try bootstrapper.installIfNeeded(into: runtime)
                        result = .success(runtime)
                    } catch {
                        runtime.close()
                        throw error
                    }
                } catch {
                    result = .failure(error)
                }

                DispatchQueue.main.async {
                    self?.finishPreparation(result)
                }
            }
        } catch {
            finishPreparation(.failure(error))
        }
    }

    func updatePolicy(
        _ policy: BrowserRuntimePolicy,
        completion: @escaping (Result<UInt64, Error>) -> Void
    ) {
        guard case .ready(let environment) = state else {
            completion(.failure(runtimeUnavailableError()))
            return
        }
        preparationQueue.async { [weak self] in
            let result = Result { try environment.runtime.updatePolicy(policy) }
            DispatchQueue.main.async {
                guard let self else { return }
                if case .success = result {
                    self.currentPolicy = policy
                    self.policyStore.save(policy)
                }
                completion(result)
            }
        }
    }

    func syncNow(completion: @escaping (Result<BrowserSyncSummary, Error>) -> Void) {
        guard case .ready(let environment) = state else {
            completion(.failure(runtimeUnavailableError()))
            return
        }
        syncWorkItem?.cancel()
        syncWorkItem = nil
        syncScheduleGeneration &+= 1
        syncCompletions.append(completion)
        startSyncIfNeeded(environment: environment)
    }

    func clearResolverCache(
        completion: @escaping (Result<BrowserSyncSummary, Error>) -> Void
    ) {
        guard case .ready(let environment) = state else {
            completion(.failure(runtimeUnavailableError()))
            return
        }
        preparationQueue.async {
            let result = Result { try environment.runtime.clearResolverCache() }
            DispatchQueue.main.async {
                completion(result)
            }
        }
    }

    func proofDetails(
        for hostOrURL: String,
        completion: @escaping (Result<BrowserProofDetails, Error>) -> Void
    ) {
        guard case .ready(let environment) = state else {
            completion(.failure(runtimeUnavailableError()))
            return
        }
        preparationQueue.async {
            let result = Result { try environment.runtime.proofDetails(for: hostOrURL) }
            DispatchQueue.main.async {
                completion(result)
            }
        }
    }

    func resumeForegroundSync(observer: @escaping (BrowserSyncSummary) -> Void) {
        isForegroundSyncEnabled = true
        syncObserver = observer
        scheduleForegroundSync(after: 0)
    }

    func suspendForegroundSync() {
        isForegroundSyncEnabled = false
        syncObserver = nil
        syncWorkItem?.cancel()
        syncWorkItem = nil
        syncScheduleGeneration &+= 1
    }

    func close() {
        suspendForegroundSync()
        let pendingSyncCompletions = syncCompletions
        syncCompletions.removeAll()
        let closedError = BrowserCoreError.runtimeUnavailable("process is closed")
        pendingSyncCompletions.forEach { $0(.failure(closedError)) }
        let runtime: BrowserRuntime?
        switch state {
        case .ready(let environment):
            runtime = environment.runtime
        default:
            runtime = nil
        }
        state = .closed
        if let runtime {
            preparationQueue.async {
                runtime.close()
            }
        }
    }

    private func finishPreparation(_ result: Result<BrowserRuntime, Error>) {
        guard case .preparing(let callbacks) = state else {
            if case .success(let runtime) = result {
                preparationQueue.async { runtime.close() }
            }
            return
        }

        switch result {
        case .success(let runtime):
            let environment = Environment(
                runtime: runtime,
                profile: PersistentWebKitProfile()
            )
            state = .ready(environment)
            callbacks.forEach { $0(.success(environment)) }
            // Network synchronization is deliberately not a readiness gate. Foreground
            // scheduling starts only after the exact bundled snapshot and persisted policy are
            // installed, so snapshot-backed verification is available immediately.
            if isForegroundSyncEnabled {
                scheduleForegroundSync(after: 0)
            }
        case .failure(let error):
            state = .failed(error)
            callbacks.forEach { $0(.failure(error)) }
        }
    }

    private func startSyncIfNeeded(environment: Environment) {
        guard !syncInFlight else { return }
        syncInFlight = true
        preparationQueue.async { [weak self] in
            let result = Result { try environment.runtime.syncOnce() }
            DispatchQueue.main.async {
                self?.finishSync(result)
            }
        }
    }

    private func finishSync(_ result: Result<BrowserSyncSummary, Error>) {
        syncInFlight = false
        let callbacks = syncCompletions
        syncCompletions.removeAll()

        let summary: BrowserSyncSummary
        switch result {
        case .success(let value):
            summary = value
            consecutiveSyncFailures = value.requiresRetry ? consecutiveSyncFailures + 1 : 0
        case .failure(let error):
            summary = .failure(error)
            consecutiveSyncFailures += 1
        }
        if isForegroundSyncEnabled {
            syncObserver?(summary)
            let delay = syncSchedulingPolicy.delay(
                after: summary,
                consecutiveFailures: consecutiveSyncFailures
            )
            scheduleForegroundSync(after: delay)
        }
        callbacks.forEach { $0(result) }
    }

    private func scheduleForegroundSync(after delay: TimeInterval) {
        syncWorkItem?.cancel()
        syncWorkItem = nil
        syncScheduleGeneration &+= 1
        guard isForegroundSyncEnabled, case .ready = state else { return }
        let generation = syncScheduleGeneration

        let workItem = DispatchWorkItem { [weak self] in
            DispatchQueue.main.async {
                self?.runScheduledForegroundSync(generation: generation)
            }
        }
        syncWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
    }

    private func runScheduledForegroundSync(generation: UInt64) {
        guard generation == syncScheduleGeneration,
              isForegroundSyncEnabled,
              case .ready(let environment) = state else { return }
        syncWorkItem = nil
        startSyncIfNeeded(environment: environment)
    }

    private func runtimeUnavailableError() -> BrowserCoreError {
        let detail: String
        switch state {
        case .idle: detail = "process is not prepared"
        case .preparing: detail = "process is still preparing"
        case .ready: detail = "runtime environment is unavailable"
        case .failed(let error): detail = error.localizedDescription
        case .closed: detail = "process is closed"
        }
        return .runtimeUnavailable(detail)
    }

    private static func makeDataDirectory() throws -> URL {
        let fileManager = FileManager.default
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw BrowserCoreError.runtimeUnavailable("Application Support is unavailable")
        }
        let directory = applicationSupport
            .appendingPathComponent("HnsDaneBrowser", isDirectory: true)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        )
        return directory
    }
}
