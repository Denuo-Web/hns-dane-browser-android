package com.denuoweb.hnsdane.net

import java.util.Collections
import java.util.IdentityHashMap
import java.util.Locale
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

internal fun interface LocalBrowserProxyFactory {
    fun start(config: RustBrowserProxyConfig): LocalBrowserProxy?
}

internal enum class BrowserProxyRoute {
    Proxy,
    CompatibilityInterceptor,
    Block,
}

/** Process-lifetime serialization keeps old proxy joins ahead of replacement starts. */
internal object BrowserProxyLifecycleWorker : Executor {
    private val delegate = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "hns-browser-proxy-lifecycle").apply { isDaemon = true }
    }

    override fun execute(command: Runnable) = delegate.execute(command)
}

/**
 * Serializes the process-wide WebView proxy override around immutable, scoped proxy instances.
 *
 * Public methods and platform callbacks are expected on [callbackExecutor]. Proxy construction and
 * blocking destruction always run on [workerExecutor]. Read-only request/certificate helpers are
 * safe to call from WebView callback threads through the volatile published binding.
 */
internal class BrowserProxyCoordinator(
    private val overrideController: BrowserProxyOverrideController,
    private val proxyFactory: LocalBrowserProxyFactory,
    private val workerExecutor: Executor,
    private val callbackExecutor: Executor,
    private val onAvailabilityChanged: (Boolean) -> Unit = {},
) : HnsLocalCertificateDerVerifier {
    private enum class Phase {
        Idle,
        Acquiring,
        Clearing,
        Starting,
        Applying,
    }

    private class Binding(
        val config: RustBrowserProxyConfig,
        val proxy: LocalBrowserProxy,
    )

    private class StartOperation(
        val id: Long,
        val desiredRevision: Long,
        val lifecycleEpoch: Long,
        val config: RustBrowserProxyConfig,
    )

    private class ApplyOperation(
        val id: Long,
        val desiredRevision: Long,
        val lifecycleEpoch: Long,
        val binding: Binding,
    )

    private class PendingNavigation(
        val targetHost: String?,
        val load: () -> Unit,
    )

    private class StatusContext(
        val binding: Binding,
        var host: String,
    )

    private class RoutingSnapshot(
        val binding: Binding? = null,
        val compatibilityScope: String? = null,
    )

    private var phase = Phase.Idle
    private var enabled = false
    private var ownershipReady = false
    private var destroyed = false
    private var desiredConfig: RustBrowserProxyConfig? = null
    private var desiredRevision = 0L
    private var lifecycleEpoch = 0L
    private var nextOperationId = 0L
    private var failedRevision: Long? = null
    private var retirementsInFlight = 0
    private var overrideInstalled = false
    private var activeBinding: Binding? = null
    private var candidateBinding: Binding? = null
    private var startOperation: StartOperation? = null
    private var applyOperation: ApplyOperation? = null
    private var acquireOperationId: Long? = null
    private var clearOperationId: Long? = null
    private var pendingNavigation: PendingNavigation? = null
    private var statusContext: StatusContext? = null
    private val retiredProxies = Collections.newSetFromMap(IdentityHashMap<LocalBrowserProxy, Boolean>())
    private val publicationLock = Any()

    @Volatile
    private var publishedBinding: Binding? = null

    @Volatile
    private var publishedAvailable = false

    @Volatile
    private var challengeBinding: Binding? = null

    @Volatile
    private var routingSnapshot = RoutingSnapshot()

    @Volatile
    private var ownershipRevokedGate = false

    val isProxyAvailable: Boolean
        get() = publishedAvailable

    /** Enables reconciliation, preserving a navigation queued before Activity.onStart. */
    fun resume(config: RustBrowserProxyConfig?) {
        if (destroyed) return
        if (!enabled) ownershipReady = false
        enabled = true
        updateDesiredConfig(config, retryFailedStart = false)
        reconcile()
    }

    /** Updates the desired scope without causing a page load. */
    fun ensure(config: RustBrowserProxyConfig?) {
        if (destroyed) return
        updateDesiredConfig(config, retryFailedStart = false)
        reconcile()
    }

    /**
     * Queues the latest navigation until the matching override is committed, or until the native
     * proxy has failed and the caller's fail-closed compatibility interceptor must take over.
     */
    fun navigate(
        config: RustBrowserProxyConfig?,
        targetHost: String?,
        load: () -> Unit,
    ) {
        if (destroyed) return
        val canonicalTargetHost = targetHost?.let(::canonicalBrowserProxyHost)
        require((config == null) == (canonicalTargetHost == null)) {
            "HNS proxy configuration and target host must either both be present or both be absent"
        }
        if (canonicalTargetHost != null && statusContext != null) {
            activeBinding?.let { binding ->
                activeBinding = null
                unpublish(binding)
                retire(binding.proxy)
            }
            statusContext = null
        }
        val effectiveConfig = updateDesiredConfig(config, retryFailedStart = true)
        if (effectiveConfig != null) {
            require(scopeContainsHost(effectiveConfig.scopeHost, requireNotNull(canonicalTargetHost))) {
                "HNS navigation target must be inside its proxy scope"
            }
        }
        pendingNavigation = PendingNavigation(canonicalTargetHost, load)
        reconcile()
    }

    /** Revokes callback trust immediately and drains the native proxy on the worker. */
    fun suspend() {
        if (destroyed) return
        enabled = false
        ownershipReady = false
        lifecycleEpoch = nextMonotonicId(lifecycleEpoch)
        revokePublishedBindings()
        reconcile()
        overrideController.releaseOwnership()
    }

    /** Permanently revokes this coordinator. Late start/apply callbacks can only clean up. */
    fun destroy() {
        if (destroyed) return
        destroyed = true
        enabled = false
        ownershipReady = false
        lifecycleEpoch = nextMonotonicId(lifecycleEpoch)
        pendingNavigation = null
        desiredConfig = null
        desiredRevision = nextMonotonicId(desiredRevision)
        failedRevision = null
        publishCompatibilityScope(null)
        revokePublishedBindings()
        reconcile()
        overrideController.releaseOwnership()
    }

    fun coversHost(host: String): Boolean {
        val canonicalHost = canonicalBrowserProxyHost(host) ?: return false
        return routingSnapshot.binding?.covers(canonicalHost) == true
    }

    /** One immutable volatile decision for off-main WebView interception callbacks. */
    fun routeForHnsHost(host: String): BrowserProxyRoute {
        val canonicalHost = canonicalBrowserProxyHost(host) ?: return BrowserProxyRoute.Block
        val snapshot = routingSnapshot
        if (snapshot.binding?.covers(canonicalHost) == true) return BrowserProxyRoute.Proxy
        if (snapshot.compatibilityScope?.let { scopeContainsHost(it, canonicalHost) } == true) {
            return BrowserProxyRoute.CompatibilityInterceptor
        }
        return BrowserProxyRoute.Block
    }

    fun authorizationForChallenge(host: String, realm: String): LoopbackProxyAuthorization? {
        val binding = challengeBinding ?: publishedBinding ?: return null
        val authorization = binding.proxy.endpoint.authorization
        if (!authorization.matchesChallenge(host, realm)) return null
        return authorization.takeIf {
            challengeBinding === binding || (publishedBinding === binding && publishedAvailable)
        }
    }

    override fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean {
        val canonicalHost = canonicalBrowserProxyHost(host) ?: return false
        if (certificateDer.isEmpty()) return false
        val binding = publishedBinding ?: return false
        if (!publishedAvailable || !binding.covers(canonicalHost)) return false
        val matches = binding.proxy.matchesLocalCertificate(canonicalHost, certificateDer)
        return matches && publishedBinding === binding && publishedAvailable
    }

    /** Updates the exact main-frame host for an in-scope redirect on the committed navigation. */
    fun noteMainFrameHost(host: String) {
        val canonicalHost = canonicalBrowserProxyHost(host) ?: return
        val binding = publishedBinding ?: return
        val context = statusContext ?: return
        if (publishedAvailable && context.binding === binding && binding.covers(canonicalHost)) {
            context.host = canonicalHost
        }
    }

    /** Consumes status only for the exact live instance and most recently committed navigation. */
    fun takeMainFrameStatus(host: String): LocalBrowserProxyStatus? {
        val canonicalHost = canonicalBrowserProxyHost(host) ?: return null
        val binding = publishedBinding ?: return null
        val context = statusContext ?: return null
        if (
            !publishedAvailable ||
            context.binding !== binding ||
            context.host != canonicalHost ||
            !binding.covers(canonicalHost)
        ) {
            return null
        }
        statusContext = null
        val status = binding.proxy.takeMainFrameStatus(canonicalHost)
        return status.takeIf { publishedBinding === binding && publishedAvailable }
    }

    private fun updateDesiredConfig(
        requested: RustBrowserProxyConfig?,
        retryFailedStart: Boolean,
    ): RustBrowserProxyConfig? {
        val normalized = requested?.normalized() ?: run {
            if (desiredConfig != null) {
                desiredConfig = null
                desiredRevision = nextMonotonicId(desiredRevision)
                failedRevision = null
            }
            if (pendingNavigation?.targetHost != null) pendingNavigation = null
            publishCompatibilityScope(null)
            revokeIncompatibleBindings()
            return null
        }
        val compatible = compatibleInFlightConfig(normalized)
        val effective = compatible ?: normalized
        if (!sameProxyConfig(desiredConfig, effective)) {
            desiredConfig = effective
            desiredRevision = nextMonotonicId(desiredRevision)
            failedRevision = null
            publishCompatibilityScope(null)
        } else if (retryFailedStart && failedRevision == desiredRevision) {
            failedRevision = null
            publishCompatibilityScope(null)
        }
        pendingNavigation?.let { pending ->
            val targetHost = pending.targetHost
            if (targetHost == null || !scopeContainsHost(effective.scopeHost, targetHost)) {
                pendingNavigation = null
            }
        }
        revokeIncompatibleBindings()
        return effective
    }

    private fun compatibleInFlightConfig(requested: RustBrowserProxyConfig): RustBrowserProxyConfig? {
        val configs = listOfNotNull(
            activeBinding?.config,
            candidateBinding?.config,
            startOperation?.config,
            desiredConfig,
        )
        return configs.firstOrNull { existing ->
            sameProxySettings(existing, requested) && scopeContainsHost(existing.scopeHost, requested.scopeHost)
        }
    }

    private fun revokeIncompatibleBindings() {
        val desired = desiredConfig
        activeBinding?.takeUnless { binding -> binding.isCompatibleWith(desired) }?.let { binding ->
            if (activeBinding === binding) activeBinding = null
            unpublish(binding)
            retire(binding.proxy)
        }
        candidateBinding?.takeUnless { binding -> binding.isCompatibleWith(desired) }?.let { binding ->
            if (candidateBinding === binding) candidateBinding = null
            clearChallenge(binding)
            retire(binding.proxy)
        }
    }

    private fun revokePublishedBindings() {
        activeBinding?.let { binding ->
            activeBinding = null
            unpublish(binding)
            retire(binding.proxy)
        }
        candidateBinding?.let { binding ->
            candidateBinding = null
            clearChallenge(binding)
            retire(binding.proxy)
        }
        if (activeBinding == null) publishAvailability(null)
        statusContext = null
        publishCompatibilityScope(null)
    }

    private fun reconcile() {
        revokeIncompatibleBindings()
        if (phase != Phase.Idle) return

        if (ownershipRevokedGate) {
            revokePublishedBindings()
            if (overrideInstalled) beginClearOverride()
            return
        }

        if (destroyed || !enabled) {
            revokePublishedBindings()
            if (overrideInstalled) beginClearOverride()
            return
        }

        if (!ownershipReady) {
            beginAcquireOverrideOwnership()
            return
        }

        val desired = desiredConfig
        val active = activeBinding
        if (active != null && active.isCompatibleWith(desired) && overrideInstalled) {
            if (publishAvailability(active)) {
                deliverPendingNavigation(active)
            } else {
                reconcile()
            }
            return
        }

        if (active != null) {
            activeBinding = null
            unpublish(active)
            retire(active.proxy)
        }
        if (overrideInstalled) {
            beginClearOverride()
            return
        }
        if (desired == null) {
            publishAvailability(null)
            deliverPendingNavigation(null)
            return
        }
        if (failedRevision == desiredRevision) {
            publishAvailability(null)
            if (publishCompatibilityScope(desired.scopeHost)) deliverPendingNavigation(null)
            return
        }
        if (retirementsInFlight > 0) return
        beginProxyStart(desired)
    }

    private fun beginClearOverride() {
        nextOperationId = nextMonotonicId(nextOperationId)
        val operationId = nextOperationId
        clearOperationId = operationId
        phase = Phase.Clearing
        overrideController.clear { cleared ->
            postCallback {
                if (phase != Phase.Clearing || clearOperationId != operationId) return@postCallback
                clearOperationId = null
                phase = Phase.Idle
                if (cleared) {
                    overrideInstalled = false
                    reconcile()
                } else {
                    enabled = false
                    ownershipReady = false
                    pendingNavigation = null
                    publishAvailability(null)
                    publishCompatibilityScope(null)
                }
            }
        }
    }

    private fun beginAcquireOverrideOwnership() {
        nextOperationId = nextMonotonicId(nextOperationId)
        val operationId = nextOperationId
        val operationLifecycleEpoch = lifecycleEpoch
        acquireOperationId = operationId
        phase = Phase.Acquiring
        overrideController.acquire(
            onOwnershipRevoked = {
                withdrawForOwnershipRevocation()
            },
            onComplete = { acquired ->
                postCallback {
                    if (phase != Phase.Acquiring || acquireOperationId != operationId) return@postCallback
                    acquireOperationId = null
                    phase = Phase.Idle
                    val lifecycleIsCurrent = lifecycleEpoch == operationLifecycleEpoch
                    if (acquired && lifecycleIsCurrent && enabled && !destroyed && !ownershipRevokedGate) {
                        ownershipReady = true
                    } else if (!acquired && lifecycleIsCurrent) {
                        enabled = false
                        pendingNavigation = null
                        publishAvailability(null)
                        publishCompatibilityScope(null)
                    }
                    reconcile()
                }
            },
        )
    }

    private fun withdrawForOwnershipRevocation() {
        val (published, challenged, wasAvailable) = synchronized(publicationLock) {
            ownershipRevokedGate = true
            Triple(publishedBinding, challengeBinding, publishedAvailable).also {
                publishedBinding = null
                challengeBinding = null
                routingSnapshot = RoutingSnapshot()
                publishedAvailable = false
            }
        }
        runCatching { published?.proxy?.requestStop() }
        if (challenged !== published) runCatching { challenged?.proxy?.requestStop() }
        postCallback(
            rejected = {
                published?.proxy?.let(::destroyDetached)
                if (challenged !== published) challenged?.proxy?.let(::destroyDetached)
                runCatching { overrideController.clear { _ -> } }
            },
        ) {
            onOwnershipRevoked(wasAvailable)
        }
    }

    private fun onOwnershipRevoked(wasAvailable: Boolean) {
        if (wasAvailable) onAvailabilityChanged(false)
        if (destroyed) return
        enabled = false
        ownershipReady = false
        lifecycleEpoch = nextMonotonicId(lifecycleEpoch)
        pendingNavigation = null
        failedRevision = null
        revokePublishedBindings()
        reconcile()
    }

    private fun beginProxyStart(config: RustBrowserProxyConfig) {
        nextOperationId = nextMonotonicId(nextOperationId)
        val operation = StartOperation(nextOperationId, desiredRevision, lifecycleEpoch, config)
        startOperation = operation
        phase = Phase.Starting
        executeWorker(
            task = { runCatching { proxyFactory.start(config) }.getOrNull() },
            rejected = { onProxyStarted(operation, null) },
            callbackRejected = { proxy -> proxy?.let(::destroyOnCurrentWorker) },
            complete = { proxy -> onProxyStarted(operation, proxy) },
        )
    }

    private fun onProxyStarted(operation: StartOperation, proxy: LocalBrowserProxy?) {
        val ownsPhase = phase == Phase.Starting && startOperation?.id == operation.id
        if (ownsPhase) {
            startOperation = null
            phase = Phase.Idle
        }
        if (proxy == null) {
            if (ownsPhase && operation.isCurrent()) {
                failedRevision = desiredRevision
            }
            reconcile()
            return
        }

        val proxyScope = canonicalBrowserProxyHost(proxy.scopeHost)
        val validProxy = proxyScope == operation.config.scopeHost && proxy.endpoint.port in 1..65535
        if (!ownsPhase || !operation.isCurrent() || !validProxy) {
            retire(proxy)
            reconcile()
            return
        }

        val binding = Binding(operation.config, proxy)
        candidateBinding = binding
        if (!publishChallenge(binding)) {
            candidateBinding = null
            retire(proxy)
            reconcile()
            return
        }
        val apply = ApplyOperation(
            id = operation.id,
            desiredRevision = operation.desiredRevision,
            lifecycleEpoch = operation.lifecycleEpoch,
            binding = binding,
        )
        applyOperation = apply
        phase = Phase.Applying
        overrideController.applyLoopbackProxy(proxy.endpoint.port, proxy.scopeHost) { applied ->
            postCallback(
                rejected = { cleanupRejectedApplyCallback(apply) },
            ) {
                onProxyApplied(apply, applied)
            }
        }
    }

    private fun onProxyApplied(operation: ApplyOperation, applied: Boolean) {
        val ownsPhase = phase == Phase.Applying && applyOperation === operation
        if (!ownsPhase) return
        applyOperation = null
        phase = Phase.Idle
        // A false callback may mean this owner lost its claim after the platform set completed.
        // Only a confirmed clear proves that no process-global override remains.
        overrideInstalled = true

        val stillCandidate = candidateBinding === operation.binding
        if (stillCandidate) candidateBinding = null
        val canPublish =
            stillCandidate &&
                applied &&
                operation.isCurrent() &&
                operation.binding.isCompatibleWith(desiredConfig)
        if (canPublish) {
            if (publishAvailability(operation.binding)) {
                activeBinding = operation.binding
                clearChallenge(operation.binding)
                deliverPendingNavigation(operation.binding)
            } else {
                clearChallenge(operation.binding)
                if (stillCandidate) retire(operation.binding.proxy)
                reconcile()
            }
        } else {
            clearChallenge(operation.binding)
            if (stillCandidate) retire(operation.binding.proxy)
            if (!applied && operation.isCurrent()) {
                failedRevision = desiredRevision
            }
            publishAvailability(null)
            reconcile()
        }
    }

    private fun deliverPendingNavigation(binding: Binding?) {
        if (ownershipRevokedGate) return
        val pending = pendingNavigation ?: return
        val targetHost = pending.targetHost
        if (targetHost == null) {
            if (desiredConfig != null || overrideInstalled || binding != null) return
            pendingNavigation = null
            statusContext = null
            pending.load()
            return
        }

        if (binding == null) {
            if (desiredConfig == null || failedRevision != desiredRevision || overrideInstalled) return
            pendingNavigation = null
            statusContext = null
            pending.load()
            return
        }
        if (binding !== publishedBinding || !publishedAvailable || !binding.covers(targetHost)) return

        binding.proxy.discardMainFrameStatus(targetHost)
        if (binding !== publishedBinding || !publishedAvailable) return
        pendingNavigation = null
        statusContext = StatusContext(binding, targetHost)
        pending.load()
    }

    private fun publishAvailability(binding: Binding?): Boolean {
        var availabilityChange: Boolean? = null
        val published = synchronized(publicationLock) {
            val effectiveBinding = binding.takeUnless { it != null && ownershipRevokedGate }
            publishedBinding = effectiveBinding
            routingSnapshot = RoutingSnapshot(binding = effectiveBinding)
            val available = effectiveBinding != null
            if (publishedAvailable != available) {
                publishedAvailable = available
                availabilityChange = available
            }
            binding == null || effectiveBinding === binding
        }
        availabilityChange?.let(onAvailabilityChanged)
        return published
    }

    private fun unpublish(binding: Binding) {
        if (publishedBinding === binding) {
            publishAvailability(null)
            statusContext = null
        }
    }

    private fun publishCompatibilityScope(scope: String?): Boolean = synchronized(publicationLock) {
        if (publishedBinding == null && !ownershipRevokedGate) {
            routingSnapshot = RoutingSnapshot(compatibilityScope = scope)
            true
        } else {
            scope == null
        }
    }

    private fun publishChallenge(binding: Binding): Boolean = synchronized(publicationLock) {
        if (ownershipRevokedGate) {
            false
        } else {
            challengeBinding = binding
            true
        }
    }

    private fun clearChallenge(binding: Binding) {
        synchronized(publicationLock) {
            if (challengeBinding === binding) challengeBinding = null
        }
    }

    private fun retire(proxy: LocalBrowserProxy) {
        if (!retiredProxies.add(proxy)) return
        runCatching { proxy.requestStop() }
        retirementsInFlight += 1
        executeWorker(
            task = {
                runCatching { proxy.joinAndDestroy() }
                Unit
            },
            rejected = {
                Thread(
                    {
                        runCatching { proxy.joinAndDestroy() }
                        postRetirementComplete()
                    },
                    "hns-browser-proxy-emergency-cleanup",
                ).apply { isDaemon = true }.start()
            },
            callbackRejected = {},
            complete = { retirementComplete() },
        )
    }

    private fun postRetirementComplete() {
        try {
            callbackExecutor.execute(::retirementComplete)
        } catch (_: RejectedExecutionException) {
            // With no callback executor there is no safe state thread on which to start a successor.
        }
    }

    private fun retirementComplete() {
        retirementsInFlight = (retirementsInFlight - 1).coerceAtLeast(0)
        reconcile()
    }

    private fun <T> executeWorker(
        task: () -> T,
        rejected: () -> Unit,
        callbackRejected: (T) -> Unit,
        complete: (T) -> Unit,
    ) {
        try {
            workerExecutor.execute {
                val result = task()
                try {
                    callbackExecutor.execute { complete(result) }
                } catch (_: RejectedExecutionException) {
                    callbackRejected(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            rejected()
        }
    }

    private fun postCallback(
        rejected: () -> Unit = {},
        callback: () -> Unit,
    ) {
        try {
            callbackExecutor.execute(callback)
        } catch (_: RejectedExecutionException) {
            rejected()
        }
    }

    private fun cleanupRejectedApplyCallback(operation: ApplyOperation) {
        destroyDetached(operation.binding.proxy)
        runCatching { overrideController.clear { _ -> } }
    }

    private fun destroyDetached(proxy: LocalBrowserProxy) {
        runCatching { proxy.requestStop() }
        try {
            workerExecutor.execute {
                runCatching { proxy.joinAndDestroy() }
            }
        } catch (_: RejectedExecutionException) {
            Thread(
                { runCatching { proxy.joinAndDestroy() } },
                "hns-browser-proxy-emergency-cleanup",
            ).apply { isDaemon = true }.start()
        }
    }

    private fun destroyOnCurrentWorker(proxy: LocalBrowserProxy) {
        runCatching { proxy.requestStop() }
        runCatching { proxy.joinAndDestroy() }
    }

    private fun StartOperation.isCurrent(): Boolean =
        !destroyed &&
            enabled &&
            !ownershipRevokedGate &&
            this@BrowserProxyCoordinator.desiredRevision == this.desiredRevision &&
            this@BrowserProxyCoordinator.lifecycleEpoch == this.lifecycleEpoch &&
            desiredConfig?.let { sameProxyConfig(it, config) } == true

    private fun ApplyOperation.isCurrent(): Boolean =
        !destroyed &&
            enabled &&
            !ownershipRevokedGate &&
            this@BrowserProxyCoordinator.desiredRevision == this.desiredRevision &&
            this@BrowserProxyCoordinator.lifecycleEpoch == this.lifecycleEpoch &&
            desiredConfig?.let { binding.isCompatibleWith(it) } == true

    private fun Binding.isCompatibleWith(config: RustBrowserProxyConfig?): Boolean =
        config != null &&
            sameProxySettings(this.config, config) &&
            scopeContainsHost(this.config.scopeHost, config.scopeHost)

    private fun Binding.covers(host: String): Boolean = scopeContainsHost(proxy.scopeHost, host)
}

private fun RustBrowserProxyConfig.normalized(): RustBrowserProxyConfig {
    val canonicalScope = requireNotNull(canonicalBrowserProxyHost(scopeHost)) {
        "HNS proxy scope must be a canonicalizable host"
    }
    return if (canonicalScope == scopeHost) {
        this
    } else {
        RustBrowserProxyConfig(
            dataDir = dataDir,
            network = network,
            scopeHost = canonicalScope,
            strictHnsMode = strictHnsMode,
            dohResolverUrl = dohResolverUrl,
            statelessDaneCertificates = statelessDaneCertificates,
        )
    }
}

private fun sameProxyConfig(first: RustBrowserProxyConfig?, second: RustBrowserProxyConfig?): Boolean =
    when {
        first == null || second == null -> first == null && second == null
        else -> sameProxySettings(first, second) && first.scopeHost == second.scopeHost
    }

private fun sameProxySettings(first: RustBrowserProxyConfig, second: RustBrowserProxyConfig): Boolean =
    first.dataDir == second.dataDir &&
        first.network == second.network &&
        first.strictHnsMode == second.strictHnsMode &&
        first.dohResolverUrl == second.dohResolverUrl &&
        first.statelessDaneCertificates == second.statelessDaneCertificates

internal fun canonicalBrowserProxyHost(host: String): String? {
    val canonical = host.trim().trimEnd('.').lowercase(Locale.US)
    if (canonical.isEmpty() || canonical.length > 253 || !canonical.all(Char::isAscii)) return null
    if (canonical.split('.').any { label ->
            label.isEmpty() ||
                label.length > 63 ||
                !label.first().isLetterOrDigit() ||
                !label.last().isLetterOrDigit() ||
                !label.all { character -> character.isLetterOrDigit() || character == '-' }
        }
    ) {
        return null
    }
    return canonical
}

private fun scopeContainsHost(scope: String, host: String): Boolean =
    host == scope || host.endsWith(".$scope")

private fun Char.isAscii(): Boolean = code in 0..0x7f

private fun nextMonotonicId(current: Long): Long {
    check(current < Long.MAX_VALUE) { "browser proxy operation counter exhausted" }
    return current + 1L
}
