package com.denuoweb.hnsdane.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.ArrayDeque
import java.util.LinkedList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

class BrowserProxyCoordinatorTest {
    @Test
    fun directNavigationWaitsForProcessOverrideOwnershipBarrier() {
        val fixture = Fixture()
        fixture.overrideController.autoAcquire = false
        fixture.coordinator.navigate(null, null) { fixture.loads += "direct" }
        fixture.coordinator.resume(null)

        assertTrue(fixture.loads.isEmpty())
        fixture.overrideController.completeAcquire(true)
        assertEquals(listOf("direct"), fixture.loads)
    }

    @Test
    fun rejectedProcessOwnerCanNeverLoadOrStart() {
        val fixture = Fixture()
        fixture.overrideController.autoAcquire = false
        fixture.factory.results += fixture.proxy("alpha")
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "alpha"
        }
        fixture.coordinator.resume(fixture.config("alpha"))

        fixture.overrideController.completeAcquire(false)
        assertTrue(fixture.loads.isEmpty())
        assertEquals(0, fixture.worker.size)
        assertFalse(fixture.coordinator.isProxyAvailable)
    }

    @Test
    fun processOwnershipRevocationImmediatelyWithdrawsAdmissionAndTrust() {
        val fixture = Fixture()
        val proxy = fixture.activate("alpha")
        proxy.certificateMatches = true
        assertEquals(BrowserProxyRoute.Proxy, fixture.coordinator.routeForHnsHost("alpha"))
        assertTrue(fixture.coordinator.matchesLocalCertificate("alpha", byteArrayOf(1)))

        fixture.overrideController.revokeOwnership()

        assertFalse(fixture.coordinator.isProxyAvailable)
        assertEquals(BrowserProxyRoute.Block, fixture.coordinator.routeForHnsHost("alpha"))
        assertNull(
            fixture.coordinator.authorizationForChallenge(
                "127.0.0.1",
                proxy.endpoint.authorization.realm,
            ),
        )
        assertFalse(fixture.coordinator.matchesLocalCertificate("alpha", byteArrayOf(1)))
        assertEquals(1, proxy.stopCalls)

        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") { fixture.loads += "stale" }
        assertFalse(fixture.loads.contains("stale"))
    }

    @Test
    fun ownershipRevocationWithdrawsVolatileRouteBeforeQueuedStateCleanup() {
        val callbacks = QueuedExecutor()
        val worker = QueuedExecutor()
        val overrideController = FakeOverrideController()
        val factory = FakeProxyFactory()
        val proxy = FakeProxy("alpha", 43210)
        factory.results += proxy
        val coordinator = BrowserProxyCoordinator(
            overrideController = overrideController,
            proxyFactory = factory,
            workerExecutor = worker,
            callbackExecutor = callbacks,
        )
        val config = RustBrowserProxyConfig("/tmp/browser", "regtest", "alpha", false, "", false)
        coordinator.resume(null)
        callbacks.runNext()
        coordinator.navigate(config, "alpha") {}
        worker.runNext()
        callbacks.runNext()
        overrideController.completeApply(true)
        callbacks.runNext()
        assertEquals(BrowserProxyRoute.Proxy, coordinator.routeForHnsHost("alpha"))

        overrideController.revokeOwnership()

        assertEquals(BrowserProxyRoute.Block, coordinator.routeForHnsHost("alpha"))
        assertFalse(coordinator.isProxyAvailable)
        assertEquals(1, callbacks.size)
    }

    @Test
    fun rejectedRevocationCallbackCanNeverRepublishStoppedBinding() {
        val callbackExecutor = RejectableDirectExecutor()
        val fixture = Fixture(callbackExecutor = callbackExecutor)
        val proxy = fixture.activate("alpha")
        callbackExecutor.reject = true

        fixture.overrideController.revokeOwnership()
        fixture.coordinator.ensure(fixture.config("alpha"))

        assertEquals(BrowserProxyRoute.Block, fixture.coordinator.routeForHnsHost("alpha"))
        assertFalse(fixture.coordinator.isProxyAvailable)
        assertEquals(1, proxy.stopCalls)
        assertTrue(fixture.overrideController.clearCalls >= 1)
        fixture.worker.runNext()
        assertEquals(1, proxy.joinCalls)
    }

    @Test
    fun queuedApplyCompletionCannotCrossSynchronousRevocationGate() {
        val callbacks = QueuedExecutor()
        val worker = QueuedExecutor()
        val overrideController = FakeOverrideController()
        val factory = FakeProxyFactory()
        val proxy = FakeProxy("alpha", 43210)
        factory.results += proxy
        val coordinator = BrowserProxyCoordinator(
            overrideController = overrideController,
            proxyFactory = factory,
            workerExecutor = worker,
            callbackExecutor = callbacks,
        )
        val config = RustBrowserProxyConfig("/tmp/browser", "regtest", "alpha", false, "", false)
        val loads = mutableListOf<String>()
        coordinator.resume(null)
        callbacks.runNext()
        coordinator.navigate(config, "alpha") { loads += "alpha" }
        worker.runNext()
        callbacks.runNext()
        overrideController.completeApply(true)
        overrideController.revokeOwnership()

        callbacks.runNext()

        assertTrue(loads.isEmpty())
        assertFalse(coordinator.isProxyAvailable)
        assertEquals(BrowserProxyRoute.Block, coordinator.routeForHnsHost("alpha"))
        assertEquals(1, proxy.stopCalls)
    }

    @Test
    fun twoCoordinatorsShareProcessQueueThroughRevocationClearAndReplacementApply() {
        val processQueue = BrowserProxyOverrideOperationQueue()
        val platform = ImmediateProxyPlatform()
        val worker = QueuedExecutor()
        val firstFactory = FakeProxyFactory()
        val firstProxy = FakeProxy("alpha", 43210)
        firstFactory.results += firstProxy
        val firstLoads = mutableListOf<String>()
        val first = BrowserProxyCoordinator(
            overrideController = QueueBackedOverrideController(processQueue, platform),
            proxyFactory = firstFactory,
            workerExecutor = worker,
            callbackExecutor = Executor(Runnable::run),
        )
        val alpha = RustBrowserProxyConfig("/tmp/browser", "regtest", "alpha", false, "", false)
        first.navigate(alpha, "alpha") { firstLoads += "alpha" }
        first.resume(alpha)
        worker.runNext()

        assertEquals(listOf("alpha"), firstLoads)
        assertEquals(BrowserProxyRoute.Proxy, first.routeForHnsHost("alpha"))

        val secondFactory = FakeProxyFactory()
        val secondProxy = FakeProxy("beta", 43211)
        secondFactory.results += secondProxy
        val secondLoads = mutableListOf<String>()
        val second = BrowserProxyCoordinator(
            overrideController = QueueBackedOverrideController(processQueue, platform),
            proxyFactory = secondFactory,
            workerExecutor = worker,
            callbackExecutor = Executor(Runnable::run),
        )
        val beta = RustBrowserProxyConfig("/tmp/browser", "regtest", "beta", false, "", false)
        second.navigate(beta, "beta") { secondLoads += "beta" }
        second.resume(beta)

        assertEquals(BrowserProxyRoute.Block, first.routeForHnsHost("alpha"))
        assertEquals(1, firstProxy.stopCalls)
        assertEquals(1, platform.clearCalls)
        assertEquals(2, worker.size)

        worker.runNext()
        assertEquals(1, firstProxy.joinCalls)
        worker.runNext()

        assertEquals(listOf("beta"), secondLoads)
        assertEquals(BrowserProxyRoute.Proxy, second.routeForHnsHost("beta"))
        assertEquals(listOf(43210 to "alpha", 43211 to "beta"), platform.applyCalls)
        assertEquals(1, platform.clearCalls)
    }

    @Test
    fun hnsNavigationWaitsForExactStartedAndAppliedProxy() {
        val fixture = Fixture()
        val proxy = fixture.proxy("alpha")
        fixture.factory.results += proxy
        fixture.coordinator.resume(null)

        fixture.coordinator.navigate(fixture.config("Alpha."), "ALPHA.") {
            fixture.loads += "alpha"
        }

        assertTrue(fixture.loads.isEmpty())
        assertEquals(1, fixture.worker.size)
        assertTrue(fixture.overrideController.applyCalls.isEmpty())

        fixture.worker.runNext()
        assertTrue(fixture.loads.isEmpty())
        assertEquals(listOf(43210 to "alpha"), fixture.overrideController.applyCalls)
        assertFalse(fixture.coordinator.isProxyAvailable)
        assertEquals(BrowserProxyRoute.Block, fixture.coordinator.routeForHnsHost("alpha"))
        assertSame(
            proxy.endpoint.authorization,
            fixture.coordinator.authorizationForChallenge("127.0.0.1", proxy.endpoint.authorization.realm),
        )

        fixture.overrideController.completeApply(true)
        assertEquals(listOf("alpha"), fixture.loads)
        assertTrue(fixture.coordinator.isProxyAvailable)
        assertEquals(listOf("alpha"), proxy.discardedHosts)
        assertTrue(fixture.availability.last())
        assertEquals(BrowserProxyRoute.Proxy, fixture.coordinator.routeForHnsHost("sub.alpha"))
        assertEquals(BrowserProxyRoute.Block, fixture.coordinator.routeForHnsHost("other"))
    }

    @Test
    fun activeRootScopeIsReusedForSubdomainAndOldStatusIsDiscardedFirst() {
        val fixture = Fixture()
        val proxy = fixture.activate("alpha")
        fixture.loads.clear()
        proxy.discardedHosts.clear()

        fixture.coordinator.navigate(fixture.config("sub.alpha"), "sub.alpha") {
            fixture.loads += "sub"
        }

        assertEquals(listOf("sub.alpha"), proxy.discardedHosts)
        assertEquals(listOf("sub"), fixture.loads)
        assertEquals(0, fixture.worker.size)
        assertEquals(1, fixture.overrideController.applyCalls.size)
        assertTrue(fixture.coordinator.coversHost("deep.sub.alpha"))
    }

    @Test
    fun scopeRotationRevokesClearsJoinsThenStartsReplacement() {
        val fixture = Fixture()
        val first = fixture.activate("alpha")
        fixture.loads.clear()
        val second = fixture.proxy("beta", port = 43211)
        fixture.factory.results += second

        fixture.coordinator.navigate(fixture.config("beta"), "beta") {
            fixture.loads += "beta"
        }

        assertEquals(1, first.stopCalls)
        assertFalse(fixture.coordinator.isProxyAvailable)
        assertEquals(1, fixture.overrideController.clearCalls)
        assertEquals(1, fixture.worker.size)
        assertTrue(fixture.factory.startedConfigs.none { it.scopeHost == "beta" })

        fixture.overrideController.completeClear()
        assertEquals(1, fixture.worker.size)
        fixture.worker.runNext()
        assertEquals(1, first.joinCalls)
        assertTrue(fixture.factory.startedConfigs.none { it.scopeHost == "beta" })

        fixture.worker.runNext()
        assertEquals("beta", fixture.factory.startedConfigs.last().scopeHost)
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("beta"), fixture.loads)
        assertTrue(fixture.coordinator.isProxyAvailable)
    }

    @Test
    fun staleSuccessfulApplyIsActivelyClearedAndNeverLoadsOldNavigation() {
        val fixture = Fixture()
        val first = fixture.proxy("alpha")
        val second = fixture.proxy("beta", port = 43211)
        fixture.factory.results += first
        fixture.factory.results += second
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "alpha"
        }
        fixture.worker.runNext()

        fixture.coordinator.navigate(fixture.config("beta"), "beta") {
            fixture.loads += "beta"
        }
        assertEquals(1, first.stopCalls)
        assertEquals(1, fixture.worker.size)

        fixture.overrideController.completeApply(true)
        assertTrue(fixture.loads.isEmpty())
        assertEquals(1, fixture.overrideController.clearCalls)
        assertFalse(fixture.coordinator.isProxyAvailable)

        fixture.overrideController.completeClear()
        fixture.worker.runNext()
        assertEquals(1, first.joinCalls)
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("beta"), fixture.loads)
    }

    @Test
    fun duplicateOldClearCannotReleaseLaterTransition() {
        val fixture = Fixture()
        fixture.activate("alpha")
        fixture.loads.clear()
        fixture.factory.results += fixture.proxy("beta", port = 43211)
        fixture.coordinator.navigate(fixture.config("beta"), "beta") { fixture.loads += "beta" }
        fixture.overrideController.completeClear()
        fixture.worker.runNext()
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("beta"), fixture.loads)

        fixture.factory.results += fixture.proxy("gamma", port = 43212)
        fixture.coordinator.navigate(fixture.config("gamma"), "gamma") { fixture.loads += "gamma" }
        assertEquals(2, fixture.overrideController.clearCalls)

        fixture.overrideController.repeatPreviousClear()
        assertEquals(listOf("beta"), fixture.loads)
        assertFalse(fixture.coordinator.isProxyAvailable)

        fixture.overrideController.completeClear()
        fixture.worker.runNext()
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("beta", "gamma"), fixture.loads)
    }

    @Test
    fun failedClearCannotReleaseDirectNavigation() {
        val fixture = Fixture()
        fixture.activate("alpha")
        fixture.loads.clear()

        fixture.coordinator.navigate(null, null) { fixture.loads += "direct" }
        fixture.overrideController.completeClear(cleared = false)

        assertTrue(fixture.loads.isEmpty())
        assertFalse(fixture.coordinator.isProxyAvailable)
        fixture.coordinator.resume(null)
        assertEquals(2, fixture.overrideController.clearCalls)
    }

    @Test
    fun overlappingSameScopeNavigationRotatesGenerationBeforeLoadingAgain() {
        val fixture = Fixture()
        val first = fixture.activate("alpha", completeNavigation = false)
        val second = fixture.proxy("alpha", port = 43211)
        fixture.factory.results += second

        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "second"
        }

        assertEquals(1, first.stopCalls)
        assertEquals(1, fixture.overrideController.clearCalls)
        fixture.overrideController.completeClear()
        fixture.worker.runNext()
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("alpha", "second"), fixture.loads)
    }

    @Test
    fun failedStartFallsBackToInterceptorLoadAndNextNavigationCanRetry() {
        val fixture = Fixture()
        fixture.factory.results += null
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "fallback"
        }

        fixture.worker.runNext()
        assertEquals(listOf("fallback"), fixture.loads)
        assertFalse(fixture.coordinator.isProxyAvailable)
        assertEquals(
            BrowserProxyRoute.CompatibilityInterceptor,
            fixture.coordinator.routeForHnsHost("sub.alpha"),
        )
        assertEquals(BrowserProxyRoute.Block, fixture.coordinator.routeForHnsHost("other"))
        assertTrue(fixture.overrideController.applyCalls.isEmpty())

        val replacement = fixture.proxy("alpha")
        fixture.factory.results += replacement
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "retry"
        }
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("fallback", "retry"), fixture.loads)
        assertTrue(fixture.coordinator.isProxyAvailable)
    }

    @Test
    fun failedApplyWaitsForConfirmedClearBeforeCompatibilityLoad() {
        val fixture = Fixture()
        val proxy = fixture.proxy("alpha")
        fixture.factory.results += proxy
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "fallback"
        }
        fixture.worker.runNext()

        fixture.overrideController.completeApply(false)
        assertTrue(fixture.loads.isEmpty())
        assertEquals(1, fixture.overrideController.clearCalls)
        assertEquals(1, proxy.stopCalls)

        fixture.overrideController.completeClear()
        assertEquals(listOf("fallback"), fixture.loads)
        assertEquals(BrowserProxyRoute.CompatibilityInterceptor, fixture.coordinator.routeForHnsHost("alpha"))
    }

    @Test
    fun incompatibleEnsureDropsQueuedNavigation() {
        val fixture = Fixture()
        fixture.factory.results += fixture.proxy("alpha")
        fixture.factory.results += fixture.proxy("beta", port = 43211)
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "alpha"
        }

        fixture.coordinator.ensure(fixture.config("beta"))
        fixture.worker.runNext()
        fixture.worker.runNext()
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)

        assertTrue(fixture.loads.isEmpty())
        assertTrue(fixture.coordinator.coversHost("beta"))
    }

    @Test
    fun suspendInvalidatesInflightWorkAndResumeUsesFreshInstance() {
        val fixture = Fixture()
        val stale = fixture.proxy("alpha")
        val fresh = fixture.proxy("alpha", port = 43211)
        fixture.factory.results += stale
        fixture.factory.results += fresh
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "alpha"
        }

        fixture.coordinator.suspend()
        fixture.coordinator.resume(fixture.config("alpha"))
        fixture.worker.runNext()
        assertEquals(1, stale.stopCalls)
        assertTrue(fixture.overrideController.applyCalls.isEmpty())

        fixture.worker.runNext()
        assertEquals(1, stale.joinCalls)
        fixture.worker.runNext()
        fixture.overrideController.completeApply(true)
        assertEquals(listOf("alpha"), fixture.loads)
        assertTrue(fixture.coordinator.isProxyAvailable)
    }

    @Test
    fun suspendAndResumeDuringAcquireRequiresAFreshOwnershipClaim() {
        val fixture = Fixture()
        fixture.overrideController.autoAcquire = false
        fixture.factory.results += fixture.proxy("alpha")
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {}
        fixture.coordinator.resume(fixture.config("alpha"))

        fixture.coordinator.suspend()
        fixture.coordinator.resume(fixture.config("alpha"))
        fixture.overrideController.completeAcquire(true)

        assertEquals(0, fixture.worker.size)
        fixture.overrideController.completeAcquire(true)
        assertEquals(1, fixture.worker.size)
    }

    @Test
    fun policyChangeRotatesEvenWhenScopeIsUnchanged() {
        val fixture = Fixture()
        val first = fixture.activate("alpha")
        val strict = fixture.proxy("alpha", port = 43211)
        fixture.factory.results += strict

        fixture.coordinator.ensure(fixture.config("alpha", strict = true))

        assertEquals(1, first.stopCalls)
        assertEquals(1, fixture.overrideController.clearCalls)
        fixture.overrideController.completeClear()
        fixture.worker.runNext()
        fixture.worker.runNext()
        assertTrue(fixture.factory.startedConfigs.last().strictHnsMode)
        fixture.overrideController.completeApply(true)
        assertTrue(fixture.coordinator.isProxyAvailable)
    }

    @Test
    fun authCertificateAndStatusAreBoundToPublishedInstanceAndNavigation() {
        val fixture = Fixture()
        val proxy = fixture.activate("alpha", completeNavigation = false)
        val authorization = fixture.coordinator.authorizationForChallenge("127.0.0.1", proxy.endpoint.authorization.realm)
        assertSame(proxy.endpoint.authorization, authorization)
        assertNull(fixture.coordinator.authorizationForChallenge("localhost", proxy.endpoint.authorization.realm))
        assertNull(fixture.coordinator.authorizationForChallenge("127.0.0.1", "stale-realm"))

        proxy.certificateMatches = true
        assertTrue(fixture.coordinator.matchesLocalCertificate("sub.alpha", byteArrayOf(1)))
        assertFalse(fixture.coordinator.matchesLocalCertificate("other", byteArrayOf(1)))

        val status = LocalBrowserProxyStatus(7, 200, null, null, null, null)
        proxy.status = status
        assertNull(fixture.coordinator.takeMainFrameStatus("sub.alpha"))
        assertSame(status, fixture.coordinator.takeMainFrameStatus("alpha"))
        assertNull(fixture.coordinator.takeMainFrameStatus("alpha"))

        fixture.coordinator.navigate(fixture.config("sub.alpha"), "sub.alpha") {}
        fixture.coordinator.noteMainFrameHost("deep.sub.alpha")
        proxy.status = status
        assertSame(status, fixture.coordinator.takeMainFrameStatus("deep.sub.alpha"))
        assertEquals("deep.sub.alpha", proxy.takenHosts.last())
    }

    @Test
    fun concurrentRevocationDropsInflightCertificateAndStatusResults() {
        val certificateFixture = Fixture()
        val certificateProxy = certificateFixture.activate("alpha")
        certificateProxy.certificateMatches = true
        certificateProxy.onCertificateCheck = certificateFixture.coordinator::suspend
        assertFalse(certificateFixture.coordinator.matchesLocalCertificate("alpha", byteArrayOf(1)))

        val statusFixture = Fixture()
        val statusProxy = statusFixture.activate("alpha", completeNavigation = false)
        statusProxy.status = LocalBrowserProxyStatus(9, 204, null, null, null, null)
        statusProxy.onStatusTake = statusFixture.coordinator::suspend
        assertNull(statusFixture.coordinator.takeMainFrameStatus("alpha"))
    }

    @Test
    fun destroyMakesLateStartCleanupOnly() {
        val fixture = Fixture()
        val proxy = fixture.proxy("alpha")
        fixture.factory.results += proxy
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {
            fixture.loads += "alpha"
        }

        fixture.coordinator.destroy()
        fixture.worker.runNext()
        assertEquals(1, proxy.stopCalls)
        assertTrue(fixture.overrideController.applyCalls.isEmpty())
        assertTrue(fixture.loads.isEmpty())
        fixture.worker.runNext()
        assertEquals(1, proxy.joinCalls)
    }

    @Test
    fun platformCallbacksAreMarshalledThroughCallbackExecutor() {
        val callbacks = QueuedExecutor()
        val worker = QueuedExecutor()
        val overrideController = FakeOverrideController()
        val coordinator = BrowserProxyCoordinator(
            overrideController = overrideController,
            proxyFactory = FakeProxyFactory(),
            workerExecutor = worker,
            callbackExecutor = callbacks,
        )
        val loads = mutableListOf<String>()

        coordinator.navigate(null, null) { loads += "direct" }
        coordinator.resume(null)
        assertTrue(loads.isEmpty())
        assertEquals(1, callbacks.size)

        callbacks.runNext()
        assertEquals(listOf("direct"), loads)
    }

    @Test
    fun rejectedWorkerUsesEmergencyProxyDestruction() {
        val fixture = Fixture()
        val proxy = fixture.activate("alpha")
        val joined = CountDownLatch(1)
        proxy.onJoin = joined::countDown
        fixture.worker.reject = true

        fixture.coordinator.navigate(fixture.config("beta"), "beta") {}

        assertEquals(1, proxy.stopCalls)
        assertTrue(joined.await(5, TimeUnit.SECONDS))
        assertEquals(1, proxy.joinCalls)
    }

    @Test
    fun rejectedApplyCallbackRevokesAndDestroysUnpublishedProxy() {
        val callbackExecutor = RejectableDirectExecutor()
        val fixture = Fixture(callbackExecutor = callbackExecutor)
        val proxy = fixture.proxy("alpha")
        fixture.factory.results += proxy
        fixture.coordinator.resume(null)
        fixture.coordinator.navigate(fixture.config("alpha"), "alpha") {}
        fixture.worker.runNext()

        callbackExecutor.reject = true
        fixture.overrideController.completeApply(true)

        assertEquals(1, proxy.stopCalls)
        assertEquals(1, fixture.overrideController.clearCalls)
        assertFalse(fixture.coordinator.isProxyAvailable)
        fixture.worker.runNext()
        assertEquals(1, proxy.joinCalls)
    }

    private class Fixture(
        callbackExecutor: Executor = Executor(Runnable::run),
    ) {
        val worker = QueuedExecutor()
        val overrideController = FakeOverrideController()
        val factory = FakeProxyFactory()
        val loads = mutableListOf<String>()
        val availability = mutableListOf<Boolean>()
        val coordinator = BrowserProxyCoordinator(
            overrideController = overrideController,
            proxyFactory = factory,
            workerExecutor = worker,
            callbackExecutor = callbackExecutor,
            onAvailabilityChanged = availability::add,
        )

        fun config(host: String, strict: Boolean = false): RustBrowserProxyConfig =
            RustBrowserProxyConfig(
                dataDir = "/tmp/browser",
                network = "regtest",
                scopeHost = host,
                strictHnsMode = strict,
                dohResolverUrl = "https://resolver.test/dns-query",
                statelessDaneCertificates = false,
            )

        fun proxy(host: String, port: Int = 43210): FakeProxy = FakeProxy(host, port)

        fun activate(host: String, completeNavigation: Boolean = true): FakeProxy {
            val proxy = proxy(host)
            factory.results += proxy
            coordinator.resume(null)
            coordinator.navigate(config(host), host) { loads += host }
            worker.runNext()
            overrideController.completeApply(true)
            if (completeNavigation) coordinator.takeMainFrameStatus(host)
            return proxy
        }
    }

    private class QueuedExecutor : Executor {
        private val tasks = ArrayDeque<Runnable>()
        var reject = false
        val size: Int
            get() = tasks.size

        override fun execute(command: Runnable) {
            if (reject) throw RejectedExecutionException("rejected for test")
            tasks += command
        }

        fun runNext() {
            tasks.removeFirst().run()
        }
    }

    private class RejectableDirectExecutor : Executor {
        var reject = false

        override fun execute(command: Runnable) {
            if (reject) throw RejectedExecutionException("rejected for test")
            command.run()
        }
    }

    private class FakeOverrideController : BrowserProxyOverrideController {
        val applyCalls = mutableListOf<Pair<Int, String>>()
        var clearCalls = 0
        private val applyCallbacks = ArrayDeque<(Boolean) -> Unit>()
        private val clearCallbacks = ArrayDeque<(Boolean) -> Unit>()
        private val acquireCallbacks = ArrayDeque<(Boolean) -> Unit>()
        private var previousClearCallback: ((Boolean) -> Unit)? = null
        private var ownershipRevoked: (() -> Unit)? = null
        var autoAcquire = true

        override fun acquire(onOwnershipRevoked: () -> Unit, onComplete: (Boolean) -> Unit) {
            ownershipRevoked = onOwnershipRevoked
            if (autoAcquire) {
                onComplete(true)
            } else {
                acquireCallbacks += onComplete
            }
        }

        override fun releaseOwnership() {
            ownershipRevoked = null
        }

        override fun applyLoopbackProxy(port: Int, hnsHost: String?, onComplete: (Boolean) -> Unit) {
            applyCalls += port to requireNotNull(hnsHost)
            applyCallbacks += onComplete
        }

        override fun clear(onComplete: (Boolean) -> Unit) {
            clearCalls += 1
            clearCallbacks += onComplete
        }

        fun completeApply(applied: Boolean) {
            applyCallbacks.removeFirst().invoke(applied)
        }

        fun completeAcquire(acquired: Boolean) {
            acquireCallbacks.removeFirst().invoke(acquired)
        }

        fun completeClear(cleared: Boolean = true) {
            clearCallbacks.removeFirst().also { previousClearCallback = it }.invoke(cleared)
        }

        fun repeatPreviousClear() {
            requireNotNull(previousClearCallback).invoke(true)
        }

        fun revokeOwnership() {
            requireNotNull(ownershipRevoked).invoke()
        }
    }

    private class QueueBackedOverrideController(
        private val queue: BrowserProxyOverrideOperationQueue,
        private val platform: ImmediateProxyPlatform,
    ) : BrowserProxyOverrideController {
        private val owner = queue.newOwner()

        override fun acquire(onOwnershipRevoked: () -> Unit, onComplete: (Boolean) -> Unit) {
            queue.acquire(owner, platform::clear, onOwnershipRevoked, onComplete)
        }

        override fun releaseOwnership() = queue.release(owner)

        override fun applyLoopbackProxy(port: Int, hnsHost: String?, onComplete: (Boolean) -> Unit) {
            queue.apply(
                owner = owner,
                platformApply = { complete -> platform.apply(port, requireNotNull(hnsHost), complete) },
                onComplete = onComplete,
            )
        }

        override fun clear(onComplete: (Boolean) -> Unit) {
            queue.clear(owner, platform::clear, onComplete)
        }
    }

    private class ImmediateProxyPlatform {
        val applyCalls = mutableListOf<Pair<Int, String>>()
        var clearCalls = 0

        fun apply(port: Int, host: String, complete: (Boolean) -> Unit) {
            applyCalls += port to host
            complete(true)
        }

        fun clear(complete: (Boolean) -> Unit) {
            clearCalls += 1
            complete(true)
        }
    }

    private class FakeProxyFactory : LocalBrowserProxyFactory {
        val results = LinkedList<LocalBrowserProxy?>()
        val startedConfigs = mutableListOf<RustBrowserProxyConfig>()

        override fun start(config: RustBrowserProxyConfig): LocalBrowserProxy? {
            startedConfigs += config
            return results.removeFirst()
        }
    }

    private class FakeProxy(
        override val scopeHost: String,
        port: Int,
    ) : LocalBrowserProxy {
        override val endpoint = LocalBrowserProxyEndpoint(
            nativeHandle = port.toLong(),
            port = port,
            instanceId = LocalProxyInstanceId("session-$port", port.toLong()),
            authorization = LoopbackProxyAuthorization.createForTest(
                realm = "realm-$port",
                username = "user-$port",
                password = "password-$port",
            ),
        )
        var stopCalls = 0
        var joinCalls = 0
        var certificateMatches = false
        var status: LocalBrowserProxyStatus? = null
        var onCertificateCheck: (() -> Unit)? = null
        var onStatusTake: (() -> Unit)? = null
        var onJoin: (() -> Unit)? = null
        val discardedHosts = mutableListOf<String>()
        val takenHosts = mutableListOf<String>()

        override fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean {
            onCertificateCheck?.invoke()
            return certificateMatches
        }

        override fun takeMainFrameStatus(host: String): LocalBrowserProxyStatus? {
            takenHosts += host
            onStatusTake?.invoke()
            return status.also { status = null }
        }

        override fun discardMainFrameStatus(host: String) {
            discardedHosts += host
            status = null
        }

        override fun requestStop() {
            if (stopCalls == 0) stopCalls = 1
        }

        override fun joinAndDestroy() {
            if (joinCalls == 0) joinCalls = 1
            onJoin?.invoke()
        }
    }
}
