package com.denuoweb.hnsdane.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsProxyControllerTest {
    @Test
    fun loopbackProxyConfigScopesProxyToCurrentHnsHostWhenReverseBypassIsSupported() {
        val config = loopbackProxyConfig(
            port = 12345,
            hnsHost = "Nathan.Woodburn.",
        )

        assertTrue(config.isReverseBypassEnabled)
        assertEquals(listOf("nathan.woodburn", "*.nathan.woodburn"), config.bypassRules)
        assertEquals("http://127.0.0.1:12345", config.proxyRules.single().url)
    }

    @Test
    fun loopbackProxyRequiresReverseBypassAndHostScope() {
        assertTrue(canApplyLoopbackProxy("nathan.woodburn", reverseBypassSupported = true))
        assertFalse(canApplyLoopbackProxy("nathan.woodburn", reverseBypassSupported = false))
        assertFalse(canApplyLoopbackProxy(null, reverseBypassSupported = true))
        assertFalse(canApplyLoopbackProxy("   ", reverseBypassSupported = true))
    }

    @Test
    fun processQueueClearsLateOldApplyBeforeNewOwnerIsAcquired() {
        val queue = BrowserProxyOverrideOperationQueue()
        val oldOwner = queue.newOwner()
        queue.acquire(oldOwner, { finish -> finish(true) }) { assertTrue(it) }
        var finishOldApply: ((Boolean) -> Unit)? = null
        var oldApplyResult: Boolean? = null
        queue.apply(
            owner = oldOwner,
            platformApply = { finish -> finishOldApply = finish },
            onComplete = { applied -> oldApplyResult = applied },
        )

        val newOwner = queue.newOwner()
        var finishOwnershipClear: ((Boolean) -> Unit)? = null
        var acquired: Boolean? = null
        queue.acquire(
            owner = newOwner,
            platformClear = { finish -> finishOwnershipClear = finish },
            onComplete = { result -> acquired = result },
        )

        assertEquals(null, finishOwnershipClear)
        requireNotNull(finishOldApply).invoke(true)
        assertEquals(false, oldApplyResult)
        assertTrue(finishOwnershipClear != null)
        assertEquals(null, acquired)

        requireNotNull(finishOwnershipClear).invoke(true)
        assertEquals(true, acquired)
    }

    @Test
    fun newerAcquisitionRevokesOlderClaimBeforePlatformHandoff() {
        val queue = BrowserProxyOverrideOperationQueue()
        val oldOwner = queue.newOwner()
        var revocations = 0
        queue.acquire(
            owner = oldOwner,
            platformClear = { finish -> finish(true) },
            onOwnershipRevoked = { revocations += 1 },
            onComplete = { assertTrue(it) },
        )
        queue.apply(oldOwner, { finish -> finish(true) }) { assertTrue(it) }

        val newOwner = queue.newOwner()
        var finishHandoff: ((Boolean) -> Unit)? = null
        queue.acquire(
            owner = newOwner,
            platformClear = { finish -> finishHandoff = finish },
            onComplete = {},
        )

        assertEquals(1, revocations)
        assertTrue(finishHandoff != null)
    }

    @Test
    fun releasedNewerOwnerDoesNotPermitRetiredOwnerToReclaim() {
        val queue = BrowserProxyOverrideOperationQueue()
        val oldOwner = queue.newOwner()
        queue.acquire(oldOwner, { finish -> finish(true) }) { assertTrue(it) }

        val newOwner = queue.newOwner()
        queue.acquire(newOwner, { finish -> finish(true) }) { assertTrue(it) }
        queue.release(newOwner)

        var platformClearCalls = 0
        var reacquired: Boolean? = null
        queue.acquire(
            owner = oldOwner,
            platformClear = { finish ->
                platformClearCalls += 1
                finish(true)
            },
            onComplete = { result -> reacquired = result },
        )

        assertEquals(0, platformClearCalls)
        assertEquals(false, reacquired)
    }

    @Test
    fun retiredOwnerCannotClearNewerCommittedOverride() {
        val queue = BrowserProxyOverrideOperationQueue()
        val oldOwner = queue.newOwner()
        queue.acquire(oldOwner, { finish -> finish(true) }) { assertTrue(it) }
        var finishOldApply: ((Boolean) -> Unit)? = null
        queue.apply(oldOwner, { finish -> finishOldApply = finish }) {}
        requireNotNull(finishOldApply).invoke(true)

        val newOwner = queue.newOwner()
        var finishAcquire: ((Boolean) -> Unit)? = null
        queue.acquire(newOwner, { finish -> finishAcquire = finish }) {}
        requireNotNull(finishAcquire).invoke(true)

        var finishNewApply: ((Boolean) -> Unit)? = null
        queue.apply(newOwner, { finish -> finishNewApply = finish }) {}
        requireNotNull(finishNewApply).invoke(true)

        var oldPlatformClearCalls = 0
        var oldClearCompleted = false
        queue.clear(
            oldOwner,
            platformClear = {
                oldPlatformClearCalls += 1
                it(true)
            },
            onComplete = { oldClearCompleted = true },
        )
        assertEquals(0, oldPlatformClearCalls)
        assertTrue(oldClearCompleted)

        var finishNewClear: ((Boolean) -> Unit)? = null
        queue.clear(newOwner, { finish -> finishNewClear = finish }) {}
        assertTrue(finishNewClear != null)
        requireNotNull(finishNewClear).invoke(true)
    }

    @Test
    fun constructingFutureOwnerDoesNotPreventCurrentOwnerFromClearing() {
        val queue = BrowserProxyOverrideOperationQueue()
        val currentOwner = queue.newOwner()
        queue.acquire(currentOwner, { finish -> finish(true) }) { assertTrue(it) }
        var finishApply: ((Boolean) -> Unit)? = null
        queue.apply(currentOwner, { finish -> finishApply = finish }) {}
        requireNotNull(finishApply).invoke(true)

        queue.newOwner()
        var platformClearCalls = 0
        queue.clear(
            currentOwner,
            platformClear = { finish ->
                platformClearCalls += 1
                finish(true)
            },
            onComplete = {},
        )

        assertEquals(1, platformClearCalls)
    }

    @Test
    fun failedClearRetainsOwnershipUntilAConfirmedClear() {
        val queue = BrowserProxyOverrideOperationQueue()
        val oldOwner = queue.newOwner()
        queue.acquire(oldOwner, { finish -> finish(true) }) { assertTrue(it) }
        queue.apply(oldOwner, { finish -> finish(true) }) { assertTrue(it) }

        var oldClearResult: Boolean? = null
        queue.clear(oldOwner, { finish -> finish(false) }) { oldClearResult = it }
        assertEquals(false, oldClearResult)

        val newOwner = queue.newOwner()
        var replacementClearCalled = false
        queue.acquire(
            newOwner,
            platformClear = { finish ->
                replacementClearCalled = true
                finish(true)
            },
            onComplete = { assertTrue(it) },
        )
        assertTrue(replacementClearCalled)
    }

    @Test
    fun applyExceptionStillRequiresAPlatformClear() {
        val queue = BrowserProxyOverrideOperationQueue()
        val owner = queue.newOwner()
        queue.acquire(owner, { finish -> finish(true) }) { assertTrue(it) }
        var applyResult: Boolean? = null
        queue.apply(
            owner,
            platformApply = { throw IllegalStateException("platform mutated before throwing") },
            onComplete = { applyResult = it },
        )
        assertEquals(false, applyResult)

        var platformClearCalls = 0
        queue.clear(
            owner,
            platformClear = { finish ->
                platformClearCalls += 1
                finish(true)
            },
            onComplete = { assertTrue(it) },
        )

        assertEquals(1, platformClearCalls)
    }
}
