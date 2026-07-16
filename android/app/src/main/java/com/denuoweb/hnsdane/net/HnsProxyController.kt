package com.denuoweb.hnsdane.net

import android.content.Context
import androidx.core.content.ContextCompat
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import java.util.ArrayDeque
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

internal interface BrowserProxyOverrideController {
    fun acquire(onOwnershipRevoked: () -> Unit, onComplete: (Boolean) -> Unit)

    fun releaseOwnership()

    fun applyLoopbackProxy(port: Int, hnsHost: String?, onComplete: (Boolean) -> Unit)

    fun clear(onComplete: (Boolean) -> Unit)
}

class HnsProxyController(
    private val context: Context,
) : BrowserProxyOverrideController {
    private val overrideOwner = processOverrideQueue.newOwner()

    override fun acquire(onOwnershipRevoked: () -> Unit, onComplete: (Boolean) -> Unit) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            onComplete(true)
            return
        }
        processOverrideQueue.acquire(
            owner = overrideOwner,
            platformClear = { complete ->
                ProxyController.getInstance().clearProxyOverride(
                    ContextCompat.getMainExecutor(context),
                ) {
                    complete(true)
                }
            },
            onOwnershipRevoked = onOwnershipRevoked,
            onComplete = onComplete,
        )
    }

    override fun releaseOwnership() {
        processOverrideQueue.release(overrideOwner)
    }

    override fun applyLoopbackProxy(port: Int, hnsHost: String?, onComplete: (Boolean) -> Unit) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            onComplete(false)
            return
        }

        val reverseBypassSupported = WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE_REVERSE_BYPASS)
        if (!canApplyLoopbackProxy(hnsHost, reverseBypassSupported)) {
            onComplete(false)
            return
        }

        val proxyConfig = loopbackProxyConfig(port, requireNotNull(hnsHost))

        processOverrideQueue.apply(
            owner = overrideOwner,
            platformApply = { complete ->
                ProxyController.getInstance().setProxyOverride(
                    proxyConfig,
                    ContextCompat.getMainExecutor(context),
                ) {
                    complete(true)
                }
            },
            onComplete = onComplete,
        )
    }

    override fun clear(onComplete: (Boolean) -> Unit) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            onComplete(true)
            return
        }

        processOverrideQueue.clear(
            owner = overrideOwner,
            platformClear = { complete ->
                ProxyController.getInstance().clearProxyOverride(
                    ContextCompat.getMainExecutor(context),
                ) {
                    complete(true)
                }
            },
            onComplete = onComplete,
        )
    }

    private companion object {
        val processOverrideQueue = BrowserProxyOverrideOperationQueue()
    }
}

/**
 * Serializes the process-global ProxyController and prevents a retired Activity owner from clearing
 * a newer owner's committed override. Owner generations are a permanent process high-water mark:
 * after a newer Activity claims the controller, an older Activity must remain retired even if the
 * newer owner later releases it. This fail-closed rule prevents a stale Activity from resurrecting
 * proxy state after a lifecycle handoff.
 */
internal class BrowserProxyOverrideOperationQueue {
    internal class Owner internal constructor(val generation: Long) {
        var onOwnershipRevoked: (() -> Unit)? = null
    }

    private val lock = Any()
    private val pending = ArrayDeque<() -> Unit>()
    private var running = false
    private var nextGeneration = 0L
    private var latestGeneration = 0L
    private var activeOwner: Owner? = null
    private var claimedOwner: Owner? = null

    fun newOwner(): Owner = synchronized(lock) {
        check(nextGeneration < Long.MAX_VALUE) { "browser proxy owner counter exhausted" }
        nextGeneration += 1L
        Owner(nextGeneration)
    }

    fun acquire(
        owner: Owner,
        platformClear: ((Boolean) -> Unit) -> Unit,
        onOwnershipRevoked: () -> Unit = {},
        onComplete: (Boolean) -> Unit,
    ) {
        val revokePrevious = synchronized(lock) {
            when {
                owner.generation > latestGeneration -> {
                    latestGeneration = owner.generation
                    val previous = claimedOwner?.takeUnless { it === owner }
                    claimedOwner = owner
                    owner.onOwnershipRevoked = onOwnershipRevoked
                    previous?.onOwnershipRevoked.also { previous?.onOwnershipRevoked = null }
                }
                owner.generation == latestGeneration -> {
                    claimedOwner = owner
                    owner.onOwnershipRevoked = onOwnershipRevoked
                    null
                }
                else -> null
            }
        }
        runCatching { revokePrevious?.invoke() }
        enqueue operation@{
            if (!isLatest(owner)) {
                finishInline { onComplete(false) }
                return@operation
            }
            val previousOwner = synchronized(lock) { activeOwner }
            if (previousOwner == null || previousOwner === owner) {
                finishInline { onComplete(true) }
                return@operation
            }
            val completed = AtomicBoolean(false)
            val finish: (Boolean) -> Unit = finish@{ cleared ->
                if (!completed.compareAndSet(false, true)) return@finish
                if (cleared) {
                    synchronized(lock) {
                        if (activeOwner === previousOwner) activeOwner = null
                    }
                }
                try {
                    onComplete(cleared && isLatest(owner))
                } finally {
                    operationComplete()
                }
            }
            try {
                platformClear(finish)
            } catch (_: RuntimeException) {
                finish(false)
            }
        }
    }

    fun release(owner: Owner) {
        synchronized(lock) {
            if (claimedOwner === owner) claimedOwner = null
            owner.onOwnershipRevoked = null
            // Deliberately retain latestGeneration. An older owner cannot safely reclaim the
            // process-global override after observing a newer lifecycle generation.
        }
    }

    fun apply(
        owner: Owner,
        platformApply: ((Boolean) -> Unit) -> Unit,
        onComplete: (Boolean) -> Unit,
    ) {
        enqueue operation@{
            if (!isLatest(owner)) {
                finishInline { onComplete(false) }
                return@operation
            }
            // Once the platform call begins, only a confirmed clear can prove that no global
            // override was installed; a synchronous failure may occur after platform mutation.
            synchronized(lock) { activeOwner = owner }
            val completed = AtomicBoolean(false)
            val finish: (Boolean) -> Unit = finish@{ applied ->
                if (!completed.compareAndSet(false, true)) return@finish
                try {
                    onComplete(applied && isLatest(owner))
                } finally {
                    operationComplete()
                }
            }
            try {
                platformApply(finish)
            } catch (_: RuntimeException) {
                finish(false)
            }
        }
    }

    fun clear(
        owner: Owner,
        platformClear: ((Boolean) -> Unit) -> Unit,
        onComplete: (Boolean) -> Unit,
    ) {
        enqueue operation@{
            if (synchronized(lock) { activeOwner !== owner }) {
                try {
                    onComplete(true)
                } finally {
                    operationComplete()
                }
                return@operation
            }
            val completed = AtomicBoolean(false)
            val finish: (Boolean) -> Unit = finish@{ cleared ->
                if (!completed.compareAndSet(false, true)) return@finish
                if (cleared) {
                    synchronized(lock) {
                        if (activeOwner === owner) activeOwner = null
                    }
                }
                try {
                    onComplete(cleared)
                } finally {
                    operationComplete()
                }
            }
            try {
                platformClear(finish)
            } catch (_: RuntimeException) {
                finish(false)
            }
        }
    }

    private fun enqueue(operation: () -> Unit) {
        val first = synchronized(lock) {
            pending.addLast(operation)
            if (running) {
                null
            } else {
                running = true
                pending.removeFirst()
            }
        }
        first?.invoke()
    }

    private fun operationComplete() {
        val next = synchronized(lock) {
            if (pending.isEmpty()) {
                running = false
                null
            } else {
                pending.removeFirst()
            }
        }
        next?.invoke()
    }

    private fun isLatest(owner: Owner): Boolean = synchronized(lock) {
        owner.generation == latestGeneration
    }

    private fun finishInline(callback: () -> Unit) {
        try {
            callback()
        } finally {
            operationComplete()
        }
    }
}

internal fun loopbackProxyConfig(
    port: Int,
    hnsHost: String,
): ProxyConfig {
    val builder = ProxyConfig.Builder()
        .addProxyRule("http://127.0.0.1:$port")

    val normalizedHost = hnsHost
        .trim()
        .trimEnd('.')
        .lowercase(Locale.US)
    require(normalizedHost.isNotBlank()) { "hnsHost must not be blank" }

    builder
        .addBypassRule(normalizedHost)
        .addBypassRule("*.$normalizedHost")
        .setReverseBypassEnabled(true)

    return builder.build()
}

internal fun canApplyLoopbackProxy(
    hnsHost: String?,
    reverseBypassSupported: Boolean,
): Boolean {
    val normalizedHost = hnsHost
        .orEmpty()
        .trim()
        .trimEnd('.')
    return reverseBypassSupported && normalizedHost.isNotBlank()
}
