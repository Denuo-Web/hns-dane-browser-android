package com.denuoweb.hnsdane.net

import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import androidx.webkit.ServiceWorkerClientCompat
import com.denuoweb.hnsdane.core.BrowserNamespaceClass
import com.denuoweb.hnsdane.core.BrowserNamespacePolicy
import com.denuoweb.hnsdane.core.HnsHostPolicy
import com.denuoweb.hnsdane.core.NativeGatewayHostDecision
import java.io.ByteArrayInputStream

internal class HnsServiceWorkerGatewayClient(
    private val interceptor: HnsWebViewGatewayInterceptor,
    private val namespacePolicy: BrowserNamespacePolicy,
    private val enabled: () -> Boolean = { true },
    private val proxyRoute: (WebResourceRequest) -> BrowserProxyRoute? = { null },
) : ServiceWorkerClientCompat() {
    override fun shouldInterceptRequest(request: WebResourceRequest): WebResourceResponse? {
        return when (
            serviceWorkerRouteAction(
                route = proxyRoute(request),
                enabled = enabled(),
                scheme = request.url.scheme,
                host = request.url.host,
                namespacePolicy = namespacePolicy,
            )
        ) {
            ServiceWorkerRouteAction.Direct -> null
            ServiceWorkerRouteAction.Block -> blockedHnsProxyResponse()
            ServiceWorkerRouteAction.SharedRuntimeGateway -> interceptor.interceptServiceWorker(request)
        }
    }
}

/**
 * WebView does not deliver Service Worker TLS failures to the page's [android.webkit.WebViewClient],
 * so a worker fetch cannot accept the live Rust proxy certificate through `onReceivedSslError`.
 * Keep the coordinator's exact scope/transition decision, but execute admitted worker requests
 * through the shared Rust runtime gateway instead of Chromium's CONNECT path.
 */
internal enum class ServiceWorkerRouteAction {
    SharedRuntimeGateway,
    Block,
    Direct,
}

internal fun serviceWorkerRouteAction(
    route: BrowserProxyRoute?,
    enabled: Boolean = true,
    scheme: String? = null,
    host: String? = null,
    namespacePolicy: BrowserNamespacePolicy,
): ServiceWorkerRouteAction =
    when {
        !enabled && (route != null || requiresProtectedHttpRouting(scheme, host, namespacePolicy)) ->
            ServiceWorkerRouteAction.Block
        !enabled -> ServiceWorkerRouteAction.Direct
        route == BrowserProxyRoute.Block -> ServiceWorkerRouteAction.Block
        route == null && requiresProtectedHttpRouting(scheme, host, namespacePolicy) ->
            ServiceWorkerRouteAction.Block
        else -> ServiceWorkerRouteAction.SharedRuntimeGateway
    }

/**
 * Routes from the raw request host rather than [com.denuoweb.hnsdane.core.BrowserUrlClassifier].
 * Android's URL classifier intentionally rejects a trailing root dot, while HNS resolution and
 * the proxy scope canonicalizer accept it. Keeping the raw host here prevents that spelling from
 * bypassing the coordinator's exact-scope decision.
 */
internal fun serviceWorkerProxyRoute(
    scheme: String?,
    host: String?,
    namespacePolicy: BrowserNamespacePolicy,
    routeForHnsHost: (String) -> BrowserProxyRoute,
): BrowserProxyRoute? {
    if (!isHttpScheme(scheme)) return null
    val requestHost = host.orEmpty()
    return when (namespacePolicy.classifyHost(requestHost)) {
        BrowserNamespaceClass.NativeGateway -> BrowserProxyRoute.CompatibilityInterceptor
        BrowserNamespaceClass.Hns -> routeForHnsHost(requestHost)
        BrowserNamespaceClass.Icann -> null
        BrowserNamespaceClass.Invalid,
        BrowserNamespaceClass.Unavailable,
        -> BrowserProxyRoute.Block
    }
}

object DisabledServiceWorkerClient : ServiceWorkerClientCompat() {
    override fun shouldInterceptRequest(request: WebResourceRequest): WebResourceResponse? {
        return when (disabledServiceWorkerRouteAction(request.url.scheme, request.url.host, NativeBridge)) {
            ServiceWorkerRouteAction.Block -> blockedHnsProxyResponse()
            ServiceWorkerRouteAction.Direct,
            ServiceWorkerRouteAction.SharedRuntimeGateway,
            -> null
        }
    }
}

internal fun disabledServiceWorkerRouteAction(
    scheme: String?,
    host: String?,
    namespacePolicy: BrowserNamespacePolicy,
): ServiceWorkerRouteAction =
    if (requiresProtectedHttpRouting(scheme, host, namespacePolicy)) {
        ServiceWorkerRouteAction.Block
    } else {
        ServiceWorkerRouteAction.Direct
    }

private fun requiresProtectedHttpRouting(
    scheme: String?,
    host: String?,
    namespacePolicy: BrowserNamespacePolicy,
): Boolean =
    isHttpScheme(scheme) &&
        HnsHostPolicy.nativeGatewayDecision(host.orEmpty(), namespacePolicy) !=
        NativeGatewayHostDecision.Direct

private fun isHttpScheme(scheme: String?): Boolean =
    scheme.equals("http", ignoreCase = true) || scheme.equals("https", ignoreCase = true)

/** Prevents an older Activity from overwriting the process-global Service Worker client. */
internal class ServiceWorkerClientOwnershipGate {
    internal class Owner internal constructor(val generation: Long)

    private val lock = Any()
    private var nextGeneration = 0L
    private var latestGeneration = 0L

    fun newOwner(): Owner = synchronized(lock) {
        check(nextGeneration < Long.MAX_VALUE) { "service worker client owner counter exhausted" }
        nextGeneration += 1L
        Owner(nextGeneration)
    }

    fun install(owner: Owner, installClient: () -> Unit): Boolean = synchronized(lock) {
        if (owner.generation < latestGeneration) {
            false
        } else {
            latestGeneration = owner.generation
            installClient()
            true
        }
    }

    fun disable(owner: Owner, installDisabledClient: () -> Unit): Boolean = synchronized(lock) {
        if (owner.generation != latestGeneration) {
            false
        } else {
            // Retain the high-water generation so an older Activity cannot reclaim the singleton.
            installDisabledClient()
            true
        }
    }
}

internal object ProcessServiceWorkerClientOwnership {
    private val gate = ServiceWorkerClientOwnershipGate()

    fun newOwner(): ServiceWorkerClientOwnershipGate.Owner = gate.newOwner()

    fun install(owner: ServiceWorkerClientOwnershipGate.Owner, installClient: () -> Unit): Boolean =
        gate.install(owner, installClient)

    fun disable(owner: ServiceWorkerClientOwnershipGate.Owner, installDisabledClient: () -> Unit): Boolean =
        gate.disable(owner, installDisabledClient)
}

internal fun blockedHnsProxyResponse(): WebResourceResponse {
    val body = "503 HNS Proxy Transition\n".toByteArray(Charsets.UTF_8)
    return WebResourceResponse(
        "text/plain",
        "utf-8",
        503,
        "HNS Proxy Transition",
        mapOf("Cache-Control" to "no-store"),
        ByteArrayInputStream(body),
    )
}
