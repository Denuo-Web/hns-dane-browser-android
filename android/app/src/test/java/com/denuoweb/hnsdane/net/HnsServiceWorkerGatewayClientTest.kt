package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.BrowserNamespaceClass
import com.denuoweb.hnsdane.core.FixedBrowserNamespacePolicy
import com.denuoweb.hnsdane.core.TEST_BROWSER_NAMESPACE_POLICY
import org.junit.Assert.assertEquals
import org.junit.Test

class HnsServiceWorkerGatewayClientTest {
    private val namespacePolicy = TEST_BROWSER_NAMESPACE_POLICY

    @Test
    fun admittedProxyRouteUsesSharedRuntimeGatewayBecauseWorkerCannotAcceptLocalTlsChallenge() {
        assertEquals(
            ServiceWorkerRouteAction.SharedRuntimeGateway,
            serviceWorkerRouteAction(BrowserProxyRoute.Proxy, namespacePolicy = namespacePolicy),
        )
    }

    @Test
    fun compatibilityAndUnclassifiedRoutesKeepExistingGatewayBehavior() {
        assertEquals(
            ServiceWorkerRouteAction.SharedRuntimeGateway,
            serviceWorkerRouteAction(
                BrowserProxyRoute.CompatibilityInterceptor,
                namespacePolicy = namespacePolicy,
            ),
        )
        assertEquals(
            ServiceWorkerRouteAction.SharedRuntimeGateway,
            serviceWorkerRouteAction(null, namespacePolicy = namespacePolicy),
        )
    }

    @Test
    fun transitionRouteFailsClosed() {
        assertEquals(
            ServiceWorkerRouteAction.Block,
            serviceWorkerRouteAction(BrowserProxyRoute.Block, namespacePolicy = namespacePolicy),
        )
    }

    @Test
    fun trailingDotHnsHostStillUsesTheCoordinatorScopeDecision() {
        val routedHosts = mutableListOf<String>()
        assertEquals(
            BrowserProxyRoute.Block,
            serviceWorkerProxyRoute("https", "otherhns.", namespacePolicy) { host ->
                routedHosts += host
                BrowserProxyRoute.Block
            },
        )
        assertEquals(listOf("otherhns."), routedHosts)
        assertEquals(
            BrowserProxyRoute.Proxy,
            serviceWorkerProxyRoute("https", "allowedhns.", namespacePolicy) { BrowserProxyRoute.Proxy },
        )
    }

    @Test
    fun missingRouteForNativeGatewayTargetFailsClosedInForegroundAndBackground() {
        for (enabled in listOf(true, false)) {
            assertEquals(
                ServiceWorkerRouteAction.Block,
                serviceWorkerRouteAction(
                    route = null,
                    enabled = enabled,
                    scheme = "https",
                    host = "otherhns.",
                    namespacePolicy = namespacePolicy,
                ),
            )
        }
    }

    @Test
    fun sharedRustCompatibilityHostUsesTheGatewayRoute() {
        assertEquals(
            BrowserProxyRoute.CompatibilityInterceptor,
            serviceWorkerProxyRoute(
                "https",
                "dane-test.denuoweb.com",
                namespacePolicy,
            ) { BrowserProxyRoute.Block },
        )
    }

    @Test
    fun suspendedSecuritySensitiveRoutesFailClosedWhileIcannRemainsDirect() {
        assertEquals(
            ServiceWorkerRouteAction.Block,
            serviceWorkerRouteAction(
                BrowserProxyRoute.Proxy,
                enabled = false,
                namespacePolicy = namespacePolicy,
            ),
        )
        assertEquals(
            ServiceWorkerRouteAction.Block,
            serviceWorkerRouteAction(
                BrowserProxyRoute.CompatibilityInterceptor,
                enabled = false,
                namespacePolicy = namespacePolicy,
            ),
        )
        assertEquals(
            ServiceWorkerRouteAction.Direct,
            serviceWorkerRouteAction(null, enabled = false, namespacePolicy = namespacePolicy),
        )
    }

    @Test
    fun destroyedClientBlocksHnsWithoutCapturingAnActivityAndLeavesIcannDirect() {
        assertEquals(
            ServiceWorkerRouteAction.Block,
            disabledServiceWorkerRouteAction("https", "shakeshift", namespacePolicy),
        )
        assertEquals(
            ServiceWorkerRouteAction.Direct,
            disabledServiceWorkerRouteAction("https", "example.com", namespacePolicy),
        )
        assertEquals(
            ServiceWorkerRouteAction.Direct,
            disabledServiceWorkerRouteAction("data", null, namespacePolicy),
        )
    }

    @Test
    fun unavailableSharedPolicyNeverFallsThroughToDirectNetworking() {
        val unavailable = FixedBrowserNamespacePolicy(emptyMap(), BrowserNamespaceClass.Unavailable)

        assertEquals(
            BrowserProxyRoute.Block,
            serviceWorkerProxyRoute("https", "unknown.example", unavailable) { BrowserProxyRoute.Proxy },
        )
        assertEquals(
            ServiceWorkerRouteAction.Block,
            disabledServiceWorkerRouteAction("https", "unknown.example", unavailable),
        )
    }

    @Test
    fun newerActivityOwnsTheProcessClientAndOlderActivityCannotOverwriteOrDisableIt() {
        val gate = ServiceWorkerClientOwnershipGate()
        val first = gate.newOwner()
        val events = mutableListOf<String>()
        assertEquals(true, gate.install(first) { events += "first" })

        val second = gate.newOwner()
        assertEquals(true, gate.install(second) { events += "second" })
        assertEquals(false, gate.install(first) { events += "stale-install" })
        assertEquals(false, gate.disable(first) { events += "stale-disable" })
        assertEquals(true, gate.disable(second) { events += "disabled" })
        assertEquals(false, gate.install(first) { events += "stale-reclaim" })

        assertEquals(listOf("first", "second", "disabled"), events)
    }

    @Test
    fun constructingFutureOwnerDoesNotInvalidateTheInstalledClient() {
        val gate = ServiceWorkerClientOwnershipGate()
        val current = gate.newOwner()
        val events = mutableListOf<String>()
        gate.install(current) { events += "current" }

        gate.newOwner()
        assertEquals(true, gate.disable(current) { events += "disabled" })
        assertEquals(listOf("current", "disabled"), events)
    }
}
