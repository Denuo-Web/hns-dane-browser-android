package com.denuoweb.hnsdane.net

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsProxyWebSocketPolicyTest {
    @Test
    fun policyKeepsAllowedSocketsNativeAndBlocksCrossScopeHnsTargets() {
        val script = HnsProxyWebSocketPolicy.script()

        assertTrue(script.contains("new NativeWebSocket"))
        assertTrue(script.contains("requiresHnsResolution(targetHost)"))
        assertTrue(script.contains("!inPageScope(targetHost, pageHost)"))
        assertTrue(script.contains("HNS WebSocket target is outside the active proxy scope"))
        assertTrue(script.contains("window.WebSocket = ProxyScopedWebSocket"))
        assertFalse(script.contains("hnsWebSocketBridge"))
        assertFalse(script.contains("postMessage"))
    }

    @Test
    fun policyEmbedsCurrentIcannAndSpecialUseClassification() {
        val script = HnsProxyWebSocketPolicy.script()

        assertTrue(script.contains("'com'"))
        assertTrue(script.contains("'org'"))
        assertTrue(script.contains("'localhost'"))
        assertTrue(script.contains("specialUseSuffixes.has(suffix)"))
    }
}
