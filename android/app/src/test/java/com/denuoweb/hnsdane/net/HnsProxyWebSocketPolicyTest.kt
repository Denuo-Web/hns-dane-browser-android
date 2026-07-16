package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.BrowserWebSocketScopePolicySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsProxyWebSocketPolicyTest {
    @Test
    fun installsTheCompleteScriptReturnedBySharedRust() {
        val rustScript =
            """
            window.__hnsRustNamespacePolicyVersion = 1;
            window.WebSocket = ProxyScopedWebSocket;
            """.trimIndent()
        val source = BrowserWebSocketScopePolicySource { rustScript }

        assertEquals(rustScript, HnsProxyWebSocketPolicy.script(source))
    }

    @Test
    fun missingSharedRustPolicyDisablesWebSockets() {
        val script = HnsProxyWebSocketPolicy.script(BrowserWebSocketScopePolicySource { null })

        assertTrue(script.contains("window.__hnsRustNamespacePolicyUnavailable = true"))
        assertTrue(script.contains("window.WebSocket = BlockedWebSocket"))
        assertTrue(script.contains("SecurityError"))
        assertFalse(script.contains("requiresHnsResolution"))
        assertFalse(script.contains("icannTlds"))
    }
}
