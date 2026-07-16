package com.denuoweb.hnsdane.net

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.denuoweb.hnsdane.core.BrowserNamespaceClass
import com.denuoweb.hnsdane.core.HnsHostPolicy
import com.denuoweb.hnsdane.core.NativeGatewayHostDecision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SharedBrowserNamespacePolicyInstrumentationTest {
    @Test
    fun jniClassificationUsesSharedRustRoutingPolicy() {
        assertTrue(NativeBridge.isLoaded)
        assertEquals(BrowserNamespaceClass.Hns, NativeBridge.classifyHost("welcome"))
        assertEquals(BrowserNamespaceClass.Hns, NativeBridge.classifyHost("sub.welcome"))
        assertEquals(BrowserNamespaceClass.Icann, NativeBridge.classifyHost("example.com"))
        assertEquals(BrowserNamespaceClass.Icann, NativeBridge.classifyHost("printer.local"))
        assertEquals(
            BrowserNamespaceClass.NativeGateway,
            NativeBridge.classifyHost("DANE-TEST.DENUOWEB.COM."),
        )
        assertEquals(BrowserNamespaceClass.Invalid, NativeBridge.classifyHost("two words"))
        assertEquals(
            NativeGatewayHostDecision.Required,
            HnsHostPolicy.nativeGatewayDecision("dane-test.denuoweb.com", NativeBridge),
        )
    }

    @Test
    fun jniReturnsTheCompleteRustWebSocketScopePolicy() {
        val script = NativeBridge.webSocketScopePolicyScript()

        assertNotNull(script)
        requireNotNull(script)
        assertTrue(script.contains("window.__hnsRustNamespacePolicyVersion = 1"))
        assertTrue(script.contains("requiresHnsResolution(targetHost)"))
        assertTrue(script.contains("'com'"))
        assertTrue(script.contains("'localhost'"))
        assertFalse(script.contains("hnsWebSocketBridge"))
        assertFalse(script.contains("postMessage"))
    }
}
