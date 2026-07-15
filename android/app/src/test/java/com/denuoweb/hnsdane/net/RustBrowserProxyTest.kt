package com.denuoweb.hnsdane.net

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RustBrowserProxyTest {
    @Test
    fun endpointBundleIsStrictlyParsedAndCredentialsAreRedacted() {
        val bundle = endpointBundle(
            handle = 41L,
            port = 43123,
            generation = 7L,
            session = "session-secret",
            realm = "realm-secret",
            username = "hns-browser",
            password = "password-secret",
        )

        val endpoint = requireNotNull(parseRustProxyEndpointBundle(bundle))

        assertEquals(41L, endpoint.nativeHandle)
        assertEquals(43123, endpoint.port)
        assertEquals(LocalProxyInstanceId("session-secret", 7L), endpoint.instanceId)
        assertEquals("realm-secret", endpoint.authorization.realm)
        assertEquals("hns-browser", endpoint.authorization.username)
        assertEquals("password-secret", endpoint.authorization.password)
        val rendered = endpoint.toString() + endpoint.instanceId.toString()
        assertFalse(rendered.contains("session-secret"))
        assertFalse(rendered.contains("realm-secret"))
        assertFalse(rendered.contains("password-secret"))
    }

    @Test
    fun endpointBundleRejectsMalformedTruncatedAndTrailingData() {
        val valid = endpointBundle()

        assertNull(parseRustProxyEndpointBundle(valid.copyOfRange(0, valid.size - 1)))
        assertNull(parseRustProxyEndpointBundle(valid + 0))
        assertNull(parseRustProxyEndpointBundle(valid.copyOf().also { it[0] = 'X'.code.toByte() }))
        assertNull(parseRustProxyEndpointBundle(valid.copyOf().also { it[4] = 2 }))
        assertNull(parseRustProxyEndpointBundle(endpointBundle(handle = 0L)))
        assertNull(parseRustProxyEndpointBundle(endpointBundle(port = 0)))
        assertNull(parseRustProxyEndpointBundle(endpointBundle(generation = 0L)))
        assertEquals(41L, rustProxyHandleFromBundle(valid))
        assertNull(rustProxyHandleFromBundle(byteArrayOf()))
    }

    @Test
    fun rustProxyRevokesBeforeWorkerDestroyAndNeverMatchesAfterStop() {
        val nativeApi = FakeRustBrowserProxyNativeApi()
        val config = RustBrowserProxyConfig(
            dataDir = "/tmp/runtime",
            network = "regtest",
            scopeHost = "welcome",
            strictHnsMode = true,
            dohResolverUrl = "https://resolver.example/dns-query",
            statelessDaneCertificates = true,
        )
        val proxy = requireNotNull(RustBrowserProxy.start(config, nativeApi))

        assertEquals(config, nativeApi.startedConfig)
        assertTrue(proxy.matchesLocalCertificate("welcome", byteArrayOf(1, 2, 3)))
        proxy.requestStop()
        proxy.requestStop()
        assertFalse(proxy.matchesLocalCertificate("welcome", byteArrayOf(1, 2, 3)))
        assertEquals(1, nativeApi.stopRequests)
        assertEquals(0, nativeApi.destroys)

        proxy.joinAndDestroy()
        proxy.joinAndDestroy()
        assertEquals(1, nativeApi.stopRequests)
        assertEquals(1, nativeApi.destroys)
        assertFalse(proxy.toString().contains("welcome"))
    }

    private class FakeRustBrowserProxyNativeApi : RustBrowserProxyNativeApi {
        var startedConfig: RustBrowserProxyConfig? = null
        var stopRequests = 0
        var destroys = 0

        override fun start(config: RustBrowserProxyConfig): LocalBrowserProxyEndpoint {
            startedConfig = config
            return requireNotNull(parseRustProxyEndpointBundle(endpointBundle()))
        }

        override fun requestStop(endpoint: LocalBrowserProxyEndpoint): Boolean {
            stopRequests += 1
            return true
        }

        override fun destroy(nativeHandle: Long) {
            assertEquals(41L, nativeHandle)
            destroys += 1
        }

        override fun matchesLocalCertificate(
            endpoint: LocalBrowserProxyEndpoint,
            host: String,
            certificateDer: ByteArray,
        ): Boolean = host == "welcome" && certificateDer.contentEquals(byteArrayOf(1, 2, 3))
    }

    companion object {
        private fun endpointBundle(
            handle: Long = 41L,
            port: Int = 43123,
            generation: Long = 7L,
            session: String = "session-secret",
            realm: String = "realm-secret",
            username: String = "hns-browser",
            password: String = "password-secret",
        ): ByteArray = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(byteArrayOf('H'.code.toByte(), 'N'.code.toByte(), 'S'.code.toByte(), 'P'.code.toByte()))
                output.writeByte(1)
                output.writeLong(handle)
                output.writeShort(port)
                output.writeLong(generation)
                listOf(session, realm, username, password).forEach { value ->
                    val encoded = value.toByteArray(Charsets.US_ASCII)
                    output.writeShort(encoded.size)
                    output.write(encoded)
                }
            }
            bytes.toByteArray()
        }
    }
}
