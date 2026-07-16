package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.HnsPageResolverPolicy
import com.denuoweb.hnsdane.core.HnsPageSecurityPath
import com.denuoweb.hnsdane.core.HnsPageTlsPolicy
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
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
        assertEquals(200, proxy.takeMainFrameStatus("welcome")?.statusCode)
        proxy.discardMainFrameStatus("welcome")
        assertEquals(1, nativeApi.statusDiscards)
        proxy.requestStop()
        proxy.requestStop()
        assertFalse(proxy.matchesLocalCertificate("welcome", byteArrayOf(1, 2, 3)))
        assertNull(proxy.takeMainFrameStatus("welcome"))
        assertEquals(1, nativeApi.stopRequests)
        assertEquals(1, nativeApi.statusTakes)
        assertEquals(0, nativeApi.destroys)

        proxy.joinAndDestroy()
        proxy.joinAndDestroy()
        assertEquals(1, nativeApi.stopRequests)
        assertEquals(1, nativeApi.destroys)
        assertFalse(proxy.toString().contains("welcome"))
    }

    @Test
    fun inFlightCertificateAndStatusResultsAreRejectedAfterConcurrentStop() {
        val config = RustBrowserProxyConfig(
            dataDir = "/tmp/runtime",
            network = "regtest",
            scopeHost = "welcome",
            strictHnsMode = true,
            dohResolverUrl = "",
            statelessDaneCertificates = false,
        )

        val certificateApi = FakeRustBrowserProxyNativeApi().apply {
            matchEntered = CountDownLatch(1)
            matchRelease = CountDownLatch(1)
        }
        val certificateProxy = requireNotNull(RustBrowserProxy.start(config, certificateApi))
        val certificateResult = AtomicBoolean(true)
        val certificateThread = Thread {
            certificateResult.set(
                certificateProxy.matchesLocalCertificate("welcome", byteArrayOf(1, 2, 3)),
            )
        }.apply { start() }
        assertTrue(requireNotNull(certificateApi.matchEntered).await(2, TimeUnit.SECONDS))
        certificateProxy.requestStop()
        requireNotNull(certificateApi.matchRelease).countDown()
        certificateThread.join(2_000)
        assertFalse(certificateThread.isAlive)
        assertFalse(certificateResult.get())
        certificateProxy.joinAndDestroy()

        val statusApi = FakeRustBrowserProxyNativeApi().apply {
            statusEntered = CountDownLatch(1)
            statusRelease = CountDownLatch(1)
        }
        val statusProxy = requireNotNull(RustBrowserProxy.start(config, statusApi))
        val statusResult = AtomicReference<LocalBrowserProxyStatus?>()
        val statusThread = Thread {
            statusResult.set(statusProxy.takeMainFrameStatus("welcome"))
        }.apply { start() }
        assertTrue(requireNotNull(statusApi.statusEntered).await(2, TimeUnit.SECONDS))
        statusProxy.requestStop()
        requireNotNull(statusApi.statusRelease).countDown()
        statusThread.join(2_000)
        assertFalse(statusThread.isAlive)
        assertNull(statusResult.get())
        statusProxy.joinAndDestroy()
    }

    @Test
    fun statusBundleIsStrictlyParsedTypedAndTraceRedacted() {
        val endpoint = requireNotNull(parseRustProxyEndpointBundle(endpointBundle()))
        val trace = """{"mode":"strict","url":"https://welcome/private?secret=1"}"""

        val status = requireNotNull(
            parseRustProxyStatusBundle(
                statusBundle(tlsPolicy = 2, resolverPolicy = 1, securityPath = 8, trace = trace),
                endpoint,
                "Welcome.",
            ),
        )

        assertEquals(204, status.statusCode)
        assertEquals(12L, status.sequence)
        assertEquals(HnsPageTlsPolicy.WebPkiFallback, status.tlsPolicy)
        assertEquals(HnsPageResolverPolicy.HnsDohCompatibility, status.resolverPolicy)
        assertEquals(HnsPageSecurityPath.HnsThirdPartyDoh, status.securityPath)
        assertEquals(trace, status.resolutionTraceJson)
        assertFalse(status.toString().contains("private"))
        assertFalse(status.toString().contains("secret"))
    }

    @Test
    fun statusBundleRejectsStaleMalformedAndTrailingData() {
        val endpoint = requireNotNull(parseRustProxyEndpointBundle(endpointBundle()))
        val valid = statusBundle()

        assertNull(parseRustProxyStatusBundle(valid, endpoint, "other"))
        assertNull(parseRustProxyStatusBundle(valid.copyOfRange(0, valid.size - 1), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(valid + 0, endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(valid.copyOf().also { it[0] = 'X'.code.toByte() }, endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(valid.copyOf().also { it[4] = 2 }, endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(generation = 8L), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(sequence = 0L), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(mainFrame = false), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(tlsPolicy = 9), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(resolverPolicy = 9), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(securityPath = 9), endpoint, "welcome"))
        assertNull(parseRustProxyStatusBundle(statusBundle(host = "wel_come"), endpoint, "wel_come"))
        assertNull(
            parseRustProxyStatusBundle(
                statusBundle(traceBytes = byteArrayOf(0xc3.toByte(), 0x28)),
                endpoint,
                "welcome",
            ),
        )
    }

    @Test
    fun statusBundleMapsTheCompleteSecurityPathVocabularyAndOptionalValues() {
        val endpoint = requireNotNull(parseRustProxyEndpointBundle(endpointBundle()))
        val paths = listOf(
            1 to HnsPageSecurityPath.DaneAuthoritativeDoh,
            2 to HnsPageSecurityPath.DaneAuthoritativeDns53,
            3 to HnsPageSecurityPath.DaneThirdPartyDoh,
            4 to HnsPageSecurityPath.StatelessDane,
            5 to HnsPageSecurityPath.DaneIcannDoh,
            6 to HnsPageSecurityPath.HnsAuthoritativeDoh,
            7 to HnsPageSecurityPath.HnsAuthoritativeDns53,
            8 to HnsPageSecurityPath.HnsThirdPartyDoh,
        )
        paths.forEach { (code, expected) ->
            val status = requireNotNull(
                parseRustProxyStatusBundle(
                    statusBundle(securityPath = code),
                    endpoint,
                    "welcome",
                ),
            )
            assertEquals(expected, status.securityPath)
        }

        val absent = requireNotNull(
            parseRustProxyStatusBundle(
                statusBundle(
                    tlsPolicy = 0,
                    resolverPolicy = 0,
                    securityPath = 0,
                    traceBytes = byteArrayOf(),
                ),
                endpoint,
                "welcome",
            ),
        )
        assertNull(absent.tlsPolicy)
        assertNull(absent.resolverPolicy)
        assertNull(absent.securityPath)
        assertNull(absent.resolutionTraceJson)
    }

    private class FakeRustBrowserProxyNativeApi : RustBrowserProxyNativeApi {
        var startedConfig: RustBrowserProxyConfig? = null
        var stopRequests = 0
        var destroys = 0
        var statusTakes = 0
        var statusDiscards = 0
        var matchEntered: CountDownLatch? = null
        var matchRelease: CountDownLatch? = null
        var statusEntered: CountDownLatch? = null
        var statusRelease: CountDownLatch? = null

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
        ): Boolean {
            matchEntered?.countDown()
            matchRelease?.await(2, TimeUnit.SECONDS)
            return host == "welcome" && certificateDer.contentEquals(byteArrayOf(1, 2, 3))
        }

        override fun takeMainFrameStatus(
            endpoint: LocalBrowserProxyEndpoint,
            host: String,
        ): LocalBrowserProxyStatus? {
            statusTakes += 1
            statusEntered?.countDown()
            statusRelease?.await(2, TimeUnit.SECONDS)
            return LocalBrowserProxyStatus(1, 200, null, null, null, null)
        }

        override fun discardMainFrameStatus(
            endpoint: LocalBrowserProxyEndpoint,
            host: String,
        ): Boolean {
            statusDiscards += 1
            return true
        }
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

        private fun statusBundle(
            generation: Long = 7L,
            sequence: Long = 12L,
            statusCode: Int = 204,
            mainFrame: Boolean = true,
            tlsPolicy: Int = 1,
            resolverPolicy: Int = 1,
            securityPath: Int = 1,
            host: String = "welcome",
            trace: String = """{"mode":"strict"}""",
            traceBytes: ByteArray = trace.toByteArray(Charsets.UTF_8),
        ): ByteArray = ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(byteArrayOf('H'.code.toByte(), 'N'.code.toByte(), 'S'.code.toByte(), 'S'.code.toByte()))
                output.writeByte(1)
                output.writeLong(generation)
                output.writeLong(sequence)
                output.writeShort(statusCode)
                output.writeByte(if (mainFrame) 1 else 0)
                output.writeByte(tlsPolicy)
                output.writeByte(resolverPolicy)
                output.writeByte(securityPath)
                val encodedHost = host.toByteArray(Charsets.US_ASCII)
                output.writeShort(encodedHost.size)
                output.write(encodedHost)
                output.writeInt(traceBytes.size)
                output.write(traceBytes)
            }
            bytes.toByteArray()
        }
    }
}
