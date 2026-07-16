package com.denuoweb.hnsdane.net

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

@RunWith(AndroidJUnit4::class)
class RustBrowserProxyInstrumentationTest {
    @Test
    fun runtimeGatewayJniUsesPersistentHandleAndPreservesFileBodyContract() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dataDir = context.filesDir.resolve("runtime-gateway-instrumentation-${UUID.randomUUID()}")
        assertTrue(dataDir.mkdirs())
        val config = HnsGatewayRuntimeConfig(
            network = "regtest",
            strictHnsMode = false,
            dohResolverUrl = "not-a-valid-doh-url",
            statelessDaneCertificates = false,
        )

        try {
            val encoded = requireNotNull(
                NativeBridge.httpResponse(
                    dataDir = dataDir.absolutePath,
                    config = config,
                    method = "GET",
                    scheme = "https",
                    host = TEST_HOST,
                    port = 443,
                    pathAndQuery = "/gateway-smoke",
                    headers = emptyList(),
                    body = ByteArray(0),
                ),
            )
            assertEquals(400, responseStatus(encoded.toString(StandardCharsets.ISO_8859_1)))

            val fileResponse = requireNotNull(
                NativeBridge.httpResponseBodyFile(
                    dataDir = dataDir.absolutePath,
                    config = config,
                    method = "GET",
                    scheme = "https",
                    host = TEST_HOST,
                    port = 443,
                    pathAndQuery = "/gateway-file-smoke",
                    headers = emptyList(),
                    body = ByteArray(0),
                ),
            )
            try {
                assertEquals(400, responseStatus(fileResponse.head.toString(StandardCharsets.ISO_8859_1)))
                assertTrue(fileResponse.openBodyStream().use { it.readBytes() }.isNotEmpty())
            } finally {
                fileResponse.deleteBodyFile()
            }
        } finally {
            NativeBridge.closeRuntimes()
            dataDir.deleteRecursively()
        }
    }

    @Test
    fun rustProxyJniEnforcesAdmissionStatusTrustAndWorkerTeardown() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dataDir = context.filesDir.resolve("rust-proxy-instrumentation-${UUID.randomUUID()}")
        assertTrue(dataDir.mkdirs())
        val proxy = requireNotNull(
            RustBrowserProxy.start(
                RustBrowserProxyConfig(
                    dataDir = dataDir.absolutePath,
                    network = "regtest",
                    scopeHost = TEST_HOST,
                    strictHnsMode = false,
                    dohResolverUrl = "",
                    statelessDaneCertificates = false,
                ),
            ),
        )

        try {
            assertEquals(
                407,
                responseStatus(
                    sendProxyRequest(
                        proxy.endpoint.port,
                        "CONNECT $TEST_HOST:443 HTTP/1.1\r\nHost: $TEST_HOST:443\r\n\r\n",
                    ),
                ),
            )
            assertEquals(
                403,
                responseStatus(
                    sendProxyRequest(
                        proxy.endpoint.port,
                        "CONNECT other:443 HTTP/1.1\r\nHost: other:443\r\n" +
                            proxyAuthorizationHeader(proxy) +
                            "\r\n",
                    ),
                ),
            )

            proxy.discardMainFrameStatus(TEST_HOST)
            assertEquals(
                413,
                responseStatus(
                    sendProxyRequest(
                        proxy.endpoint.port,
                        "GET http://$TEST_HOST/ HTTP/1.1\r\n" +
                            "Host: $TEST_HOST\r\n" +
                            proxyAuthorizationHeader(proxy) +
                            "Sec-Fetch-Dest: document\r\n" +
                            "Content-Length: 999999999\r\n\r\n",
                    ),
                ),
            )
            assertEquals(413, proxy.takeMainFrameStatus(TEST_HOST)?.statusCode)
            assertNull(proxy.takeMainFrameStatus(TEST_HOST))

            val certificate = connectAndCaptureLocalCertificate(proxy)
            assertTrue(proxy.matchesLocalCertificate(TLS_HOST, certificate.encoded))
            assertFalse(proxy.matchesLocalCertificate(TEST_HOST, certificate.encoded))
            assertFalse(proxy.matchesLocalCertificate(TLS_HOST, certificate.encoded.copyOf().also { it[0] = 0 }))

            proxy.requestStop()
            assertFalse(proxy.matchesLocalCertificate(TLS_HOST, certificate.encoded))

            val destroyed = CountDownLatch(1)
            val destroyedOffMain = AtomicBoolean(false)
            Thread(
                {
                    destroyedOffMain.set(
                        Thread.currentThread() !== InstrumentationRegistry.getInstrumentation().targetContext.mainLooper.thread,
                    )
                    proxy.joinAndDestroy()
                    destroyed.countDown()
                },
                "rust-proxy-instrumentation-destroy",
            ).start()
            assertTrue(destroyed.await(10, TimeUnit.SECONDS))
            assertTrue(destroyedOffMain.get())
        } finally {
            proxy.requestStop()
            if (proxy.endpoint.nativeHandle > 0L) {
                val cleaned = CountDownLatch(1)
                Thread {
                    proxy.joinAndDestroy()
                    cleaned.countDown()
                }.start()
                assertTrue(cleaned.await(10, TimeUnit.SECONDS))
            }
            NativeBridge.closeRuntimes()
            dataDir.deleteRecursively()
        }
    }

    private fun connectAndCaptureLocalCertificate(proxy: RustBrowserProxy): X509Certificate {
        Socket(InetAddress.getByName("127.0.0.1"), proxy.endpoint.port).use { socket ->
            socket.soTimeout = SOCKET_TIMEOUT_MS
            socket.getOutputStream().write(
                (
                    "CONNECT $TLS_HOST:443 HTTP/1.1\r\n" +
                        "Host: $TLS_HOST:443\r\n" +
                        proxyAuthorizationHeader(proxy) +
                        "\r\n"
                    ).toByteArray(StandardCharsets.ISO_8859_1),
            )
            socket.getOutputStream().flush()
            assertEquals(200, responseStatus(readHeaders(socket.getInputStream())))

            val tlsSocket = trustAllSslContext().socketFactory
                .createSocket(socket, TLS_HOST, 443, false) as SSLSocket
            tlsSocket.use {
                it.soTimeout = SOCKET_TIMEOUT_MS
                it.useClientMode = true
                it.sslParameters = it.sslParameters.apply {
                    applicationProtocols = arrayOf("http/1.1")
                }
                it.startHandshake()
                return it.session.peerCertificates.single() as X509Certificate
            }
        }
    }

    private fun sendProxyRequest(port: Int, request: String): String =
        Socket(InetAddress.getByName("127.0.0.1"), port).use { socket ->
            socket.soTimeout = SOCKET_TIMEOUT_MS
            socket.getOutputStream().write(request.toByteArray(StandardCharsets.ISO_8859_1))
            socket.getOutputStream().flush()
            readHeaders(socket.getInputStream())
        }

    private fun proxyAuthorizationHeader(proxy: RustBrowserProxy): String =
        "Proxy-Authorization: ${proxy.endpoint.authorization.authorizationHeaderValue()}\r\n"

    private fun responseStatus(headers: String): Int =
        headers.lineSequence().first().split(' ')[1].toInt()

    private fun readHeaders(input: InputStream): String {
        val output = ByteArrayOutputStream()
        var matched = 0
        while (matched < HEADER_END.size) {
            val next = input.read()
            require(next >= 0) { "unexpected end of stream" }
            output.write(next)
            matched = if (next.toByte() == HEADER_END[matched]) matched + 1 else 0
        }
        return output.toByteArray().toString(StandardCharsets.ISO_8859_1)
    }

    private fun trustAllSslContext(): SSLContext {
        val trustAll = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) = Unit

                override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) = Unit

                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            },
        )
        return SSLContext.getInstance("TLS").apply {
            init(null, trustAll, SecureRandom())
        }
    }

    private companion object {
        const val TEST_HOST = "connecttest"
        const val TLS_HOST = "tls.connecttest"
        const val SOCKET_TIMEOUT_MS = 10_000
        val HEADER_END = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
    }
}
