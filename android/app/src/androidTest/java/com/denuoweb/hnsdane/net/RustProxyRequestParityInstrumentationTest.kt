package com.denuoweb.hnsdane.net

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
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
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Device-side parity coverage for request framing after the Kotlin proxy removal.
 *
 * The regtest runtime intentionally has no proof for [TEST_HOST], so the request finishes with a
 * fail-closed HNS response. Reaching that typed response proves that the authenticated Rust proxy
 * accepted CONNECT, completed local TLS, consumed the entire inner request body, and dispatched it
 * through the shared runtime. Origin-success semantics remain covered by the Rust backend tests and
 * the signed-device live-domain matrix.
 */
@RunWith(AndroidJUnit4::class)
class RustProxyRequestParityInstrumentationTest {
    @Test
    fun rustProxyJniTerminatesTlsAndAdmitsContentLengthAndChunkedPosts() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dataDir = context.filesDir.resolve("rust-request-parity-${UUID.randomUUID()}")
        assertTrue(dataDir.mkdirs())
        val proxy = requireNotNull(
            RustBrowserProxy.start(
                RustBrowserProxyConfig(
                    dataDir = dataDir.absolutePath,
                    network = "regtest",
                    scopeHost = TEST_HOST,
                    strictHnsMode = true,
                    dohResolverUrl = "",
                    statelessDaneCertificates = false,
                ),
            ),
        )

        try {
            val contentLength = sendInnerRequest(
                proxy,
                "POST /form?q=secret HTTP/1.1\r\n" +
                    "Host: $TEST_HOST\r\n" +
                    "Sec-Fetch-Dest: document\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Content-Length: 7\r\n" +
                    "Connection: close\r\n\r\n" +
                    "payload",
            )
            assertFailClosedBackendResponse(proxy, contentLength, expectMainFrameStatus = false)

            proxy.discardMainFrameStatus(TEST_HOST)
            val chunked = sendInnerRequest(
                proxy,
                "POST /chunked?q=private HTTP/1.1\r\n" +
                    "Host: $TEST_HOST\r\n" +
                    "Sec-Fetch-Dest: document\r\n" +
                    "Content-Type: application/octet-stream\r\n" +
                    "Transfer-Encoding: chunked\r\n" +
                    "Trailer: X-Upload-Complete\r\n" +
                    "Connection: close\r\n\r\n" +
                    "3\r\npay\r\n4\r\nload\r\n0\r\nX-Upload-Complete: yes\r\n\r\n",
            )
            assertFailClosedBackendResponse(proxy, chunked, expectMainFrameStatus = false)

            val mainFrame = sendInnerRequest(
                proxy,
                "GET /status?q=mailbox-secret HTTP/1.1\r\n" +
                    "Host: $TEST_HOST\r\n" +
                    "Sec-Fetch-Dest: document\r\n" +
                    "Connection: close\r\n\r\n",
            )
            assertFailClosedBackendResponse(proxy, mainFrame, expectMainFrameStatus = true)
        } finally {
            proxy.requestStop()
            val destroyed = CountDownLatch(1)
            Thread {
                proxy.joinAndDestroy()
                destroyed.countDown()
            }.start()
            assertTrue(destroyed.await(10, TimeUnit.SECONDS))
            NativeBridge.closeRuntimes()
            dataDir.deleteRecursively()
        }
    }

    private fun sendInnerRequest(
        proxy: RustBrowserProxy,
        request: String,
    ): ProxyResponseAndCertificate {
        Socket(InetAddress.getByName("127.0.0.1"), proxy.endpoint.port).use { socket ->
            socket.soTimeout = SOCKET_TIMEOUT_MS
            socket.getOutputStream().write(
                (
                    "CONNECT $TEST_HOST:443 HTTP/1.1\r\n" +
                        "Host: $TEST_HOST:443\r\n" +
                        proxyAuthorizationHeader(proxy) +
                        "\r\n"
                    ).toByteArray(StandardCharsets.ISO_8859_1),
            )
            socket.getOutputStream().flush()
            assertEquals(200, responseStatus(readHeaders(socket.getInputStream())))

            val tlsSocket = trustAllSslContext().socketFactory
                .createSocket(socket, TEST_HOST, 443, false) as SSLSocket
            tlsSocket.use {
                it.soTimeout = SOCKET_TIMEOUT_MS
                it.useClientMode = true
                it.sslParameters = it.sslParameters.apply {
                    applicationProtocols = arrayOf("http/1.1")
                    serverNames = listOf(SNIHostName(TEST_HOST))
                }
                it.startHandshake()
                val certificate = it.session.peerCertificates.single() as X509Certificate
                assertTrue(proxy.matchesLocalCertificate(TEST_HOST, certificate.encoded))
                assertFalse(proxy.matchesLocalCertificate("other.$TEST_HOST", certificate.encoded))

                it.getOutputStream().write(request.toByteArray(StandardCharsets.ISO_8859_1))
                it.getOutputStream().flush()
                return ProxyResponseAndCertificate(
                    headers = readHeaders(it.getInputStream()),
                    certificate = certificate,
                )
            }
        }
    }

    private fun assertFailClosedBackendResponse(
        proxy: RustBrowserProxy,
        response: ProxyResponseAndCertificate,
        expectMainFrameStatus: Boolean,
    ) {
        val statusCode = responseStatus(response.headers)
        assertTrue("expected fail-closed HNS response, got $statusCode", statusCode in 400..599)
        assertNotEquals(400, statusCode)
        assertNotEquals(407, statusCode)
        assertNotEquals(411, statusCode)
        assertNotEquals(413, statusCode)
        assertTrue(proxy.matchesLocalCertificate(TEST_HOST, response.certificate.encoded))
        assertFalse(response.headers.contains("q=secret"))
        assertFalse(response.headers.contains("q=private"))
        assertFalse(response.headers.contains("mailbox-secret"))
        assertFalse(response.headers.contains("payload"))
        assertFalse(response.headers.contains("X-Upload-Complete"))

        if (!expectMainFrameStatus) {
            // POST is deliberately excluded from the main-frame navigation mailbox.
            assertNull(proxy.takeMainFrameStatus(TEST_HOST))
            return
        }

        val status = proxy.takeMainFrameStatus(TEST_HOST)
        assertNotNull(status)
        assertEquals(statusCode, status?.statusCode)
        val trace = status?.resolutionTraceJson.orEmpty()
        assertFalse(trace.contains("q=secret"))
        assertFalse(trace.contains("q=private"))
        assertFalse(trace.contains("payload"))
        assertFalse(trace.contains("X-Upload-Complete"))
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

    private data class ProxyResponseAndCertificate(
        val headers: String,
        val certificate: X509Certificate,
    )

    private companion object {
        // Conscrypt intentionally suppresses SNI for single-label hostnames; use an HNS
        // subdomain so this raw SSLSocket exercises the proxy's required exact-SNI path.
        const val TEST_HOST = "request.connecttest"
        const val SOCKET_TIMEOUT_MS = 10_000
        val HEADER_END = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
    }
}
