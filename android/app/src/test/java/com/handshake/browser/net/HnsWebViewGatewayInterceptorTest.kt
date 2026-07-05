package com.handshake.browser.net

import com.handshake.browser.core.HnsPageTlsPolicy
import com.handshake.browser.core.HnsPageResolverPolicy
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets
import kotlin.io.path.createTempDirectory

class HnsWebViewGatewayInterceptorTest {
    @Before
    fun clearGatewayEvents() {
        GatewayEventLog.clear()
    }

    @Test
    fun hnsHttpsGetUsesNativeGatewayBridge() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX-Test: yes\r\nContent-Length: 2\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-intercept-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept(
            method = "GET",
            url = "https://welcome/path?q=1#fragment",
            requestHeaders = mapOf(
                "Accept" to "text/html",
                "Host" to "ignored",
                "Connection" to "keep-alive",
            ),
        )

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "GET",
                "https",
                "welcome",
                443,
                "/path?q=1",
                listOf("Accept" to "text/html"),
                "",
            ),
            bridge.calls.single(),
        )
        requireNotNull(response)
        assertEquals(200, response.statusCode)
        assertEquals("OK", response.reason)
        assertEquals("text/html", response.mimeType)
        assertEquals("utf-8", response.encoding)
        assertEquals("yes", response.headers["X-Test"])
        assertEquals("ok", response.body.toString(StandardCharsets.UTF_8))
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsHttpsGetCanUseFileBackedNativeGatewayBody() {
        val bridge = FileGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 8\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
            "streamed".toByteArray(StandardCharsets.UTF_8),
        )
        val dataDir = createTempDirectory("hns-webview-file-body-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept(
            method = "GET",
            url = "https://welcome/file",
            requestHeaders = mapOf("Accept" to "text/plain"),
        )

        requireNotNull(response)
        assertEquals(200, response.statusCode)
        assertEquals("text/plain", response.mimeType)
        assertEquals("", response.body.toString(StandardCharsets.UTF_8))
        val streamed = response.openBodyStream().use { input ->
            input.readBytes().toString(StandardCharsets.UTF_8)
        }
        assertEquals("streamed", streamed)
        assertFalse(bridge.bodyFile.exists())
        assertEquals(1, bridge.calls.size)
        dataDir.deleteRecursively()
    }

    @Test
    fun normalWebRequestIsNotIntercepted() {
        val bridge = RecordingGatewayBridge(ByteArray(0))
        val dataDir = createTempDirectory("hns-webview-normal-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        assertNull(interceptor.intercept("GET", "https://example.com/", emptyMap()))
        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun serviceWorkerStyleHnsFetchUsesNativeGatewayPolicy() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-service-worker-intercept-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept(
            method = "GET",
            url = "https://welcome/sw-cache",
            requestHeaders = mapOf(
                "Accept" to "*/*",
                "Proxy-Connection" to "keep-alive",
            ),
        )

        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "GET",
                "https",
                "welcome",
                443,
                "/sw-cache",
                listOf("Accept" to "*/*"),
                "",
            ),
            bridge.calls.single(),
        )
        requireNotNull(response)
        assertEquals(204, response.statusCode)
        assertEquals("No Content", response.reason)
        dataDir.deleteRecursively()
    }

    @Test
    fun strictHnsModeAddsInternalGatewayHeaderAndStripsSpoofedValue() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-strict-mode-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            strictHnsMode = { true },
        )

        interceptor.intercept(
            method = "GET",
            url = "https://welcome/",
            requestHeaders = mapOf(HNS_GATEWAY_STRICT_MODE_HEADER to "0"),
        )

        assertEquals(
            listOf(HNS_GATEWAY_STRICT_MODE_HEADER to "1"),
            bridge.calls.single().headers,
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun dohResolverAddsInternalGatewayHeaderAndStripsSpoofedValue() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-doh-resolver-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            dohResolverUrl = { "https://resolver.example/dns-query" },
        )

        interceptor.intercept(
            method = "GET",
            url = "https://welcome/",
            requestHeaders = mapOf(HNS_GATEWAY_DOH_RESOLVER_HEADER to "https://spoofed.example/dns-query"),
        )

        assertEquals(
            listOf(HNS_GATEWAY_DOH_RESOLVER_HEADER to "https://resolver.example/dns-query"),
            bridge.calls.single().headers,
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun dottedHnsFetchUsesNativeGatewayWhenTldIsNotCommonIcann() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-dotted-webview-intercept-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept(
            method = "GET",
            url = "https://welcome.2d/path",
            requestHeaders = emptyMap(),
        )

        requireNotNull(response)
        assertEquals(
            GatewayCall(
                dataDir.absolutePath,
                "GET",
                "https",
                "welcome.2d",
                443,
                "/path",
                emptyList(),
                "",
            ),
            bridge.calls.single(),
        )
        dataDir.deleteRecursively()
    }

    @Test
    fun emojiHnsFetchUsesPunycodeNativeGatewayHost() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-emoji-webview-intercept-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept(
            method = "GET",
            url = "https://🤝/path",
            requestHeaders = emptyMap(),
        )

        requireNotNull(response)
        assertEquals("xn--5p9h", bridge.calls.single().host)
        dataDir.deleteRecursively()
    }

    @Test
    fun mainFrameHnsResponseReportsFinalStatus() {
        val statuses = mutableListOf<Int>()
        val tlsPolicies = mutableListOf<HnsPageTlsPolicy?>()
        val resolverPolicies = mutableListOf<HnsPageResolverPolicy?>()
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 502 HNS Origin Address Missing\r\nX-HNS-TLS-Policy: webpki-fallback\r\nX-HNS-Resolver-Policy: hns-doh-compat\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-main-frame-status-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge) { status, tlsPolicy, resolverPolicy, _ ->
            statuses += status
            tlsPolicies += tlsPolicy
            resolverPolicies += resolverPolicy
        }

        val response = interceptor.intercept(
            method = "GET",
            url = "https://welcome/",
            requestHeaders = emptyMap(),
            isForMainFrame = true,
        )

        requireNotNull(response)
        assertEquals(502, response.statusCode)
        assertEquals(listOf(502), statuses)
        assertEquals(listOf(HnsPageTlsPolicy.WebPkiFallback), tlsPolicies)
        assertEquals(listOf(HnsPageResolverPolicy.HnsDohCompatibility), resolverPolicies)
        dataDir.deleteRecursively()
    }

    @Test
    fun subresourceHnsResponseDoesNotReportMainFrameStatus() {
        val statuses = mutableListOf<Int>()
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-subresource-status-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge) { status, _, _, _ ->
            statuses += status
        }

        interceptor.intercept(
            method = "GET",
            url = "https://welcome/app.css",
            requestHeaders = emptyMap(),
            isForMainFrame = false,
        )

        assertTrue(statuses.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsRedirectToRelativeHnsPathIsFollowedThroughNativeGateway() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 302 Found\r\nLocation: /next?q=1\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\ndone"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-redirect-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept("GET", "https://welcome/start", emptyMap())

        assertEquals(2, bridge.calls.size)
        assertEquals("/start", bridge.calls[0].pathAndQuery)
        assertEquals("/next?q=1", bridge.calls[1].pathAndQuery)
        requireNotNull(response)
        assertEquals(200, response.statusCode)
        assertEquals("done", response.body.toString(StandardCharsets.UTF_8))
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsRedirectToIcannHostFailsClosed() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-external-redirect-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept("GET", "https://welcome/start", emptyMap())

        assertEquals(1, bridge.calls.size)
        requireNotNull(response)
        assertEquals(502, response.statusCode)
        assertEquals("HNS Redirect Unsupported", response.reason)
        assertTrue(response.body.toString(StandardCharsets.UTF_8).contains("inside HNS resolution policy"))
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsPostFailsClosedBeforeNativeGatewayBecauseWebViewBodyIsUnavailable() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-method-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept("POST", "https://welcome/form", emptyMap())

        requireNotNull(response)
        assertEquals(501, response.statusCode)
        assertEquals("HNS Method Unsupported", response.reason)
        assertTrue(response.body.toString(StandardCharsets.UTF_8).contains("bodyless requests"))
        assertTrue(bridge.calls.isEmpty())
        val event = GatewayEventLog.snapshot().single()
        assertEquals("webview_reject", event.stage)
        assertEquals("welcome", event.host)
        assertEquals(501, event.status)
        assertEquals("HNS_Method_Unsupported", event.reason)
        assertFalse(GatewayEventLog.snapshotText().contains("form"))
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsPostFallsThroughWhenProxyFallbackIsAvailable() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-proxy-fallback-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(
            dataDir,
            bridge,
            allowProxyFallbackForBodyRequests = { true },
        )

        val response = interceptor.intercept("POST", "https://welcome/form", emptyMap())

        assertNull(response)
        assertTrue(bridge.calls.isEmpty())
        dataDir.deleteRecursively()
    }

    @Test
    fun malformedNativeGatewayResponseFailsClosed() {
        val bridge = RecordingGatewayBridge("not http".toByteArray(StandardCharsets.ISO_8859_1))
        val dataDir = createTempDirectory("hns-webview-malformed-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept("GET", "http://welcome/", emptyMap())

        requireNotNull(response)
        assertEquals(502, response.statusCode)
        assertEquals("HNS Gateway Error", response.reason)
        val event = GatewayEventLog.snapshot().single()
        assertEquals("webview_malformed_response", event.stage)
        assertEquals("welcome", event.host)
        assertEquals(502, event.status)
        assertEquals("HNS_Gateway_Error", event.reason)
        dataDir.deleteRecursively()
    }

    @Test
    fun hnsWebViewGatewayFailureRecordsSanitizedEvent() {
        val bridge = RecordingGatewayBridge(
            "HTTP/1.1 502 HNS Origin Address Missing\r\nContent-Length: 11\r\n\r\nsecret-body"
                .toByteArray(StandardCharsets.ISO_8859_1),
        )
        val dataDir = createTempDirectory("hns-webview-event-test").toFile()
        val interceptor = HnsWebViewGatewayInterceptor(dataDir, bridge)

        val response = interceptor.intercept("GET", "https://welcome/private?q=token", emptyMap())

        requireNotNull(response)
        assertEquals(502, response.statusCode)
        val event = GatewayEventLog.snapshot().single()
        assertEquals("webview_native_response", event.stage)
        assertEquals("welcome", event.host)
        assertEquals(502, event.status)
        assertEquals("HNS_Origin_Address_Missing", event.reason)
        val text = GatewayEventLog.snapshotText()
        assertFalse(text.contains("private"))
        assertFalse(text.contains("token"))
        assertFalse(text.contains("secret-body"))
        dataDir.deleteRecursively()
    }

    private data class GatewayCall(
        val dataDir: String,
        val method: String,
        val scheme: String,
        val host: String,
        val port: Int,
        val pathAndQuery: String,
        val headers: List<Pair<String, String>>,
        val body: String,
    )

    private class RecordingGatewayBridge(
        private vararg val responses: ByteArray,
    ) : HnsGatewayBridge {
        val calls = mutableListOf<GatewayCall>()

        override fun httpResponse(
            dataDir: String,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): ByteArray {
            val response = responses.getOrElse(calls.size) { responses.last() }
            calls += GatewayCall(
                dataDir,
                method,
                scheme,
                host,
                port,
                pathAndQuery,
                headers,
                body.toString(StandardCharsets.ISO_8859_1),
            )
            return response
        }
    }

    private class FileGatewayBridge(
        private val responseHead: ByteArray,
        private val responseBody: ByteArray,
    ) : HnsGatewayBridge {
        val calls = mutableListOf<GatewayCall>()
        lateinit var bodyFile: File

        override fun httpResponse(
            dataDir: String,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): ByteArray {
            error("byte-array fallback should not be used")
        }

        override fun httpResponseBodyFile(
            dataDir: String,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): HnsGatewayFileResponse {
            bodyFile = File.createTempFile("hns-test-", ".body", File(dataDir))
            bodyFile.writeBytes(responseBody)
            calls += GatewayCall(
                dataDir,
                method,
                scheme,
                host,
                port,
                pathAndQuery,
                headers,
                body.toString(StandardCharsets.ISO_8859_1),
            )
            return HnsGatewayFileResponse(responseHead, bodyFile)
        }
    }
}
