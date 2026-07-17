package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.TEST_BROWSER_NAMESPACE_POLICY
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets
import kotlin.io.path.createTempDirectory

class HnsNativeDownloadFetcherTest {
    @Test
    fun fetchUsesFileBackedGatewayAndInternalHeaders() {
        val dataDir = createTempDirectory("hns-download-fetch-test").toFile()
        val bridge = QueueGatewayBridge(
            GatewayResponse.file(
                head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 7\r\n\r\n",
                body = "payload",
            ),
        )
        val fetcher = HnsNativeDownloadFetcher(
            dataDir = dataDir,
            hnsGatewayBridge = bridge,
            namespacePolicy = TEST_BROWSER_NAMESPACE_POLICY,
            strictHnsMode = { true },
            dohResolverUrl = { "https://resolver.example/dns-query" },
            statelessDaneCertificates = { true },
            experimentalP2pDnsRelay = { true },
            legacyHnsDohCompatibility = { false },
            handshakeNetwork = { "testnet" },
        )

        val response = fetcher.fetch("https://welcome/file.txt", "agent/1")

        assertEquals("https://welcome/file.txt", response.finalUrl)
        assertEquals(200, response.statusCode)
        assertEquals("text/plain", response.mimeType)
        assertEquals("payload", response.bodyFile.readText())
        assertEquals(
            GatewayCall(
                method = "GET",
                scheme = "https",
                host = "welcome",
                port = 443,
                pathAndQuery = "/file.txt",
                headers = listOf(
                    "Accept" to "*/*",
                    "User-Agent" to "agent/1",
                ),
            ),
            bridge.calls.single(),
        )
        assertEquals(
            HnsGatewayRuntimeConfig(
                network = "testnet",
                strictHnsMode = true,
                dohResolverUrl = "https://resolver.example/dns-query",
                statelessDaneCertificates = true,
                experimentalP2pDnsRelay = true,
                legacyHnsDohCompatibility = false,
            ),
            bridge.configs.single(),
        )
        response.bodyFile.delete()
        dataDir.deleteRecursively()
    }

    @Test
    fun fetchFollowsHnsRedirectsOnly() {
        val dataDir = createTempDirectory("hns-download-redirect-test").toFile()
        val bridge = QueueGatewayBridge(
            GatewayResponse.file(
                head = "HTTP/1.1 302 Found\r\nLocation: /final.bin\r\nContent-Length: 0\r\n\r\n",
                body = "",
            ),
            GatewayResponse.file(
                head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n",
                body = "done",
            ),
        )
        val fetcher = HnsNativeDownloadFetcher(dataDir, bridge, TEST_BROWSER_NAMESPACE_POLICY)

        val response = fetcher.fetch("https://welcome/start.bin", null)

        assertEquals("https://welcome/final.bin", response.finalUrl)
        assertEquals(listOf("/start.bin", "/final.bin"), bridge.calls.map { it.pathAndQuery })
        assertFalse(bridge.bodyFiles.first().exists())
        assertEquals("done", response.bodyFile.readText())
        response.bodyFile.delete()
        dataDir.deleteRecursively()
    }

    @Test
    fun fetchRejectsRedirectOutsideHnsScopeAndDeletesBody() {
        val dataDir = createTempDirectory("hns-download-reject-redirect-test").toFile()
        val bridge = QueueGatewayBridge(
            GatewayResponse.file(
                head = "HTTP/1.1 302 Found\r\nLocation: https://example.com/file\r\nContent-Length: 0\r\n\r\n",
                body = "",
            ),
        )
        val fetcher = HnsNativeDownloadFetcher(dataDir, bridge, TEST_BROWSER_NAMESPACE_POLICY)

        assertThrows(HnsNativeDownloadException::class.java) {
            fetcher.fetch("https://welcome/start.bin", null)
        }

        assertFalse(bridge.bodyFiles.single().exists())
        dataDir.deleteRecursively()
    }

    @Test
    fun fetchRejectsSecureTransportDowngradeAndDeletesBody() {
        val dataDir = createTempDirectory("hns-download-downgrade-test").toFile()
        val bridge = QueueGatewayBridge(
            GatewayResponse.file(
                head = "HTTP/1.1 302 Found\r\nLocation: http://welcome/file\r\nContent-Length: 0\r\n\r\n",
                body = "",
            ),
        )
        val fetcher = HnsNativeDownloadFetcher(dataDir, bridge, TEST_BROWSER_NAMESPACE_POLICY)

        assertThrows(HnsNativeDownloadException::class.java) {
            fetcher.fetch("https://welcome/start.bin", null)
        }

        assertFalse(bridge.bodyFiles.single().exists())
        dataDir.deleteRecursively()
    }

    private data class GatewayCall(
        val method: String,
        val scheme: String,
        val host: String,
        val port: Int,
        val pathAndQuery: String,
        val headers: List<Pair<String, String>>,
    )

    private sealed class GatewayResponse {
        data class FileBody(
            val head: ByteArray,
            val body: ByteArray,
        ) : GatewayResponse()

        companion object {
            fun file(head: String, body: String): GatewayResponse =
                FileBody(
                    head.toByteArray(StandardCharsets.ISO_8859_1),
                    body.toByteArray(StandardCharsets.UTF_8),
                )
        }
    }

    private class QueueGatewayBridge(
        private vararg val responses: GatewayResponse,
    ) : HnsGatewayBridge {
        val calls = mutableListOf<GatewayCall>()
        val bodyFiles = mutableListOf<File>()
        val configs = mutableListOf<HnsGatewayRuntimeConfig>()

        override fun httpResponse(
            dataDir: String,
            config: HnsGatewayRuntimeConfig,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): ByteArray? = null

        override fun httpResponseBodyFile(
            dataDir: String,
            config: HnsGatewayRuntimeConfig,
            method: String,
            scheme: String,
            host: String,
            port: Int,
            pathAndQuery: String,
            headers: List<Pair<String, String>>,
            body: ByteArray,
        ): HnsGatewayFileResponse {
            configs += config
            calls += GatewayCall(method, scheme, host, port, pathAndQuery, headers)
            val response = responses.getOrElse(calls.lastIndex) { responses.last() } as GatewayResponse.FileBody
            val bodyFile = File.createTempFile("hns-download-test-", ".body", File(dataDir))
            bodyFile.writeBytes(response.body)
            bodyFiles += bodyFile
            return HnsGatewayFileResponse(response.head, bodyFile)
        }
    }
}
