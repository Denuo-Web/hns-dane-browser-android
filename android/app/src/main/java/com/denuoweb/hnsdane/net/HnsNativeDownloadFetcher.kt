package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.BrowserNamespacePolicy
import com.denuoweb.hnsdane.core.HnsHostPolicy
import java.io.File
import java.io.IOException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale

internal class HnsNativeDownloadFetcher(
    private val dataDir: File,
    private val hnsGatewayBridge: HnsGatewayBridge = NativeBridge,
    private val namespacePolicy: BrowserNamespacePolicy,
    private val strictHnsMode: () -> Boolean = { false },
    private val dohResolverUrl: () -> String = { "" },
    private val statelessDaneCertificates: () -> Boolean = { false },
    private val handshakeNetwork: () -> String = { DEFAULT_NETWORK },
) {
    @Throws(IOException::class)
    fun fetch(
        url: String,
        userAgent: String?,
    ): HnsNativeDownloadResponse {
        var currentUrl = url
        repeat(MAX_HNS_DOWNLOAD_REDIRECTS + 1) { redirectIndex ->
            val target = HnsNativeDownloadTarget.parse(currentUrl, namespacePolicy)
                ?: throw HnsNativeDownloadException("HNS download URL is not supported.")
            val response = request(target, userAgent, currentUrl)

            if (response.statusCode in REDIRECT_STATUS_CODES) {
                val location = response.headerValue("Location")
                    ?: run {
                        response.deleteBodyFile()
                        throw HnsNativeDownloadException("HNS download redirect did not include a Location header.")
                    }
                val redirectedUrl = target.resolve(location)
                response.deleteBodyFile()
                currentUrl = redirectedUrl
                    ?: throw HnsNativeDownloadException("HNS download redirect target is invalid.")
                val redirectedTarget = HnsNativeDownloadTarget.parse(currentUrl, namespacePolicy)
                if (redirectedTarget == null) {
                    throw HnsNativeDownloadException("HNS download redirect left native HNS resolution scope.")
                }
                if (target.scheme == "https" && redirectedTarget.scheme == "http") {
                    throw HnsNativeDownloadException("HNS download redirect attempted a secure transport downgrade.")
                }
                if (redirectIndex == MAX_HNS_DOWNLOAD_REDIRECTS) {
                    throw HnsNativeDownloadException("HNS download exceeded the redirect limit.")
                }
                return@repeat
            }

            if (response.statusCode !in 200..299) {
                response.deleteBodyFile()
                throw HnsNativeDownloadException("HNS gateway returned HTTP ${response.statusCode} ${response.reason}.")
            }
            return response
        }
        throw HnsNativeDownloadException("HNS download exceeded the redirect limit.")
    }

    private fun request(
        target: HnsNativeDownloadTarget,
        userAgent: String?,
        finalUrl: String,
    ): HnsNativeDownloadResponse {
        val headers = gatewayHeaders(userAgent)
        val runtimeConfig = gatewayRuntimeConfig()
        val fileResponse = hnsGatewayBridge.httpResponseBodyFile(
            dataDir = dataDir.absolutePath,
            config = runtimeConfig,
            method = "GET",
            scheme = target.scheme,
            host = target.host,
            port = target.port,
            pathAndQuery = target.pathAndQuery,
            headers = headers,
            body = ByteArray(0),
        )
        if (fileResponse != null) {
            return parseFileResponse(finalUrl, fileResponse)
        }

        val bytes = hnsGatewayBridge.httpResponse(
            dataDir = dataDir.absolutePath,
            config = runtimeConfig,
            method = "GET",
            scheme = target.scheme,
            host = target.host,
            port = target.port,
            pathAndQuery = target.pathAndQuery,
            headers = headers,
            body = ByteArray(0),
        ) ?: throw HnsNativeDownloadException("Native HNS gateway is unavailable.")

        val parsed = parseDownloadGatewayHttpResponseHead(bytes)
            ?: throw HnsNativeDownloadException("Native HNS gateway returned a malformed response.")
        val responseBodyBytes = bytes.size - parsed.bodyStart
        if (responseBodyBytes > MAX_HNS_DOWNLOAD_BODY_BYTES) {
            throw HnsNativeDownloadException("HNS download response is too large.")
        }
        val bodyFile = createBodyFile()
        try {
            bodyFile.writeBytes(bytes.copyOfRange(parsed.bodyStart, bytes.size))
        } catch (error: Exception) {
            bodyFile.delete()
            throw error
        }
        return HnsNativeDownloadResponse(
            finalUrl = finalUrl,
            statusCode = parsed.statusCode,
            reason = parsed.reason,
            headers = parsed.headers,
            mimeType = parsed.mimeType,
            bodyFile = bodyFile,
        )
    }

    private fun parseFileResponse(
        finalUrl: String,
        fileResponse: HnsGatewayFileResponse,
    ): HnsNativeDownloadResponse {
        val parsed = parseDownloadGatewayHttpResponseHead(fileResponse.head)
            ?: run {
                fileResponse.deleteBodyFile()
                throw HnsNativeDownloadException("Native HNS gateway returned a malformed response.")
            }
        return HnsNativeDownloadResponse(
            finalUrl = finalUrl,
            statusCode = parsed.statusCode,
            reason = parsed.reason,
            headers = parsed.headers,
            mimeType = parsed.mimeType,
            bodyFile = fileResponse.bodyFile,
        )
    }

    private fun gatewayHeaders(userAgent: String?): List<Pair<String, String>> {
        val headers = mutableListOf("Accept" to "*/*")
        userAgent?.trim()?.takeIf { it.isNotBlank() }?.let { headers += "User-Agent" to it }
        return headers
    }

    private fun gatewayRuntimeConfig(): HnsGatewayRuntimeConfig =
        HnsGatewayRuntimeConfig(
            network = handshakeNetwork(),
            strictHnsMode = strictHnsMode(),
            dohResolverUrl = dohResolverUrl(),
            statelessDaneCertificates = statelessDaneCertificates(),
        )

    private fun createBodyFile(): File {
        return HnsDownloadStagingStore.create(dataDir)
            ?: throw HnsNativeDownloadException("Could not create HNS download staging file.")
    }

    companion object {
        private const val MAX_HNS_DOWNLOAD_REDIRECTS = 5
        internal const val MAX_HNS_DOWNLOAD_BODY_BYTES = 8 * 1024 * 1024
        private const val DEFAULT_NETWORK = "mainnet"
        private val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)

        internal fun pruneStaging(dataDir: File) {
            HnsDownloadStagingStore.prune(dataDir)
        }
    }
}

private object HnsDownloadStagingStore {
    private const val PREFIX = "hns-download-"
    private const val SUFFIX = ".body"
    private const val MAX_FILES = 32
    private const val MAX_TOTAL_BYTES = 256L * 1024 * 1024
    private const val MAX_AGE_MILLIS = 24L * 60 * 60 * 1_000

    @Synchronized
    fun create(dataDir: File): File? {
        val directory = File(dataDir, "hns/downloads")
        if (!directory.exists() && !directory.mkdirs()) {
            return null
        }
        pruneDirectory(directory)
        val files = matchingFiles(directory)
        if (
            files.size >= MAX_FILES ||
            files.sumOf { it.length() } > MAX_TOTAL_BYTES - HnsNativeDownloadFetcher.MAX_HNS_DOWNLOAD_BODY_BYTES
        ) {
            return null
        }
        return runCatching { File.createTempFile(PREFIX, SUFFIX, directory) }.getOrNull()
    }

    @Synchronized
    fun prune(dataDir: File) {
        pruneDirectory(File(dataDir, "hns/downloads"))
    }

    private fun pruneDirectory(directory: File, nowMillis: Long = System.currentTimeMillis()) {
        if (!directory.isDirectory) return
        var retained = 0
        var retainedBytes = 0L
        matchingFiles(directory).sortedByDescending(File::lastModified).forEach { file ->
            val size = file.length()
            val expired = nowMillis - file.lastModified() > MAX_AGE_MILLIS
            val overBudget = retained >= MAX_FILES || retainedBytes > MAX_TOTAL_BYTES - size
            if (expired || overBudget) {
                file.delete()
            } else if (file.isFile) {
                retained += 1
                retainedBytes += size
            }
        }
    }

    private fun matchingFiles(directory: File): List<File> =
        directory.listFiles().orEmpty().filter {
            it.isFile && it.name.startsWith(PREFIX) && it.name.endsWith(SUFFIX)
        }
}

internal data class HnsNativeDownloadResponse(
    val finalUrl: String,
    val statusCode: Int,
    val reason: String,
    val headers: Map<String, String>,
    val mimeType: String,
    val bodyFile: File,
) {
    fun headerValue(name: String): String? =
        headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    fun deleteBodyFile() {
        GatewayResponseBodyStore.release(bodyFile)
    }
}

internal class HnsNativeDownloadException(message: String) : IOException(message)

private data class HnsNativeDownloadTarget(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathAndQuery: String,
) {
    companion object {
        fun parse(
            url: String,
            namespacePolicy: BrowserNamespacePolicy,
        ): HnsNativeDownloadTarget? {
            val uri = runCatching { URI(url) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase(Locale.US) ?: return null
            if (scheme != "http" && scheme != "https") {
                return null
            }
            val host = uri.httpAuthorityHost() ?: return null
            if (!HnsHostPolicy.requiresNativeGatewayResolution(host, namespacePolicy)) {
                return null
            }
            val port = when (val explicitPort = uri.port) {
                -1 -> if (scheme == "https") 443 else 80
                in 1..65535 -> explicitPort
                else -> return null
            }
            val rawPath = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
            val pathAndQuery = if (uri.rawQuery == null) rawPath else "$rawPath?${uri.rawQuery}"
            return HnsNativeDownloadTarget(scheme, host, port, pathAndQuery)
        }
    }

    fun resolve(location: String): String? =
        runCatching { asUri().resolve(location).toString() }.getOrNull()

    private fun asUri(): URI {
        val portPart = when {
            scheme == "http" && port == 80 -> ""
            scheme == "https" && port == 443 -> ""
            else -> ":$port"
        }
        return URI("$scheme://$host$portPart$pathAndQuery")
    }
}

private data class ParsedHnsDownloadGatewayHttpHead(
    val statusCode: Int,
    val reason: String,
    val mimeType: String,
    val headers: Map<String, String>,
    val bodyStart: Int,
)

private fun parseDownloadGatewayHttpResponseHead(response: ByteArray): ParsedHnsDownloadGatewayHttpHead? {
    val split = response.indexOfHeaderEnd()
    if (split < 0) {
        return null
    }

    val headerText = response.copyOfRange(0, split).toString(StandardCharsets.ISO_8859_1)
    val lines = headerText.split("\r\n")
    val statusParts = lines.firstOrNull()?.split(' ', limit = 3) ?: return null
    if (statusParts.size < 2 || !statusParts[0].startsWith("HTTP/")) {
        return null
    }
    val headers = linkedMapOf<String, String>()
    for (line in lines.drop(1).filter { it.isNotEmpty() }) {
        val separator = line.indexOf(':')
        if (separator <= 0) {
            return null
        }
        val name = line.substring(0, separator).trim()
        val value = line.substring(separator + 1).trim()
        if (name.isNotEmpty()) {
            headers[name] = value
        }
    }
    val contentType = headers.entries
        .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
        ?.value
    return ParsedHnsDownloadGatewayHttpHead(
        statusCode = statusParts[1].toIntOrNull()?.takeIf { it in 100..999 } ?: return null,
        reason = statusParts.getOrNull(2)?.ifBlank { null } ?: "OK",
        mimeType = contentType
            ?.substringBefore(';')
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?: "application/octet-stream",
        headers = headers,
        bodyStart = split + HEADER_END.size,
    )
}

private fun ByteArray.indexOfHeaderEnd(): Int {
    for (index in 0..(size - HEADER_END.size)) {
        if (HEADER_END.indices.all { offset -> this[index + offset] == HEADER_END[offset] }) {
            return index
        }
    }
    return -1
}

private val HEADER_END = byteArrayOf(
    '\r'.code.toByte(),
    '\n'.code.toByte(),
    '\r'.code.toByte(),
    '\n'.code.toByte(),
)
