package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.HnsHostPolicy
import java.io.File
import java.io.IOException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale

internal class HnsNativeDownloadFetcher(
    private val dataDir: File,
    private val hnsGatewayBridge: HnsGatewayBridge = NativeBridge,
    private val strictHnsMode: () -> Boolean = { false },
    private val dohResolverUrl: () -> String = { "" },
    private val statelessDaneCertificates: () -> Boolean = { false },
) {
    @Throws(IOException::class)
    fun fetch(
        url: String,
        userAgent: String?,
    ): HnsNativeDownloadResponse {
        var currentUrl = url
        repeat(MAX_HNS_DOWNLOAD_REDIRECTS + 1) { redirectIndex ->
            val target = HnsNativeDownloadTarget.parse(currentUrl)
                ?: throw HnsNativeDownloadException("HNS download URL is not supported.")
            val response = request(target, userAgent, currentUrl)

            if (response.statusCode in REDIRECT_STATUS_CODES) {
                val location = response.headerValue("Location")
                    ?: run {
                        response.bodyFile.delete()
                        throw HnsNativeDownloadException("HNS download redirect did not include a Location header.")
                    }
                val redirectedUrl = target.resolve(location)
                response.bodyFile.delete()
                currentUrl = redirectedUrl
                    ?: throw HnsNativeDownloadException("HNS download redirect target is invalid.")
                if (HnsNativeDownloadTarget.parse(currentUrl) == null) {
                    throw HnsNativeDownloadException("HNS download redirect left native HNS resolution scope.")
                }
                if (redirectIndex == MAX_HNS_DOWNLOAD_REDIRECTS) {
                    throw HnsNativeDownloadException("HNS download exceeded the redirect limit.")
                }
                return@repeat
            }

            if (response.statusCode !in 200..299) {
                response.bodyFile.delete()
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
        val fileResponse = hnsGatewayBridge.httpResponseBodyFile(
            dataDir = dataDir.absolutePath,
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
        val bodyFile = createBodyFile()
        bodyFile.writeBytes(bytes.copyOfRange(parsed.bodyStart, bytes.size))
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
                fileResponse.bodyFile.delete()
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
        if (strictHnsMode()) {
            headers += HNS_GATEWAY_STRICT_MODE_HEADER to "1"
        }
        dohResolverUrl().takeIf { it.isNotBlank() }?.let { resolver ->
            headers += HNS_GATEWAY_DOH_RESOLVER_HEADER to resolver
        }
        if (statelessDaneCertificates()) {
            headers += HNS_GATEWAY_STATELESS_DANE_HEADER to "1"
        }
        return headers
    }

    private fun createBodyFile(): File {
        val downloadDir = File(dataDir, "hns/downloads")
        if (!downloadDir.exists() && !downloadDir.mkdirs()) {
            throw HnsNativeDownloadException("Could not create HNS download staging directory.")
        }
        return File.createTempFile("hns-download-", ".body", downloadDir)
    }

    private companion object {
        const val MAX_HNS_DOWNLOAD_REDIRECTS = 5
        val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)
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
}

internal class HnsNativeDownloadException(message: String) : IOException(message)

private data class HnsNativeDownloadTarget(
    val scheme: String,
    val host: String,
    val port: Int,
    val pathAndQuery: String,
) {
    companion object {
        fun parse(url: String): HnsNativeDownloadTarget? {
            val uri = runCatching { URI(url) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase(Locale.US) ?: return null
            if (scheme != "http" && scheme != "https") {
                return null
            }
            val host = uri.httpAuthorityHost() ?: return null
            if (!HnsHostPolicy.requiresNativeGatewayResolution(host)) {
                return null
            }
            val port = when {
                uri.port > 0 -> uri.port
                scheme == "https" -> 443
                else -> 80
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
