package com.denuoweb.hnsdane.core

import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Locale

enum class BrowserTargetKind {
    ExactUrl,
    HnsName,
    NativeGateway,
    Blocked,
    Search,
}

data class BrowserTarget(
    val kind: BrowserTargetKind,
    val url: String,
    val displayHost: String?,
)

class BrowserUrlClassifier(
    private val namespacePolicy: BrowserNamespacePolicy,
    private val searchBaseUrl: String = "https://duckduckgo.com/?q=",
) {
    fun classify(input: String): BrowserTarget {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) {
            return search(trimmed)
        }

        if (trimmed.any(Char::isWhitespace)) {
            return search(trimmed)
        }

        val lower = trimmed.lowercase(Locale.US)
        if (lower.startsWith("https://") || lower.startsWith("http://")) {
            return exact(trimmed)
        }

        if ("://" in trimmed) {
            return search(trimmed)
        }

        val hostCandidate = trimmed.substringBefore('/').substringBefore('?').substringBefore('#')
        if (hostCandidate.isBlank()) {
            return search(trimmed)
        }

        val asciiHost = HostnameAscii.toAscii(hostCandidate)
            ?: return search(trimmed)

        if (!isValidHost(asciiHost)) {
            return search(trimmed)
        }

        val suffix = trimmed.removePrefix(hostCandidate)
        val normalizedSuffix = if (suffix.isEmpty()) "/" else suffix
        val kind = targetKindForHost(asciiHost)
        val scheme = "https"
        val url = "$scheme://$asciiHost$normalizedSuffix"
        return BrowserTarget(kind, url, asciiHost)
    }

    private fun exact(url: String): BrowserTarget {
        val uri = runCatching { URI(url) }.getOrNull() ?: return search(url)
        val scheme = uri.scheme?.lowercase(Locale.US)
        if (scheme != "http" && scheme != "https") {
            return search(url)
        }
        val authority = uri.httpAuthority()
            ?: return search(url)
        val host = authority.host.takeIf(::isValidHttpHost)
            ?: return search(url)
        val kind = targetKindForHost(host)
        return BrowserTarget(kind, uri.withAuthority(authority) ?: return search(url), host)
    }

    private fun targetKindForHost(host: String): BrowserTargetKind {
        return when (namespacePolicy.classifyHost(host)) {
            BrowserNamespaceClass.Hns -> BrowserTargetKind.HnsName
            BrowserNamespaceClass.Icann -> BrowserTargetKind.ExactUrl
            BrowserNamespaceClass.NativeGateway -> BrowserTargetKind.NativeGateway
            BrowserNamespaceClass.Invalid,
            BrowserNamespaceClass.Unavailable,
            -> BrowserTargetKind.Blocked
        }
    }

    private fun search(query: String): BrowserTarget {
        val encoded = URLEncoder.encode(query, StandardCharsets.UTF_8)
        return BrowserTarget(BrowserTargetKind.Search, searchBaseUrl + encoded, null)
    }

    private fun isValidHost(host: String): Boolean {
        if (host.length > 253 || host.startsWith(".") || host.endsWith(".")) {
            return false
        }

        return host.split('.').all { label ->
            label.isNotEmpty() &&
                label.length <= 63 &&
                !label.startsWith("-") &&
                !label.endsWith("-") &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    private fun isValidHttpHost(host: String): Boolean {
        if (host.contains(':')) {
            return host.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }
        }

        return isValidHost(host)
    }

    private fun URI.httpAuthority(): ParsedHttpAuthority? {
        val authority = rawAuthority ?: return null
        if (authority.isBlank() || authority.contains('@')) {
            return null
        }

        val hostPart = if (authority.startsWith("[")) {
            val endBracket = authority.indexOf(']')
            if (endBracket <= 1) {
                return null
            }
            val remainder = authority.substring(endBracket + 1)
            if (remainder.isNotEmpty() && !isValidPortSuffix(remainder)) {
                return null
            }
            authority.substring(1, endBracket)
        } else {
            val colonCount = authority.count { it == ':' }
            if (colonCount > 1) {
                return null
            }
            if (colonCount == 1) {
                val separator = authority.indexOf(':')
                val remainder = authority.substring(separator)
                if (!isValidPortSuffix(remainder)) {
                    return null
                }
                authority.substring(0, separator)
            } else {
                authority
            }
        }

        val host = normalizeHost(hostPart) ?: return null
        val portSuffix = if (authority.startsWith("[")) {
            authority.substring(authority.indexOf(']') + 1)
        } else if (authority.count { it == ':' } == 1) {
            authority.substring(authority.indexOf(':'))
        } else {
            ""
        }
        return ParsedHttpAuthority(host, portSuffix)
    }

    private fun normalizeHost(host: String): String? {
        return HostnameAscii.toAscii(host)
    }

    private fun isValidPortSuffix(value: String): Boolean =
        value.length > 1 &&
            value[0] == ':' &&
            value.drop(1).toIntOrNull()?.let { it in 1..65535 } == true

    private fun URI.withAuthority(authority: ParsedHttpAuthority): String? {
        val scheme = scheme?.lowercase(Locale.US) ?: return null
        val host = if (authority.host.contains(':')) "[${authority.host}]" else authority.host
        val path = rawPath.orEmpty()
        val query = rawQuery?.let { "?$it" }.orEmpty()
        val fragment = rawFragment?.let { "#$it" }.orEmpty()
        return "$scheme://$host${authority.portSuffix}$path$query$fragment"
    }

    private data class ParsedHttpAuthority(
        val host: String,
        val portSuffix: String,
    )
}
