package com.handshake.browser.core

import java.util.Locale

object HnsHostPolicy {
    fun requiresHnsResolution(host: String): Boolean {
        val normalized = host
            .trim()
            .removeSurrounding("[", "]")
            .trimEnd('.')
            .lowercase(Locale.US)

        if (normalized.isEmpty() || normalized == "localhost" || normalized.endsWith(".localhost")) {
            return false
        }

        if (normalized in RESERVED_NON_HNS_SINGLE_LABELS) {
            return false
        }

        if (isIpLiteral(normalized)) {
            return false
        }

        val labels = normalized.split('.')
        if (labels.size == 1) {
            return true
        }

        return labels.last() !in IcannTlds.ALL
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(':')) {
            return host.all { it.isDigit() || it in 'a'..'f' || it == ':' || it == '.' }
        }

        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.isNotEmpty() &&
                part.length <= 3 &&
                part.all(Char::isDigit) &&
                part.toIntOrNull()?.let { it in 0..255 } == true
        }
    }

    private val RESERVED_NON_HNS_SINGLE_LABELS = setOf("example", "invalid", "local", "test")

}
