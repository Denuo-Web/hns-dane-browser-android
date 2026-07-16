package com.denuoweb.hnsdane.net

import android.net.http.SslError
import com.denuoweb.hnsdane.core.BrowserNamespacePolicy
import com.denuoweb.hnsdane.core.HnsHostPolicy
import java.net.URI
import java.util.Locale

fun interface HnsLocalCertificateDerVerifier {
    fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean
}

object HnsWebViewSslErrorPolicy {
    fun canProceed(
        error: SslError,
        certificateVerifier: HnsLocalCertificateDerVerifier,
        namespacePolicy: BrowserNamespacePolicy,
    ): Boolean {
        val certificateDer = runCatching {
            error.certificate?.getX509Certificate()?.encoded
        }.getOrNull()
        return canProceed(error.url, certificateDer, certificateVerifier, namespacePolicy)
    }

    internal fun canProceed(
        url: String?,
        certificateDer: ByteArray?,
        certificateVerifier: HnsLocalCertificateDerVerifier,
        namespacePolicy: BrowserNamespacePolicy,
    ): Boolean {
        val uri = url?.let { runCatching { URI(it) }.getOrNull() } ?: return false
        val host = eligiblePinnedLocalCertificateHost(uri, namespacePolicy) ?: return false
        val presentedCertificateDer = certificateDer?.takeIf(ByteArray::isNotEmpty) ?: return false
        return runCatching {
            certificateVerifier.matchesLocalCertificate(host, presentedCertificateDer)
        }.getOrDefault(false)
    }

    internal fun isEligiblePinnedLocalCertificateUrl(
        url: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        return eligiblePinnedLocalCertificateHost(uri, namespacePolicy) != null
    }

    private fun eligiblePinnedLocalCertificateHost(
        uri: URI,
        namespacePolicy: BrowserNamespacePolicy,
    ): String? {
        if (uri.scheme?.lowercase(Locale.US) !in setOf("https", "wss")) {
            return null
        }
        val host = uri.httpAuthorityHost() ?: return null
        return host.takeIf { HnsHostPolicy.requiresHnsResolution(it, namespacePolicy) }
    }
}
