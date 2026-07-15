package com.denuoweb.hnsdane.net

import android.net.http.SslError
import com.denuoweb.hnsdane.core.HnsHostPolicy
import java.net.URI
import java.util.Locale

fun interface HnsLocalCertificateDerVerifier {
    fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean
}

internal object KotlinFallbackHnsLocalCertificateVerifier : HnsLocalCertificateDerVerifier {
    override fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean =
        HnsLocalCertificateRegistry.hasPinnedCertificateDer(host, certificateDer)
}

object HnsWebViewSslErrorPolicy {
    fun canProceed(error: SslError): Boolean =
        canProceed(error, KotlinFallbackHnsLocalCertificateVerifier)

    fun canProceed(
        error: SslError,
        certificateVerifier: HnsLocalCertificateDerVerifier,
    ): Boolean {
        val certificateDer = runCatching {
            error.certificate?.getX509Certificate()?.encoded
        }.getOrNull()
        return canProceed(error.url, certificateDer, certificateVerifier)
    }

    internal fun canProceed(
        url: String?,
        certificateDer: ByteArray?,
        certificateVerifier: HnsLocalCertificateDerVerifier,
    ): Boolean {
        val uri = url?.let { runCatching { URI(it) }.getOrNull() } ?: return false
        val host = eligiblePinnedLocalCertificateHost(uri) ?: return false
        val presentedCertificateDer = certificateDer?.takeIf(ByteArray::isNotEmpty) ?: return false
        return runCatching {
            certificateVerifier.matchesLocalCertificate(host, presentedCertificateDer)
        }.getOrDefault(false)
    }

    internal fun isEligiblePinnedLocalCertificateUrl(url: String): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        return eligiblePinnedLocalCertificateHost(uri) != null
    }

    private fun eligiblePinnedLocalCertificateHost(uri: URI): String? {
        if (uri.scheme?.lowercase(Locale.US) !in setOf("https", "wss")) {
            return null
        }
        val host = uri.httpAuthorityHost() ?: return null
        return host.takeIf { HnsHostPolicy.requiresHnsResolution(it) }
    }
}
