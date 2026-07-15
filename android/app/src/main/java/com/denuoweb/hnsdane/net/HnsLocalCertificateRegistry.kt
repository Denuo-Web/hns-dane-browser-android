package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.HostnameAscii
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale

object HnsLocalCertificateRegistry {
    private const val MAX_PINNED_HOSTS = 128
    private val pinnedFingerprints = LinkedHashMap<String, ByteArray>(16, 0.75f, true)

    @Synchronized
    fun trustHostCertificate(host: String, certificateSha256: ByteArray) {
        val normalized = normalizeHost(host) ?: return
        if (certificateSha256.size != SHA256_BYTES) {
            return
        }
        if (!pinnedFingerprints.containsKey(normalized) && pinnedFingerprints.size >= MAX_PINNED_HOSTS) {
            pinnedFingerprints.entries.iterator().run {
                if (hasNext()) {
                    next()
                    remove()
                }
            }
        }
        pinnedFingerprints[normalized] = certificateSha256.copyOf()
    }

    fun hasPinnedCertificate(host: String, certificate: X509Certificate): Boolean {
        return hasPinnedCertificateDer(host, certificate.encoded)
    }

    internal fun hasPinnedCertificateDer(host: String, certificateDer: ByteArray): Boolean {
        if (certificateDer.isEmpty()) {
            return false
        }
        return hasPinnedFingerprint(host, sha256(certificateDer))
    }

    @Synchronized
    internal fun hasPinnedFingerprint(host: String, certificateSha256: ByteArray): Boolean {
        val normalized = normalizeHost(host) ?: return false
        val pinned = pinnedFingerprints[normalized] ?: return false
        return pinned.contentEquals(certificateSha256)
    }

    @Synchronized
    internal fun untrustHostCertificate(host: String) {
        normalizeHost(host)?.let(pinnedFingerprints::remove)
    }

    @Synchronized
    internal fun clear() {
        pinnedFingerprints.clear()
    }

    @Synchronized
    internal fun size(): Int = pinnedFingerprints.size

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun normalizeHost(host: String): String? {
        val normalized = HostnameAscii.toAscii(host.trim().trimEnd('.'))
            ?.lowercase(Locale.US)
            ?: return null
        return normalized.takeIf {
            it.length <= 253 && it.split('.').all { label ->
                label.isNotEmpty() && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-')
            }
        }
    }

    private const val SHA256_BYTES = 32
}
