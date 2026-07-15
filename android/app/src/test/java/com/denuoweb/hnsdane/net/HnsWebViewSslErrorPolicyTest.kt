package com.denuoweb.hnsdane.net

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsWebViewSslErrorPolicyTest {
    @Test
    fun pinnedLocalCertificatesAreEligibleForWebSocketSslErrors() {
        assertTrue(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("wss://welcome/socket"))
    }

    @Test
    fun pinnedLocalCertificatesAreEligibleForHttpsSslErrors() {
        assertTrue(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("https://welcome/"))
    }

    @Test
    fun emojiHnsTlsUrlsAreEligibleAfterPunycodeNormalization() {
        assertTrue(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("https://🤝/"))
    }

    @Test
    fun pinnedLocalCertificatesRejectNonHnsAndNonTlsUrls() {
        assertFalse(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("https://example.com/"))
        assertFalse(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("ws://welcome/socket"))
        assertFalse(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("not a url"))
    }

    @Test
    fun injectedVerifierAuthorizesOnlyTheExactHnsHostAndCertificateDer() {
        val verifier = exactVerifier("welcome", EXPECTED_CERTIFICATE_DER)

        assertTrue(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                EXPECTED_CERTIFICATE_DER,
                verifier,
            ),
        )
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://other/",
                EXPECTED_CERTIFICATE_DER,
                verifier,
            ),
        )
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                OTHER_CERTIFICATE_DER,
                verifier,
            ),
        )
    }

    @Test
    fun stoppedOrStaleLiveVerifierFailsClosed() {
        var activeGeneration = 7L
        val verifierGeneration = 7L
        val verifier = HnsLocalCertificateDerVerifier { host, certificateDer ->
            verifierGeneration == activeGeneration &&
                host == "welcome" &&
                certificateDer.contentEquals(EXPECTED_CERTIFICATE_DER)
        }

        assertTrue(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                EXPECTED_CERTIFICATE_DER,
                verifier,
            ),
        )

        activeGeneration = 8L
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                EXPECTED_CERTIFICATE_DER,
                verifier,
            ),
        )

        activeGeneration = 0L
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                EXPECTED_CERTIFICATE_DER,
                verifier,
            ),
        )
    }

    @Test
    fun missingMalformedAndRejectedCertificateDerFailClosed() {
        val verifier = exactVerifier("welcome", EXPECTED_CERTIFICATE_DER)
        val permissiveVerifier = HnsLocalCertificateDerVerifier { _, _ -> true }

        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", null, permissiveVerifier))
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                ByteArray(0),
                permissiveVerifier,
            ),
        )
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                MALFORMED_CERTIFICATE_DER,
                verifier,
            ),
        )
    }

    @Test
    fun verifierFailureAndIcannUrlsFailClosed() {
        val throwingVerifier = HnsLocalCertificateDerVerifier { _, _ -> error("stopped proxy") }
        var icannVerifierCalled = false
        val permissiveVerifier = HnsLocalCertificateDerVerifier { _, _ ->
            icannVerifierCalled = true
            true
        }

        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://welcome/",
                EXPECTED_CERTIFICATE_DER,
                throwingVerifier,
            ),
        )
        assertFalse(
            HnsWebViewSslErrorPolicy.canProceed(
                "https://example.com/",
                EXPECTED_CERTIFICATE_DER,
                permissiveVerifier,
            ),
        )
        assertFalse(icannVerifierCalled)
    }

    private fun exactVerifier(
        expectedHost: String,
        expectedCertificateDer: ByteArray,
    ): HnsLocalCertificateDerVerifier =
        HnsLocalCertificateDerVerifier { host, certificateDer ->
            host == expectedHost && certificateDer.contentEquals(expectedCertificateDer)
        }

    private companion object {
        val EXPECTED_CERTIFICATE_DER = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
        val OTHER_CERTIFICATE_DER = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x02)
        val MALFORMED_CERTIFICATE_DER = byteArrayOf(0x30, 0x7f)
    }
}
