package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.TEST_BROWSER_NAMESPACE_POLICY
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsWebViewSslErrorPolicyTest {
    private val namespacePolicy = TEST_BROWSER_NAMESPACE_POLICY

    @Test
    fun pinnedLocalCertificatesAreEligibleForWebSocketSslErrors() {
        assertTrue(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("wss://welcome/socket", namespacePolicy))
    }

    @Test
    fun pinnedLocalCertificatesAreEligibleForHttpsSslErrors() {
        assertTrue(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("https://welcome/", namespacePolicy))
    }

    @Test
    fun emojiHnsTlsUrlsAreEligibleAfterPunycodeNormalization() {
        assertTrue(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("https://🤝/", namespacePolicy))
    }

    @Test
    fun pinnedLocalCertificatesRejectNonHnsAndNonTlsUrls() {
        assertFalse(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("https://example.com/", namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("ws://welcome/socket", namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.isEligiblePinnedLocalCertificateUrl("not a url", namespacePolicy))
    }

    @Test
    fun injectedVerifierAuthorizesOnlyTheExactHnsHostAndCertificateDer() {
        val verifier = exactVerifier("welcome", EXPECTED_CERTIFICATE_DER)

        assertTrue(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", EXPECTED_CERTIFICATE_DER, verifier, namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://other/", EXPECTED_CERTIFICATE_DER, verifier, namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", OTHER_CERTIFICATE_DER, verifier, namespacePolicy))
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

        assertTrue(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", EXPECTED_CERTIFICATE_DER, verifier, namespacePolicy))
        activeGeneration = 8L
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", EXPECTED_CERTIFICATE_DER, verifier, namespacePolicy))
        activeGeneration = 0L
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", EXPECTED_CERTIFICATE_DER, verifier, namespacePolicy))
    }

    @Test
    fun missingMalformedAndRejectedCertificateDerFailClosed() {
        val verifier = exactVerifier("welcome", EXPECTED_CERTIFICATE_DER)
        val permissiveVerifier = HnsLocalCertificateDerVerifier { _, _ -> true }

        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", null, permissiveVerifier, namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", ByteArray(0), permissiveVerifier, namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", MALFORMED_CERTIFICATE_DER, verifier, namespacePolicy))
    }

    @Test
    fun verifierFailureAndIcannUrlsFailClosed() {
        val throwingVerifier = HnsLocalCertificateDerVerifier { _, _ -> error("stopped proxy") }
        var icannVerifierCalled = false
        val permissiveVerifier = HnsLocalCertificateDerVerifier { _, _ ->
            icannVerifierCalled = true
            true
        }

        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://welcome/", EXPECTED_CERTIFICATE_DER, throwingVerifier, namespacePolicy))
        assertFalse(HnsWebViewSslErrorPolicy.canProceed("https://example.com/", EXPECTED_CERTIFICATE_DER, permissiveVerifier, namespacePolicy))
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
