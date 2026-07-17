package com.denuoweb.hnsdane.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HnsPageSecurityPathTest {
    @Test
    fun parsesEveryNativeSecurityPathValue() {
        val expectations = mapOf(
            "dane-authoritative-doh" to HnsPageSecurityPath.DaneAuthoritativeDoh,
            "dane-authoritative-dns53" to HnsPageSecurityPath.DaneAuthoritativeDns53,
            "dane-third-party-doh" to HnsPageSecurityPath.DaneThirdPartyDoh,
            "stateless-dane" to HnsPageSecurityPath.StatelessDane,
            "dane-icann-doh" to HnsPageSecurityPath.DaneIcannDoh,
            "hns-authoritative-doh" to HnsPageSecurityPath.HnsAuthoritativeDoh,
            "hns-authoritative-dns53" to HnsPageSecurityPath.HnsAuthoritativeDns53,
            "hns-third-party-doh" to HnsPageSecurityPath.HnsThirdPartyDoh,
            "dane-p2p-dns-relay" to HnsPageSecurityPath.DaneP2pDnsRelay,
            "hns-p2p-dns-relay" to HnsPageSecurityPath.HnsP2pDnsRelay,
        )

        expectations.forEach { (headerValue, expected) ->
            assertEquals(expected, HnsPageSecurityPath.fromHeaderValue(headerValue))
        }
    }

    @Test
    fun unknownOrAbsentValueDoesNotOverrideLegacyState() {
        assertNull(HnsPageSecurityPath.fromHeaderValue(null))
        assertNull(HnsPageSecurityPath.fromHeaderValue(""))
        assertNull(HnsPageSecurityPath.fromHeaderValue("future-security-path"))
    }
}
