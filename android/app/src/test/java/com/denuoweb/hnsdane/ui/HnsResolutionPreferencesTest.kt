package com.denuoweb.hnsdane.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HnsResolutionPreferencesTest {
    @Test
    fun defaultDohResolverUsesWorkingZorroNode() {
        assertEquals(
            "https://zorro.hnsdoh.com/dns-query",
            HnsResolutionPreferences.DEFAULT_DOH_RESOLVER_URL,
        )
    }

    @Test
    fun handshakeNetworkFromIdSupportsKnownNetworks() {
        assertEquals(HandshakeNetwork.Mainnet, HandshakeNetwork.fromId("mainnet"))
        assertEquals(HandshakeNetwork.Testnet, HandshakeNetwork.fromId("testnet"))
        assertEquals(HandshakeNetwork.Regtest, HandshakeNetwork.fromId("regtest"))
    }

    @Test
    fun handshakeNetworkFromIdDefaultsToMainnet() {
        assertEquals(HandshakeNetwork.Mainnet, HandshakeNetwork.fromId(null))
        assertEquals(HandshakeNetwork.Mainnet, HandshakeNetwork.fromId("unknown"))
    }

    @Test
    fun normalizeDohResolverUrlAcceptsHttpsEndpoint() {
        assertEquals(
            "https://resolver.example/dns-query",
            HnsResolutionPreferences.normalizeDohResolverUrl(" https://Resolver.Example/dns-query "),
        )
        assertEquals(
            "https://resolver.example:8443/query",
            HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example:8443/query"),
        )
    }

    @Test
    fun normalizeDohResolverUrlUsesDefaultForBlank() {
        assertEquals(
            HnsResolutionPreferences.DEFAULT_DOH_RESOLVER_URL,
            HnsResolutionPreferences.normalizeDohResolverUrl(" "),
        )
    }

    @Test
    fun normalizeDohResolverUrlRejectsUnsafeUrls() {
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("http://resolver.example/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://user@resolver.example/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example/dns-query#frag"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example:0/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example:65536/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example:25/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example:6667/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://[::1]/dns-query"))
        assertNull(HnsResolutionPreferences.normalizeDohResolverUrl("https://resolver.example/" + "x".repeat(5_000)))
    }
}
