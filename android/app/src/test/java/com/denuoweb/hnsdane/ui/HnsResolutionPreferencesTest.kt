package com.denuoweb.hnsdane.ui

import com.denuoweb.hnsdane.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HnsResolutionPreferencesTest {
    @Test
    fun relayControlsUseSafeIndependentDefaults() {
        assertEquals("mainnet", HnsResolutionPreferences.DEFAULT_HANDSHAKE_NETWORK)
        assertFalse(HnsResolutionPreferences.DEFAULT_STRICT_HNS_MODE)
        assertTrue(HnsResolutionPreferences.DEFAULT_EXPERIMENTAL_P2P_DNS_RELAY)
        assertTrue(HnsResolutionPreferences.DEFAULT_LEGACY_HNS_DOH_COMPATIBILITY)
    }

    @Test
    fun buildDefaultsMatchSelectedApplicationVariant() {
        val relayTestBuild = BuildConfig.APPLICATION_ID.endsWith(".relaytest")

        assertEquals(
            if (relayTestBuild) HandshakeNetwork.Regtest else HandshakeNetwork.Mainnet,
            HnsResolutionPreferences.buildDefaultHandshakeNetwork(),
        )
        assertEquals(relayTestBuild, HnsResolutionPreferences.buildDefaultStrictHnsMode())
        assertTrue(HnsResolutionPreferences.buildDefaultExperimentalP2pDnsRelay())
        assertEquals(
            !relayTestBuild,
            HnsResolutionPreferences.buildDefaultLegacyHnsDohCompatibility(),
        )
    }

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
    fun normalizeStaticRelayPeerEndpointAcceptsExplicitIpPorts() {
        assertEquals(
            "1.2.3.4:13038",
            HnsResolutionPreferences.normalizeStaticRelayPeerEndpoint("001.002.003.004:13038"),
        )
        val ipv6 = HnsResolutionPreferences.normalizeStaticRelayPeerEndpoint(
            "[2001:db8::1]:14038",
        )
        assertTrue(ipv6?.startsWith("[2001:db8:") == true)
        assertTrue(ipv6?.endsWith("]:14038") == true)
    }

    @Test
    fun normalizeStaticRelayPeerEndpointRejectsAmbiguousOrUnsafeSyntax() {
        for (endpoint in listOf(
            "",
            "relay.example",
            "relay.example:12038",
            "relay.example:0",
            "relay.example:65536",
            "https://relay.example:12038",
            "user@relay.example:12038",
            "relay_example:12038",
            "1.2.3.999:12038",
            "2001:db8::1:12038",
            "[fe80::1%2]:12038",
        )) {
            assertNull(endpoint, HnsResolutionPreferences.normalizeStaticRelayPeerEndpoint(endpoint))
        }
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
