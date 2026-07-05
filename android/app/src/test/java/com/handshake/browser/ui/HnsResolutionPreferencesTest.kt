package com.handshake.browser.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HnsResolutionPreferencesTest {
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
    }
}
