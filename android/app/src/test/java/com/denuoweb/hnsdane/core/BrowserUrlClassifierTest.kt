package com.denuoweb.hnsdane.core

import org.junit.Assert.assertEquals
import org.junit.Test

class BrowserUrlClassifierTest {
    private val classifier = BrowserUrlClassifier(TEST_BROWSER_NAMESPACE_POLICY)

    @Test
    fun singleLabelDefaultsToHnsHttpsGateway() {
        val target = classifier.classify("welcome")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://welcome/", target.url)
        assertEquals("welcome", target.displayHost)
    }

    @Test
    fun hnsPathPreservesSuffix() {
        val target = classifier.classify("welcome/path?q=1#top")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://welcome/path?q=1#top", target.url)
    }

    @Test
    fun dottedHnsHostUsesHnsModeWhenTldIsNotCommonIcann() {
        val target = classifier.classify("welcome.2d/path?q=1")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://welcome.2d/path?q=1", target.url)
        assertEquals("welcome.2d", target.displayHost)
    }

    @Test
    fun explicitHnsHttpUrlUsesHnsMode() {
        val target = classifier.classify("http://welcome/path")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("http://welcome/path", target.url)
        assertEquals("welcome", target.displayHost)
    }

    @Test
    fun explicitHnsHttpsUrlUsesHnsModeForFailClosedUi() {
        val target = classifier.classify("https://welcome/path")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://welcome/path", target.url)
        assertEquals("welcome", target.displayHost)
    }

    @Test
    fun emojiHnsNameDefaultsToPunycodeHnsHttpsGateway() {
        val target = classifier.classify("🤝")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://xn--5p9h/", target.url)
        assertEquals("xn--5p9h", target.displayHost)
    }

    @Test
    fun explicitEmojiHnsUrlUsesPunycodeHnsMode() {
        val target = classifier.classify("https://🤝")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://xn--5p9h", target.url)
        assertEquals("xn--5p9h", target.displayHost)
    }

    @Test
    fun dottedHostUsesNormalWebMode() {
        val target = classifier.classify("example.com")

        assertEquals(BrowserTargetKind.ExactUrl, target.kind)
        assertEquals("https://example.com/", target.url)
    }

    @Test
    fun icannDaneTestHostUsesNativeGatewayMode() {
        val target = classifier.classify("dane-test.denuoweb.com")

        assertEquals(BrowserTargetKind.NativeGateway, target.kind)
        assertEquals("https://dane-test.denuoweb.com/", target.url)
        assertEquals("dane-test.denuoweb.com", target.displayHost)
    }

    @Test
    fun discordGgUsesNormalWebMode() {
        val target = classifier.classify("discord.gg")

        assertEquals(BrowserTargetKind.ExactUrl, target.kind)
        assertEquals("https://discord.gg/", target.url)
        assertEquals("discord.gg", target.displayHost)
    }

    @Test
    fun currentIcannTldsUseNormalWebMode() {
        for (host in listOf(
            "example.zip",
            "example.museum",
            "example.arpa",
            "example.xn--p1ai",
            "example.google",
        )) {
            val target = classifier.classify(host)

            assertEquals(host, BrowserTargetKind.ExactUrl, target.kind)
            assertEquals("https://$host/", target.url)
        }
    }

    @Test
    fun appAssetHttpsUrlsLoadAsExactUrls() {
        val target = classifier.classify(
            "https://appassets.androidplatform.net/assets/example.txt",
        )

        assertEquals(BrowserTargetKind.ExactUrl, target.kind)
        assertEquals(
            "https://appassets.androidplatform.net/assets/example.txt",
            target.url,
        )
    }

    @Test
    fun fileUrlsDoNotLoadAsExactUrls() {
        val target = classifier.classify("file:///android_asset/example.txt")

        assertEquals(BrowserTargetKind.Search, target.kind)
    }

    @Test
    fun malformedHttpUrlsBecomeSearches() {
        for (input in listOf("https://", "https:///path", "http://example.com:bad/")) {
            val target = classifier.classify(input)

            assertEquals(input, BrowserTargetKind.Search, target.kind)
        }
    }

    @Test
    fun userInfoHttpUrlsBecomeSearches() {
        val target = classifier.classify("https://example.com@welcome/path")

        assertEquals(BrowserTargetKind.Search, target.kind)
    }

    @Test
    fun explicitDottedHnsUrlUsesHnsModeWhenTldIsNotCommonIcann() {
        val target = classifier.classify("https://welcome.2d/path")

        assertEquals(BrowserTargetKind.HnsName, target.kind)
        assertEquals("https://welcome.2d/path", target.url)
        assertEquals("welcome.2d", target.displayHost)
    }

    @Test
    fun reservedSingleLabelsUseNormalWebMode() {
        for (host in listOf(
            "localhost", "example", "invalid", "local", "test",
            "app.alt", "foo.example", "foo.internal", "foo.invalid", "foo.local", "foo.localhost", "foo.onion", "foo.test",
        )) {
            val target = classifier.classify(host)

            assertEquals(host, BrowserTargetKind.ExactUrl, target.kind)
            assertEquals("https://$host/", target.url)
        }
    }

    @Test
    fun wordsBecomeSearch() {
        val target = classifier.classify("two words")

        assertEquals(BrowserTargetKind.Search, target.kind)
        assertEquals("https://duckduckgo.com/?q=two+words", target.url)
    }

    @Test
    fun unavailableSharedPolicyFailsClosedInsteadOfUsingNormalWebMode() {
        val classifier = BrowserUrlClassifier(
            FixedBrowserNamespacePolicy(emptyMap(), BrowserNamespaceClass.Unavailable),
        )

        val target = classifier.classify("https://unknown.example/path")

        assertEquals(BrowserTargetKind.Blocked, target.kind)
        assertEquals("https://unknown.example/path", target.url)
    }
}
