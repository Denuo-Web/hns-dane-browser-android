package com.denuoweb.hnsdane.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class MainFrameMatchKeyTest {
    @Test
    fun treatsMissingRootPathAsRootDocument() {
        assertEquals(
            normalizedMainFrameMatchKey("https://shakeshift"),
            normalizedMainFrameMatchKey("https://shakeshift/"),
        )
    }

    @Test
    fun ignoresFragmentsButKeepsPathAndQuery() {
        assertEquals(
            "https://shakeshift/search?q=name",
            normalizedMainFrameMatchKey("https://SHAKESHIFT:443/search?q=name#results"),
        )
        assertNotEquals(
            normalizedMainFrameMatchKey("https://shakeshift/"),
            normalizedMainFrameMatchKey("https://shakeshift/app.css"),
        )
    }
}
