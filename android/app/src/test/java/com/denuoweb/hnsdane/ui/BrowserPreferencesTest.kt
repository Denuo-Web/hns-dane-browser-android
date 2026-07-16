package com.denuoweb.hnsdane.ui

import com.denuoweb.hnsdane.core.BrowserTargetKind
import com.denuoweb.hnsdane.core.BrowserUrlClassifier
import com.denuoweb.hnsdane.core.TEST_BROWSER_NAMESPACE_POLICY
import org.junit.Assert.assertEquals
import org.junit.Test

class BrowserPreferencesTest {
    @Test
    fun defaultHomepageIsTheBundledStartPage() {
        assertEquals(
            "https://appassets.androidplatform.net/assets/start.html",
            BrowserPreferences.DEFAULT_HOME,
        )

        val target = BrowserUrlClassifier(TEST_BROWSER_NAMESPACE_POLICY).classify(BrowserPreferences.DEFAULT_HOME)
        assertEquals(BrowserTargetKind.ExactUrl, target.kind)
        assertEquals(BrowserPreferences.DEFAULT_HOME, target.url)
    }
}
