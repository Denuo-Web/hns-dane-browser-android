package com.handshake.browser.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import org.w3c.dom.NodeList
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class HnsSyncForegroundServiceManifestTest {
    @Test
    fun manifestDeclaresDataSyncForegroundService() {
        val document = DocumentBuilderFactory.newInstance()
            .apply { isNamespaceAware = true }
            .newDocumentBuilder()
            .parse(locateManifest())

        assertTrue(document.getElementsByTagName("uses-permission").hasAndroidName(FOREGROUND_SERVICE))
        assertTrue(document.getElementsByTagName("uses-permission").hasAndroidName(FOREGROUND_SERVICE_DATA_SYNC))

        val service = document.getElementsByTagName("service")
            .elements()
            .firstOrNull { it.getAttributeNS(ANDROID_NS, "name") == HNS_SYNC_SERVICE }

        assertNotNull(service)
        assertEquals("false", service?.getAttributeNS(ANDROID_NS, "exported"))
        assertEquals("dataSync", service?.getAttributeNS(ANDROID_NS, "foregroundServiceType"))

        val settings = document.getElementsByTagName("activity")
            .elements()
            .firstOrNull { it.getAttributeNS(ANDROID_NS, "name") == SETTINGS_ACTIVITY }

        assertNotNull(settings)
        assertEquals("false", settings?.getAttributeNS(ANDROID_NS, "exported"))

        val cookieSettings = document.getElementsByTagName("activity")
            .elements()
            .firstOrNull { it.getAttributeNS(ANDROID_NS, "name") == COOKIE_SETTINGS_ACTIVITY }

        assertNotNull(cookieSettings)
        assertEquals("false", cookieSettings?.getAttributeNS(ANDROID_NS, "exported"))

        val legal = document.getElementsByTagName("activity")
            .elements()
            .firstOrNull { it.getAttributeNS(ANDROID_NS, "name") == LEGAL_ACTIVITY }

        assertNotNull(legal)
        assertEquals("false", legal?.getAttributeNS(ANDROID_NS, "exported"))
    }

    private fun locateManifest(): File {
        val workingDir = File(System.getProperty("user.dir") ?: ".")
        return generateSequence(workingDir) { it.parentFile }
            .flatMap { directory ->
                sequenceOf(
                    directory.resolve("src/main/AndroidManifest.xml"),
                    directory.resolve("app/src/main/AndroidManifest.xml"),
                    directory.resolve("android/app/src/main/AndroidManifest.xml"),
                )
            }
            .firstOrNull { it.isFile }
            ?: error("Unable to locate AndroidManifest.xml from $workingDir")
    }

    private fun NodeList.hasAndroidName(value: String): Boolean =
        elements().any { it.getAttributeNS(ANDROID_NS, "name") == value }

    private fun NodeList.elements(): Sequence<Element> =
        (0 until length).asSequence().mapNotNull { item(it) as? Element }

    private companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
        const val HNS_SYNC_SERVICE = ".net.HnsSyncForegroundService"
        const val SETTINGS_ACTIVITY = ".ui.SettingsActivity"
        const val COOKIE_SETTINGS_ACTIVITY = ".ui.CookieSettingsActivity"
        const val LEGAL_ACTIVITY = ".ui.LegalActivity"
        const val FOREGROUND_SERVICE = "android.permission.FOREGROUND_SERVICE"
        const val FOREGROUND_SERVICE_DATA_SYNC = "android.permission.FOREGROUND_SERVICE_DATA_SYNC"
    }
}
