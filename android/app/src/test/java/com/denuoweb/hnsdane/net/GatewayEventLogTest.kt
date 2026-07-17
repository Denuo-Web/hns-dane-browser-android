package com.denuoweb.hnsdane.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import kotlin.io.path.createTempDirectory

class GatewayEventLogTest {
    @Before
    fun clearGatewayEvents() {
        GatewayEventLog.configure(null)
        GatewayEventLog.clear()
    }

    @Test
    fun eventLogIsBoundedToRecentEvents() {
        repeat(30) { index ->
            GatewayEventLog.record("native_response", "host$index", 500 + index, "failure")
        }

        val events = GatewayEventLog.snapshot()
        assertEquals(25, events.size)
        assertEquals("host5", events.first().host)
        assertEquals("host29", events.last().host)
    }

    @Test
    fun eventLogSanitizesHostStageAndReason() {
        GatewayEventLog.record(
            "Native Response: /private?q=secret",
            "Private.Welcome./private?q=secret",
            503,
            "HNS Resolution Unavailable /private?q=secret",
        )

        val event = GatewayEventLog.snapshot().single()
        assertEquals("native_response", event.stage)
        assertEquals("welcome", event.host)
        assertEquals("HNS_Resolution_Unavailable", event.reason)

        val text = GatewayEventLog.snapshotText()
        assertFalse(text.contains("/"))
        assertFalse(text.contains("?"))
        assertFalse(text.contains("="))
        assertFalse(text.contains("secret"))
        assertFalse(text.contains("private"))
        assertTrue(text.contains("welcome"))
    }

    @Test
    fun eventLogRedactsIpv4AndIpv6Literals() {
        GatewayEventLog.record("native_response", "192.0.2.44", 502, "failure")
        GatewayEventLog.record("native_response", "[2001:db8::44]", 502, "failure")

        val events = GatewayEventLog.snapshot()
        assertEquals(listOf("ip-literal", "ip-literal"), events.map { it.host })
        assertFalse(GatewayEventLog.snapshotText().contains("192.0.2.44"))
        assertFalse(GatewayEventLog.snapshotText().contains("2001:db8"))
    }

    @Test
    fun eventLogPersistsBoundedSanitizedEvents() {
        val store = createTempDirectory("gateway-events").toFile().resolve("events.log")
        GatewayEventLog.configure(store)
        repeat(30) { index ->
            GatewayEventLog.record(
                "Native Response /private$index?q=secret",
                "Welcome$index./private?q=secret",
                500 + index,
                "HNS Resolution Unavailable /private?q=secret",
            )
        }

        GatewayEventLog.configure(null)
        GatewayEventLog.configure(store)

        val events = GatewayEventLog.snapshot()
        assertEquals(25, events.size)
        assertEquals("welcome5", events.first().host)
        assertEquals("welcome29", events.last().host)
        val text = GatewayEventLog.snapshotText()
        assertFalse(text.contains("private"))
        assertFalse(text.contains("secret"))
        assertFalse(text.contains("?"))
        assertTrue(store.readLines().size <= 25)
        store.parentFile?.deleteRecursively()
    }

    @Test
    fun clearDeletesPersistedEvents() {
        val root = createTempDirectory("gateway-events-clear").toFile()
        val store = root.resolve("events.log")
        GatewayEventLog.configure(store)
        GatewayEventLog.record("native_response", "welcome", 200, "ok")

        assertTrue(store.isFile)
        assertTrue(GatewayEventLog.clear())
        assertTrue(GatewayEventLog.snapshot().isEmpty())
        assertFalse(store.exists())

        GatewayEventLog.configure(null)
        root.deleteRecursively()
    }

    @Test
    fun clearFailureDoesNotClaimOrHideDeletion() {
        val root = createTempDirectory("gateway-events-clear-failure").toFile()
        val store = root.resolve("events.log").apply { mkdirs() }
        store.resolve("undeletable-child").writeText("still present")
        GatewayEventLog.configure(store)
        GatewayEventLog.record("native_response", "welcome", 500, "failure")

        assertFalse(GatewayEventLog.clear())
        assertEquals(1, GatewayEventLog.snapshot().size)

        GatewayEventLog.configure(null)
        root.deleteRecursively()
    }
}
