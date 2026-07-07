package com.denuoweb.hnsdane.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticReportTest {
    @Test
    fun markdownIncludesOperationalFieldsAndEscapesCodeFences() {
        val report = DiagnosticReport.markdown(
            buildLabel = "debug 0.3.1 (22)",
            rustCore = "hns-dane-browser-rust-core/0.3.1",
            rustDiagnostics = """{"securityDefault":"fail-closed","note":"```"}""",
            proxyOverrideSupported = true,
            thirdPartyCookiesBlocked = true,
            generatedAtMillis = 0,
        )

        assertTrue(report.contains("# HNS DANE Browser Diagnostic Bundle"))
        assertTrue(report.contains("Generated: 1970-01-01T00:00:00Z"))
        assertTrue(report.contains("Build: debug 0.3.1 (22)"))
        assertTrue(report.contains("Rust core: hns-dane-browser-rust-core/0.3.1"))
        assertTrue(report.contains("Proxy override supported: true"))
        assertFalse(report.contains("## Sync Status"))
        assertFalse(report.contains("## Recent Gateway Events"))
        assertTrue(report.contains("` ` `"))
        assertFalse(report.contains("\"note\":\"```\""))
    }
}
