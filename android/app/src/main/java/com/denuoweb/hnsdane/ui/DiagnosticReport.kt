package com.denuoweb.hnsdane.ui

import java.time.Instant

internal object DiagnosticReport {
    fun markdown(
        buildLabel: String,
        rustCore: String,
        rustDiagnostics: String,
        proxyOverrideSupported: Boolean,
        thirdPartyCookiesBlocked: Boolean,
        generatedAtMillis: Long = System.currentTimeMillis(),
    ): String =
        buildString {
            appendLine("# HNS DANE Browser Diagnostic Bundle")
            appendLine()
            appendLine("Generated: ${Instant.ofEpochMilli(generatedAtMillis)}")
            appendLine("Build: $buildLabel")
            appendLine("Rust core: $rustCore")
            appendLine("Proxy override supported: $proxyOverrideSupported")
            appendLine("Third-party cookies blocked: $thirdPartyCookiesBlocked")
            appendLine()
            appendLine("## Rust Diagnostics")
            appendCodeBlock(rustDiagnostics)
        }

    private fun StringBuilder.appendCodeBlock(value: String) {
        appendLine("```")
        appendLine(value.replace("```", "` ` `"))
        appendLine("```")
    }
}
