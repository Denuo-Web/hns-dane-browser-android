package com.denuoweb.hnsdane.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import org.json.JSONArray
import org.json.JSONObject

class HnsTlsaInspectorActivity : ComponentActivity() {
    private val url: String
        get() = intent.getStringExtra(EXTRA_URL).orEmpty()

    private val traceJson: String
        get() = intent.getStringExtra(EXTRA_TRACE_JSON).orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setSecondaryScreen(
            title = "TLSA / DANE Inspector",
            onSwipeLeft = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.TlsaInspector, forward = true, url, traceJson)
            },
            onSwipeRight = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.TlsaInspector, forward = false, url, traceJson)
            },
        ) {
            addView(hnsDiagnosticTabs(HnsDiagnosticTool.TlsaInspector, url, traceJson))
            addView(screenSection("Summary") {
                addView(fieldReportText(friendlySummary()))
            })
            addView(screenSection("Export") {
                addScreenRow(preferenceRow(
                    title = "Copy JSON",
                    summary = "Copy the raw TLSA/DANE trace payload.",
                    actionLabel = "Copy",
                ) {
                    copy("TLSA inspector JSON", rawJson())
                })
                addScreenRow(preferenceRow(
                    title = "Copy Markdown",
                    summary = "Copy a compact Markdown report.",
                    actionLabel = "Copy",
                ) {
                    copy("TLSA inspector Markdown", markdownReport())
                })
            })
            addView(screenSection("Raw export") {
                addView(reportText(rawJson(), monospace = true))
            })
        }
    }

    private fun friendlySummary(): String {
        val trace = parsedTrace()
            ?: return "No resolver trace is available. Load an HTTPS HNS page first."
        val tls = trace.optJSONObject("tls")
            ?: return "No HTTPS TLSA/DANE trace is available for this page."
        val dane = tls.optJSONObject("dane")
        val certificate = tls.optJSONObject("certificate")
        return buildString {
            appendLine("URL: ${url.ifBlank { trace.optString("url", "unknown") }}")
            appendLine("Host: ${trace.optString("host", "unknown")}")
            appendLine("TLS mode: ${HnsTlsaTraceFormat.tlsMode(tls)}")
            appendLine("TLSA owner: ${tls.optString("tlsaOwner", "unknown")}")
            appendLine("TLSA status: ${HnsTlsaTraceFormat.tlsaStatus(tls)}")
            appendLine("TLSA found: ${HnsTlsaTraceFormat.tlsaFound(tls)}")
            appendLine("TLSA source: ${HnsTlsaTraceFormat.tlsaSource(tls)}")
            appendLine("DNSSEC secure: ${HnsTlsaTraceFormat.dnssecSecure(tls)}")
            appendLine("DANE decision: ${HnsTlsaTraceFormat.daneDecision(tls)}")
            appendLine("Matched usage: ${dane?.optString("matchedUsage", "none") ?: "none"}")
            appendLine("Certificate match: ${dane?.optString("certificateMatch", "unknown") ?: "unknown"}")
            appendLine("WebPKI fallback: ${if (dane?.optBoolean("webPkiFallback", false) == true) "yes" else "no"}")
            appendLine("WebPKI status: ${certificate?.optString("webPkiStatus", "unknown") ?: "unknown"}")
            appendLine("Certificate SHA-256: ${certificate?.optString("endEntitySha256", "unknown") ?: "unknown"}")
            appendLine("SPKI SHA-256: ${certificate?.optString("spkiSha256", "unknown") ?: "unknown"}")
            appendLine("Intermediate certs: ${certificate?.optString("intermediateCount", "unknown") ?: "unknown"}")
            appendLine()
            appendLine("TLSA records:")
            appendLine(recordsText(tls.optJSONArray("records")))
            appendLine()
            appendLine("SPKI DER:")
            appendLine(certificate?.optString("spkiDerHex")?.takeIf { it.isNotBlank() } ?: "unavailable")
        }
    }

    private fun recordsText(records: JSONArray?): String =
        if (records == null || records.length() == 0) {
            "none"
        } else {
            (0 until records.length()).joinToString("\n") { index ->
                val record = records.optJSONObject(index)
                "- usage=${record?.optString("usage", "unknown") ?: "unknown"}, " +
                    "selector=${record?.optString("selector", "unknown") ?: "unknown"}, " +
                    "matching=${record?.optString("matching", "unknown") ?: "unknown"}, " +
                    "association=${record?.optString("associationDataHex", "unknown") ?: "unknown"}"
            }
        }

    private fun markdownReport(): String =
        "# TLSA / DANE Report\n\n```\n${rawJson()}\n```\n"

    private fun rawJson(): String =
        traceJson.ifBlank { """{"error":"no_hns_tlsa_trace_available"}""" }

    private fun parsedTrace(): JSONObject? =
        runCatching { JSONObject(traceJson) }.getOrNull()

    private fun copy(label: String, value: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_URL = "com.denuoweb.hnsdane.HNS_TLSA_URL"
        const val EXTRA_TRACE_JSON = "com.denuoweb.hnsdane.HNS_TLSA_TRACE_JSON"
    }
}
