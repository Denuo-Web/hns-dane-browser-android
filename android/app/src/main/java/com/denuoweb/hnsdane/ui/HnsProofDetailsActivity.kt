package com.denuoweb.hnsdane.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.denuoweb.hnsdane.core.HnsHostPolicy
import com.denuoweb.hnsdane.net.NativeBridge
import org.json.JSONArray
import org.json.JSONObject

class HnsProofDetailsActivity : ComponentActivity() {
    private val url: String
        get() = intent.getStringExtra(EXTRA_URL).orEmpty()

    private val traceJson: String
        get() = intent.getStringExtra(EXTRA_TRACE_JSON).orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val host = proofHost()
        val trace = parsedTrace()
        val isIcann = HnsResolutionTraceFormat.isIcann(trace) || HnsHostPolicy.isIcannDaneTestHost(host)
        val detailsJson = if (host.isBlank()) {
            """{"host":"","name":null,"nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"invalid_input","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"no HNS host is available for this page"}"""
        } else if (isIcann) {
            icannDetailsJson(host, trace)
        } else {
            NativeBridge.hnsProofDetails(filesDir.absolutePath, host)
        }

        setSecondaryScreen(
            title = if (isIcann) "DNSSEC Details" else "HNS Proof Details",
            onSwipeLeft = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.ProofDetails, forward = true, url, traceJson)
            },
            onSwipeRight = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.ProofDetails, forward = false, url, traceJson)
            },
        ) {
            addView(hnsDiagnosticTabs(HnsDiagnosticTool.ProofDetails, url, traceJson))
            addView(screenSection("Summary") {
                addView(fieldReportText(friendlySummary(detailsJson)))
            })
            addView(screenSection("Export") {
                addScreenRow(preferenceRow(
                    title = "Copy JSON",
                    summary = "Copy the raw validation details payload.",
                    actionLabel = "Copy",
                ) {
                    copy(if (isIcann) "DNSSEC details JSON" else "HNS proof details JSON", detailsJson)
                })
                addScreenRow(preferenceRow(
                    title = "Copy Markdown",
                    summary = "Copy a compact Markdown report.",
                    actionLabel = "Copy",
                ) {
                    copy(if (isIcann) "DNSSEC details Markdown" else "HNS proof details Markdown", markdownReport(detailsJson))
                })
            })
            addView(screenSection("Raw export") {
                addView(reportText(detailsJson, monospace = true))
            })
        }
    }

    private fun proofHost(): String {
        val traceHost = runCatching {
            JSONObject(traceJson).optString("host")
        }.getOrDefault("")
        if (traceHost.isNotBlank()) {
            return traceHost
        }
        val uriHost = runCatching {
            Uri.parse(url).host
        }.getOrNull().orEmpty()
        if (uriHost.isNotBlank()) {
            return uriHost
        }
        return url
            .substringAfter("://", url)
            .substringBefore("/")
            .substringBefore("?")
            .substringBefore("#")
            .substringBefore(":")
            .trim()
    }

    private fun friendlySummary(detailsJson: String): String {
        val details = parsedDetails(detailsJson)
            ?: return "No validation details are available for this page yet."
        if (details.optString("nameClass") == "icann") {
            return icannFriendlySummary(details)
        }
        val currentTip = details.optJSONObject("currentTip")
        val resourceValueHex = details.optString("resourceValueHex")
        return buildString {
            appendLine("Host: ${details.optString("host", "unknown")}")
            appendLine("Name: ${details.optString("name", "unknown")}")
            appendLine("Name hash: ${details.optString("nameHash", "unknown")}")
            appendLine("Tree root: ${details.optString("treeRoot", "none")}")
            appendLine("Block height: ${details.optString("blockHeight", "none")}")
            appendLine("Proof status: ${details.optString("proofStatus", "unknown")}")
            appendLine("Cache status: ${details.optString("cacheStatus", "unknown")}")
            appendLine("Current tip: ${currentTipText(currentTip)}")
            appendLine("Secure: ${details.optString("secure", "unknown")}")
            appendLine("Exists: ${details.optString("exists", "unknown")}")
            appendLine("Record types: ${arrayText(details.optJSONArray("recordTypes"))}")
            appendLine("Resource value: ${resourceValueHex.ifBlank { "none" }}")
            appendLine("Error: ${details.optString("error", "none").takeIf { it != "null" } ?: "none"}")
        }
    }

    private fun icannDetailsJson(host: String, trace: JSONObject?): String =
        JSONObject()
            .put("host", host)
            .put("nameClass", "icann")
            .put("hnsProof", "not_applicable")
            .put("proofStatus", "not_applicable")
            .put("dnssec", trace?.optString("dnssec", "unknown") ?: "unknown")
            .put("resolutionSource", trace?.optString("resolutionSource", "unknown") ?: "unknown")
            .put("resourceRecords", trace?.optJSONArray("resourceRecords") ?: JSONArray())
            .put("error", JSONObject.NULL)
            .toString()

    private fun icannFriendlySummary(details: JSONObject): String =
        buildString {
            appendLine("Host: ${details.optString("host", "unknown")}")
            appendLine("Namespace: ICANN DNS")
            appendLine("HNS proof: not applicable")
            appendLine("DNSSEC: ${details.optString("dnssec", "unknown")}")
            appendLine("Resolution source: ${HnsResolutionTraceFormat.resolutionSource(details)}")
            appendLine("Record types: ${arrayText(details.optJSONArray("resourceRecords"))}")
            appendLine("Error: ${details.optString("error", "none").takeIf { it != "null" } ?: "none"}")
        }

    private fun currentTipText(currentTip: JSONObject?): String =
        if (currentTip == null) {
            "unknown"
        } else {
            "height ${currentTip.optString("height", "unknown")}, tree ${currentTip.optString("treeRoot", "unknown")}"
        }

    private fun arrayText(array: JSONArray?): String =
        if (array == null || array.length() == 0) {
            "none"
        } else {
            (0 until array.length()).joinToString(", ") { index -> array.optString(index) }
        }

    private fun markdownReport(detailsJson: String): String {
        val details = parsedDetails(detailsJson)
        val isIcann = details?.optString("nameClass") == "icann"
        return buildString {
            appendLine(if (isIcann) "# DNSSEC Details" else "# HNS Proof Details")
            appendLine()
            appendLine("Host: ${details?.optString("host", "unknown") ?: "unknown"}")
            if (isIcann) {
                appendLine("Namespace: ICANN DNS")
                appendLine("DNSSEC: ${details?.optString("dnssec", "unknown") ?: "unknown"}")
            } else {
                appendLine("Name: ${details?.optString("name", "unknown") ?: "unknown"}")
                appendLine("Proof status: ${details?.optString("proofStatus", "unknown") ?: "unknown"}")
                appendLine("Cache status: ${details?.optString("cacheStatus", "unknown") ?: "unknown"}")
            }
            appendLine()
            appendLine("```json")
            appendLine(detailsJson)
            appendLine("```")
        }
    }

    private fun parsedDetails(detailsJson: String): JSONObject? =
        runCatching { JSONObject(detailsJson) }.getOrNull()

    private fun parsedTrace(): JSONObject? =
        HnsResolutionTraceFormat.parse(traceJson)

    private fun copy(label: String, value: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_URL = "com.denuoweb.hnsdane.HNS_PROOF_URL"
        const val EXTRA_TRACE_JSON = "com.denuoweb.hnsdane.HNS_PROOF_TRACE_JSON"
    }
}
