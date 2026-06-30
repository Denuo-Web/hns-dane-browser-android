package com.handshake.browser.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.handshake.browser.net.NativeBridge
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
        val detailsJson = if (host.isBlank()) {
            """{"host":"","name":null,"nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"invalid_input","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"no HNS host is available for this page"}"""
        } else {
            NativeBridge.hnsProofDetails(filesDir.absolutePath, host)
        }

        setSecondaryScreen("HNS Proof Details") {
            addView(screenSection("Summary") {
                addView(reportText(friendlySummary(detailsJson)))
            })
            addView(screenSection("Export") {
                addScreenRow(preferenceRow(
                    title = "Copy JSON",
                    summary = "Copy the raw proof details payload.",
                    actionLabel = "Copy",
                ) {
                    copy("HNS proof details JSON", detailsJson)
                })
                addScreenRow(preferenceRow(
                    title = "Copy Markdown",
                    summary = "Copy a compact Markdown report.",
                    actionLabel = "Copy",
                ) {
                    copy("HNS proof details Markdown", markdownReport(detailsJson))
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
            ?: return "No HNS proof details are available for this page yet."
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
        return buildString {
            appendLine("# HNS Proof Details")
            appendLine()
            appendLine("Host: ${details?.optString("host", "unknown") ?: "unknown"}")
            appendLine("Name: ${details?.optString("name", "unknown") ?: "unknown"}")
            appendLine("Proof status: ${details?.optString("proofStatus", "unknown") ?: "unknown"}")
            appendLine("Cache status: ${details?.optString("cacheStatus", "unknown") ?: "unknown"}")
            appendLine()
            appendLine("```json")
            appendLine(detailsJson)
            appendLine("```")
        }
    }

    private fun parsedDetails(detailsJson: String): JSONObject? =
        runCatching { JSONObject(detailsJson) }.getOrNull()

    private fun copy(label: String, value: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_URL = "com.handshake.browser.HNS_PROOF_URL"
        const val EXTRA_TRACE_JSON = "com.handshake.browser.HNS_PROOF_TRACE_JSON"
    }
}
