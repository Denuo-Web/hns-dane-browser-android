package com.handshake.browser.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.handshake.browser.net.NativeBridge
import org.json.JSONArray
import org.json.JSONObject

class HnsDomainWizardActivity : ComponentActivity() {
    private lateinit var input: EditText
    private lateinit var output: TextView
    private var lastReport: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        input = EditText(this).apply {
            hint = "myname/ or www.myname/"
            setSingleLine(true)
            imeOptions = EditorInfo.IME_ACTION_GO
            setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_GO) {
                    analyze()
                    true
                } else {
                    false
                }
            }
        }

        output = reportText("Enter an HNS name you own, then run the local proof/resource analyzer.")

        setSecondaryScreen("HNS Domain Setup") {
            addView(screenSection("Domain") {
                addView(input, LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ))
                addScreenRow(preferenceRow(
                    title = "Analyze domain",
                    summary = "Check the local HNS proof and resource records.",
                    actionLabel = "Analyze",
                ) {
                    analyze()
                })
                addScreenRow(preferenceRow(
                    title = "Copy report",
                    summary = "Copy the current analysis as text.",
                    actionLabel = "Copy",
                ) {
                    copy(lastReport.ifBlank { output.text.toString() })
                })
            })
            addView(screenSection("Report") {
                addView(output)
            })
        }
    }

    private fun analyze() {
        val host = normalizeHost(input.text.toString())
        if (host.isBlank()) {
            output.text = "Enter a valid HNS name first."
            return
        }
        val proofJson = NativeBridge.hnsProofDetails(filesDir.absolutePath, host)
        lastReport = reportFor(host, proofJson)
        output.text = lastReport
    }

    private fun reportFor(host: String, proofJson: String): String {
        val proof = runCatching { JSONObject(proofJson) }.getOrNull()
            ?: return "Could not parse proof details.\n\nRaw:\n$proofJson"
        val name = proof.optString("name", host.substringAfterLast("."))
        val status = proof.optString("proofStatus", "unknown")
        val cacheStatus = proof.optString("cacheStatus", "unknown")
        val recordTypes = proof.optJSONArray("recordTypes")
        val records = proof.optJSONArray("resourceRecords")
        val hasNs = hasRecordType(recordTypes, "NS")
        val hasAddress = hasRecordType(recordTypes, "A") || hasRecordType(recordTypes, "AAAA")
        val hasDs = hasRecordType(recordTypes, "DS")
        val hasTxt = hasRecordType(recordTypes, "TXT")

        return buildString {
            appendLine("# HNS Domain Wizard")
            appendLine()
            appendLine("Host: $host")
            appendLine("Root: $name")
            appendLine("Proof status: $status")
            appendLine("Cache status: $cacheStatus")
            appendLine("Records: ${arrayText(recordTypes)}")
            appendLine()
            appendLine("Current problem:")
            appendLine(problemText(status, cacheStatus, hasNs, hasAddress, hasDs))
            appendLine()
            appendLine("Suggested fix:")
            appendLine(suggestedFix(name, status, hasNs, hasAddress, hasDs))
            appendLine()
            appendLine("Strict HNS + DANE checklist:")
            appendLine("- HNS resource has NS plus usable GLUE4/GLUE6, or direct SYNTH4/SYNTH6.")
            appendLine("- Authoritative DNS answers UDP 53 and TCP 53 for $name.")
            appendLine("- HNS DS matches child DNSKEY, and child zone has valid RRSIG/NSEC denial data.")
            appendLine("- HTTPS sites publish TLSA at _443._tcp.$host.")
            appendLine()
            appendLine("Decoded records:")
            appendLine(recordsText(records))
            if (hasTxt) {
                appendLine()
                appendLine("TXT records are visible, but TXT alone does not make a browser-loadable origin.")
            }
            appendLine()
            appendLine("Raw proof JSON:")
            appendLine(proofJson)
        }
    }

    private fun problemText(
        status: String,
        cacheStatus: String,
        hasNs: Boolean,
        hasAddress: Boolean,
        hasDs: Boolean,
    ): String = when {
        status == "unavailable" ->
            "No local proof is available yet ($cacheStatus). Sync first, then retry."
        status == "not_found" ->
            "The HNS root proof says this name does not currently exist."
        status != "verified" ->
            "The local proof is not verified yet: $status."
        !hasNs && !hasAddress ->
            "The name has no browser-usable NS/address data."
        hasNs && !hasAddress ->
            "The name delegates to NS records, but no local address is visible in the HNS proof. The delegated nameserver must be reachable and authoritative."
        hasAddress && !hasDs ->
            "The name has address data, but no HNS DS. It can load directly, but strict delegated DNSSEC/DANE is not fully established."
        else ->
            "The HNS resource looks browser-usable. If loading fails, inspect the Resolver Trace and TLSA Inspector for delegated DNS or DANE failures."
    }

    private fun suggestedFix(
        name: String,
        status: String,
        hasNs: Boolean,
        hasAddress: Boolean,
        hasDs: Boolean,
    ): String = when {
        status == "unavailable" ->
            "Run sync until the app has the current header tip, then open this wizard again."
        status == "not_found" ->
            "Register or renew $name, then publish an HNS resource."
        !hasNs && !hasAddress ->
            "Add either:\n\nSYNTH4 203.0.113.10\n\nor:\n\nNS ns1.$name.\nGLUE4 ns1.$name. 203.0.113.10"
        hasNs && !hasAddress ->
            "If ns1.$name is in-bailiwick, add GLUE4/GLUE6. Then configure authoritative DNS to answer:\n\n$name. A 203.0.113.20\nwww.$name. A 203.0.113.20"
        !hasDs ->
            "For strict HNS+DANE, add DS in HNS, DNSKEY/RRSIG in your authoritative zone, and TLSA for _443._tcp.$name."
        else ->
            "Verify your webserver answers on the published A/AAAA target, then use Resolver Trace for transport-level failures."
    }

    private fun normalizeHost(value: String): String =
        value
            .trim()
            .substringAfter("://", value.trim())
            .substringBefore("/")
            .substringBefore("?")
            .substringBefore("#")
            .substringBefore(":")
            .trimEnd('.')
            .lowercase()

    private fun hasRecordType(recordTypes: JSONArray?, expected: String): Boolean =
        recordTypes != null && (0 until recordTypes.length()).any { index ->
            recordTypes.optString(index).equals(expected, ignoreCase = true)
        }

    private fun arrayText(array: JSONArray?): String =
        if (array == null || array.length() == 0) {
            "none"
        } else {
            (0 until array.length()).joinToString(", ") { index -> array.optString(index) }
        }

    private fun recordsText(records: JSONArray?): String =
        if (records == null || records.length() == 0) {
            "none"
        } else {
            (0 until records.length()).joinToString("\n") { index ->
                val record = records.optJSONObject(index)
                "- ${record?.optString("type", "unknown") ?: "unknown"} " +
                    "${record?.optString("name", "unknown") ?: "unknown"} " +
                    "rdata=${record?.optString("rdataHex", "unknown") ?: "unknown"}"
            }
        }

    private fun copy(value: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText("HNS domain wizard report", value))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }
}
