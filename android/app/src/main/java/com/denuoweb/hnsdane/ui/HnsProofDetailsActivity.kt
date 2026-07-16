package com.denuoweb.hnsdane.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.denuoweb.hnsdane.R
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
        val isIcann =
            HnsResolutionTraceFormat.isIcann(trace) || HnsHostPolicy.isNativeGatewayHost(host, NativeBridge)
        val detailsJson = if (host.isBlank()) {
            """{"host":"","name":null,"nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"invalid_input","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"no_hns_host_available"}"""
        } else if (isIcann) {
            icannDetailsJson(host, trace)
        } else {
            NativeBridge.hnsProofDetails(
                filesDir.absolutePath,
                host,
                HnsResolutionPreferences.handshakeNetworkId(this),
            )
        }

        setSecondaryScreen(
            title = if (isIcann) getString(R.string.screen_dnssec_details) else getString(R.string.screen_hns_proof_details),
            onSwipeLeft = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.ProofDetails, forward = true, url, traceJson)
            },
            onSwipeRight = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.ProofDetails, forward = false, url, traceJson)
            },
        ) {
            addView(hnsDiagnosticTabs(HnsDiagnosticTool.ProofDetails, url, traceJson))
            addView(screenSection(getString(R.string.section_summary)) {
                addView(fieldReportText(friendlySummary(detailsJson)))
            })
            addView(screenSection(getString(R.string.section_export)) {
                addScreenRow(preferenceRow(
                    title = getString(R.string.row_copy_json),
                    summary = getString(R.string.export_validation_details_json_summary),
                    actionLabel = getString(R.string.action_copy),
                ) {
                    copy(
                        if (isIcann) {
                            getString(R.string.copy_label_dnssec_json)
                        } else {
                            getString(R.string.copy_label_hns_proof_json)
                        },
                        detailsJson,
                    )
                })
                addScreenRow(preferenceRow(
                    title = getString(R.string.row_copy_markdown),
                    summary = getString(R.string.row_copy_markdown_summary),
                    actionLabel = getString(R.string.action_copy),
                ) {
                    copy(
                        if (isIcann) {
                            getString(R.string.copy_label_dnssec_markdown)
                        } else {
                            getString(R.string.copy_label_hns_proof_markdown)
                        },
                        markdownReport(detailsJson),
                    )
                })
            })
            addView(screenSection(getString(R.string.section_raw_export)) {
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
            ?: return getString(R.string.trace_no_validation_details)
        if (details.optString("nameClass") == "icann") {
            return icannFriendlySummary(details)
        }
        val currentTip = details.optJSONObject("currentTip")
        val resourceValueHex = details.optString("resourceValueHex")
        return buildString {
            appendLine(getString(R.string.trace_field_host, details.optString("host", getString(R.string.common_unknown))))
            appendLine(getString(R.string.proof_field_name, details.optString("name", getString(R.string.common_unknown))))
            appendLine(getString(R.string.proof_field_name_hash, details.optString("nameHash", getString(R.string.common_unknown))))
            appendLine(getString(R.string.proof_field_tree_root, details.optString("treeRoot", getString(R.string.common_none))))
            appendLine(getString(R.string.proof_field_block_height, details.optString("blockHeight", getString(R.string.common_none))))
            appendLine(getString(R.string.wizard_field_proof_status, details.optString("proofStatus", getString(R.string.common_unknown))))
            appendLine(getString(R.string.wizard_field_cache_status, details.optString("cacheStatus", getString(R.string.common_unknown))))
            appendLine(getString(R.string.proof_field_current_tip, currentTipText(currentTip)))
            appendLine(getString(R.string.proof_field_secure, details.optString("secure", getString(R.string.common_unknown))))
            appendLine(getString(R.string.proof_field_exists, details.optString("exists", getString(R.string.common_unknown))))
            appendLine(getString(R.string.proof_field_record_types, arrayText(details.optJSONArray("recordTypes"))))
            appendLine(getString(R.string.proof_field_resource_value, resourceValueHex.ifBlank { getString(R.string.common_none) }))
            appendLine(getString(R.string.proof_field_error, LocalizedTraceText.valueOrNone(this@HnsProofDetailsActivity, details.optString("error"))))
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
            appendLine(getString(R.string.trace_field_host, details.optString("host", getString(R.string.common_unknown))))
            appendLine(getString(R.string.trace_field_namespace, getString(R.string.trace_namespace_icann_dns)))
            appendLine(getString(R.string.trace_field_hns_proof, getString(R.string.proof_not_applicable)))
            appendLine(getString(R.string.trace_field_dnssec, details.optString("dnssec", getString(R.string.common_unknown))))
            appendLine(getString(R.string.trace_field_resolution_source, LocalizedTraceText.resolutionSource(this@HnsProofDetailsActivity, details)))
            appendLine(getString(R.string.proof_field_record_types, arrayText(details.optJSONArray("resourceRecords"))))
            appendLine(getString(R.string.proof_field_error, LocalizedTraceText.valueOrNone(this@HnsProofDetailsActivity, details.optString("error"))))
        }

    private fun currentTipText(currentTip: JSONObject?): String =
        if (currentTip == null) {
            getString(R.string.common_unknown)
        } else {
            getString(
                R.string.proof_current_tip_text,
                currentTip.optString("height", getString(R.string.common_unknown)),
                currentTip.optString("treeRoot", getString(R.string.common_unknown)),
            )
        }

    private fun arrayText(array: JSONArray?): String =
        if (array == null || array.length() == 0) {
            getString(R.string.common_none)
        } else {
            (0 until array.length()).joinToString(", ") { index -> array.optString(index) }
        }

    private fun markdownReport(detailsJson: String): String {
        val details = parsedDetails(detailsJson)
        val isIcann = details?.optString("nameClass") == "icann"
        return buildString {
            appendLine(
                if (isIcann) {
                    getString(R.string.proof_markdown_dnssec_title)
                } else {
                    getString(R.string.proof_markdown_hns_title)
                },
            )
            appendLine()
            appendLine(getString(R.string.trace_field_host, details?.optString("host", getString(R.string.common_unknown)) ?: getString(R.string.common_unknown)))
            if (isIcann) {
                appendLine(getString(R.string.trace_field_namespace, getString(R.string.trace_namespace_icann_dns)))
                appendLine(getString(R.string.trace_field_dnssec, details?.optString("dnssec", getString(R.string.common_unknown)) ?: getString(R.string.common_unknown)))
            } else {
                appendLine(getString(R.string.proof_field_name, details?.optString("name", getString(R.string.common_unknown)) ?: getString(R.string.common_unknown)))
                appendLine(getString(R.string.wizard_field_proof_status, details?.optString("proofStatus", getString(R.string.common_unknown)) ?: getString(R.string.common_unknown)))
                appendLine(getString(R.string.wizard_field_cache_status, details?.optString("cacheStatus", getString(R.string.common_unknown)) ?: getString(R.string.common_unknown)))
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
        Toast.makeText(this, getString(R.string.common_copied), Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_URL = "com.denuoweb.hnsdane.HNS_PROOF_URL"
        const val EXTRA_TRACE_JSON = "com.denuoweb.hnsdane.HNS_PROOF_TRACE_JSON"
    }
}
