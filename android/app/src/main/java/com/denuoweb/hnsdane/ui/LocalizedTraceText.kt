package com.denuoweb.hnsdane.ui

import android.content.Context
import com.denuoweb.hnsdane.R
import com.denuoweb.hnsdane.core.HnsHostPolicy
import org.json.JSONArray
import org.json.JSONObject

internal object LocalizedTraceText {
    fun valueOrUnknown(context: Context, value: String?): String =
        value
            ?.takeIf { it.isNotBlank() && it != "null" }
            ?: context.getString(R.string.common_unknown)

    fun valueOrNone(context: Context, value: String?): String =
        value
            ?.takeIf { it.isNotBlank() && it != "null" }
            ?: context.getString(R.string.common_none)

    fun yesNo(context: Context, value: Boolean): String =
        context.getString(if (value) R.string.common_yes else R.string.common_no)

    fun nullableValue(context: Context, json: JSONObject, key: String): String =
        if (!json.has(key) || json.isNull(key)) {
            context.getString(R.string.common_unknown)
        } else {
            json.opt(key)?.toString() ?: context.getString(R.string.common_unknown)
        }

    fun jsonArrayText(context: Context, array: JSONArray?): String =
        array?.join(", ") ?: context.getString(R.string.common_unknown)

    fun namespace(context: Context, trace: JSONObject?): String =
        when (fieldText(trace, "nameClass", "")) {
            "icann" -> context.getString(R.string.trace_namespace_icann_dns)
            "hns" -> context.getString(R.string.trace_namespace_handshake)
            "search" -> context.getString(R.string.trace_namespace_search)
            else -> context.getString(R.string.common_unknown)
        }

    fun resolutionSource(context: Context, trace: JSONObject?): String =
        when (val source = fieldText(trace, "resolutionSource", "")) {
            "trusted_icann_doh" -> context.getString(R.string.trace_source_trusted_icann_doh)
            "icann_dns" -> context.getString(R.string.trace_source_icann_dns)
            "authoritative_dns" -> context.getString(R.string.trace_source_authoritative_dns)
            "authoritative_doh" -> context.getString(R.string.trace_source_authoritative_doh)
            "hns_doh" -> context.getString(R.string.trace_source_hns_doh)
            "hns_resource" -> context.getString(R.string.trace_source_hns_resource)
            "" -> context.getString(R.string.common_unknown)
            else -> source.replace('_', ' ')
        }

    fun attemptProtocolLabel(context: Context, protocol: String): String =
        when (protocol) {
            "udp53" -> context.getString(R.string.trace_protocol_authoritative_udp53)
            "tcp53" -> context.getString(R.string.trace_protocol_authoritative_tcp53)
            "authoritative_doh" -> context.getString(R.string.trace_protocol_authoritative_doh)
            "dns_interception_probe" -> context.getString(R.string.trace_protocol_dns_interception_probe)
            "hns_doh" -> context.getString(R.string.trace_protocol_hns_doh)
            "icann_doh" -> context.getString(R.string.trace_protocol_icann_doh)
            else -> protocol
        }

    fun tlsMode(context: Context, tls: JSONObject?): String =
        statusValue(context, fieldText(tls, "mode", "not_evaluated"))

    fun dnssecSecure(context: Context, tls: JSONObject?): String =
        statusValue(context, fieldText(tls, "dnssecSecure", "not_evaluated"))

    fun daneDecision(context: Context, tls: JSONObject?): String {
        val dane = tls?.optJSONObject("dane")
        return statusValue(context, fieldText(dane, "decision", "not_evaluated"))
    }

    fun tlsaFound(context: Context, tls: JSONObject?): String =
        when (tlsaStatusCode(tls)) {
            "present" -> context.getString(R.string.common_yes)
            "absent" -> context.getString(R.string.common_no)
            "not_evaluated" -> blockedText(context, tls)
            else -> yesNo(context, tls?.optBoolean("tlsaFound", false) == true)
        }

    fun tlsaStatus(context: Context, tls: JSONObject?): String =
        when (tlsaStatusCode(tls)) {
            "present" -> context.getString(R.string.trace_tlsa_present)
            "absent" -> context.getString(R.string.trace_tlsa_absent)
            "not_evaluated" -> blockedText(context, tls)
            else -> context.getString(R.string.common_unknown)
        }

    fun tlsaSource(context: Context, tls: JSONObject?): String =
        when (val source = fieldText(tls, "tlsaSource", "")) {
            "native_tlsa" -> context.getString(R.string.trace_tlsa_native)
            "" -> context.getString(R.string.common_none)
            else -> source.replace('_', ' ')
        }

    fun tlsaBlockedBy(tls: JSONObject?): String? =
        fieldText(tls, "tlsaBlockedBy", "")
            .takeIf { it.isNotBlank() && it != "none" }

    fun blockedReasonLabel(context: Context, reason: String): String =
        when (reason) {
            "local_hns_proof_unavailable" -> context.getString(R.string.trace_block_local_hns_proof_unavailable)
            "local_chain_not_current" -> context.getString(R.string.trace_block_local_chain_not_current)
            "no_verified_nameserver_address" -> context.getString(R.string.trace_block_no_verified_nameserver_address)
            "authoritative_nameserver_transport_failed" ->
                context.getString(R.string.trace_block_authoritative_nameserver_transport_failed)
            "authoritative_nameserver_invalid_response" ->
                context.getString(R.string.trace_block_authoritative_nameserver_invalid_response)
            "delegated_dnssec_validation_failed" ->
                context.getString(R.string.trace_block_delegated_dnssec_validation_failed)
            "hns_resource_invalid" -> context.getString(R.string.trace_block_hns_resource_invalid)
            "hns_authoritative_doh_invalid" -> context.getString(R.string.trace_block_hns_authoritative_doh_invalid)
            "hns_proof_validation_failed" -> context.getString(R.string.trace_block_hns_proof_validation_failed)
            "insecure_resolution" -> context.getString(R.string.trace_block_insecure_resolution)
            "origin_address_missing" -> context.getString(R.string.trace_block_origin_address_missing)
            "https_service_unsupported" -> context.getString(R.string.trace_block_https_service_unsupported)
            "hns_request_mismatch" -> context.getString(R.string.trace_block_hns_request_mismatch)
            "transport_unsupported" -> context.getString(R.string.trace_block_transport_unsupported)
            "scheme_unsupported" -> context.getString(R.string.trace_block_scheme_unsupported)
            "origin_certificate_expired" -> context.getString(R.string.trace_block_origin_certificate_expired)
            "origin_certificate_invalid" -> context.getString(R.string.trace_block_origin_certificate_invalid)
            "tls_failed" -> context.getString(R.string.trace_block_tls_failed)
            "origin_transport_failed" -> context.getString(R.string.trace_block_origin_transport_failed)
            "http3_failed" -> context.getString(R.string.trace_block_http3_failed)
            "quic_failed" -> context.getString(R.string.trace_block_quic_failed)
            "dane_validation_failed" -> context.getString(R.string.trace_block_dane_validation_failed)
            else -> reason.replace('_', ' ')
        }

    fun proofTabTitle(context: Context, traceJson: String): String =
        if (HnsResolutionTraceFormat.isIcann(HnsResolutionTraceFormat.parse(traceJson))) {
            context.getString(R.string.diagnostic_tab_dnssec)
        } else {
            context.getString(R.string.diagnostic_tab_hns_proof)
        }

    fun isIcann(trace: JSONObject?): Boolean {
        if (trace == null) {
            return false
        }
        if (fieldText(trace, "nameClass", "") == "icann") {
            return true
        }
        return HnsHostPolicy.isIcannDaneTestHost(fieldText(trace, "host", ""))
    }

    private fun statusValue(context: Context, value: String): String =
        when (value) {
            "not_evaluated" -> context.getString(R.string.common_not_evaluated)
            "present" -> context.getString(R.string.trace_tlsa_present)
            "absent" -> context.getString(R.string.trace_tlsa_absent)
            "yes" -> context.getString(R.string.common_yes)
            "no" -> context.getString(R.string.common_no)
            "none" -> context.getString(R.string.common_none)
            "unknown" -> context.getString(R.string.common_unknown)
            "verified" -> context.getString(R.string.trace_dane_verified)
            "no_tlsa" -> context.getString(R.string.trace_dane_no_tlsa)
            else -> value.replace('_', ' ')
        }

    private fun tlsaStatusCode(tls: JSONObject?): String =
        fieldText(tls, "tlsaStatus", "")
            .takeIf { it.isNotBlank() }
            ?: when {
                tls == null -> ""
                tls.optBoolean("tlsaFound", false) -> "present"
                else -> ""
            }

    private fun blockedText(context: Context, tls: JSONObject?): String {
        val blockedBy = tlsaBlockedBy(tls)
        return if (blockedBy == null) {
            context.getString(R.string.common_not_evaluated)
        } else {
            context.getString(R.string.common_not_evaluated_reason, blockedReasonLabel(context, blockedBy))
        }
    }

    private fun fieldText(json: JSONObject?, key: String, fallback: String): String {
        if (json == null || !json.has(key) || json.isNull(key)) {
            return fallback
        }
        val value = json.opt(key) ?: return fallback
        return value.toString().takeIf { it.isNotBlank() && it != "null" } ?: fallback
    }
}
