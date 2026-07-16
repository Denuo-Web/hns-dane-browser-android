package com.denuoweb.hnsdane.ui

import com.denuoweb.hnsdane.core.HnsHostPolicy
import com.denuoweb.hnsdane.net.NativeBridge
import org.json.JSONObject

internal object HnsResolutionTraceFormat {
    fun isIcann(trace: JSONObject?): Boolean {
        if (trace == null) {
            return false
        }
        if (fieldText(trace, "nameClass", "") == "icann") {
            return true
        }
        return HnsHostPolicy.isNativeGatewayHost(fieldText(trace, "host", ""), NativeBridge)
    }

    fun namespace(trace: JSONObject?): String =
        when (fieldText(trace, "nameClass", "")) {
            "icann" -> "ICANN DNS"
            "hns" -> "Handshake"
            "search" -> "search"
            else -> "unknown"
        }

    fun resolutionSource(trace: JSONObject?): String =
        when (val source = fieldText(trace, "resolutionSource", "")) {
            "trusted_icann_doh" -> "trusted ICANN DoH"
            "icann_dns" -> "ICANN DNS"
            "authoritative_dns" -> "authoritative DNS"
            "authoritative_doh" -> "authoritative DoH"
            "hns_doh" -> "third-party HNS DoH"
            "hns_resource" -> "HNS resource"
            "" -> "unknown"
            else -> source.replace('_', ' ')
        }

    fun proofTabTitle(traceJson: String): String =
        if (isIcann(parse(traceJson))) {
            "DNSSEC"
        } else {
            "HNS proof"
        }

    fun parse(traceJson: String): JSONObject? =
        runCatching { JSONObject(traceJson) }.getOrNull()

    private fun fieldText(json: JSONObject?, key: String, fallback: String): String {
        if (json == null || !json.has(key) || json.isNull(key)) {
            return fallback
        }
        val value = json.opt(key) ?: return fallback
        return value.toString().takeIf { it.isNotBlank() && it != "null" } ?: fallback
    }
}

internal object HnsTlsaTraceFormat {
    fun tlsMode(tls: JSONObject?): String =
        fieldText(tls, "mode", "not evaluated")

    fun dnssecSecure(tls: JSONObject?): String =
        fieldText(tls, "dnssecSecure", "not evaluated")

    fun daneDecision(tls: JSONObject?): String {
        val dane = tls?.optJSONObject("dane")
        return fieldText(dane, "decision", "not_evaluated")
    }

    fun tlsaFound(tls: JSONObject?): String =
        when (tlsaStatusCode(tls)) {
            "present" -> "yes"
            "absent" -> "no"
            "not_evaluated" -> blockedText(tls)
            else -> {
                if (tls?.optBoolean("tlsaFound", false) == true) {
                    "yes"
                } else {
                    "no"
                }
            }
        }

    fun tlsaStatus(tls: JSONObject?): String =
        when (tlsaStatusCode(tls)) {
            "present" -> "present"
            "absent" -> "absent"
            "not_evaluated" -> blockedText(tls)
            else -> "unknown"
        }

    fun tlsaSource(tls: JSONObject?): String =
        when (val source = fieldText(tls, "tlsaSource", "")) {
            "native_tlsa" -> "native TLSA"
            "" -> "none"
            else -> source.replace('_', ' ')
        }

    fun tlsaBlockedBy(tls: JSONObject?): String? =
        fieldText(tls, "tlsaBlockedBy", "")
            .takeIf { it.isNotBlank() && it != "none" }

    private fun tlsaStatusCode(tls: JSONObject?): String =
        fieldText(tls, "tlsaStatus", "")
            .takeIf { it.isNotBlank() }
            ?: when {
                tls == null -> ""
                tls.optBoolean("tlsaFound", false) -> "present"
                else -> ""
            }

    private fun blockedText(tls: JSONObject?): String {
        val blockedBy = tlsaBlockedBy(tls)
        return if (blockedBy == null) {
            "not evaluated"
        } else {
            "not evaluated (${blockedReasonLabel(blockedBy)})"
        }
    }

    private fun blockedReasonLabel(reason: String): String =
        when (reason) {
            "local_hns_proof_unavailable" -> "local HNS proof unavailable"
            "local_chain_not_current" -> "local chain not current"
            "no_verified_nameserver_address" -> "no verified nameserver address"
            "authoritative_nameserver_transport_failed" -> "authoritative nameserver transport failed"
            "authoritative_nameserver_invalid_response" -> "authoritative nameserver invalid response"
            "delegated_dnssec_validation_failed" -> "delegated DNSSEC validation failed"
            "hns_resource_invalid" -> "HNS resource invalid"
            "hns_authoritative_doh_invalid" -> "HNS authoritative DoH invalid"
            "hns_proof_validation_failed" -> "HNS proof validation failed"
            "insecure_resolution" -> "insecure resolver result"
            "origin_address_missing" -> "origin address missing"
            "https_service_unsupported" -> "HTTPS service unsupported"
            "hns_request_mismatch" -> "HNS request mismatch"
            "transport_unsupported" -> "transport unsupported"
            "scheme_unsupported" -> "scheme unsupported"
            "origin_certificate_expired" -> "origin certificate expired"
            "origin_certificate_invalid" -> "origin certificate invalid"
            "tls_failed" -> "TLS failed"
            "origin_transport_failed" -> "origin transport failed"
            "http3_failed" -> "HTTP/3 failed"
            "quic_failed" -> "QUIC failed"
            "dane_validation_failed" -> "DANE validation failed"
            else -> reason.replace('_', ' ')
        }

    private fun fieldText(json: JSONObject?, key: String, fallback: String): String {
        if (json == null || !json.has(key) || json.isNull(key)) {
            return fallback
        }
        val value = json.opt(key) ?: return fallback
        return value.toString().takeIf { it.isNotBlank() && it != "null" } ?: fallback
    }
}
