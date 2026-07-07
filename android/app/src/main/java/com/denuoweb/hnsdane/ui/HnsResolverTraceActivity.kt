package com.denuoweb.hnsdane.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import org.json.JSONObject

class HnsResolverTraceActivity : ComponentActivity() {
    private val url: String
        get() = intent.getStringExtra(EXTRA_URL).orEmpty()

    private val traceJson: String
        get() = intent.getStringExtra(EXTRA_TRACE_JSON).orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setSecondaryScreen(
            title = "Resolver Trace",
            onSwipeLeft = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.ResolverTrace, forward = true, url, traceJson)
            },
            onSwipeRight = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.ResolverTrace, forward = false, url, traceJson)
            },
        ) {
            addView(hnsDiagnosticTabs(HnsDiagnosticTool.ResolverTrace, url, traceJson))
            addView(screenSection("Summary") {
                addView(fieldReportText(friendlySummary()))
            })
            addView(screenSection("Export") {
                addScreenRow(preferenceRow(
                    title = "Copy JSON",
                    summary = "Copy the raw resolver trace payload.",
                    actionLabel = "Copy",
                ) {
                    copy("resolver trace JSON", rawJson())
                })
                addScreenRow(preferenceRow(
                    title = "Copy Markdown",
                    summary = "Copy a compact Markdown report.",
                    actionLabel = "Copy",
                ) {
                    copy("resolver trace Markdown", markdownReport())
                })
            })
            addView(screenSection("Raw export") {
                addView(reportText(rawJson(), monospace = true))
            })
        }
    }

    private fun friendlySummary(): String {
        val trace = parsedTrace()
            ?: return "No resolver trace is available for the current page yet."
        if (HnsResolutionTraceFormat.isIcann(trace)) {
            return icannSummary(trace)
        }
        val fallback = trace.optJSONObject("fallback")
        val authoritativeDns = trace.optJSONObject("authoritativeDns")
        val tls = trace.optJSONObject("tls")
        return buildString {
            appendLine("URL: ${url.ifBlank { trace.optString("url", "unknown") }}")
            appendLine("Host: ${trace.optString("host", "unknown")}")
            appendLine("Root: ${trace.optString("root", "unknown")}")
            appendLine("Mode: ${trace.optString("mode", "unknown")}")
            appendLine("HNS proof: ${trace.optString("hnsProof", "unknown")}")
            appendLine("Local best height: ${nullableTraceValue(trace, "localBestHeight")}")
            appendLine("Target height: ${nullableTraceValue(trace, "targetHeight")}")
            appendLine("Estimated target height: ${nullableTraceValue(trace, "estimatedTargetHeight")}")
            appendLine("Local chain stale: ${nullableTraceValue(trace, "localChainStale")}")
            appendLine("Delegation: ${if (trace.optBoolean("delegation", false)) "yes" else "no"}")
            appendLine("Resolution source: ${HnsResolutionTraceFormat.resolutionSource(trace)}")
            appendLine("Resource records: ${trace.optJSONArray("resourceRecords")?.join(", ") ?: "unknown"}")
            appendLine("Nameserver candidates: ${trace.optJSONArray("nameserverCandidates")?.join(", ") ?: "unknown"}")
            appendLine("Authoritative UDP 53: ${authoritativeDns?.optString("udp53") ?: "unknown"}")
            appendLine("Authoritative TCP 53: ${authoritativeDns?.optString("tcp53") ?: "unknown"}")
            appendLine("Authoritative DoH: ${authoritativeDns?.optString("doh") ?: "unknown"}")
            appendLine("Resolver attempts: ${dnsAttemptsSummary(trace)}")
            appendLine("DNSSEC: ${trace.optString("dnssec", "unknown")}")
            appendLine("Origin address: ${trace.optString("originAddress", "unknown")}")
            appendLine("TLSA owner: ${tls?.optString("tlsaOwner")?.takeIf { it.isNotBlank() } ?: "none"}")
            appendLine("TLSA status: ${HnsTlsaTraceFormat.tlsaStatus(tls)}")
            appendLine("TLSA source: ${HnsTlsaTraceFormat.tlsaSource(tls)}")
            appendLine("DANE: ${HnsTlsaTraceFormat.daneDecision(tls)}")
            appendLine("DoH fallback: ${if (fallback?.optBoolean("used", false) == true) "yes" else "no"}")
            appendLine("Fallback reason: ${fallback?.optString("reason")?.takeIf { it.isNotBlank() } ?: "none"}")
            appendLine("Final error: ${trace.optString("finalError", "none").takeIf { it != "null" } ?: "none"}")
            appendLine()
            appendLine("Suggested fix:")
            appendLine(suggestedFix(trace))
        }
    }

    private fun icannSummary(trace: JSONObject): String {
        val fallback = trace.optJSONObject("fallback")
        val tls = trace.optJSONObject("tls")
        return buildString {
            appendLine("URL: ${url.ifBlank { trace.optString("url", "unknown") }}")
            appendLine("Host: ${trace.optString("host", "unknown")}")
            appendLine("Namespace: ${HnsResolutionTraceFormat.namespace(trace)}")
            appendLine("Mode: ${trace.optString("mode", "unknown")}")
            appendLine("DNSSEC: ${trace.optString("dnssec", "unknown")}")
            appendLine("Resolution source: ${HnsResolutionTraceFormat.resolutionSource(trace)}")
            appendLine("Resource records: ${trace.optJSONArray("resourceRecords")?.join(", ") ?: "unknown"}")
            appendLine("Resolver attempts: ${dnsAttemptsSummary(trace)}")
            appendLine("Origin address: ${trace.optString("originAddress", "unknown")}")
            appendLine("TLSA owner: ${tls?.optString("tlsaOwner")?.takeIf { it.isNotBlank() } ?: "none"}")
            appendLine("TLSA status: ${HnsTlsaTraceFormat.tlsaStatus(tls)}")
            appendLine("TLSA source: ${HnsTlsaTraceFormat.tlsaSource(tls)}")
            appendLine("DANE: ${HnsTlsaTraceFormat.daneDecision(tls)}")
            appendLine("DoH fallback: ${if (fallback?.optBoolean("used", false) == true) "yes" else "no"}")
            appendLine("Final error: ${trace.optString("finalError", "none").takeIf { it != "null" } ?: "none"}")
            appendLine()
            appendLine("Suggested fix:")
            appendLine(suggestedFix(trace))
        }
    }

    private fun nullableTraceValue(trace: JSONObject, key: String): String =
        if (!trace.has(key) || trace.isNull(key)) {
            "unknown"
        } else {
            trace.opt(key)?.toString() ?: "unknown"
        }

    private fun dnsAttemptsSummary(trace: JSONObject): String {
        val attempts = trace.optJSONArray("dnsAttempts") ?: return "none"
        if (attempts.length() == 0) {
            return "none"
        }
        return (0 until attempts.length()).joinToString(" | ") { index ->
            val attempt = attempts.optJSONObject(index)
            val protocol = attemptProtocolLabel(
                attempt?.optString("protocol")?.takeIf { it.isNotBlank() } ?: "unknown",
            )
            val server = attempt?.optString("server")?.takeIf { it.isNotBlank() } ?: "unknown"
            val status = attempt?.optString("status")?.takeIf { it.isNotBlank() } ?: "unknown"
            val elapsed = attempt
                ?.takeIf { it.has("elapsedMs") }
                ?.optLong("elapsedMs")
                ?.let { "${it}ms" }
                ?: "unknown"
            "$protocol $server $status $elapsed"
        }
    }

    private fun attemptProtocolLabel(protocol: String): String =
        when (protocol) {
            "udp53" -> "Authoritative UDP 53"
            "tcp53" -> "Authoritative TCP 53"
            "authoritative_doh" -> "Authoritative DoH"
            "hns_doh" -> "Compatibility HNS DoH"
            "icann_doh" -> "Trusted ICANN DoH"
            else -> protocol
        }

    private fun suggestedFix(trace: JSONObject): String {
        if (HnsResolutionTraceFormat.isIcann(trace)) {
            return suggestedIcannFix(trace)
        }
        val hnsProof = trace.optString("hnsProof")
        val authoritativeDns = trace.optJSONObject("authoritativeDns")
        val udp53 = authoritativeDns?.optString("udp53").orEmpty()
        val tcp53 = authoritativeDns?.optString("tcp53").orEmpty()
        val doh = authoritativeDns?.optString("doh").orEmpty()
        val dnssec = trace.optString("dnssec")
        val fallback = trace.optJSONObject("fallback")
        val nameserverCandidates = trace.optJSONArray("nameserverCandidates")
        val tls = trace.optJSONObject("tls")
        val tlsaBlockedBy = HnsTlsaTraceFormat.tlsaBlockedBy(tls)
        return when {
            hnsProof == "stale" || trace.optBoolean("localChainStale", false) ->
                "Let HNS sync catch up, then retry. The local proof is valid for its historical block, but not current enough to decide whether the name exists now."
            hnsProof == "unavailable" || hnsProof == "unknown" ->
                "Sync headers/proofs first, then retry. No verified HNS proof was available."
            nameserverCandidates == null || nameserverCandidates.length() == 0 ->
                "Add usable HNS delegation data: NS plus GLUE4/GLUE6 or SYNTH4/SYNTH6. For networks that block port 53, publish an RFC 9461 _dns nameserver SVCB record in the signed zone."
            udp53 in setOf("timeout", "transport_error") &&
                tcp53 in setOf("timeout", "transport_error", "not_attempted") &&
                doh == "ok" ->
                "Direct authoritative DNS on port 53 failed, but the RFC 9461-discovered authoritative DoH endpoint answered and validated. Keep UDP/TCP 53 reachable where possible."
            udp53 in setOf("timeout", "transport_error") && tcp53 in setOf("timeout", "transport_error", "not_attempted") && doh.isBlank() ->
                "Your delegated nameserver candidate did not answer reliably. Ensure authoritative DNS is reachable on UDP/TCP 53 or publish an RFC 9461 _dns SVCB record for an RFC 8484 DoH endpoint in the signed zone."
            udp53 in setOf("timeout", "transport_error") && tcp53 in setOf("timeout", "transport_error", "not_attempted") ->
                "Your delegated nameserver candidate did not answer reliably. Ensure authoritative DNS is reachable on UDP 53 and TCP 53."
            dnssec == "bogus" ->
                "Fix the delegated DNSSEC chain: HNS DS must match child DNSKEY, signatures must be current, and denial data must be valid."
            tlsaBlockedBy in setOf("delegated_dnssec_validation_failed", "insecure_resolution") ->
                "Fix delegated DNSSEC first. TLSA/DANE was not evaluated because secure resolution failed before the TLSA lookup."
            originCertificateExpired(trace, tls) ->
                "Renew the origin HTTPS certificate. The gateway reached an HTTPS origin, but TLS failed because the certificate is past its validity window."
            trace.optString("originAddress") == "missing" ->
                "Serve A/AAAA for the requested host from delegated DNS. HNS GLUE/SYNTH data is only used to reach nameservers, not as the origin address."
            fallback?.optBoolean("used", false) == true ->
                "Compatibility DoH fallback was used. Enable Strict HNS mode to verify whether the site works fully without third-party DoH."
            else ->
                "No obvious fix from this trace. If HTTPS fails, inspect TLSA/DANE once certificate tracing is enabled."
        }
    }

    private fun suggestedIcannFix(trace: JSONObject): String {
        val tls = trace.optJSONObject("tls")
        val tlsaBlockedBy = HnsTlsaTraceFormat.tlsaBlockedBy(tls)
        return when {
            trace.optString("dnssec") == "bogus" ->
                "Fix the ICANN DNSSEC chain: DS, DNSKEY, signatures, and denial records must validate."
            originCertificateExpired(trace, tls) ->
                "Renew the origin HTTPS certificate. TLS failed because the certificate is past its validity window."
            trace.optString("originAddress") == "missing" ->
                "Publish a DNSSEC-validated A or AAAA record for this host."
            tlsaBlockedBy in setOf("delegated_dnssec_validation_failed", "insecure_resolution") ->
                "Fix ICANN DNSSEC first. TLSA/DANE was not evaluated because secure DNS validation failed."
            HnsTlsaTraceFormat.daneDecision(tls) == "verified" ->
                "The ICANN DNSSEC and DANE path is working for this page."
            else ->
                "No obvious fix from this trace. Check TLSA/DANE details if HTTPS validation fails."
        }
    }

    private fun originCertificateExpired(trace: JSONObject, tls: JSONObject?): Boolean {
        if (HnsTlsaTraceFormat.tlsaBlockedBy(tls) == "origin_certificate_expired") {
            return true
        }
        val finalError = trace.optString("finalError", "").lowercase()
        return finalError.contains("certificate expired") ||
            finalError.contains("certificate has expired") ||
            finalError.contains("cert has expired") ||
            finalError.contains("not valid after")
    }

    private fun markdownReport(): String =
        if (HnsResolutionTraceFormat.isIcann(parsedTrace())) {
            "# ICANN DNSSEC Resolution Report\n\n```\n${rawJson()}\n```\n"
        } else {
            "# HNS Resolution Report\n\n```\n${rawJson()}\n```\n"
        }

    private fun rawJson(): String =
        traceJson.ifBlank { """{"error":"no_hns_resolver_trace_available"}""" }

    private fun parsedTrace(): JSONObject? =
        runCatching { JSONObject(traceJson) }.getOrNull()

    private fun copy(label: String, value: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_URL = "com.denuoweb.hnsdane.HNS_TRACE_URL"
        const val EXTRA_TRACE_JSON = "com.denuoweb.hnsdane.HNS_TRACE_JSON"
    }
}
