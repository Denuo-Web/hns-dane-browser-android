package com.denuoweb.hnsdane.ui

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class HnsTlsaTraceFormatTest {
    @Test
    fun reportsPresentTlsaAsFound() {
        val tls = JSONObject(
            """{"tlsaEvaluated":true,"tlsaStatus":"present","tlsaBlockedBy":null,"tlsaFound":true,"dnssecSecure":true,"dane":{"decision":"verified"}}""",
        )

        assertEquals("present", HnsTlsaTraceFormat.tlsaStatus(tls))
        assertEquals("yes", HnsTlsaTraceFormat.tlsaFound(tls))
        assertEquals("true", HnsTlsaTraceFormat.dnssecSecure(tls))
        assertEquals("verified", HnsTlsaTraceFormat.daneDecision(tls))
    }

    @Test
    fun reportsAbsentTlsaAsEvaluatedNo() {
        val tls = JSONObject(
            """{"tlsaEvaluated":true,"tlsaStatus":"absent","tlsaBlockedBy":null,"tlsaFound":false,"dnssecSecure":true,"dane":{"decision":"no_tlsa"}}""",
        )

        assertEquals("absent", HnsTlsaTraceFormat.tlsaStatus(tls))
        assertEquals("no", HnsTlsaTraceFormat.tlsaFound(tls))
        assertEquals("none", HnsTlsaTraceFormat.tlsaSource(tls))
        assertEquals("no_tlsa", HnsTlsaTraceFormat.daneDecision(tls))
    }

    @Test
    fun reportsNativeTlsaSource() {
        val tls = JSONObject(
            """{"tlsaEvaluated":true,"tlsaStatus":"present","tlsaSource":"native_tlsa","tlsaFound":true}""",
        )

        assertEquals("native TLSA", HnsTlsaTraceFormat.tlsaSource(tls))
    }

    @Test
    fun reportsIcannResolutionTraceLabels() {
        val trace = JSONObject(
            """{"nameClass":"icann","host":"dane-test.denuoweb.com","resolutionSource":"trusted_icann_doh"}""",
        )

        assertEquals(true, HnsResolutionTraceFormat.isIcann(trace))
        assertEquals("ICANN DNS", HnsResolutionTraceFormat.namespace(trace))
        assertEquals("trusted ICANN DoH", HnsResolutionTraceFormat.resolutionSource(trace))
    }

    @Test
    fun reportsThirdPartyHnsDohResolutionSource() {
        val trace = JSONObject(
            """{"nameClass":"hns","host":"denuoweb","resolutionSource":"hns_doh"}""",
        )

        assertEquals("third-party HNS DoH", HnsResolutionTraceFormat.resolutionSource(trace))
    }

    @Test
    fun reportsDnssecBlockedTlsaAsNotEvaluated() {
        val tls = JSONObject(
            """{"tlsaEvaluated":false,"tlsaStatus":"not_evaluated","tlsaBlockedBy":"delegated_dnssec_validation_failed","tlsaFound":false,"dnssecSecure":null,"dane":{"decision":"not_evaluated"}}""",
        )

        val blocked = "not evaluated (delegated DNSSEC validation failed)"
        assertEquals(blocked, HnsTlsaTraceFormat.tlsaStatus(tls))
        assertEquals(blocked, HnsTlsaTraceFormat.tlsaFound(tls))
        assertEquals("not evaluated", HnsTlsaTraceFormat.dnssecSecure(tls))
        assertEquals("delegated_dnssec_validation_failed", HnsTlsaTraceFormat.tlsaBlockedBy(tls))
    }
}
