package com.denuoweb.hnsdane.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class SecurityStatusLabelsTest {
    @Test
    fun explicitSecurityPathLabelsStayUnambiguous() {
        val document = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(locateDefaultStrings())
        val labels = (0 until document.getElementsByTagName("string").length)
            .asSequence()
            .mapNotNull { document.getElementsByTagName("string").item(it) as? Element }
            .associate { it.getAttribute("name") to it.textContent }

        assertEquals(
            mapOf(
                "security_dane_via_authoritative_doh" to "DANE via ADoH",
                "security_dane_via_authoritative_dns53" to "DANE via DNS53",
                "security_dane_via_third_party_doh" to "DANE via 3rd DoH",
                "security_stateless_dane" to "Stateless DANE",
                "security_dane_via_icann_doh" to "DANE via ICANN DoH",
                "security_hns_via_authoritative_doh" to "HNS via ADoH",
                "security_hns_via_authoritative_dns53" to "HNS via DNS53",
                "security_hns_via_third_party_doh" to "HNS via 3rd DoH",
            ),
            labels.filterKeys { it in EXPLICIT_SECURITY_LABELS },
        )
    }

    private fun locateDefaultStrings(): File {
        val workingDir = File(System.getProperty("user.dir") ?: ".")
        return generateSequence(workingDir) { it.parentFile }
            .flatMap { directory ->
                sequenceOf(
                    directory.resolve("src/main/res/values/strings.xml"),
                    directory.resolve("app/src/main/res/values/strings.xml"),
                    directory.resolve("android/app/src/main/res/values/strings.xml"),
                )
            }
            .firstOrNull { it.isFile }
            ?: error("Unable to locate default strings.xml from $workingDir")
    }

    private companion object {
        val EXPLICIT_SECURITY_LABELS = setOf(
            "security_dane_via_authoritative_doh",
            "security_dane_via_authoritative_dns53",
            "security_dane_via_third_party_doh",
            "security_stateless_dane",
            "security_dane_via_icann_doh",
            "security_hns_via_authoritative_doh",
            "security_hns_via_authoritative_dns53",
            "security_hns_via_third_party_doh",
        )
    }
}
