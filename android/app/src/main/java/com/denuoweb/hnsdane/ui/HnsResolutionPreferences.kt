package com.denuoweb.hnsdane.ui

import android.content.Context
import androidx.annotation.StringRes
import com.denuoweb.hnsdane.R
import java.net.URI
import java.util.Locale

enum class HandshakeNetwork(
    val id: String,
    @param:StringRes private val displayNameRes: Int,
    @param:StringRes private val summaryRes: Int,
) {
    Mainnet(
        id = "mainnet",
        displayNameRes = R.string.handshake_network_mainnet,
        summaryRes = R.string.handshake_network_mainnet_summary,
    ),
    Testnet(
        id = "testnet",
        displayNameRes = R.string.handshake_network_testnet,
        summaryRes = R.string.handshake_network_testnet_summary,
    ),
    Regtest(
        id = "regtest",
        displayNameRes = R.string.handshake_network_regtest,
        summaryRes = R.string.handshake_network_regtest_summary,
    );

    fun displayName(context: Context): String =
        context.getString(displayNameRes)

    fun summary(context: Context): String =
        context.getString(summaryRes)

    companion object {
        fun fromId(id: String?): HandshakeNetwork =
            entries.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: Mainnet
    }
}

internal object HnsResolutionPreferences {
    const val DEFAULT_DOH_RESOLVER_URL = "https://hnsdoh.com/dns-query"

    private const val PREFS = "hns_resolution_preferences"
    private const val KEY_HANDSHAKE_NETWORK = "handshake_network"
    private const val KEY_STRICT_HNS_MODE = "strict_hns_mode"
    private const val KEY_DOH_RESOLVER_URL = "doh_resolver_url"
    private const val KEY_STATELESS_DANE_CERTIFICATES = "stateless_dane_certificates"

    fun handshakeNetwork(context: Context): HandshakeNetwork =
        HandshakeNetwork.fromId(
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_HANDSHAKE_NETWORK, HandshakeNetwork.Mainnet.id),
        )

    fun handshakeNetworkId(context: Context): String =
        handshakeNetwork(context).id

    fun setHandshakeNetwork(context: Context, network: HandshakeNetwork) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_HANDSHAKE_NETWORK, network.id)
            .apply()
    }

    fun strictHnsMode(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_STRICT_HNS_MODE, false)

    fun setStrictHnsMode(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_STRICT_HNS_MODE, enabled)
            .apply()
    }

    fun statelessDaneCertificates(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_STATELESS_DANE_CERTIFICATES, false)

    fun setStatelessDaneCertificates(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_STATELESS_DANE_CERTIFICATES, enabled)
            .apply()
    }

    fun dohResolverUrl(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_DOH_RESOLVER_URL, DEFAULT_DOH_RESOLVER_URL)
            ?.let(::normalizeDohResolverUrl)
            ?: DEFAULT_DOH_RESOLVER_URL

    fun setDohResolverUrl(context: Context, input: String): String? {
        val normalized = normalizeDohResolverUrl(input) ?: return null
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_DOH_RESOLVER_URL, normalized)
            .apply()
        return normalized
    }

    fun resetDohResolverUrl(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_DOH_RESOLVER_URL)
            .apply()
    }

    fun normalizeDohResolverUrl(input: String): String? {
        val trimmed = input.trim()
        if (trimmed.isBlank()) {
            return DEFAULT_DOH_RESOLVER_URL
        }
        if (trimmed.length > MAX_DOH_URL_CHARS) {
            return null
        }
        val uri = runCatching { URI(trimmed) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            uri.host.isNullOrBlank() ||
            uri.host.contains(':') ||
            uri.userInfo != null ||
            uri.fragment != null
        ) {
            return null
        }
        val explicitPort = uri.port
        if (explicitPort != -1 && (explicitPort !in 1..65535 || isBrowserUnsafePort(explicitPort))) {
            return null
        }
        val path = uri.rawPath?.takeIf { it.isNotBlank() } ?: "/dns-query"
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        val port = if (explicitPort != -1 && explicitPort != 443) ":$explicitPort" else ""
        return "https://${uri.host.lowercase(Locale.US)}$port$path$query"
    }

    private fun isBrowserUnsafePort(port: Int): Boolean =
        port in BROWSER_UNSAFE_PORTS || port in 6665..6669

    private val BROWSER_UNSAFE_PORTS = setOf(
        1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
        87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139,
        143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548,
        554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659,
        4045, 4190, 5060, 5061, 6000, 6566, 6679, 6697, 10080,
    )

    private const val MAX_DOH_URL_CHARS = 4 * 1024
}
