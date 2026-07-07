package com.denuoweb.hnsdane.ui

import android.content.Context
import java.net.URI
import java.util.Locale

internal object HnsResolutionPreferences {
    const val DEFAULT_DOH_RESOLVER_URL = "https://hnsdoh.com/dns-query"

    private const val PREFS = "hns_resolution_preferences"
    private const val KEY_STRICT_HNS_MODE = "strict_hns_mode"
    private const val KEY_DOH_RESOLVER_URL = "doh_resolver_url"
    private const val KEY_STATELESS_DANE_CERTIFICATES = "stateless_dane_certificates"

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
        val uri = runCatching { URI(trimmed) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            uri.host.isNullOrBlank() ||
            uri.userInfo != null ||
            uri.fragment != null
        ) {
            return null
        }
        val path = uri.rawPath?.takeIf { it.isNotBlank() } ?: "/dns-query"
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        val port = if (uri.port >= 0 && uri.port != 443) ":${uri.port}" else ""
        return "https://${uri.host.lowercase(Locale.US)}$port$path$query"
    }
}
