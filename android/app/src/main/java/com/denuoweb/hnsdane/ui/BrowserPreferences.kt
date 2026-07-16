package com.denuoweb.hnsdane.ui

import android.content.Context
import com.denuoweb.hnsdane.core.BrowserNamespacePolicy
import com.denuoweb.hnsdane.core.BrowserTargetKind
import com.denuoweb.hnsdane.core.BrowserUrlClassifier
import java.util.Locale

internal object BrowserPreferences {
    const val DEFAULT_HOME = "https://appassets.androidplatform.net/assets/start.html"

    private const val PREFS = "browser_preferences"
    private const val KEY_HOMEPAGE = "homepage_url"

    fun homepage(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_HOMEPAGE, DEFAULT_HOME)
            ?.ifBlank { DEFAULT_HOME }
            ?: DEFAULT_HOME

    fun setHomepage(
        context: Context,
        input: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): String? {
        val normalized = normalizeHomepage(input, namespacePolicy) ?: return null
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_HOMEPAGE, normalized)
            .apply()
        return normalized
    }

    fun resetHomepage(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_HOMEPAGE)
            .apply()
    }

    fun normalizeHomepage(
        input: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): String? {
        val trimmed = input.trim()
        if (trimmed.isBlank() || trimmed.length > MAX_HOMEPAGE_CHARS) {
            return null
        }

        val lower = trimmed.lowercase(Locale.US)
        if (lower.startsWith("https://") || lower.startsWith("http://")) {
            return trimmed
        }

        if ("://" in trimmed) {
            return null
        }

        val target = BrowserUrlClassifier(namespacePolicy).classify(trimmed)
        return target.url.takeUnless {
            target.kind == BrowserTargetKind.Search || target.kind == BrowserTargetKind.Blocked
        }
    }

    private const val MAX_HOMEPAGE_CHARS = 16 * 1024
}
