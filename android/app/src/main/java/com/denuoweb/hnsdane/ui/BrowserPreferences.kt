package com.denuoweb.hnsdane.ui

import android.content.Context
import com.denuoweb.hnsdane.core.BrowserTargetKind
import com.denuoweb.hnsdane.core.BrowserUrlClassifier
import java.util.Locale

internal object BrowserPreferences {
    const val DEFAULT_HOME = "https://denuoweb/homepage"

    private const val PREFS = "browser_preferences"
    private const val KEY_HOMEPAGE = "homepage_url"

    fun homepage(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_HOMEPAGE, DEFAULT_HOME)
            ?.ifBlank { DEFAULT_HOME }
            ?: DEFAULT_HOME

    fun setHomepage(context: Context, input: String): String? {
        val normalized = normalizeHomepage(input) ?: return null
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

    fun normalizeHomepage(input: String): String? {
        val trimmed = input.trim()
        if (trimmed.isBlank()) {
            return null
        }

        val lower = trimmed.lowercase(Locale.US)
        if (lower.startsWith("https://") || lower.startsWith("http://")) {
            return trimmed
        }

        if ("://" in trimmed) {
            return null
        }

        val target = BrowserUrlClassifier().classify(trimmed)
        return target.url.takeUnless { target.kind == BrowserTargetKind.Search }
    }
}
