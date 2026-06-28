package com.handshake.browser.ui

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

internal data class BrowserHistoryEntry(
    val url: String,
    val title: String,
    val visitedAtMillis: Long,
)

internal object BrowserHistoryStore {
    private const val PREFS = "browser_history"
    private const val KEY_ENTRIES = "entries_json"
    private const val MAX_ENTRIES = 250

    @Synchronized
    fun entries(context: Context): List<BrowserHistoryEntry> =
        parseEntries(
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_ENTRIES, null),
        )

    @Synchronized
    fun record(
        context: Context,
        url: String,
        title: String?,
        visitedAtMillis: Long = System.currentTimeMillis(),
    ) {
        val normalizedUrl = url.trim()
        if (shouldSkip(normalizedUrl)) {
            return
        }

        val normalizedTitle = title
            ?.trim()
            ?.takeUnless { it.equals(normalizedUrl, ignoreCase = true) }
            .orEmpty()

        val updated = listOf(
            BrowserHistoryEntry(
                url = normalizedUrl,
                title = normalizedTitle,
                visitedAtMillis = visitedAtMillis,
            ),
        ) + entries(context).filterNot { it.url == normalizedUrl }

        save(context, updated.take(MAX_ENTRIES))
    }

    @Synchronized
    fun clear(context: Context): Int {
        val count = entries(context).size
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_ENTRIES)
            .apply()
        return count
    }

    private fun shouldSkip(url: String): Boolean {
        val lower = url.lowercase()
        return url.isBlank() ||
            lower == "about:blank" ||
            lower.startsWith("data:") ||
            lower.startsWith("blob:")
    }

    private fun parseEntries(json: String?): List<BrowserHistoryEntry> {
        if (json.isNullOrBlank()) {
            return emptyList()
        }

        val array = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val url = item.optString("url").trim()
            if (url.isBlank()) {
                null
            } else {
                BrowserHistoryEntry(
                    url = url,
                    title = item.optString("title").trim(),
                    visitedAtMillis = item.optLong("visitedAtMillis", 0L),
                )
            }
        }
    }

    private fun save(context: Context, entries: List<BrowserHistoryEntry>) {
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(
                JSONObject()
                    .put("url", entry.url)
                    .put("title", entry.title)
                    .put("visitedAtMillis", entry.visitedAtMillis),
            )
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_ENTRIES, array.toString())
            .apply()
    }
}
