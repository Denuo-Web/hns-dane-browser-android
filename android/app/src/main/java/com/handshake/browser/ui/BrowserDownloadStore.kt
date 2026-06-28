package com.handshake.browser.ui

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

internal data class BrowserDownloadRecord(
    val downloadId: Long,
    val url: String,
    val fileName: String,
    val mimeType: String,
    val queuedAtMillis: Long,
)

internal object BrowserDownloadStore {
    private const val PREFS = "browser_downloads"
    private const val KEY_RECORDS = "records_json"
    private const val MAX_RECORDS = 100

    @Synchronized
    fun records(context: Context): List<BrowserDownloadRecord> =
        parseRecords(
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(KEY_RECORDS, null),
        )

    @Synchronized
    fun record(
        context: Context,
        downloadId: Long,
        url: String,
        fileName: String,
        mimeType: String?,
        queuedAtMillis: Long = System.currentTimeMillis(),
    ) {
        val updated = listOf(
            BrowserDownloadRecord(
                downloadId = downloadId,
                url = url,
                fileName = fileName,
                mimeType = mimeType.orEmpty(),
                queuedAtMillis = queuedAtMillis,
            ),
        ) + records(context).filterNot { it.downloadId == downloadId }

        save(context, updated.take(MAX_RECORDS))
    }

    @Synchronized
    fun clear(context: Context): Int {
        val count = records(context).size
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_RECORDS)
            .apply()
        return count
    }

    private fun parseRecords(json: String?): List<BrowserDownloadRecord> {
        if (json.isNullOrBlank()) {
            return emptyList()
        }

        val array = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val downloadId = item.optLong("downloadId", -1L)
            val url = item.optString("url").trim()
            val fileName = item.optString("fileName").trim()
            if (downloadId < 0L || url.isBlank()) {
                null
            } else {
                BrowserDownloadRecord(
                    downloadId = downloadId,
                    url = url,
                    fileName = fileName.ifBlank { "download" },
                    mimeType = item.optString("mimeType").trim(),
                    queuedAtMillis = item.optLong("queuedAtMillis", 0L),
                )
            }
        }
    }

    private fun save(context: Context, records: List<BrowserDownloadRecord>) {
        val array = JSONArray()
        records.forEach { record ->
            array.put(
                JSONObject()
                    .put("downloadId", record.downloadId)
                    .put("url", record.url)
                    .put("fileName", record.fileName)
                    .put("mimeType", record.mimeType)
                    .put("queuedAtMillis", record.queuedAtMillis),
            )
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_RECORDS, array.toString())
            .apply()
    }
}
