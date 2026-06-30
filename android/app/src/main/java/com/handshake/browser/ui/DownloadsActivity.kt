package com.handshake.browser.ui

import android.app.AlertDialog
import android.app.DownloadManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.text.format.DateFormat
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity

class DownloadsActivity : ComponentActivity() {
    private lateinit var listContainer: LinearLayout
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = preferenceSummary("")
        listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        setSecondaryScreen("Downloads") {
            addView(screenSection("Download records") {
                addScreenRow(preferenceRow(
                    title = "App-queued downloads",
                    summaryView = status,
                ))
                addScreenRow(preferenceRow(
                    title = "Open system downloads",
                    summary = "View downloaded files in Android DownloadManager.",
                    actionLabel = "Open",
                ) {
                    openSystemDownloads()
                })
                addScreenRow(preferenceRow(
                    title = "Clear download records",
                    summary = "Remove this browser's download list. Downloaded files stay on the device.",
                    actionLabel = "Clear",
                    destructive = true,
                ) {
                    confirmClearDownloadRecords()
                })
            })
            addView(screenSection("Recent downloads") {
                addView(listContainer)
            })
        }

        refreshDownloads()
    }

    private fun refreshDownloads() {
        listContainer.removeAllViews()
        val records = BrowserDownloadStore.records(this)
        status.text = if (records.isEmpty()) {
            "No app-queued downloads yet."
        } else {
            "${records.size} app-queued download${if (records.size == 1) "" else "s"}."
        }

        if (records.isEmpty()) {
            listContainer.addScreenRow(preferenceRow(
                title = "No recent downloads",
                summary = "Downloads queued by this browser will appear here.",
            ))
        } else {
            records.forEach { record ->
                listContainer.addScreenRow(downloadRow(record))
            }
        }
    }

    private fun downloadRow(record: BrowserDownloadRecord): LinearLayout =
        preferenceRow(
            title = record.fileName,
            summary = buildString {
                appendLine("Queued: ${formatTime(record.queuedAtMillis)}")
                appendLine("Status: ${downloadStatus(record.downloadId)}")
                appendLine("URL: ${record.url}")
            },
            summaryMaxLines = 4,
        )

    private fun downloadStatus(downloadId: Long): String {
        val manager = getSystemService(DownloadManager::class.java)
        val cursor = manager.query(DownloadManager.Query().setFilterById(downloadId))
            ?: return "Unknown"
        cursor.use {
            if (!it.moveToFirst()) {
                return "No longer listed by DownloadManager"
            }
            return when (it.getInt(it.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS))) {
                DownloadManager.STATUS_PENDING -> "Pending"
                DownloadManager.STATUS_PAUSED -> "Paused"
                DownloadManager.STATUS_RUNNING -> progressText(it)
                DownloadManager.STATUS_SUCCESSFUL -> "Complete"
                DownloadManager.STATUS_FAILED -> "Failed (${it.getInt(it.getColumnIndexOrThrow(DownloadManager.COLUMN_REASON))})"
                else -> "Unknown"
            }
        }
    }

    private fun progressText(cursor: android.database.Cursor): String {
        val downloaded = cursor.getLong(
            cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR),
        )
        val total = cursor.getLong(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_TOTAL_SIZE_BYTES))
        return if (total > 0L) {
            "Downloading $downloaded / $total bytes"
        } else {
            "Downloading $downloaded bytes"
        }
    }

    private fun openSystemDownloads() {
        try {
            startActivity(Intent(DownloadManager.ACTION_VIEW_DOWNLOADS))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, "No system downloads app is available", Toast.LENGTH_SHORT).show()
        }
    }

    private fun confirmClearDownloadRecords() {
        val count = BrowserDownloadStore.records(this).size
        if (count == 0) {
            Toast.makeText(this, "Download records are already empty", Toast.LENGTH_SHORT).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Clear download records?")
            .setMessage("This clears this browser's download list. It does not delete downloaded files.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                val cleared = BrowserDownloadStore.clear(this)
                Toast.makeText(this, "Cleared $cleared download record(s)", Toast.LENGTH_SHORT).show()
                refreshDownloads()
            }
            .show()
    }

    private fun formatTime(queuedAtMillis: Long): String =
        if (queuedAtMillis <= 0L) {
            "Unknown time"
        } else {
            DateFormat.format("yyyy-MM-dd HH:mm", queuedAtMillis).toString()
        }
}
