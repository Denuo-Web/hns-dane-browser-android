package com.handshake.browser.ui

import android.app.AlertDialog
import android.app.DownloadManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.text.format.DateFormat
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity

class DownloadsActivity : ComponentActivity() {
    private lateinit var listContainer: LinearLayout
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = bodyText("")
        listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 32, 32, 32)
            applySystemBarPadding()
            addView(heading("Downloads"))
            addView(status)
            addView(actionButton("Open system downloads") {
                openSystemDownloads()
            })
            addView(actionButton("Clear app download records") {
                confirmClearDownloadRecords()
            })
            addView(bodyText("This screen tracks downloads queued by this browser. Files are managed by Android DownloadManager."))
            addView(listContainer)
        }

        setContentView(
            ScrollView(this).apply {
                addView(root)
            },
        )

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

        records.forEach { record ->
            listContainer.addView(subheading(record.fileName))
            listContainer.addView(bodyText(
                buildString {
                    appendLine("Queued: ${formatTime(record.queuedAtMillis)}")
                    appendLine("Status: ${downloadStatus(record.downloadId)}")
                    appendLine("URL: ${record.url}")
                },
            ))
        }
    }

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

    private fun heading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 24f
            setPadding(0, 0, 0, 14)
        }

    private fun subheading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 18f
            setPadding(0, 18, 0, 8)
        }

    private fun bodyText(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 15f
            setTextIsSelectable(true)
            setPadding(0, 8, 0, 12)
        }

    private fun actionButton(text: String, action: () -> Unit): Button =
        Button(this).apply {
            this.text = text
            setAllCaps(false)
            setOnClickListener { action() }
        }
}
