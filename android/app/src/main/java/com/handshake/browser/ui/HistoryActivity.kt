package com.handshake.browser.ui

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.format.DateFormat
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity

class HistoryActivity : ComponentActivity() {
    private lateinit var listContainer: LinearLayout
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = preferenceSummary("")
        listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        setSecondaryScreen("History") {
            addView(screenSection("Browsing history") {
                addScreenRow(preferenceRow(
                    title = "Saved pages",
                    summaryView = status,
                ))
                addScreenRow(preferenceRow(
                    title = "Clear history",
                    summary = "Remove saved browsing history from this device.",
                    actionLabel = "Clear",
                    destructive = true,
                ) {
                    confirmClearHistory()
                })
            })
            addView(screenSection("Recent pages") {
                addView(listContainer)
            })
        }

        refreshHistory()
    }

    private fun refreshHistory() {
        listContainer.removeAllViews()
        val entries = BrowserHistoryStore.entries(this)
        status.text = if (entries.isEmpty()) {
            "No browsing history yet."
        } else {
            "${entries.size} recent page${if (entries.size == 1) "" else "s"}."
        }

        if (entries.isEmpty()) {
            listContainer.addScreenRow(preferenceRow(
                title = "No recent pages",
                summary = "Pages you visit will appear here.",
            ))
        } else {
            entries.forEach { entry ->
                listContainer.addScreenRow(historyRow(entry))
            }
        }
    }

    private fun historyRow(entry: BrowserHistoryEntry): LinearLayout =
        preferenceRow(
            title = entry.title.ifBlank { entry.url },
            summary = "${formatTime(entry.visitedAtMillis)}\n${entry.url}",
            actionLabel = "Open",
            summaryMaxLines = 3,
        ) {
            startActivity(
                Intent(this, MainActivity::class.java)
                    .putExtra(MainActivity.EXTRA_LOAD_URL, entry.url)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        }

    private fun confirmClearHistory() {
        val count = BrowserHistoryStore.entries(this).size
        if (count == 0) {
            Toast.makeText(this, "History is already empty", Toast.LENGTH_SHORT).show()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Clear history?")
            .setMessage("This removes the app's local list of recently visited pages.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                val cleared = BrowserHistoryStore.clear(this)
                Toast.makeText(this, "Cleared $cleared history item(s)", Toast.LENGTH_SHORT).show()
                refreshHistory()
            }
            .show()
    }

    private fun formatTime(visitedAtMillis: Long): String =
        if (visitedAtMillis <= 0L) {
            "Unknown time"
        } else {
            DateFormat.format("yyyy-MM-dd HH:mm", visitedAtMillis).toString()
        }
}
