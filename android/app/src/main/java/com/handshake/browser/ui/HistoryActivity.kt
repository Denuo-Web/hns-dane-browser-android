package com.handshake.browser.ui

import android.app.AlertDialog
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

class HistoryActivity : ComponentActivity() {
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
            addView(heading("History"))
            addView(status)
            addView(actionButton("Clear history") {
                confirmClearHistory()
            })
            addView(listContainer)
        }

        setContentView(
            ScrollView(this).apply {
                addView(root)
            },
        )

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

        entries.forEach { entry ->
            listContainer.addView(historyButton(entry))
            listContainer.addView(bodyText(
                "${formatTime(entry.visitedAtMillis)}\n${entry.url}",
            ))
        }
    }

    private fun historyButton(entry: BrowserHistoryEntry): Button =
        actionButton(entry.title.ifBlank { entry.url }) {
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

    private fun heading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 24f
            setPadding(0, 0, 0, 14)
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
