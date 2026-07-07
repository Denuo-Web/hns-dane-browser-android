package com.denuoweb.hnsdane.ui

import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.denuoweb.hnsdane.net.HnsSyncForegroundService
import com.denuoweb.hnsdane.net.NativeBridge
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class HnsSyncActivity : ComponentActivity() {
    private lateinit var syncStatus: TextView
    private var syncRunInProgress = false
    private var activePoller: AtomicBoolean? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        syncStatus = preferenceSummary(
            text = NativeBridge.syncStatus(filesDir.absolutePath),
            selectable = true,
            maxLines = Int.MAX_VALUE,
            bold = true,
        )

        setSecondaryScreen("HNS Sync") {
            addView(screenSection("HNS sync") {
                addScreenRow(preferenceRow(
                    title = "Sync status",
                    summaryView = syncStatus,
                ))
                addScreenRow(preferenceRow(
                    title = "Run sync now",
                    summary = "Start a foreground HNS sync and watch the status update here.",
                    actionLabel = "Run",
                ) {
                    runSyncNow()
                })
            })
        }
    }

    override fun onDestroy() {
        activePoller?.set(false)
        super.onDestroy()
    }

    private fun runSyncNow() {
        if (syncRunInProgress) {
            Toast.makeText(this, "Sync is already running", Toast.LENGTH_SHORT).show()
            return
        }

        syncRunInProgress = true
        HnsSyncForegroundService.start(this)
        syncStatus.text = "running"

        val running = AtomicBoolean(true)
        activePoller = running
        thread(name = "hns-sync-status-poll") {
            while (running.get()) {
                Thread.sleep(SYNC_STATUS_POLL_MS)
                val status = NativeBridge.syncStatus(filesDir.absolutePath)
                runOnUiThread {
                    if (running.get()) {
                        syncStatus.text = "running $status"
                    }
                }
            }
        }
        thread(name = "hns-sync-now") {
            val status = NativeBridge.syncOnce(filesDir.absolutePath)
            running.set(false)
            runOnUiThread {
                syncStatus.text = status
                syncRunInProgress = false
            }
        }
    }

    private companion object {
        const val SYNC_STATUS_POLL_MS = 2_000L
    }
}
