package com.handshake.browser.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.webkit.WebViewFeature
import com.handshake.browser.BuildConfig
import com.handshake.browser.net.GatewayEventLog
import com.handshake.browser.net.HnsSyncForegroundService
import com.handshake.browser.net.NativeBridge
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class DiagnosticsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        GatewayEventLog.configureAppStorage(filesDir)
        HnsSyncForegroundService.start(this)

        var latestSyncStatus = NativeBridge.syncStatus(filesDir.absolutePath)
        var syncRunInProgress = false
        val syncStatus = preferenceSummary(
            text = latestSyncStatus,
            selectable = true,
            maxLines = Int.MAX_VALUE,
        )

        setSecondaryScreen("Diagnostics") {
            addView(screenSection("App and runtime") {
                addScreenRow(preferenceRow(
                    title = "Build",
                    summary = buildLabel(),
                    selectableSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Rust core",
                    summary = NativeBridge.version(),
                    selectableSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Rust diagnostics",
                    summary = NativeBridge.diagnostics(),
                    selectableSummary = true,
                    summaryMaxLines = Int.MAX_VALUE,
                ))
                addScreenRow(preferenceRow(
                    title = "Proxy override",
                    summary = WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE).toString(),
                    selectableSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Third-party cookies blocked",
                    summary = BrowserCookiePreferences.blockThirdPartyCookies(this@DiagnosticsActivity).toString(),
                    selectableSummary = true,
                ))
            })
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
                    if (syncRunInProgress) {
                        Toast.makeText(this@DiagnosticsActivity, "Sync is already running", Toast.LENGTH_SHORT).show()
                        return@preferenceRow
                    }
                    syncRunInProgress = true
                    HnsSyncForegroundService.start(this@DiagnosticsActivity)
                    syncStatus.text = "running"
                    val running = AtomicBoolean(true)
                    thread(name = "hns-sync-status-poll") {
                        while (running.get()) {
                            Thread.sleep(SYNC_STATUS_POLL_MS)
                            val status = NativeBridge.syncStatus(filesDir.absolutePath)
                            runOnUiThread {
                                if (running.get()) {
                                    latestSyncStatus = status
                                    syncStatus.text = "running $status"
                                }
                            }
                        }
                    }
                    thread(name = "hns-sync-now") {
                        val status = NativeBridge.syncOnce(filesDir.absolutePath)
                        running.set(false)
                        runOnUiThread {
                            latestSyncStatus = status
                            syncStatus.text = status
                            syncRunInProgress = false
                        }
                    }
                })
            })
            addView(screenSection("Gateway") {
                addScreenRow(preferenceRow(
                    title = "Recent gateway events",
                    summary = GatewayEventLog.snapshotText(),
                    selectableSummary = true,
                    summaryMaxLines = Int.MAX_VALUE,
                ))
            })
            addView(screenSection("Diagnostic bundle") {
                addScreenRow(preferenceRow(
                    title = "Copy diagnostic bundle",
                    summary = "Copy build, sync, runtime, and gateway details.",
                    actionLabel = "Copy",
                ) {
                    copyDiagnosticBundle(latestSyncStatus)
                })
                addScreenRow(preferenceRow(
                    title = "Share diagnostic bundle",
                    summary = "Send the same diagnostic report through Android sharing.",
                    actionLabel = "Share",
                ) {
                    shareDiagnosticBundle(latestSyncStatus)
                })
            })
        }
    }

    private fun copyDiagnosticBundle(syncStatus: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText("HNS Browser diagnostic bundle", diagnosticBundle(syncStatus)))
        Toast.makeText(this, "Diagnostic bundle copied", Toast.LENGTH_SHORT).show()
    }

    private fun shareDiagnosticBundle(syncStatus: String) {
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/markdown"
            putExtra(Intent.EXTRA_SUBJECT, "HNS Browser diagnostic bundle")
            putExtra(Intent.EXTRA_TEXT, diagnosticBundle(syncStatus))
        }
        startActivity(Intent.createChooser(sendIntent, "Share diagnostic bundle"))
    }

    private fun diagnosticBundle(syncStatus: String): String =
        DiagnosticReport.markdown(
            buildLabel = buildLabel(),
            rustCore = NativeBridge.version(),
            rustDiagnostics = NativeBridge.diagnostics(),
            syncStatus = syncStatus,
            proxyOverrideSupported = WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE),
            thirdPartyCookiesBlocked = BrowserCookiePreferences.blockThirdPartyCookies(this),
            gatewayEvents = GatewayEventLog.snapshotText(),
        )

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) "debug demo" else "release"
        return "$channel ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
    }

    private companion object {
        const val SYNC_STATUS_POLL_MS = 2_000L
    }
}
