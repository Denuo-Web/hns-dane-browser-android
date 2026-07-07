package com.denuoweb.hnsdane.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.denuoweb.hnsdane.net.GatewayEvent
import com.denuoweb.hnsdane.net.GatewayEventLog

class GatewayActivity : ComponentActivity() {
    private val url: String
        get() = intent.getStringExtra(EXTRA_URL).orEmpty()

    private val traceJson: String
        get() = intent.getStringExtra(EXTRA_TRACE_JSON).orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        GatewayEventLog.configureAppStorage(filesDir)

        setSecondaryScreen(
            title = "Gateway",
            onSwipeLeft = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.Gateway, forward = true, url, traceJson)
            },
            onSwipeRight = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.Gateway, forward = false, url, traceJson)
            },
        ) {
            addView(hnsDiagnosticTabs(HnsDiagnosticTool.Gateway, url, traceJson))
            addView(screenSection("Recent gateway events") {
                addView(fieldReportText(gatewaySummary()))
            })
            addView(screenSection("Export") {
                addScreenRow(preferenceRow(
                    title = "Copy gateway events",
                    summary = "Copy the current gateway event log.",
                    actionLabel = "Copy",
                ) {
                    copyGatewayEvents()
                })
            })
        }
    }

    private fun gatewaySummary(): String {
        val events = GatewayEventLog.snapshot()
        if (events.isEmpty()) {
            return "Recent gateway events: none"
        }
        return events.joinToString(separator = "\n\n") { event ->
            eventSummary(event)
        }
    }

    private fun eventSummary(event: GatewayEvent): String =
        buildString {
            appendLine("Timestamp: ${event.timestampMillis}")
            appendLine("Stage: ${event.stage}")
            appendLine("Host: ${event.host}")
            appendLine("Status: ${event.status}")
            append("Reason: ${event.reason}")
        }

    private fun copyGatewayEvents() {
        val events = GatewayEventLog.snapshotText()
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText("HNS DANE Browser gateway events", events))
        Toast.makeText(this, "Gateway events copied", Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_URL = "com.denuoweb.hnsdane.GATEWAY_URL"
        const val EXTRA_TRACE_JSON = "com.denuoweb.hnsdane.GATEWAY_TRACE_JSON"
    }
}
