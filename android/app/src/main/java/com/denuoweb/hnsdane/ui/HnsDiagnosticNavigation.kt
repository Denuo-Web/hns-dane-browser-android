package com.denuoweb.hnsdane.ui

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity

internal enum class HnsDiagnosticTool(
    private val defaultTitle: String,
) {
    ResolverTrace("Resolver trace"),
    ProofDetails("HNS proof"),
    TlsaInspector("TLSA / DANE"),
    Diagnostics("Diagnostics"),
    Gateway("Gateway");

    fun next(): HnsDiagnosticTool =
        entries[(ordinal + 1) % entries.size]

    fun previous(): HnsDiagnosticTool =
        entries[(ordinal + entries.size - 1) % entries.size]

    fun title(traceJson: String): String =
        when (this) {
            ProofDetails -> HnsResolutionTraceFormat.proofTabTitle(traceJson)
            else -> defaultTitle
        }
}

internal fun ComponentActivity.hnsDiagnosticTabs(
    current: HnsDiagnosticTool,
    url: String,
    traceJson: String,
): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, uiDp(2), 0, uiDp(10))
        HnsDiagnosticTool.entries.forEach { tool ->
            addView(hnsDiagnosticTab(tool, traceJson, selected = tool == current) {
                if (tool != current) {
                    openHnsDiagnosticTool(tool, url, traceJson)
                }
            }, LinearLayout.LayoutParams(
                0,
                uiDp(44),
                1f,
            ).apply {
                leftMargin = if (tool.ordinal == 0) 0 else uiDp(4)
            })
        }
    }

internal fun ComponentActivity.openAdjacentHnsDiagnostic(
    current: HnsDiagnosticTool,
    forward: Boolean,
    url: String,
    traceJson: String,
) {
    openHnsDiagnosticTool(
        tool = if (forward) current.next() else current.previous(),
        url = url,
        traceJson = traceJson,
    )
}

private fun ComponentActivity.hnsDiagnosticTab(
    tool: HnsDiagnosticTool,
    traceJson: String,
    selected: Boolean,
    action: () -> Unit,
): TextView =
    TextView(this).apply {
        text = tool.title(traceJson)
        textSize = 11f
        typeface = if (selected) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
        gravity = Gravity.CENTER
        maxLines = 2
        includeFontPadding = false
        setPadding(uiDp(3), 0, uiDp(3), 0)
        setTextColor(if (selected) Color.WHITE else Color.rgb(21, 101, 192))
        setBackgroundColor(if (selected) Color.rgb(21, 101, 192) else Color.rgb(232, 240, 254))
        if (!selected) {
            isClickable = true
            isFocusable = true
            setOnClickListener { action() }
        }
    }

private fun ComponentActivity.openHnsDiagnosticTool(
    tool: HnsDiagnosticTool,
    url: String,
    traceJson: String,
) {
    val targetIntent = when (tool) {
        HnsDiagnosticTool.ResolverTrace -> Intent(this, HnsResolverTraceActivity::class.java)
            .putExtra(HnsResolverTraceActivity.EXTRA_URL, url)
            .putExtra(HnsResolverTraceActivity.EXTRA_TRACE_JSON, traceJson)
        HnsDiagnosticTool.ProofDetails -> Intent(this, HnsProofDetailsActivity::class.java)
            .putExtra(HnsProofDetailsActivity.EXTRA_URL, url)
            .putExtra(HnsProofDetailsActivity.EXTRA_TRACE_JSON, traceJson)
        HnsDiagnosticTool.TlsaInspector -> Intent(this, HnsTlsaInspectorActivity::class.java)
            .putExtra(HnsTlsaInspectorActivity.EXTRA_URL, url)
            .putExtra(HnsTlsaInspectorActivity.EXTRA_TRACE_JSON, traceJson)
        HnsDiagnosticTool.Diagnostics -> Intent(this, DiagnosticsActivity::class.java)
            .putExtra(DiagnosticsActivity.EXTRA_URL, url)
            .putExtra(DiagnosticsActivity.EXTRA_TRACE_JSON, traceJson)
        HnsDiagnosticTool.Gateway -> Intent(this, GatewayActivity::class.java)
            .putExtra(GatewayActivity.EXTRA_URL, url)
            .putExtra(GatewayActivity.EXTRA_TRACE_JSON, traceJson)
    }
    startActivity(targetIntent)
    finish()
}
