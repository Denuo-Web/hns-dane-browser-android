package com.denuoweb.hnsdane.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.webkit.WebViewFeature
import com.denuoweb.hnsdane.BuildConfig
import com.denuoweb.hnsdane.net.NativeBridge

class DiagnosticsActivity : ComponentActivity() {
    private val url: String
        get() = intent.getStringExtra(EXTRA_URL).orEmpty()

    private val traceJson: String
        get() = intent.getStringExtra(EXTRA_TRACE_JSON).orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setSecondaryScreen(
            title = "Diagnostics",
            onSwipeLeft = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.Diagnostics, forward = true, url, traceJson)
            },
            onSwipeRight = {
                openAdjacentHnsDiagnostic(HnsDiagnosticTool.Diagnostics, forward = false, url, traceJson)
            },
        ) {
            addView(hnsDiagnosticTabs(HnsDiagnosticTool.Diagnostics, url, traceJson))
            addView(screenSection("App and runtime") {
                addScreenRow(preferenceRow(
                    title = "Build",
                    summary = buildLabel(),
                    selectableSummary = true,
                    boldSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Rust core",
                    summary = NativeBridge.version(),
                    selectableSummary = true,
                    boldSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Rust diagnostics",
                    summary = NativeBridge.diagnostics(),
                    selectableSummary = true,
                    summaryMaxLines = Int.MAX_VALUE,
                    boldSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Proxy override",
                    summary = WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE).toString(),
                    selectableSummary = true,
                    boldSummary = true,
                ))
                addScreenRow(preferenceRow(
                    title = "Third-party cookies blocked",
                    summary = BrowserCookiePreferences.blockThirdPartyCookies(this@DiagnosticsActivity).toString(),
                    selectableSummary = true,
                    boldSummary = true,
                ))
            })
            addView(screenSection("Diagnostic bundle") {
                addScreenRow(preferenceRow(
                    title = "Copy diagnostic bundle",
                    summary = "Copy build, runtime, and native core details.",
                    actionLabel = "Copy",
                ) {
                    copyDiagnosticBundle()
                })
                addScreenRow(preferenceRow(
                    title = "Share diagnostic bundle",
                    summary = "Send the same diagnostic report through Android sharing.",
                    actionLabel = "Share",
                ) {
                    shareDiagnosticBundle()
                })
            })
        }
    }

    private fun copyDiagnosticBundle() {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText("HNS DANE Browser diagnostic bundle", diagnosticBundle()))
        Toast.makeText(this, "Diagnostic bundle copied", Toast.LENGTH_SHORT).show()
    }

    private fun shareDiagnosticBundle() {
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/markdown"
            putExtra(Intent.EXTRA_SUBJECT, "HNS DANE Browser diagnostic bundle")
            putExtra(Intent.EXTRA_TEXT, diagnosticBundle())
        }
        startActivity(Intent.createChooser(sendIntent, "Share diagnostic bundle"))
    }

    private fun diagnosticBundle(): String =
        DiagnosticReport.markdown(
            buildLabel = buildLabel(),
            rustCore = NativeBridge.version(),
            rustDiagnostics = NativeBridge.diagnostics(),
            proxyOverrideSupported = WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE),
            thirdPartyCookiesBlocked = BrowserCookiePreferences.blockThirdPartyCookies(this),
        )

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) "debug demo" else "release"
        return "$channel ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
    }

    companion object {
        const val EXTRA_URL = "com.denuoweb.hnsdane.DIAGNOSTICS_URL"
        const val EXTRA_TRACE_JSON = "com.denuoweb.hnsdane.DIAGNOSTICS_TRACE_JSON"
    }
}
