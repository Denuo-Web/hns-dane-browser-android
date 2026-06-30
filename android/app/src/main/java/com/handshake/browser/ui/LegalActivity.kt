package com.handshake.browser.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.handshake.browser.BuildConfig

class LegalActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setSecondaryScreen("Legal") {
            addView(screenSection("App") {
                addScreenRow(preferenceRow(
                    title = "Build",
                    summary = buildLabel(),
                    selectableSummary = true,
                ))
            })
            addView(screenSection("Privacy policy") {
                addScreenRow(preferenceRow(
                    title = "Summary",
                    summary = BrowserAppInfo.PRIVACY_POLICY_SUMMARY,
                    selectableSummary = true,
                    summaryMaxLines = Int.MAX_VALUE,
                ))
                addScreenRow(preferenceRow(
                    title = "Privacy policy URL",
                    summary = BrowserAppInfo.PRIVACY_POLICY_URL,
                    actionLabel = "Open",
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.PRIVACY_POLICY_URL),
                        "privacy policy URL",
                        BrowserAppInfo.PRIVACY_POLICY_URL,
                    )
                })
            })
            addView(screenSection("License") {
                addScreenRow(preferenceRow(
                    title = BrowserAppInfo.LICENSE_NAME,
                    summary = BrowserAppInfo.LICENSE_SUMMARY,
                    selectableSummary = true,
                    summaryMaxLines = Int.MAX_VALUE,
                ))
                addScreenRow(preferenceRow(
                    title = "Source code",
                    summary = BrowserAppInfo.SOURCE_CODE_URL,
                    actionLabel = "Open",
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.SOURCE_CODE_URL),
                        "source code URL",
                        BrowserAppInfo.SOURCE_CODE_URL,
                    )
                })
            })
            addView(screenSection("User agreement") {
                addScreenRow(preferenceRow(
                    title = "Agreement",
                    summary = BrowserAppInfo.USER_AGREEMENT,
                    selectableSummary = true,
                    summaryMaxLines = Int.MAX_VALUE,
                ))
            })
        }
    }

    private fun openLink(uri: Uri, copyLabel: String, copyText: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, uri))
        } catch (_: ActivityNotFoundException) {
            getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText(copyLabel, copyText))
            Toast.makeText(this, "Copied $copyLabel", Toast.LENGTH_SHORT).show()
        }
    }

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) "debug demo" else "release"
        return "$channel ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
    }
}
