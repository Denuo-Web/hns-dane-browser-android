package com.handshake.browser.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Paint
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.handshake.browser.BuildConfig

class LegalActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 32, 32, 32)
            applySystemBarPadding()
            addView(heading("License and User Agreement"))
            addView(row("Build", buildLabel()))
            addView(section("License"))
            addView(row(BrowserAppInfo.LICENSE_NAME, BrowserAppInfo.LICENSE_SUMMARY))
            addView(section("User Agreement"))
            addView(row("Agreement", BrowserAppInfo.USER_AGREEMENT))
            addView(linkRow(
                "Source code",
                BrowserAppInfo.SOURCE_CODE_URL,
                BrowserAppInfo.SOURCE_CODE_URL,
                "source code URL",
                BrowserAppInfo.SOURCE_CODE_URL,
            ))
        }

        setContentView(
            ScrollView(this).apply {
                addView(root)
            },
        )
    }

    private fun heading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 24f
            setPadding(0, 0, 0, 18)
        }

    private fun section(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 20f
            setPadding(0, 18, 0, 8)
        }

    private fun row(label: String, value: String): TextView =
        TextView(this).apply {
            text = "$label: $value"
            textSize = 16f
            setTextIsSelectable(true)
            setPadding(0, 10, 0, 10)
        }

    private fun linkRow(label: String, value: String, uri: String, copyLabel: String, copyText: String): TextView =
        row(label, value).apply {
            paintFlags = paintFlags or Paint.UNDERLINE_TEXT_FLAG
            setTextColor(0xff1565c0.toInt())
            setTextIsSelectable(false)
            isClickable = true
            setOnClickListener {
                openLink(Uri.parse(uri), copyLabel, copyText)
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
