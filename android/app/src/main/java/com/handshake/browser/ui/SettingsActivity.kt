package com.handshake.browser.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Paint
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.handshake.browser.net.NativeBridge

class SettingsActivity : ComponentActivity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply {
            text = "Settings"
            textSize = 16f
            setPadding(0, 10, 0, 18)
            setTextIsSelectable(true)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 32, 32, 32)
            applySystemBarPadding()
            addView(heading("Settings"))
            addView(status)
            addView(actionButton("View diagnostics") {
                startActivity(Intent(this@SettingsActivity, DiagnosticsActivity::class.java))
            })
            addView(actionButton("Cookie options") {
                startActivity(Intent(this@SettingsActivity, CookieSettingsActivity::class.java))
            })
            addView(actionButton("Clear resolver cache") {
                clearResolverCache()
            })
            addView(actionButton("License and user agreement") {
                startActivity(Intent(this@SettingsActivity, LegalActivity::class.java))
            })
            addView(bottomSpacer())
            addView(linkRow(
                "Donate HNS",
                BrowserAppInfo.HNS_DONATION_ADDRESS,
                BrowserAppInfo.HNS_DONATION_URI,
                "HNS donation address",
                BrowserAppInfo.HNS_DONATION_ADDRESS,
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
            setPadding(0, 0, 0, 14)
        }

    private fun actionButton(text: String, action: () -> Unit): Button =
        Button(this).apply {
            this.text = text
            setAllCaps(false)
            setOnClickListener { action() }
        }

    private fun linkRow(label: String, value: String, uri: String, copyLabel: String, copyText: String): TextView =
        TextView(this).apply {
            text = "$label: $value"
            textSize = 16f
            paintFlags = paintFlags or Paint.UNDERLINE_TEXT_FLAG
            setTextColor(0xff1565c0.toInt())
            setPadding(0, 18, 0, 10)
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

    private fun clearResolverCache() {
        val result = NativeBridge.clearResolverCache(filesDir.absolutePath)
        status.text = "Resolver cache: $result"
        Toast.makeText(this, "Resolver cache cleared", Toast.LENGTH_SHORT).show()
    }

    private fun bottomSpacer(): TextView =
        TextView(this).apply {
            text = ""
            setPadding(0, 24, 0, 0)
        }
}
