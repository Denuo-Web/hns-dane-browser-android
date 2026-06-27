package com.handshake.browser.ui

import android.os.Bundle
import android.view.Gravity
import android.webkit.CookieManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity

class CookieSettingsActivity : ComponentActivity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply {
            text = summary()
            textSize = 16f
            setPadding(0, 10, 0, 18)
            setTextIsSelectable(true)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(32, 32, 32, 32)
            applySystemBarPadding()
            addView(heading("Cookie Options"))
            addView(blockThirdPartyOption())
            addView(actionButton("Delete cookies") {
                deleteCookies()
            })
            addView(status)
        }

        setContentView(
            ScrollView(this).apply {
                addView(root)
            },
        )
    }

    private fun blockThirdPartyOption(): CheckBox =
        CheckBox(this).apply {
            text = "Block third-party cookies"
            textSize = 16f
            setPadding(0, 0, 0, 14)
            isChecked = BrowserCookiePreferences.blockThirdPartyCookies(this@CookieSettingsActivity)
            setOnCheckedChangeListener { _, checked ->
                BrowserCookiePreferences.setBlockThirdPartyCookies(this@CookieSettingsActivity, checked)
                status.text = summary()
            }
        }

    private fun deleteCookies() {
        CookieManager.getInstance().removeAllCookies { removedAny ->
            CookieManager.getInstance().flush()
            runOnUiThread {
                val message = if (removedAny) "Cookies deleted" else "No cookies to delete"
                status.text = "$message. ${summary()}"
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
        }
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

    private fun summary(): String =
        if (BrowserCookiePreferences.blockThirdPartyCookies(this)) {
            "First-party cookies are allowed. Third-party cookies are blocked."
        } else {
            "First-party and third-party cookies are allowed."
        }
}
