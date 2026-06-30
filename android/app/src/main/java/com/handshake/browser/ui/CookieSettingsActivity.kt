package com.handshake.browser.ui

import android.os.Bundle
import android.webkit.CookieManager
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity

class CookieSettingsActivity : ComponentActivity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = preferenceSummary(summary())

        setSecondaryScreen("Cookie Options") {
            addView(screenSection("Website data") {
                addScreenRow(checkboxRow(
                    title = "Block third-party cookies",
                    summaryView = status,
                    checked = BrowserCookiePreferences.blockThirdPartyCookies(this@CookieSettingsActivity),
                ) { checked ->
                    BrowserCookiePreferences.setBlockThirdPartyCookies(this@CookieSettingsActivity, checked)
                    status.text = summary()
                })
                addScreenRow(preferenceRow(
                    title = "Delete cookies",
                    summary = "Remove cookies stored by websites in this browser.",
                    actionLabel = "Delete",
                    destructive = true,
                ) {
                    deleteCookies()
                })
            })
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

    private fun summary(): String =
        if (BrowserCookiePreferences.blockThirdPartyCookies(this)) {
            "First-party cookies are allowed. Third-party cookies are blocked."
        } else {
            "First-party and third-party cookies are allowed."
        }
}
