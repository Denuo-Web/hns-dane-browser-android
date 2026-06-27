package com.handshake.browser.ui

import android.content.Context
import android.webkit.CookieManager
import android.webkit.WebView

internal object BrowserCookiePreferences {
    private const val PREFS = "browser_cookie_preferences"
    private const val KEY_BLOCK_THIRD_PARTY = "block_third_party_cookies"

    fun blockThirdPartyCookies(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_BLOCK_THIRD_PARTY, true)

    fun setBlockThirdPartyCookies(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_BLOCK_THIRD_PARTY, enabled)
            .apply()
    }

    fun applyTo(webView: WebView) {
        val cookieManager = CookieManager.getInstance()
        cookieManager.setAcceptCookie(true)
        cookieManager.setAcceptThirdPartyCookies(
            webView,
            !blockThirdPartyCookies(webView.context),
        )
    }
}
