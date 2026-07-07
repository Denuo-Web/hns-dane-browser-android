package com.denuoweb.hnsdane.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.denuoweb.hnsdane.BuildConfig
import com.denuoweb.hnsdane.net.NativeBridge
import org.json.JSONObject

class SettingsActivity : ComponentActivity() {
    private lateinit var homepageStatus: TextView
    private lateinit var cookieStatus: TextView
    private lateinit var hnsModeStatus: TextView
    private lateinit var statelessDaneStatus: TextView
    private lateinit var dohResolverStatus: TextView
    private lateinit var resolverCacheStatus: TextView
    private lateinit var historyStatus: TextView
    private lateinit var downloadStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        homepageStatus = preferenceSummary(BrowserPreferences.homepage(this))
        cookieStatus = preferenceSummary(cookieSummary())
        hnsModeStatus = preferenceSummary(hnsModeText())
        statelessDaneStatus = preferenceSummary(statelessDaneText())
        dohResolverStatus = preferenceSummary(HnsResolutionPreferences.dohResolverUrl(this))
        resolverCacheStatus = preferenceSummary("Ready to clear cached resolver values.")
        historyStatus = preferenceSummary(historySummary())
        downloadStatus = preferenceSummary(downloadSummary())

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.START
            setPadding(dp(20), dp(20), dp(20), dp(20))
            applySystemBarPadding()
            addView(heading("Settings"))

            addView(section("Start page") {
                addPreference(preferenceRow(
                    title = "Homepage",
                    summaryView = homepageStatus,
                    actionLabel = "Edit",
                ) {
                    showEditHomepageDialog()
                })
                currentUrlFromIntent()?.let { currentUrl ->
                    addPreference(preferenceRow(
                        title = "Set current page as homepage",
                        summary = currentUrl,
                        actionLabel = "Set",
                    ) {
                        useCurrentPageAsHomepage(currentUrl)
                    })
                }
                addPreference(preferenceRow(
                    title = "Reset homepage",
                    summary = "Restore the default Denuo Web homepage.",
                    actionLabel = "Reset",
                    destructive = true,
                ) {
                    confirmResetHomepage()
                })
            })

            addView(section("Privacy and data") {
                addPreference(preferenceRow(
                    title = "Cookies",
                    summaryView = cookieStatus,
                    actionLabel = "Manage",
                ) {
                    startActivity(Intent(this@SettingsActivity, CookieSettingsActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "History",
                    summaryView = historyStatus,
                    actionLabel = "View",
                ) {
                    startActivity(Intent(this@SettingsActivity, HistoryActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "Downloads",
                    summaryView = downloadStatus,
                    actionLabel = "View",
                ) {
                    startActivity(Intent(this@SettingsActivity, DownloadsActivity::class.java))
                })
            })

            addView(section("HNS resolution") {
                addPreference(strictHnsModeOption())
                addPreference(statelessDaneCertificateOption())
                addPreference(preferenceRow(
                    title = "Compatibility DoH resolver",
                    summaryView = dohResolverStatus,
                    actionLabel = "Edit",
                ) {
                    showEditDohResolverDialog()
                })
                addPreference(preferenceRow(
                    title = "Clear resolver cache",
                    summaryView = resolverCacheStatus,
                    actionLabel = "Clear",
                    destructive = true,
                ) {
                    confirmClearResolverCache()
                })
                addPreference(preferenceRow(
                    title = "HNS sync",
                    summary = "View sync status and run a manual sync.",
                    actionLabel = "View",
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsSyncActivity::class.java))
                })
            })

            addView(section("Diagnostics and tools") {
                addPreference(preferenceRow(
                    title = "HNS domain setup",
                    summary = "Check records and delegation for an HNS domain.",
                    actionLabel = "Open",
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsDomainWizardActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "Resolver trace",
                    summary = "Inspect resolution steps for a name.",
                    actionLabel = "Open",
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsResolverTraceActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "HNS proof details",
                    summary = "Inspect local proof data for an HNS name.",
                    actionLabel = "Open",
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsProofDetailsActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "TLSA / DANE inspector",
                    summary = "Check TLSA records and DANE policy.",
                    actionLabel = "Open",
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsTlsaInspectorActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "Diagnostics",
                    summary = "Build, runtime, and native core details.",
                    actionLabel = "View",
                ) {
                    startActivity(Intent(this@SettingsActivity, DiagnosticsActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "Gateway",
                    summary = "Inspect recent native gateway events.",
                    actionLabel = "View",
                ) {
                    startActivity(Intent(this@SettingsActivity, GatewayActivity::class.java))
                })
            })

            addView(section("About, legal, and support") {
                addPreference(preferenceRow(
                    title = "Build",
                    summary = buildLabel(),
                ))
                addPreference(preferenceRow(
                    title = "Legal",
                    summary = "Privacy policy, license, and user agreement.",
                    actionLabel = "View",
                ) {
                    startActivity(Intent(this@SettingsActivity, LegalActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = "Privacy policy",
                    summary = BrowserAppInfo.PRIVACY_POLICY_URL,
                    actionLabel = "Open",
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.PRIVACY_POLICY_URL),
                        "privacy policy URL",
                        BrowserAppInfo.PRIVACY_POLICY_URL,
                    )
                })
                addPreference(preferenceRow(
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
                addPreference(preferenceRow(
                    title = "Donate HNS",
                    summary = "Optional. Donations do not unlock features.",
                    actionLabel = "Open",
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.HNS_DONATION_URI),
                        "HNS donation address",
                        BrowserAppInfo.HNS_DONATION_ADDRESS,
                    )
                })
            })
        }

        setContentView(
            ScrollView(this).apply {
                addView(root, LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ))
            },
        )
    }

    override fun onResume() {
        super.onResume()
        if (::homepageStatus.isInitialized) {
            refreshHomepageStatus()
            refreshCookieStatus()
            refreshHnsModeStatus()
            refreshStatelessDaneStatus()
            refreshHistoryStatus()
            refreshDownloadStatus()
        }
    }

    private fun heading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.rgb(32, 33, 36))
            setPadding(0, 0, 0, dp(10))
        }

    private fun section(title: String, content: LinearLayout.() -> Unit): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(10), 0, dp(12))
            addView(sectionHeading(title))
            content()
        }

    private fun sectionHeading(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.rgb(95, 99, 104))
            setPadding(0, dp(18), 0, dp(6))
        }

    private fun LinearLayout.addPreference(row: View) {
        addView(row, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ))
        addView(divider())
    }

    private fun preferenceRow(
        title: String,
        summary: String? = null,
        summaryView: TextView? = null,
        actionLabel: String? = null,
        destructive: Boolean = false,
        action: (() -> Unit)? = null,
    ): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = dp(64)
            setPadding(0, dp(10), 0, dp(10))
            if (action != null) {
                isClickable = true
                isFocusable = true
                applySelectableBackground(this)
                setOnClickListener { action() }
            }

            val labels = LinearLayout(this@SettingsActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, 0, dp(12), 0)
                addView(preferenceTitle(title))
                val detail = summaryView ?: summary?.let { preferenceSummary(it) }
                if (detail != null) {
                    addView(detail)
                }
            }
            addView(labels, LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f,
            ))

            if (actionLabel != null) {
                addView(preferenceActionLabel(actionLabel, destructive))
            }
        }

    private fun preferenceTitle(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 16f
            setTextColor(Color.rgb(32, 33, 36))
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
        }

    private fun preferenceSummary(text: String): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(Color.rgb(95, 99, 104))
            maxLines = 3
            ellipsize = TextUtils.TruncateAt.END
            setPadding(0, dp(3), 0, 0)
        }

    private fun preferenceActionLabel(text: String, destructive: Boolean): TextView =
        TextView(this).apply {
            this.text = text
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER_VERTICAL or Gravity.END
            minWidth = dp(56)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
            setTextColor(
                if (destructive) {
                    Color.rgb(183, 28, 28)
                } else {
                    Color.rgb(21, 101, 192)
                },
            )
        }

    private fun strictHnsModeOption(): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, dp(10))
            addView(CheckBox(this@SettingsActivity).apply {
                text = "Strict HNS mode"
                textSize = 16f
                setTextColor(Color.rgb(32, 33, 36))
                setPadding(0, 0, 0, 0)
                isChecked = HnsResolutionPreferences.strictHnsMode(this@SettingsActivity)
                setOnCheckedChangeListener { _, checked ->
                    HnsResolutionPreferences.setStrictHnsMode(this@SettingsActivity, checked)
                    refreshHnsModeStatus()
                }
            })
            addView(hnsModeStatus, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                leftMargin = dp(36)
            })
        }

    private fun statelessDaneCertificateOption(): LinearLayout =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, dp(10))
            addView(CheckBox(this@SettingsActivity).apply {
                text = "Experimental stateless DANE certificates"
                textSize = 16f
                setTextColor(Color.rgb(32, 33, 36))
                setPadding(0, 0, 0, 0)
                isChecked = HnsResolutionPreferences.statelessDaneCertificates(this@SettingsActivity)
                setOnCheckedChangeListener { _, checked ->
                    HnsResolutionPreferences.setStatelessDaneCertificates(this@SettingsActivity, checked)
                    refreshStatelessDaneStatus()
                }
            })
            addView(statelessDaneStatus, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                leftMargin = dp(36)
            })
        }

    private fun divider(): View =
        View(this).apply {
            setBackgroundColor(Color.rgb(218, 220, 224))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                1,
            )
        }

    private fun applySelectableBackground(view: View) {
        val typedValue = TypedValue()
        theme.resolveAttribute(android.R.attr.selectableItemBackground, typedValue, true)
        view.setBackgroundResource(typedValue.resourceId)
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density + 0.5f).toInt()

    private fun openLink(uri: Uri, copyLabel: String, copyText: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, uri))
        } catch (_: ActivityNotFoundException) {
            getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText(copyLabel, copyText))
            Toast.makeText(this, "Copied $copyLabel", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showEditHomepageDialog() {
        val input = EditText(this).apply {
            setText(BrowserPreferences.homepage(this@SettingsActivity))
            setSingleLine(true)
            setSelection(0, text.length)
            imeOptions = EditorInfo.IME_ACTION_DONE
        }

        val dialog = AlertDialog.Builder(this)
            .setTitle("Edit homepage")
            .setMessage("Enter an http:// or https:// URL, or an HNS name such as example/ or www.example/.")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val saved = BrowserPreferences.setHomepage(this, input.text.toString())
                if (saved == null) {
                    input.error = "Enter an HTTP(S) URL or HNS name"
                    return@setOnClickListener
                }
                refreshHomepageStatus()
                Toast.makeText(this, "Homepage saved", Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun showEditDohResolverDialog() {
        val input = EditText(this).apply {
            setText(HnsResolutionPreferences.dohResolverUrl(this@SettingsActivity))
            setSingleLine(true)
            setSelection(0, text.length)
            imeOptions = EditorInfo.IME_ACTION_DONE
        }

        val dialog = AlertDialog.Builder(this)
            .setTitle("Edit DoH resolver")
            .setMessage("Enter an HTTPS DNS-over-HTTPS endpoint. Leave blank to use the default.")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Reset", null)
            .setPositiveButton("Save", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val saved = HnsResolutionPreferences.setDohResolverUrl(this, input.text.toString())
                if (saved == null) {
                    input.error = "Enter a valid HTTPS DoH URL"
                    return@setOnClickListener
                }
                refreshDohResolverStatus()
                Toast.makeText(this, "DoH resolver saved", Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                HnsResolutionPreferences.resetDohResolverUrl(this)
                refreshDohResolverStatus()
                Toast.makeText(this, "DoH resolver reset", Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun useCurrentPageAsHomepage(currentUrl: String) {
        val saved = BrowserPreferences.setHomepage(this, currentUrl)
        if (saved == null) {
            Toast.makeText(this, "Current page is not a supported homepage URL", Toast.LENGTH_SHORT).show()
            return
        }
        refreshHomepageStatus()
        Toast.makeText(this, "Homepage saved", Toast.LENGTH_SHORT).show()
    }

    private fun confirmResetHomepage() {
        AlertDialog.Builder(this)
            .setTitle("Reset homepage?")
            .setMessage("This restores the default Denuo Web homepage.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Reset") { _, _ ->
                BrowserPreferences.resetHomepage(this)
                refreshHomepageStatus()
                Toast.makeText(this, "Homepage reset", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun confirmClearResolverCache() {
        AlertDialog.Builder(this)
            .setTitle("Clear resolver cache?")
            .setMessage("The app will keep synced headers and peers, but cached HNS resource values will be removed.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                clearResolverCache()
            }
            .show()
    }

    private fun clearResolverCache() {
        val result = NativeBridge.clearResolverCache(filesDir.absolutePath)
        val status = runCatching { JSONObject(result).optString("status") }.getOrDefault("")
        val message = if (status == "cleared") {
            "Resolver cache cleared"
        } else {
            "Resolver cache did not report a successful clear"
        }
        resolverCacheStatus.text = if (status == "cleared") {
            "Cleared just now."
        } else {
            "Clear did not complete. Open diagnostics for details."
        }
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun refreshHomepageStatus() {
        homepageStatus.text = BrowserPreferences.homepage(this)
    }

    private fun refreshCookieStatus() {
        cookieStatus.text = cookieSummary()
    }

    private fun refreshHnsModeStatus() {
        hnsModeStatus.text = hnsModeText()
    }

    private fun refreshStatelessDaneStatus() {
        statelessDaneStatus.text = statelessDaneText()
    }

    private fun refreshDohResolverStatus() {
        dohResolverStatus.text = HnsResolutionPreferences.dohResolverUrl(this)
    }

    private fun refreshHistoryStatus() {
        historyStatus.text = historySummary()
    }

    private fun refreshDownloadStatus() {
        downloadStatus.text = downloadSummary()
    }

    private fun hnsModeText(): String =
        if (HnsResolutionPreferences.strictHnsMode(this)) {
            "On. Delegated resolution failures fail closed."
        } else {
            "Off. Compatibility fallback may be used after local or direct resolution fails."
        }

    private fun statelessDaneText(): String =
        if (HnsResolutionPreferences.statelessDaneCertificates(this)) {
            "On. Certificate-carried HNS proof evidence may satisfy DANE when valid."
        } else {
            "Off. HNS proof and TLSA evidence use the live resolver path."
        }

    private fun cookieSummary(): String =
        if (BrowserCookiePreferences.blockThirdPartyCookies(this)) {
            "Third-party cookies are blocked. First-party cookies are allowed."
        } else {
            "First-party and third-party cookies are allowed."
        }

    private fun historySummary(): String {
        val count = BrowserHistoryStore.entries(this).size
        return "$count saved page${if (count == 1) "" else "s"}"
    }

    private fun downloadSummary(): String {
        val count = BrowserDownloadStore.records(this).size
        return "$count app-queued record${if (count == 1) "" else "s"}"
    }

    private fun currentUrlFromIntent(): String? =
        intent.getStringExtra(EXTRA_CURRENT_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) "debug demo" else "release"
        return "$channel ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
    }

    companion object {
        const val EXTRA_CURRENT_URL = "com.denuoweb.hnsdane.CURRENT_URL"
    }
}
