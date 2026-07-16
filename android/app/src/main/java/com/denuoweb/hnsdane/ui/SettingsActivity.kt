package com.denuoweb.hnsdane.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
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
import com.denuoweb.hnsdane.HnsDaneApplication
import com.denuoweb.hnsdane.R
import com.denuoweb.hnsdane.BuildConfig
import com.denuoweb.hnsdane.net.NativeBridge
import com.denuoweb.hnsdane.net.ProcessHnsSyncSingleFlight
import org.json.JSONObject
import kotlin.concurrent.thread

class SettingsActivity : ComponentActivity() {
    private lateinit var homepageStatus: TextView
    private lateinit var cookieStatus: TextView
    private lateinit var hnsNetworkStatus: TextView
    private lateinit var hnsModeStatus: TextView
    private lateinit var statelessDaneStatus: TextView
    private lateinit var dohResolverStatus: TextView
    private lateinit var resolverCacheStatus: TextView
    private lateinit var historyStatus: TextView
    private lateinit var downloadStatus: TextView
    private lateinit var themeStatus: TextView
    private var resolverCacheClearInProgress = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val colors = themeColors()

        homepageStatus = preferenceSummary(BrowserPreferences.homepage(this))
        cookieStatus = preferenceSummary(cookieSummary())
        hnsNetworkStatus = preferenceSummary(hnsNetworkText())
        hnsModeStatus = preferenceSummary(hnsModeText())
        statelessDaneStatus = preferenceSummary(statelessDaneText())
        dohResolverStatus = preferenceSummary(HnsResolutionPreferences.dohResolverUrl(this))
        resolverCacheStatus = preferenceSummary(getString(R.string.settings_resolver_cache_ready))
        historyStatus = preferenceSummary(historySummary())
        downloadStatus = preferenceSummary(downloadSummary())
        themeStatus = preferenceSummary(themeText())

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.START
            setBackgroundColor(colors.background)
            setPadding(dp(20), dp(20), dp(20), dp(20))
            applySystemBarPadding()
            addView(heading(getString(R.string.screen_settings)))

            addView(section(getString(R.string.section_start_page)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_homepage),
                    summaryView = homepageStatus,
                    actionLabel = getString(R.string.action_edit),
                ) {
                    showEditHomepageDialog()
                })
                currentUrlFromIntent()?.let { currentUrl ->
                    addPreference(preferenceRow(
                        title = getString(R.string.row_set_current_page_homepage),
                        summary = currentUrl,
                        actionLabel = getString(R.string.action_set),
                    ) {
                        useCurrentPageAsHomepage(currentUrl)
                    })
                }
                addPreference(preferenceRow(
                    title = getString(R.string.row_reset_homepage),
                    summary = getString(R.string.row_reset_homepage_summary),
                    actionLabel = getString(R.string.action_reset),
                    destructive = true,
                ) {
                    confirmResetHomepage()
                })
            })

            addView(section(getString(R.string.section_privacy_and_data)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_cookies),
                    summaryView = cookieStatus,
                    actionLabel = getString(R.string.action_manage),
                ) {
                    startActivity(Intent(this@SettingsActivity, CookieSettingsActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_history),
                    summaryView = historyStatus,
                    actionLabel = getString(R.string.action_view),
                ) {
                    startActivity(Intent(this@SettingsActivity, HistoryActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_downloads),
                    summaryView = downloadStatus,
                    actionLabel = getString(R.string.action_view),
                ) {
                    startActivity(Intent(this@SettingsActivity, DownloadsActivity::class.java))
                })
            })

            addView(section(getString(R.string.section_appearance)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_theme),
                    summaryView = themeStatus,
                    actionLabel = getString(R.string.action_change),
                ) {
                    showThemeDialog()
                })
            })

            addView(section(getString(R.string.section_language)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_app_language),
                    summary = getString(R.string.row_app_language_summary),
                    actionLabel = getString(R.string.action_open),
                ) {
                    openAppLanguageSettings()
                })
            })

            addView(section(getString(R.string.section_hns_resolution)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_handshake_network),
                    summaryView = hnsNetworkStatus,
                    actionLabel = getString(R.string.action_change),
                ) {
                    showNetworkDialog()
                })
                addPreference(strictHnsModeOption())
                addPreference(statelessDaneCertificateOption())
                addPreference(preferenceRow(
                    title = getString(R.string.row_compatibility_doh_resolver),
                    summaryView = dohResolverStatus,
                    actionLabel = getString(R.string.action_edit),
                ) {
                    showEditDohResolverDialog()
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_clear_resolver_cache),
                    summaryView = resolverCacheStatus,
                    actionLabel = getString(R.string.action_clear),
                    destructive = true,
                ) {
                    confirmClearResolverCache()
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_hns_sync),
                    summary = getString(R.string.row_hns_sync_summary),
                    actionLabel = getString(R.string.action_view),
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsSyncActivity::class.java))
                })
            })

            addView(section(getString(R.string.section_diagnostics_tools)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_hns_domain_setup),
                    summary = getString(R.string.row_hns_domain_setup_summary),
                    actionLabel = getString(R.string.action_open),
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsDomainWizardActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_resolver_trace),
                    summary = getString(R.string.row_resolver_trace_summary),
                    actionLabel = getString(R.string.action_open),
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsResolverTraceActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_hns_proof_details),
                    summary = getString(R.string.row_hns_proof_details_summary),
                    actionLabel = getString(R.string.action_open),
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsProofDetailsActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_tlsa_dane_inspector),
                    summary = getString(R.string.row_tlsa_dane_inspector_summary),
                    actionLabel = getString(R.string.action_open),
                ) {
                    startActivity(Intent(this@SettingsActivity, HnsTlsaInspectorActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_diagnostics),
                    summary = getString(R.string.row_diagnostics_summary),
                    actionLabel = getString(R.string.action_view),
                ) {
                    startActivity(Intent(this@SettingsActivity, DiagnosticsActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_gateway),
                    summary = getString(R.string.row_gateway_summary),
                    actionLabel = getString(R.string.action_view),
                ) {
                    startActivity(Intent(this@SettingsActivity, GatewayActivity::class.java))
                })
            })

            addView(section(getString(R.string.section_about_legal_support)) {
                addPreference(preferenceRow(
                    title = getString(R.string.row_build),
                    summary = buildLabel(),
                ))
                addPreference(preferenceRow(
                    title = getString(R.string.row_legal),
                    summary = getString(R.string.row_legal_summary),
                    actionLabel = getString(R.string.action_view),
                ) {
                    startActivity(Intent(this@SettingsActivity, LegalActivity::class.java))
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_privacy_policy),
                    summary = BrowserAppInfo.PRIVACY_POLICY_URL,
                    actionLabel = getString(R.string.action_open),
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.PRIVACY_POLICY_URL),
                        getString(R.string.legal_copy_privacy_policy_url),
                        BrowserAppInfo.PRIVACY_POLICY_URL,
                    )
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_source_code),
                    summary = BrowserAppInfo.SOURCE_CODE_URL,
                    actionLabel = getString(R.string.action_open),
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.SOURCE_CODE_URL),
                        getString(R.string.legal_copy_source_code_url),
                        BrowserAppInfo.SOURCE_CODE_URL,
                    )
                })
                addPreference(preferenceRow(
                    title = getString(R.string.row_donate_hns),
                    summary = getString(R.string.row_donate_hns_summary),
                    actionLabel = getString(R.string.action_open),
                ) {
                    openLink(
                        Uri.parse(BrowserAppInfo.HNS_DONATION_URI),
                        getString(R.string.legal_copy_hns_donation_address),
                        BrowserAppInfo.HNS_DONATION_ADDRESS,
                    )
                })
            })
        }

        setContentView(
            ScrollView(this).apply {
                setBackgroundColor(colors.background)
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
            refreshHnsNetworkStatus()
            refreshHnsModeStatus()
            refreshStatelessDaneStatus()
            refreshHistoryStatus()
            refreshDownloadStatus()
            refreshThemeStatus()
        }
    }

    private fun heading(text: String): TextView =
        TextView(this).apply {
            val colors = themeColors()
            this.text = text
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(colors.primaryText)
            setPadding(0, 0, 0, dp(10))
        }

    private fun section(title: String, content: LinearLayout.() -> Unit): LinearLayout =
        LinearLayout(this).apply {
            val colors = themeColors()
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colors.background)
            setPadding(0, dp(10), 0, dp(12))
            addView(sectionHeading(title))
            content()
        }

    private fun sectionHeading(text: String): TextView =
        TextView(this).apply {
            val colors = themeColors()
            this.text = text
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(colors.secondaryText)
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
            val colors = themeColors()
            this.text = text
            textSize = 16f
            setTextColor(colors.primaryText)
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
        }

    private fun preferenceSummary(text: String): TextView =
        TextView(this).apply {
            val colors = themeColors()
            this.text = text
            textSize = 14f
            setTextColor(colors.secondaryText)
            maxLines = 3
            ellipsize = TextUtils.TruncateAt.END
            setPadding(0, dp(3), 0, 0)
        }

    private fun preferenceActionLabel(text: String, destructive: Boolean): TextView =
        TextView(this).apply {
            val colors = themeColors()
            this.text = text
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER_VERTICAL or Gravity.END
            minWidth = dp(56)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
            setTextColor(
                if (destructive) {
                    colors.destructive
                } else {
                    colors.action
                },
            )
        }

    private fun strictHnsModeOption(): LinearLayout =
        LinearLayout(this).apply {
            val colors = themeColors()
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colors.background)
            setPadding(0, dp(8), 0, dp(10))
            addView(CheckBox(this@SettingsActivity).apply {
                text = getString(R.string.settings_strict_hns_mode)
                textSize = 16f
                setTextColor(colors.primaryText)
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
            val colors = themeColors()
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colors.background)
            setPadding(0, dp(8), 0, dp(10))
            addView(CheckBox(this@SettingsActivity).apply {
                text = getString(R.string.settings_stateless_dane_certificates)
                textSize = 16f
                setTextColor(colors.primaryText)
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
            setBackgroundColor(themeColors().divider)
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
            startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (_: ActivityNotFoundException) {
            getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText(copyLabel, copyText))
            Toast.makeText(this, getString(R.string.common_copied_label, copyLabel), Toast.LENGTH_SHORT).show()
        }
    }

    private fun openAppLanguageSettings() {
        val packageUri = Uri.fromParts("package", packageName, null)
        val languageSettings = Intent(ACTION_APP_LOCALE_SETTINGS).setData(packageUri)
        try {
            startActivity(languageSettings)
            return
        } catch (_: ActivityNotFoundException) {
            // Fall through to app details on Android builds without a direct app-language panel.
        }

        try {
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(packageUri))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, getString(R.string.settings_open_language_failed), Toast.LENGTH_SHORT).show()
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
            .setTitle(R.string.settings_homepage_edit_title)
            .setMessage(R.string.settings_homepage_edit_message)
            .setView(input)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_save, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val saved = BrowserPreferences.setHomepage(this, input.text.toString(), NativeBridge)
                if (saved == null) {
                    input.error = getString(R.string.settings_homepage_error)
                    return@setOnClickListener
                }
                refreshHomepageStatus()
                Toast.makeText(this, getString(R.string.settings_homepage_saved), Toast.LENGTH_SHORT).show()
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
            .setTitle(R.string.settings_doh_edit_title)
            .setMessage(R.string.settings_doh_edit_message)
            .setView(input)
            .setNegativeButton(R.string.action_cancel, null)
            .setNeutralButton(R.string.action_reset, null)
            .setPositiveButton(R.string.action_save, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val saved = HnsResolutionPreferences.setDohResolverUrl(this, input.text.toString())
                if (saved == null) {
                    input.error = getString(R.string.settings_doh_error)
                    return@setOnClickListener
                }
                refreshDohResolverStatus()
                Toast.makeText(this, getString(R.string.settings_doh_saved), Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                HnsResolutionPreferences.resetDohResolverUrl(this)
                refreshDohResolverStatus()
                Toast.makeText(this, getString(R.string.settings_doh_reset), Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun showNetworkDialog() {
        val networks = HandshakeNetwork.entries.toTypedArray()
        val labels = networks
            .map { getString(R.string.settings_network_choice, it.displayName(this), it.summary(this)) }
            .toTypedArray()
        val current = HnsResolutionPreferences.handshakeNetwork(this)
        val selectedIndex = networks.indexOf(current).coerceAtLeast(0)

        AlertDialog.Builder(this)
            .setTitle(R.string.row_handshake_network)
            .setSingleChoiceItems(labels, selectedIndex) { dialog, index ->
                val selected = networks[index]
                if (selected != current) {
                    HnsResolutionPreferences.setHandshakeNetwork(this, selected)
                    (application as? HnsDaneApplication)?.onHandshakeNetworkChanged()
                    refreshHnsNetworkStatus()
                    val selectedName = selected.displayName(this)
                    resolverCacheStatus.text = getString(R.string.settings_resolver_cache_ready_network, selectedName)
                    Toast.makeText(this, getString(R.string.settings_network_set, selectedName), Toast.LENGTH_SHORT).show()
                }
                dialog.dismiss()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun showThemeDialog() {
        val modes = BrowserThemeMode.entries.toTypedArray()
        val labels = modes
            .map { themeChoiceText(it) }
            .toTypedArray()
        val current = BrowserThemePreferences.themeMode(this)
        val selectedIndex = modes.indexOf(current).coerceAtLeast(0)

        AlertDialog.Builder(this)
            .setTitle(R.string.settings_theme_dialog_title)
            .setSingleChoiceItems(labels, selectedIndex) { dialog, index ->
                val selected = modes[index]
                if (selected != current) {
                    BrowserThemePreferences.setThemeMode(this, selected)
                    refreshThemeStatus()
                    Toast.makeText(
                        this,
                        getString(R.string.settings_theme_set, themeChoiceText(selected)),
                        Toast.LENGTH_SHORT,
                    ).show()
                    BrowserThemePreferences.applyTo(this)
                    recreate()
                }
                dialog.dismiss()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun useCurrentPageAsHomepage(currentUrl: String) {
        val saved = BrowserPreferences.setHomepage(this, currentUrl, NativeBridge)
        if (saved == null) {
            Toast.makeText(this, getString(R.string.settings_homepage_current_unsupported), Toast.LENGTH_SHORT).show()
            return
        }
        refreshHomepageStatus()
        Toast.makeText(this, getString(R.string.settings_homepage_saved), Toast.LENGTH_SHORT).show()
    }

    private fun confirmResetHomepage() {
        AlertDialog.Builder(this)
            .setTitle(R.string.settings_homepage_reset_title)
            .setMessage(R.string.settings_homepage_reset_message)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_reset) { _, _ ->
                BrowserPreferences.resetHomepage(this)
                refreshHomepageStatus()
                Toast.makeText(this, getString(R.string.settings_homepage_reset), Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun confirmClearResolverCache() {
        val network = HnsResolutionPreferences.handshakeNetwork(this)
        val networkName = network.displayName(this)
        AlertDialog.Builder(this)
            .setTitle(R.string.settings_resolver_cache_clear_title)
            .setMessage(getString(R.string.settings_resolver_cache_clear_message, networkName))
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_clear) { _, _ ->
                clearResolverCache()
            }
            .show()
    }

    private fun clearResolverCache() {
        if (resolverCacheClearInProgress) {
            Toast.makeText(this, getString(R.string.sync_already_running), Toast.LENGTH_SHORT).show()
            return
        }
        val network = HnsResolutionPreferences.handshakeNetwork(this)
        val networkName = network.displayName(this)
        val dataDir = filesDir.absolutePath
        resolverCacheClearInProgress = true
        resolverCacheStatus.text = getString(R.string.common_running)
        thread(name = "hns-resolver-cache-clear") {
            val result = ProcessHnsSyncSingleFlight.tryRun {
                NativeBridge.clearResolverCache(dataDir, network.id)
            }
            val status = result?.let { runCatching { JSONObject(it).optString("status") }.getOrDefault("") }
            runOnUiThread {
                resolverCacheClearInProgress = false
                if (isDestroyed) {
                    return@runOnUiThread
                }
                if (status == null) {
                    resolverCacheStatus.text = getString(R.string.settings_resolver_cache_ready)
                    Toast.makeText(this, getString(R.string.sync_already_running), Toast.LENGTH_SHORT).show()
                    return@runOnUiThread
                }
                val message = if (status == "cleared") {
                    getString(R.string.settings_resolver_cache_cleared, networkName)
                } else {
                    getString(R.string.settings_resolver_cache_clear_failed)
                }
                resolverCacheStatus.text = if (status == "cleared") {
                    getString(R.string.settings_resolver_cache_cleared_status, networkName)
                } else {
                    getString(R.string.settings_resolver_cache_clear_failed_status)
                }
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun refreshHomepageStatus() {
        homepageStatus.text = BrowserPreferences.homepage(this)
    }

    private fun refreshCookieStatus() {
        cookieStatus.text = cookieSummary()
    }

    private fun refreshHnsNetworkStatus() {
        hnsNetworkStatus.text = hnsNetworkText()
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

    private fun refreshThemeStatus() {
        themeStatus.text = themeText()
    }

    private fun hnsModeText(): String =
        if (HnsResolutionPreferences.strictHnsMode(this)) {
            getString(R.string.settings_hns_mode_on)
        } else {
            getString(R.string.settings_hns_mode_off)
        }

    private fun hnsNetworkText(): String {
        val network = HnsResolutionPreferences.handshakeNetwork(this)
        return getString(R.string.settings_hns_network_summary, network.displayName(this), network.summary(this))
    }

    private fun statelessDaneText(): String =
        if (HnsResolutionPreferences.statelessDaneCertificates(this)) {
            getString(R.string.settings_stateless_dane_on)
        } else {
            getString(R.string.settings_stateless_dane_off)
        }

    private fun cookieSummary(): String =
        if (BrowserCookiePreferences.blockThirdPartyCookies(this)) {
            getString(R.string.settings_cookie_summary_blocking)
        } else {
            getString(R.string.cookie_summary_allowing_all)
        }

    private fun historySummary(): String {
        val count = BrowserHistoryStore.entries(this).size
        return resources.getQuantityString(R.plurals.settings_saved_pages, count, count)
    }

    private fun downloadSummary(): String {
        val count = BrowserDownloadStore.records(this).size
        return resources.getQuantityString(R.plurals.settings_app_queued_records, count, count)
    }

    private fun themeText(): String =
        when (BrowserThemePreferences.themeMode(this)) {
            BrowserThemeMode.System -> getString(R.string.row_theme_summary_system)
            BrowserThemeMode.Light -> getString(R.string.row_theme_summary_light)
            BrowserThemeMode.Dark -> getString(R.string.row_theme_summary_dark)
        }

    private fun themeChoiceText(mode: BrowserThemeMode): String =
        when (mode) {
            BrowserThemeMode.System -> getString(R.string.theme_choice_system)
            BrowserThemeMode.Light -> getString(R.string.theme_choice_light)
            BrowserThemeMode.Dark -> getString(R.string.theme_choice_dark)
        }

    private fun currentUrlFromIntent(): String? =
        intent.getStringExtra(EXTRA_CURRENT_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }

    private fun buildLabel(): String {
        val channel = if (BuildConfig.DEBUG) {
            getString(R.string.common_debug_demo)
        } else {
            getString(R.string.common_release)
        }
        return getString(R.string.common_build_label, channel, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE)
    }

    companion object {
        const val EXTRA_CURRENT_URL = "com.denuoweb.hnsdane.CURRENT_URL"
        private const val ACTION_APP_LOCALE_SETTINGS = "android.settings.APP_LOCALE_SETTINGS"
    }
}
