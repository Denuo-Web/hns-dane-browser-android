package com.denuoweb.hnsdane.ui

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.ContentValues
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.text.InputType
import android.text.TextUtils
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebChromeClient
import android.webkit.SslErrorHandler
import android.webkit.URLUtil
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.net.http.SslError
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupWindow
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.core.content.ContextCompat
import androidx.webkit.ServiceWorkerControllerCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebViewRenderProcess
import androidx.webkit.WebViewRenderProcessClient
import com.denuoweb.hnsdane.BuildConfig
import com.denuoweb.hnsdane.R
import com.denuoweb.hnsdane.core.BrowserSecurityPolicy
import com.denuoweb.hnsdane.core.BrowserTargetKind
import com.denuoweb.hnsdane.core.BrowserUrlClassifier
import com.denuoweb.hnsdane.core.HnsPageResolverPolicy
import com.denuoweb.hnsdane.core.HnsPageTlsPolicy
import com.denuoweb.hnsdane.core.SecurityState
import com.denuoweb.hnsdane.net.BundledHeaderSyncBridge
import com.denuoweb.hnsdane.net.GatewayEventLog
import com.denuoweb.hnsdane.net.HnsProxyController
import com.denuoweb.hnsdane.net.HnsServiceWorkerGatewayClient
import com.denuoweb.hnsdane.net.HnsSyncProgress
import com.denuoweb.hnsdane.net.HnsSyncScheduler
import com.denuoweb.hnsdane.net.HnsSyncSnapshot
import com.denuoweb.hnsdane.net.HnsNativeDownloadFetcher
import com.denuoweb.hnsdane.net.HnsWebSocketBridge
import com.denuoweb.hnsdane.net.HnsWebSocketShim
import com.denuoweb.hnsdane.net.HnsWebViewGatewayInterceptor
import com.denuoweb.hnsdane.net.HnsWebViewSslErrorPolicy
import com.denuoweb.hnsdane.net.LoopbackProxyServer
import com.denuoweb.hnsdane.net.NativeBridge
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.util.Locale
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {
    private val classifier = BrowserUrlClassifier()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val syncStatusExecutor = Executors.newSingleThreadExecutor()
    private val downloadExecutor = Executors.newSingleThreadExecutor()
    @Volatile
    private var syncStatusPolling: Boolean = false
    private val syncStatusPollRunnable = object : Runnable {
        override fun run() {
            pollSyncStatusOnce()
        }
    }
    private lateinit var webView: WebView
    private lateinit var omnibox: EditText
    private lateinit var securityLabel: TextView
    private lateinit var hamburgerButton: TextView
    private lateinit var syncProgressBar: ProgressBar
    private lateinit var syncProgressStats: TextView
    private lateinit var pageProgressBar: ProgressBar
    private lateinit var proxyController: HnsProxyController
    private lateinit var hnsWebSocketBridge: HnsWebSocketBridge
    private var loopbackProxyServer: LoopbackProxyServer? = null
    private lateinit var assetLoader: WebViewAssetLoader
    private lateinit var webViewGatewayInterceptor: HnsWebViewGatewayInterceptor
    private var proxyAvailable: Boolean = false
    private var currentTargetKind: BrowserTargetKind? = null
    private var mainFrameHnsStatusCode: Int? = null
    private var mainFrameHnsTlsPolicy: HnsPageTlsPolicy? = null
    private var mainFrameHnsResolverPolicy: HnsPageResolverPolicy? = null
    private var mainFrameHnsTraceJson: String? = null
    private var mainFrameHnsStatusUrl: String? = null
    private var lastSyncSnapshot: HnsSyncSnapshot? = null
    private var activeSyncScheduler: HnsSyncScheduler? = null
    private var activityStarted: Boolean = false
    private var activityDestroyed: Boolean = false
    private var proxyOverrideApplied: Boolean = false
    private var proxyOverrideClearing: Boolean = false
    private var proxyStartPending: Boolean = false
    private var proxyGatewayPort: Int? = null
    private var proxyScopedHost: String? = null
    @Volatile
    private var activeMainFrameUrl: String? = null
    private var pageIsLoading: Boolean = false
    private var pageLoadProgress: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val colors = themeColors()

        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        GatewayEventLog.configureAppStorage(filesDir)
        proxyController = HnsProxyController(this)
        hnsWebSocketBridge = HnsWebSocketBridge(
            dataDir = filesDir,
            activeMainFrameUrl = { activeMainFrameUrl },
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            dohResolverUrl = { HnsResolutionPreferences.dohResolverUrl(this) },
            statelessDaneCertificates = { HnsResolutionPreferences.statelessDaneCertificates(this) },
            handshakeNetwork = { HnsResolutionPreferences.handshakeNetworkId(this) },
            callbackHandler = mainHandler,
        )
        webViewGatewayInterceptor = HnsWebViewGatewayInterceptor(
            dataDir = filesDir,
            allowProxyFallbackForBodyRequests = { proxyAvailable },
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            dohResolverUrl = { HnsResolutionPreferences.dohResolverUrl(this) },
            statelessDaneCertificates = { HnsResolutionPreferences.statelessDaneCertificates(this) },
            handshakeNetwork = { HnsResolutionPreferences.handshakeNetworkId(this) },
            onMainFrameHnsStatus = { statusCode, tlsPolicy, resolverPolicy, traceJson ->
                runOnUiThread {
                    if (mainFrameHnsStatusCode == null) {
                        applyMainFrameHnsStatus(statusCode, tlsPolicy, resolverPolicy, traceJson)
                    }
                }
            },
        )
        assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
        configureServiceWorkerInterception()

        omnibox = EditText(this).apply {
            hint = getString(R.string.omnibox_hint)
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_URI or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            textSize = 16f
            minHeight = dp(48)
            imeOptions = EditorInfo.IME_ACTION_GO or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            setSelectAllOnFocus(true)
            setOnEditorActionListener { _, actionId, event ->
                val decision = omniboxEditorDecision(actionId, event?.keyCode, event?.action)
                if (decision.submit) {
                    loadFromInput()
                }
                decision.consume
            }
        }

        securityLabel = TextView(this).apply {
            gravity = Gravity.CENTER
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
            textSize = 13f
            minHeight = dp(TOOLBAR_CONTROL_HEIGHT_DP)
            setPadding(dp(8), 0, dp(8), 0)
            setTextColor(colors.securityText)
            text = getString(R.string.security_syncing)
            contentDescription = getString(R.string.security_status_content_description)
            isClickable = true
            isFocusable = true
            applyScreenSelectableBackground()
            setOnClickListener { openResolverTrace() }
        }

        syncProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = SYNC_PROGRESS_MAX
            isIndeterminate = true
        }
        syncProgressStats = TextView(this).apply {
            setPadding(16, 0, 16, 8)
            setTextColor(colors.secondaryText)
            textSize = 12f
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
            text = HnsSyncProgress.fromJson(null).summary(this@MainActivity)
        }
        pageProgressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = PAGE_PROGRESS_MAX
            progress = 0
            visibility = View.GONE
        }

        webView = WebView(this).apply {
            BrowserWebViewHardening.applyTo(this, allowJavaScript = true)
            webViewClient = BrowserClient()
            webChromeClient = BrowserChromeClient()
            setDownloadListener { url, userAgent, contentDisposition, mimeType, _ ->
                handleDownload(url, userAgent, contentDisposition, mimeType)
            }
        }
        configureHnsWebSocketBridge()
        configureRendererRecovery()

        BrowserCookiePreferences.applyTo(webView)

        val toolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(8), 0, dp(8), 0)
            addView(securityLabel, LinearLayout.LayoutParams(
                dp(SECURITY_LABEL_WIDTH_DP),
                dp(TOOLBAR_CONTROL_HEIGHT_DP),
            ))
            addView(omnibox, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(menuButton())
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colors.background)
            applySystemBarPadding()
            addView(toolbar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(syncProgressBar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(syncProgressStats, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(pageProgressBar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ))
            addView(webView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            ))
        }

        setContentView(root)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        if (savedInstanceState == null) {
            loadInitialPage(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.getStringExtra(EXTRA_LOAD_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?.let { loadTarget(classifier.classify(it)) }
    }

    override fun onStart() {
        super.onStart()
        activityStarted = true
        BrowserCookiePreferences.applyTo(webView)
        startLoopbackGateway()
        lastSyncSnapshot = HnsSyncSnapshot(
            statusJson = NativeBridge.syncStatus(
                filesDir.absolutePath,
                HnsResolutionPreferences.handshakeNetworkId(this),
            ),
            updatedAtMillis = System.currentTimeMillis(),
        )
        refreshSecurityState()
        refreshSyncProgress()
        startActiveSync()
        startSyncStatusPolling()
    }

    override fun onStop() {
        activityStarted = false
        stopSyncStatusPolling()
        stopActiveSync()
        stopLoopbackGateway()
        super.onStop()
    }

    override fun onDestroy() {
        activityDestroyed = true
        stopActiveSync()
        stopLoopbackGateway()
        hnsWebSocketBridge.close()
        syncStatusExecutor.shutdownNow()
        downloadExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun createLoopbackGateway(): LoopbackProxyServer =
        LoopbackProxyServer(
            EPHEMERAL_GATEWAY_PORT,
            filesDir,
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            dohResolverUrl = { HnsResolutionPreferences.dohResolverUrl(this) },
            statelessDaneCertificates = { HnsResolutionPreferences.statelessDaneCertificates(this) },
            handshakeNetwork = { HnsResolutionPreferences.handshakeNetworkId(this) },
            enforceHnsHostScope = true,
            scopedHnsHost = { currentHnsProxyHost() },
            onHnsStatus = { host, statusCode, tlsPolicy, resolverPolicy, traceJson ->
                runOnUiThread {
                    if (isActiveMainFrameHost(host) && mainFrameHnsStatusCode == null) {
                        applyMainFrameHnsStatus(statusCode, tlsPolicy, resolverPolicy, traceJson)
                    }
                }
            },
        )

    private fun startLoopbackGateway() {
        if (activityDestroyed) {
            return
        }
        if (proxyOverrideClearing) {
            proxyStartPending = true
            return
        }
        if (loopbackProxyServer != null) {
            return
        }
        if (currentHnsProxyHost() == null) {
            proxyStartPending = false
            return
        }

        val gateway = createLoopbackGateway()
        loopbackProxyServer = gateway
        val gatewayStarted = gateway.start()
        val gatewayPort = gateway.boundPort()
        if (gatewayStarted && gatewayPort != null) {
            proxyGatewayPort = gatewayPort
            refreshLoopbackProxyScope()
        } else {
            if (loopbackProxyServer === gateway) {
                loopbackProxyServer = null
            }
            proxyAvailable = false
            proxyGatewayPort = null
            proxyScopedHost = null
            gateway.close()
            refreshSecurityState()
        }
    }

    private fun refreshLoopbackProxyScope() {
        val hnsHost = currentHnsProxyHost()
        if (proxyOverrideClearing) {
            proxyStartPending = hnsHost != null
            return
        }
        if (hnsHost == null) {
            stopLoopbackGateway()
            return
        }

        val gateway = loopbackProxyServer
        if (gateway == null) {
            startLoopbackGateway()
            return
        }
        val gatewayPort = proxyGatewayPort ?: gateway.boundPort() ?: return
        if (proxyOverrideApplied && proxyAvailable && proxyScopedHost == hnsHost) {
            return
        }

        proxyController.applyLoopbackProxy(gatewayPort, hnsHost) { applied ->
            if (loopbackProxyServer !== gateway || currentHnsProxyHost() != hnsHost) {
                return@applyLoopbackProxy
            }
            proxyAvailable = applied
            proxyOverrideApplied = applied
            proxyScopedHost = if (applied) hnsHost else null
            if (applied) {
                refreshSecurityState()
            } else {
                stopLoopbackGateway()
            }
        }
    }

    private fun stopLoopbackGateway() {
        val gateway = loopbackProxyServer
        val shouldClearProxy = gateway != null || proxyOverrideApplied
        if (gateway != null) {
            loopbackProxyServer = null
            proxyAvailable = false
            proxyGatewayPort = null
            proxyScopedHost = null
            gateway.close()
            refreshSecurityState()
        } else {
            proxyAvailable = false
            proxyGatewayPort = null
            proxyScopedHost = null
        }

        if (!shouldClearProxy) {
            return
        }
        if (proxyOverrideClearing) {
            return
        }

        proxyOverrideClearing = true
        proxyController.clear {
            proxyOverrideClearing = false
            proxyOverrideApplied = false
            val shouldRestart = proxyStartPending && activityStarted && !activityDestroyed
            proxyStartPending = false
            if (shouldRestart) {
                startLoopbackGateway()
                refreshLoopbackProxyScope()
            } else {
                refreshSecurityState()
            }
        }
    }

    private fun configureServiceWorkerInterception() {
        if (
            !WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_BASIC_USAGE) ||
            !WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_SHOULD_INTERCEPT_REQUEST)
        ) {
            return
        }

        val serviceWorkerController = ServiceWorkerControllerCompat.getInstance()
        val serviceWorkerSettings = serviceWorkerController.serviceWorkerWebSettings
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_CACHE_MODE)) {
            serviceWorkerSettings.cacheMode = WebSettings.LOAD_NO_CACHE
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_CONTENT_ACCESS)) {
            serviceWorkerSettings.allowContentAccess = false
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_FILE_ACCESS)) {
            serviceWorkerSettings.allowFileAccess = false
        }
        serviceWorkerController.setServiceWorkerClient(
            HnsServiceWorkerGatewayClient(webViewGatewayInterceptor),
        )
    }

    private fun configureHnsWebSocketBridge() {
        if (
            !WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER) ||
            !WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)
        ) {
            return
        }
        WebViewCompat.addWebMessageListener(
            webView,
            HnsWebSocketShim.JS_OBJECT_NAME,
            setOf("*"),
            hnsWebSocketBridge,
        )
        WebViewCompat.addDocumentStartJavaScript(
            webView,
            HnsWebSocketShim.script(),
            setOf("*"),
        )
    }

    private fun configureRendererRecovery() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_VIEW_RENDERER_CLIENT_BASIC_USAGE)) {
            return
        }

        WebViewCompat.setWebViewRenderProcessClient(
            webView,
            ContextCompat.getMainExecutor(this),
            object : WebViewRenderProcessClient() {
                override fun onRenderProcessUnresponsive(
                    view: WebView,
                    renderer: WebViewRenderProcess?,
                ) {
                    Toast.makeText(
                        this@MainActivity,
                        getString(R.string.toast_webview_renderer_unresponsive),
                        Toast.LENGTH_SHORT,
                    ).show()
                    renderer?.terminate()
                }

                override fun onRenderProcessResponsive(
                    view: WebView,
                    renderer: WebViewRenderProcess?,
                ) = Unit
            },
        )
    }

    private fun startSyncStatusPolling() {
        syncStatusPolling = true
        mainHandler.removeCallbacks(syncStatusPollRunnable)
        mainHandler.postDelayed(syncStatusPollRunnable, SYNC_STATUS_POLL_MS)
    }

    private fun stopSyncStatusPolling() {
        syncStatusPolling = false
        mainHandler.removeCallbacks(syncStatusPollRunnable)
    }

    private fun pollSyncStatusOnce() {
        if (!syncStatusPolling) {
            return
        }

        syncStatusExecutor.execute {
            val snapshot = HnsSyncSnapshot(
                statusJson = NativeBridge.syncStatus(
                    filesDir.absolutePath,
                    HnsResolutionPreferences.handshakeNetworkId(this),
                ),
                updatedAtMillis = System.currentTimeMillis(),
            )
            runOnUiThread {
                if (!syncStatusPolling) {
                    return@runOnUiThread
                }
                lastSyncSnapshot = snapshot
                refreshSecurityState()
                refreshSyncProgress()
                mainHandler.postDelayed(syncStatusPollRunnable, SYNC_STATUS_POLL_MS)
            }
        }
    }

    private fun startActiveSync() {
        if (activeSyncScheduler != null || activityDestroyed) {
            return
        }

        val scheduler = HnsSyncScheduler(
            filesDir,
            bridge = BundledHeaderSyncBridge(this),
            network = { HnsResolutionPreferences.handshakeNetworkId(this) },
        )
        activeSyncScheduler = scheduler
        scheduler.start { snapshot ->
            mainHandler.post {
                if (activeSyncScheduler !== scheduler || activityDestroyed) {
                    return@post
                }
                lastSyncSnapshot = snapshot
                refreshSecurityState()
                refreshSyncProgress()
            }
        }
    }

    private fun stopActiveSync() {
        activeSyncScheduler?.close()
        activeSyncScheduler = null
    }

    private fun menuButton(): TextView =
        TextView(this).apply {
            val colors = themeColors()
            hamburgerButton = this
            text = "☰"
            textSize = 34f
            gravity = Gravity.CENTER
            contentDescription = getString(R.string.menu_hamburger_content_description)
            minWidth = dp(MENU_ICON_BUTTON_SIZE_DP)
            minHeight = dp(MENU_ICON_BUTTON_SIZE_DP)
            setPadding(dp(14), 0, dp(14), 0)
            setTextColor(colors.primaryText)
            setOnClickListener { showHamburgerMenu() }
        }

    private fun showHamburgerMenu() {
        val popup = PopupWindow(this)
        val colors = themeColors()
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colors.surface)
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                addView(menuIconButton("›", getString(R.string.menu_forward), webView.canGoForward(), popup) {
                    webView.goForward()
                })
                addView(menuIconButton("↻", getString(R.string.menu_refresh), true, popup) {
                    reloadCurrentPage()
                })
                addView(menuIconButton("⌂", getString(R.string.menu_home), true, popup) {
                    loadHomePage()
                })
            }, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(MENU_ICON_BUTTON_SIZE_DP),
            ))
            addView(menuDivider())
            addView(menuRow(getString(R.string.menu_settings), popup) { openSettings() })
        }

        popup.apply {
            contentView = content
            width = dp(MENU_POPUP_WIDTH_DP)
            height = LinearLayout.LayoutParams.WRAP_CONTENT
            isFocusable = true
            isOutsideTouchable = true
            setBackgroundDrawable(ColorDrawable(colors.surface))
            elevation = dp(8).toFloat()
        }
        popup.showAsDropDown(
            hamburgerButton,
            hamburgerButton.width - dp(MENU_POPUP_WIDTH_DP),
            0,
        )
    }

    private fun menuIconButton(
        icon: String,
        label: String,
        enabled: Boolean,
        popup: PopupWindow,
        action: () -> Unit,
    ): TextView =
        TextView(this).apply {
            val colors = themeColors()
            text = icon
            textSize = 32f
            gravity = Gravity.CENTER
            contentDescription = label
            minWidth = dp(MENU_ICON_BUTTON_SIZE_DP)
            minHeight = dp(MENU_ICON_BUTTON_SIZE_DP)
            setTextColor(colors.primaryText)
            isEnabled = enabled
            alpha = if (enabled) 1f else 0.35f
            isClickable = enabled
            isFocusable = enabled
            if (enabled) {
                applyScreenSelectableBackground()
                setOnClickListener {
                    popup.dismiss()
                    action()
                }
            }
        }.also { button ->
            button.layoutParams = LinearLayout.LayoutParams(
                dp(MENU_ICON_BUTTON_SIZE_DP),
                dp(MENU_ICON_BUTTON_SIZE_DP),
            )
        }

    private fun menuRow(
        label: String,
        popup: PopupWindow,
        action: () -> Unit,
    ): TextView =
        TextView(this).apply {
            val colors = themeColors()
            text = label
            textSize = 17f
            gravity = Gravity.CENTER_VERTICAL
            setTextColor(colors.primaryText)
            setPadding(dp(16), 0, dp(16), 0)
            minHeight = dp(MENU_ROW_HEIGHT_DP)
            isClickable = true
            isFocusable = true
            applyScreenSelectableBackground()
            setOnClickListener {
                popup.dismiss()
                action()
            }
        }.also { row ->
            row.layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(MENU_ROW_HEIGHT_DP),
            )
        }

    private fun menuDivider(): View =
        View(this).apply {
            setBackgroundColor(themeColors().divider)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(1),
            )
        }

    private fun loadInitialPage(intent: Intent?) {
        val requestedUrl = intent
            ?.getStringExtra(EXTRA_LOAD_URL)
            ?.trim()
            ?.takeIf { it.isNotBlank() }
        if (requestedUrl != null) {
            loadTarget(classifier.classify(requestedUrl))
        } else {
            loadHomePage()
        }
    }

    private fun loadHomePage() {
        loadTarget(classifier.classify(BrowserPreferences.homepage(this)))
    }

    private fun loadFromInput() {
        val input = omnibox.text.toString()
        dismissOmniboxKeyboard()
        loadTarget(classifier.classify(input))
    }

    private fun reloadCurrentPage() {
        val url = currentPageUrl() ?: activeMainFrameUrl
        if (url != null) {
            activeMainFrameUrl = url
            currentTargetKind = classifier.classify(url).kind
        }
        clearMainFrameHnsStatus()
        pageIsLoading = true
        pageLoadProgress = 0
        refreshLoopbackProxyScope()
        refreshSecurityState()
        refreshPageProgress()
        webView.reload()
    }

    private fun dismissOmniboxKeyboard() {
        val windowToken = omnibox.windowToken
        omnibox.clearFocus()
        webView.requestFocus()
        val inputMethodManager = getSystemService(InputMethodManager::class.java)
        inputMethodManager.hideSoftInputFromWindow(windowToken, 0)
        omnibox.post {
            inputMethodManager.hideSoftInputFromWindow(windowToken, 0)
        }
    }

    private fun loadTarget(target: com.denuoweb.hnsdane.core.BrowserTarget) {
        omnibox.setText(target.url)
        currentTargetKind = target.kind
        clearMainFrameHnsStatus()
        activeMainFrameUrl = target.url
        pageIsLoading = true
        pageLoadProgress = 0
        refreshLoopbackProxyScope()
        refreshSecurityState()
        refreshPageProgress()
        webView.loadUrl(target.url)
    }

    private fun refreshSecurityState() {
        if (
            pageIsLoading &&
            currentTargetKind in NATIVE_GATEWAY_TARGET_KINDS &&
            mainFrameHnsStatusCode == null
        ) {
            securityLabel.text = getString(R.string.security_loading)
            return
        }

        setSecurityState(
            BrowserSecurityPolicy.state(
                targetKind = currentTargetKind,
                proxyAvailable = proxyAvailable,
                syncStatusJson = lastSyncSnapshot?.statusJson,
                mainFrameHnsStatusCode = mainFrameHnsStatusCode,
                mainFrameHnsTlsPolicy = mainFrameHnsTlsPolicy,
                mainFrameHnsResolverPolicy = mainFrameHnsResolverPolicy,
            ),
        )
    }

    private fun applyMainFrameHnsStatus(
        statusCode: Int,
        tlsPolicy: HnsPageTlsPolicy?,
        resolverPolicy: HnsPageResolverPolicy?,
        traceJson: String?,
    ) {
        mainFrameHnsStatusCode = statusCode
        mainFrameHnsTlsPolicy = tlsPolicy
        mainFrameHnsResolverPolicy = resolverPolicy
        mainFrameHnsTraceJson = traceJson
        mainFrameHnsStatusUrl = activeMainFrameUrl
        refreshSecurityState()
    }

    private fun clearMainFrameHnsStatus() {
        mainFrameHnsStatusCode = null
        mainFrameHnsTlsPolicy = null
        mainFrameHnsResolverPolicy = null
        mainFrameHnsTraceJson = null
        mainFrameHnsStatusUrl = null
    }

    private fun clearMainFrameHnsStatusUnlessFor(url: String) {
        val statusUrl = mainFrameHnsStatusUrl
        if (statusUrl != null && statusUrl.mainFrameMatchKey() == url.mainFrameMatchKey()) {
            return
        }
        clearMainFrameHnsStatus()
    }

    private fun refreshSyncProgress() {
        if (!::syncProgressBar.isInitialized || !::syncProgressStats.isInitialized) {
            return
        }

        val progress = HnsSyncProgress.fromJson(lastSyncSnapshot?.statusJson)
        if (progress.isCurrent) {
            HnsSyncUiPreferences.setProgressVisible(this, false)
        }
        if (!HnsSyncUiPreferences.progressVisible(this)) {
            syncProgressBar.visibility = View.GONE
            syncProgressStats.visibility = View.GONE
            return
        }

        syncProgressBar.visibility = View.VISIBLE
        syncProgressStats.visibility = View.VISIBLE
        val permille = progress.progressPermille()
        syncProgressBar.isIndeterminate = permille == null
        if (permille != null) {
            syncProgressBar.progress = permille
        }
        syncProgressStats.text = progress.summary(this)
    }

    private fun refreshPageProgress() {
        if (!::pageProgressBar.isInitialized) {
            return
        }

        if (pageIsLoading) {
            pageProgressBar.visibility = View.VISIBLE
            pageProgressBar.progress = pageLoadProgress.coerceIn(0, PAGE_PROGRESS_MAX)
        } else {
            pageProgressBar.progress = PAGE_PROGRESS_MAX
            pageProgressBar.visibility = View.GONE
        }
    }

    private fun setSecurityState(state: SecurityState) {
        securityLabel.text = when (state) {
            SecurityState.Syncing -> getString(R.string.security_syncing)
            SecurityState.Loading -> getString(R.string.security_loading)
            SecurityState.HnsVerified -> getString(R.string.security_hns_verified)
            SecurityState.HnsCompatibility -> getString(R.string.security_hns_compat)
            SecurityState.DaneVerified -> getString(R.string.security_dane_verified)
            SecurityState.DaneCompatibility -> getString(R.string.security_dane_compat)
            SecurityState.WebPkiOnly -> getString(R.string.security_webpki)
            SecurityState.MixedPolicy -> getString(R.string.security_hns_webpki)
            SecurityState.ValidationFailed -> getString(R.string.security_failed)
            SecurityState.ProofUnavailable -> getString(R.string.security_proof_unavailable)
        }
    }

    private inner class BrowserClient : WebViewClient() {
        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            hnsWebSocketBridge.closeAll()
            pageIsLoading = true
            pageLoadProgress = pageLoadProgress.coerceAtLeast(5)
            omnibox.setText(url)
            activeMainFrameUrl = url
            currentTargetKind = classifier.classify(url).kind
            clearMainFrameHnsStatusUnlessFor(url)
            refreshLoopbackProxyScope()
            refreshSecurityState()
            refreshPageProgress()
        }

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val requestUrl = request.url.toString()
            val scheme = request.url.scheme?.lowercase(Locale.US)
            if (!request.isForMainFrame) {
                return scheme != null && scheme !in SUBFRAME_ALLOWED_SCHEMES
            }
            if (scheme !in WEB_NAVIGATION_SCHEMES) {
                return handleExternalMainFrameNavigation(request.url)
            }

            activeMainFrameUrl = requestUrl
            val target = classifier.classify(requestUrl)
            currentTargetKind = target.kind
            clearMainFrameHnsStatus()
            refreshLoopbackProxyScope()
            refreshSecurityState()
            return false
        }

        override fun shouldInterceptRequest(
            view: WebView,
            request: WebResourceRequest,
        ): WebResourceResponse? {
            assetLoader.shouldInterceptRequest(request.url)?.let { return it }
            val requestUrl = request.url.toString()
            val isMainFrame = request.isForMainFrame || isActiveMainFrameRequest(requestUrl)
            return webViewGatewayInterceptor.intercept(
                method = request.method,
                url = requestUrl,
                requestHeaders = request.requestHeaders.orEmpty(),
                isForMainFrame = isMainFrame,
            )
                ?.toWebResourceResponse()
                ?: super.shouldInterceptRequest(view, request)
        }

        @SuppressLint("WebViewClientOnReceivedSslError")
        override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
            if (HnsWebViewSslErrorPolicy.canProceed(error)) {
                handler.proceed()
            } else {
                handler.cancel()
            }
        }

        override fun onPageFinished(view: WebView, url: String) {
            omnibox.setText(url)
            activeMainFrameUrl = url
            pageIsLoading = false
            pageLoadProgress = PAGE_PROGRESS_MAX
            recordHistoryEntry(url, view.title)
            refreshSecurityState()
            refreshPageProgress()
        }

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            pageIsLoading = false
            pageLoadProgress = 0
            refreshSecurityState()
            refreshPageProgress()
            Toast.makeText(
                this@MainActivity,
                getString(R.string.toast_webview_renderer_restarted),
                Toast.LENGTH_SHORT,
            ).show()
            stopLoopbackGateway()
            view.destroy()
            finish()
            return true
        }
    }

    private inner class BrowserChromeClient : WebChromeClient() {
        override fun onProgressChanged(view: WebView, newProgress: Int) {
            pageLoadProgress = newProgress.coerceIn(0, PAGE_PROGRESS_MAX)
            if (pageLoadProgress < PAGE_PROGRESS_MAX) {
                pageIsLoading = true
            }
            refreshPageProgress()
        }
    }

    private fun openResolverTrace() {
        startActivity(
            Intent(this, HnsResolverTraceActivity::class.java)
                .putExtra(HnsResolverTraceActivity.EXTRA_URL, omnibox.text.toString())
                .putExtra(HnsResolverTraceActivity.EXTRA_TRACE_JSON, mainFrameHnsTraceJson),
        )
    }

    private fun openSettings() {
        val intent = Intent(this, SettingsActivity::class.java)
        currentPageUrl()?.let { intent.putExtra(SettingsActivity.EXTRA_CURRENT_URL, it) }
        startActivity(intent)
    }

    private fun handleExternalMainFrameNavigation(uri: Uri): Boolean {
        val scheme = uri.scheme?.lowercase(Locale.US)
        if (scheme == "about" && uri.toString() == "about:blank") {
            activeMainFrameUrl = uri.toString()
            currentTargetKind = BrowserTargetKind.ExactUrl
            return false
        }
        if (scheme in EXTERNAL_VIEW_SCHEMES) {
            val intent = Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)
            try {
                startActivity(intent)
            } catch (error: ActivityNotFoundException) {
                Toast.makeText(this, getString(R.string.toast_no_app_for_link), Toast.LENGTH_SHORT).show()
            }
            return true
        }

        Toast.makeText(this, getString(R.string.toast_link_not_supported), Toast.LENGTH_SHORT).show()
        return true
    }

    private fun recordHistoryEntry(url: String, title: String?) {
        BrowserHistoryStore.record(this, url, title)
    }

    private fun handleDownload(
        url: String?,
        userAgent: String?,
        contentDisposition: String?,
        mimeType: String?,
    ) {
        val downloadUrl = url?.trim().orEmpty()
        unsupportedDownloadReason(downloadUrl)?.let { reason ->
            Toast.makeText(this, reason, Toast.LENGTH_LONG).show()
            return
        }

        if (classifier.classify(downloadUrl).kind in NATIVE_GATEWAY_TARGET_KINDS) {
            handleHnsDownload(downloadUrl, userAgent, contentDisposition, mimeType)
            return
        }

        val fileName = URLUtil.guessFileName(downloadUrl, contentDisposition, mimeType)
        val request = DownloadManager.Request(Uri.parse(downloadUrl))
            .setTitle(fileName)
            .setDescription(getString(R.string.app_name))
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName)
        if (!mimeType.isNullOrBlank()) {
            request.setMimeType(mimeType)
        }
        if (!userAgent.isNullOrBlank()) {
            request.addRequestHeader("User-Agent", userAgent)
        }

        try {
            val id = getSystemService(DownloadManager::class.java).enqueue(request)
            BrowserDownloadStore.record(this, id, downloadUrl, fileName, mimeType)
            Toast.makeText(this, getString(R.string.toast_download_queued, fileName), Toast.LENGTH_SHORT).show()
        } catch (error: IllegalArgumentException) {
            Toast.makeText(
                this,
                getString(
                    R.string.toast_download_not_supported,
                    error.message ?: getString(R.string.download_error_unsupported_url),
                ),
                Toast.LENGTH_LONG,
            ).show()
        } catch (error: SecurityException) {
            Toast.makeText(
                this,
                getString(
                    R.string.toast_download_not_supported,
                    error.message ?: getString(R.string.download_error_blocked_by_android),
                ),
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    private fun handleHnsDownload(
        downloadUrl: String,
        userAgent: String?,
        contentDisposition: String?,
        mimeType: String?,
    ) {
        val strictMode = HnsResolutionPreferences.strictHnsMode(this)
        val dohResolver = HnsResolutionPreferences.dohResolverUrl(this)
        val statelessDane = HnsResolutionPreferences.statelessDaneCertificates(this)
        val handshakeNetwork = HnsResolutionPreferences.handshakeNetworkId(this)
        Toast.makeText(this, getString(R.string.toast_download_started), Toast.LENGTH_SHORT).show()
        downloadExecutor.execute {
            val result = runCatching {
                val fetcher = HnsNativeDownloadFetcher(
                    dataDir = filesDir,
                    strictHnsMode = { strictMode },
                    dohResolverUrl = { dohResolver },
                    statelessDaneCertificates = { statelessDane },
                    handshakeNetwork = { handshakeNetwork },
                )
                val response = fetcher.fetch(downloadUrl, userAgent)
                try {
                    val resolvedMimeType = mimeType
                        ?.takeIf { it.isNotBlank() }
                        ?: response.mimeType
                    val responseDisposition = response.headerValue("Content-Disposition")
                    val fileName = safeDownloadFileName(
                        URLUtil.guessFileName(
                            response.finalUrl,
                            contentDisposition?.takeIf { it.isNotBlank() } ?: responseDisposition,
                            resolvedMimeType,
                        ),
                    )
                    val savedUri = saveHnsDownloadBody(response.bodyFile, fileName, resolvedMimeType)
                    BrowserDownloadStore.recordSavedFile(
                        this,
                        savedUri.toString(),
                        response.finalUrl,
                        fileName,
                        resolvedMimeType,
                    )
                    fileName
                } finally {
                    response.bodyFile.delete()
                }
            }
            mainHandler.post {
                result
                    .onSuccess { fileName ->
                        Toast.makeText(this, getString(R.string.toast_download_saved, fileName), Toast.LENGTH_SHORT).show()
                    }
                    .onFailure { error ->
                        Toast.makeText(
                            this,
                            getString(
                                R.string.toast_download_not_supported,
                                error.message ?: getString(R.string.download_error_hns_failed),
                            ),
                            Toast.LENGTH_LONG,
                        ).show()
                    }
            }
        }
    }

    @Throws(IOException::class)
    private fun saveHnsDownloadBody(
        bodyFile: File,
        fileName: String,
        mimeType: String,
    ): Uri {
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType.ifBlank { "application/octet-stream" })
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val resolver = contentResolver
        val uri = resolver.insert(MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY), values)
            ?: throw IOException("Could not create download entry.")
        try {
            resolver.openOutputStream(uri, "w")?.use { output ->
                FileInputStream(bodyFile).use { input -> input.copyTo(output) }
            } ?: throw IOException("Could not open download entry.")
            val completed = ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }
            resolver.update(uri, completed, null, null)
            return uri
        } catch (error: Exception) {
            resolver.delete(uri, null, null)
            throw if (error is IOException) error else IOException(error.message ?: "Could not save download.", error)
        }
    }

    private fun safeDownloadFileName(fileName: String): String {
        val cleaned = fileName
            .trim()
            .replace(UNSAFE_DOWNLOAD_FILE_CHARS, "_")
            .trim('.')
            .ifBlank { "download" }
        return cleaned.take(MAX_DOWNLOAD_FILE_NAME_CHARS).ifBlank { "download" }
    }

    private fun unsupportedDownloadReason(url: String): String? {
        if (url.isBlank()) {
            return getString(R.string.toast_download_not_supported, getString(R.string.download_error_missing_url))
        }

        val uri = runCatching { Uri.parse(url) }.getOrNull()
            ?: return getString(R.string.toast_download_not_supported, getString(R.string.download_error_invalid_url))
        val scheme = uri.scheme?.lowercase()
        if (scheme == "blob" || scheme == "data") {
            return getString(
                R.string.toast_download_not_supported,
                getString(R.string.download_error_blob_data_urls, scheme),
            )
        }
        if (scheme != "http" && scheme != "https") {
            return getString(R.string.toast_download_not_supported, getString(R.string.download_error_http_https_only))
        }
        if (uri.host.equals("appassets.androidplatform.net", ignoreCase = true)) {
            return getString(R.string.toast_download_not_supported, getString(R.string.download_error_local_assets))
        }
        return null
    }

    private fun currentPageUrl(): String? =
        webView.url
            ?.trim()
            ?.takeIf { it.isNotBlank() && it != "about:blank" }
            ?: omnibox.text.toString()
                .trim()
                .takeIf { it.isNotBlank() && it != "about:blank" }

    private fun currentHnsProxyHost(): String? {
        val activeUrl = activeMainFrameUrl ?: return null
        val target = classifier.classify(activeUrl)
        if (target.kind != BrowserTargetKind.HnsName) {
            return null
        }
        return target.displayHost
            ?.trim()
            ?.trimEnd('.')
            ?.lowercase(Locale.US)
            ?.takeIf { it.isNotBlank() }
    }

    private fun isActiveMainFrameRequest(url: String): Boolean {
        val activeUrl = activeMainFrameUrl ?: return false
        return url.mainFrameMatchKey() == activeUrl.mainFrameMatchKey()
    }

    private fun isActiveMainFrameHost(host: String): Boolean {
        val activeHost = activeMainFrameUrl
            ?.let { classifier.classify(it).displayHost }
            ?: return false
        return activeHost.equals(host, ignoreCase = true)
    }

    private fun String.mainFrameMatchKey(): String =
        trim().substringBefore('#')

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_LOAD_URL = "com.denuoweb.hnsdane.LOAD_URL"

        private const val EPHEMERAL_GATEWAY_PORT = 0
        private const val SYNC_PROGRESS_MAX = 1000
        private const val PAGE_PROGRESS_MAX = 100
        private const val SYNC_STATUS_POLL_MS = 2_000L
        private const val SECURITY_LABEL_WIDTH_DP = 136
        private const val TOOLBAR_CONTROL_HEIGHT_DP = 48
        private const val MENU_ICON_BUTTON_SIZE_DP = 55
        private const val MENU_POPUP_WIDTH_DP = MENU_ICON_BUTTON_SIZE_DP * 3
        private const val MENU_ROW_HEIGHT_DP = 55
        private const val MAX_DOWNLOAD_FILE_NAME_CHARS = 120
        private val UNSAFE_DOWNLOAD_FILE_CHARS = Regex("[\\\\/:*?\"<>|\\p{Cntrl}]")
        private val WEB_NAVIGATION_SCHEMES = setOf("http", "https")
        private val EXTERNAL_VIEW_SCHEMES = setOf("mailto", "tel", "sms", "geo")
        private val SUBFRAME_ALLOWED_SCHEMES = setOf("http", "https", "about", "data", "blob")
        private val NATIVE_GATEWAY_TARGET_KINDS = setOf(
            BrowserTargetKind.HnsName,
            BrowserTargetKind.NativeGateway,
        )
    }
}

internal data class OmniboxEditorDecision(
    val submit: Boolean,
    val consume: Boolean,
)

internal fun omniboxEditorDecision(
    actionId: Int,
    keyCode: Int?,
    keyAction: Int?,
): OmniboxEditorDecision {
    val enterKey = keyCode == KeyEvent.KEYCODE_ENTER
    val submit = actionId == EditorInfo.IME_ACTION_GO ||
        (enterKey && keyAction == KeyEvent.ACTION_DOWN)
    val consume = submit || (enterKey && keyAction == KeyEvent.ACTION_UP)
    return OmniboxEditorDecision(submit = submit, consume = consume)
}
