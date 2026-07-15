package com.denuoweb.hnsdane.ui

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.ContentValues
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
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
import android.webkit.HttpAuthHandler
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
import com.denuoweb.hnsdane.HnsDaneApplication
import com.denuoweb.hnsdane.R
import com.denuoweb.hnsdane.core.BrowserSecurityPolicy
import com.denuoweb.hnsdane.core.BrowserTarget
import com.denuoweb.hnsdane.core.BrowserTargetKind
import com.denuoweb.hnsdane.core.BrowserUrlClassifier
import com.denuoweb.hnsdane.core.HnsPageResolverPolicy
import com.denuoweb.hnsdane.core.HnsPageSecurityPath
import com.denuoweb.hnsdane.core.HnsPageTlsPolicy
import com.denuoweb.hnsdane.core.SecurityState
import com.denuoweb.hnsdane.net.DisabledServiceWorkerClient
import com.denuoweb.hnsdane.net.BrowserProxyCoordinator
import com.denuoweb.hnsdane.net.BrowserProxyLifecycleWorker
import com.denuoweb.hnsdane.net.BrowserProxyRoute
import com.denuoweb.hnsdane.net.GatewayEventLog
import com.denuoweb.hnsdane.net.HnsProxyController
import com.denuoweb.hnsdane.net.HnsServiceWorkerGatewayClient
import com.denuoweb.hnsdane.net.HnsSyncProgress
import com.denuoweb.hnsdane.net.HnsSyncSnapshot
import com.denuoweb.hnsdane.net.HnsNativeDownloadFetcher
import com.denuoweb.hnsdane.net.HnsProxyWebSocketPolicy
import com.denuoweb.hnsdane.net.HnsWebViewGatewayInterceptor
import com.denuoweb.hnsdane.net.HnsWebViewSslErrorPolicy
import com.denuoweb.hnsdane.net.LocalBrowserProxyFactory
import com.denuoweb.hnsdane.net.NativeBridge
import com.denuoweb.hnsdane.net.ProcessServiceWorkerClientOwnership
import com.denuoweb.hnsdane.net.RustBrowserProxy
import com.denuoweb.hnsdane.net.RustBrowserProxyConfig
import com.denuoweb.hnsdane.net.ServiceWorkerClientOwnershipGate
import com.denuoweb.hnsdane.net.blockedHnsProxyResponse
import com.denuoweb.hnsdane.net.serviceWorkerProxyRoute
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.net.URI
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
    private lateinit var httpWarningBar: TextView
    private lateinit var proxyCoordinator: BrowserProxyCoordinator
    private lateinit var assetLoader: WebViewAssetLoader
    private lateinit var webViewGatewayInterceptor: HnsWebViewGatewayInterceptor
    private val serviceWorkerClientOwner: ServiceWorkerClientOwnershipGate.Owner =
        ProcessServiceWorkerClientOwnership.newOwner()
    private var proxyAvailable: Boolean = false
    private var currentTargetKind: BrowserTargetKind? = null
    private var mainFrameHnsStatusCode: Int? = null
    private var mainFrameHnsTlsPolicy: HnsPageTlsPolicy? = null
    private var mainFrameHnsResolverPolicy: HnsPageResolverPolicy? = null
    private var mainFrameHnsSecurityPath: HnsPageSecurityPath? = null
    private var mainFrameHnsTraceJson: String? = null
    private var mainFrameHnsStatusUrl: String? = null
    private var lastSyncSnapshot: HnsSyncSnapshot? = null
    private var syncSnapshotSubscription: Closeable? = null
    @Volatile
    private var gatewayInterceptionEnabled: Boolean = false
    private var activityDestroyed: Boolean = false
    @Volatile
    private var activeMainFrameUrl: String? = null
    private var pendingMainFrameUrl: String? = null
    private var admittedMainFrameUrl: String? = null
    private var reloadHnsPageOnNextStart: Boolean = false
    private var pageIsLoading: Boolean = false
    private var pageLoadProgress: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val colors = themeColors()

        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        GatewayEventLog.configureAppStorage(filesDir)
        NativeBridge.pruneGatewayResponseBodyFiles(filesDir.absolutePath)
        HnsNativeDownloadFetcher.pruneStaging(filesDir)
        val proxyController = HnsProxyController(this)
        proxyCoordinator = BrowserProxyCoordinator(
            overrideController = proxyController,
            proxyFactory = LocalBrowserProxyFactory(RustBrowserProxy::start),
            workerExecutor = BrowserProxyLifecycleWorker,
            callbackExecutor = ContextCompat.getMainExecutor(this),
            onAvailabilityChanged = { available ->
                proxyAvailable = available
                if (::securityLabel.isInitialized) refreshSecurityState()
            },
        )
        webViewGatewayInterceptor = HnsWebViewGatewayInterceptor(
            dataDir = filesDir,
            allowProxyFallbackForBodyRequests = { proxyAvailable },
            strictHnsMode = { HnsResolutionPreferences.strictHnsMode(this) },
            dohResolverUrl = { HnsResolutionPreferences.dohResolverUrl(this) },
            statelessDaneCertificates = { HnsResolutionPreferences.statelessDaneCertificates(this) },
            handshakeNetwork = { HnsResolutionPreferences.handshakeNetworkId(this) },
            onMainFrameHnsStatusForUrl = { url, statusCode, tlsPolicy, resolverPolicy, securityPath, traceJson ->
                runOnUiThread {
                    val target = classifier.classify(url)
                    val usesCompatibilityPath =
                        target.kind == BrowserTargetKind.NativeGateway ||
                            (
                                target.kind == BrowserTargetKind.HnsName &&
                                    target.displayHost?.let(proxyCoordinator::routeForHnsHost) ==
                                    BrowserProxyRoute.CompatibilityInterceptor
                                )
                    if (
                        pendingMainFrameUrl == null &&
                        admittedMainFrameUrl?.mainFrameMatchKey() == url.mainFrameMatchKey() &&
                        usesCompatibilityPath &&
                        mainFrameHnsStatusCode == null
                    ) {
                        applyMainFrameHnsStatus(statusCode, tlsPolicy, resolverPolicy, securityPath, traceJson)
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
        httpWarningBar = TextView(this).apply {
            text = getString(R.string.http_transport_warning)
            contentDescription = getString(R.string.http_transport_warning)
            gravity = Gravity.CENTER_VERTICAL
            setSingleLine(true)
            ellipsize = TextUtils.TruncateAt.MARQUEE
            marqueeRepeatLimit = -1
            isSelected = true
            textSize = 12f
            setPadding(dp(12), 0, dp(12), 0)
            setTextColor(Color.rgb(49, 39, 0))
            setBackgroundColor(Color.rgb(255, 214, 102))
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
        configureHnsProxyWebSocketPolicy()
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
            addView(httpWarningBar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(HTTP_WARNING_BAR_HEIGHT_DP),
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
                    navigateHistory(-1)
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
        gatewayInterceptionEnabled = true
        BrowserCookiePreferences.applyTo(webView)
        val resumeUrl = pendingMainFrameUrl ?: activeMainFrameUrl ?: currentPageUrl()
        if (reloadHnsPageOnNextStart && pendingMainFrameUrl == null && resumeUrl != null) {
            reloadHnsPageOnNextStart = false
            val target = classifier.classify(resumeUrl)
            enqueueNavigation(target) { webView.reload() }
        }
        proxyCoordinator.resume(proxyConfigForUrl(pendingMainFrameUrl ?: activeMainFrameUrl ?: resumeUrl))
        lastSyncSnapshot = HnsSyncSnapshot(
            statusJson = NativeBridge.syncStatus(
                filesDir.absolutePath,
                HnsResolutionPreferences.handshakeNetworkId(this),
            ),
            updatedAtMillis = System.currentTimeMillis(),
        )
        refreshSecurityState()
        refreshSyncProgress()
        observeForegroundSync()
        startSyncStatusPolling()
    }

    override fun onStop() {
        gatewayInterceptionEnabled = false
        reloadHnsPageOnNextStart = currentHnsHostForUrl(activeMainFrameUrl) != null
        if (::webView.isInitialized) {
            webView.stopLoading()
        }
        stopSyncStatusPolling()
        stopObservingForegroundSync()
        proxyCoordinator.suspend()
        super.onStop()
    }

    override fun onDestroy() {
        activityDestroyed = true
        gatewayInterceptionEnabled = false
        stopObservingForegroundSync()
        proxyCoordinator.destroy()
        disableServiceWorkerInterception()
        if (::webView.isInitialized) {
            webView.stopLoading()
            webView.destroy()
        }
        syncStatusExecutor.shutdownNow()
        downloadExecutor.shutdownNow()
        super.onDestroy()
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
        ProcessServiceWorkerClientOwnership.install(serviceWorkerClientOwner) {
            serviceWorkerController.setServiceWorkerClient(
                HnsServiceWorkerGatewayClient(
                    interceptor = webViewGatewayInterceptor,
                    enabled = { gatewayInterceptionEnabled },
                    proxyRoute = { request ->
                        serviceWorkerProxyRoute(
                            scheme = request.url.scheme,
                            host = request.url.host,
                            routeForHnsHost = proxyCoordinator::routeForHnsHost,
                        )
                    },
                ),
            )
        }
    }

    private fun disableServiceWorkerInterception() {
        if (
            WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_BASIC_USAGE) &&
            WebViewFeature.isFeatureSupported(WebViewFeature.SERVICE_WORKER_SHOULD_INTERCEPT_REQUEST)
        ) {
            ProcessServiceWorkerClientOwnership.disable(serviceWorkerClientOwner) {
                ServiceWorkerControllerCompat.getInstance().setServiceWorkerClient(DisabledServiceWorkerClient)
            }
        }
    }

    private fun configureHnsProxyWebSocketPolicy() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            return
        }
        WebViewCompat.addDocumentStartJavaScript(
            webView,
            HnsProxyWebSocketPolicy.script(),
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

    private fun observeForegroundSync() {
        if (syncSnapshotSubscription != null || activityDestroyed) {
            return
        }

        val app = application as? HnsDaneApplication ?: return
        syncSnapshotSubscription = app.observeSync { snapshot ->
            mainHandler.post {
                if (syncSnapshotSubscription == null || activityDestroyed) {
                    return@post
                }
                lastSyncSnapshot = snapshot
                refreshSecurityState()
                refreshSyncProgress()
            }
        }
    }

    private fun stopObservingForegroundSync() {
        syncSnapshotSubscription?.close()
        syncSnapshotSubscription = null
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
                    navigateHistory(1)
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
        val url = currentPageUrl() ?: activeMainFrameUrl ?: return
        enqueueNavigation(classifier.classify(url)) { webView.reload() }
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

    private fun loadTarget(target: BrowserTarget) {
        enqueueNavigation(target) { webView.loadUrl(target.url) }
    }

    private fun navigateHistory(offset: Int) {
        val history = webView.copyBackForwardList()
        val targetIndex = history.currentIndex + offset
        if (targetIndex !in 0 until history.size) return
        val url = history.getItemAtIndex(targetIndex).url ?: return
        enqueueNavigation(classifier.classify(url)) { webView.goBackOrForward(offset) }
    }

    private fun enqueueNavigation(target: BrowserTarget, load: () -> Unit) {
        webView.stopLoading()
        omnibox.setText(target.url)
        currentTargetKind = target.kind
        clearMainFrameHnsStatus()
        pendingMainFrameUrl = target.url
        pageIsLoading = true
        pageLoadProgress = 0
        refreshSecurityState()
        refreshPageProgress()
        refreshTransportWarning()
        val config = proxyConfigForTarget(target)
        proxyCoordinator.navigate(config, config?.scopeHost) {
            if (activityDestroyed || pendingMainFrameUrl?.mainFrameMatchKey() != target.url.mainFrameMatchKey()) {
                return@navigate
            }
            pendingMainFrameUrl = null
            admittedMainFrameUrl = target.url
            activeMainFrameUrl = target.url
            currentTargetKind = target.kind
            load()
        }
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
                mainFrameHnsSecurityPath = mainFrameHnsSecurityPath,
            ),
        )
    }

    private fun applyMainFrameHnsStatus(
        statusCode: Int,
        tlsPolicy: HnsPageTlsPolicy?,
        resolverPolicy: HnsPageResolverPolicy?,
        securityPath: HnsPageSecurityPath?,
        traceJson: String?,
    ) {
        mainFrameHnsStatusCode = statusCode
        mainFrameHnsTlsPolicy = tlsPolicy
        mainFrameHnsResolverPolicy = resolverPolicy
        mainFrameHnsSecurityPath = securityPath
        mainFrameHnsTraceJson = traceJson
        mainFrameHnsStatusUrl = activeMainFrameUrl
        refreshSecurityState()
    }

    private fun clearMainFrameHnsStatus() {
        mainFrameHnsStatusCode = null
        mainFrameHnsTlsPolicy = null
        mainFrameHnsResolverPolicy = null
        mainFrameHnsSecurityPath = null
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

    private fun refreshTransportWarning() {
        if (!::httpWarningBar.isInitialized) {
            return
        }
        httpWarningBar.visibility = if (activeMainFrameUrl.isHttpUrl()) {
            View.VISIBLE
        } else {
            View.GONE
        }
    }

    private fun setSecurityState(state: SecurityState) {
        securityLabel.text = when (state) {
            SecurityState.Syncing -> getString(R.string.security_syncing)
            SecurityState.Loading -> getString(R.string.security_loading)
            SecurityState.HnsVerified -> getString(R.string.security_hns_verified)
            SecurityState.HnsCompatibility -> getString(R.string.security_hns_compat)
            SecurityState.HnsViaAuthoritativeDoh -> getString(R.string.security_hns_via_authoritative_doh)
            SecurityState.HnsViaAuthoritativeDns53 -> getString(R.string.security_hns_via_authoritative_dns53)
            SecurityState.HnsViaThirdPartyDoh -> getString(R.string.security_hns_via_third_party_doh)
            SecurityState.DaneVerified -> getString(R.string.security_dane_verified)
            SecurityState.DaneCompatibility -> getString(R.string.security_dane_compat)
            SecurityState.DaneViaAuthoritativeDoh -> getString(R.string.security_dane_via_authoritative_doh)
            SecurityState.DaneViaAuthoritativeDns53 -> getString(R.string.security_dane_via_authoritative_dns53)
            SecurityState.DaneViaThirdPartyDoh -> getString(R.string.security_dane_via_third_party_doh)
            SecurityState.StatelessDane -> getString(R.string.security_stateless_dane)
            SecurityState.DaneViaIcannDoh -> getString(R.string.security_dane_via_icann_doh)
            SecurityState.WebPkiOnly -> getString(R.string.security_webpki)
            SecurityState.MixedPolicy -> getString(R.string.security_hns_webpki)
            SecurityState.ValidationFailed -> getString(R.string.security_failed)
            SecurityState.ProofUnavailable -> getString(R.string.security_proof_unavailable)
        }
    }

    private inner class BrowserClient : WebViewClient() {
        override fun onReceivedHttpAuthRequest(
            view: WebView,
            handler: HttpAuthHandler,
            host: String,
            realm: String,
        ) {
            val authorization = proxyCoordinator.authorizationForChallenge(host, realm)
            if (authorization != null) {
                handler.proceed(authorization.username, authorization.password)
            } else {
                handler.cancel()
            }
        }

        override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
            if (pendingMainFrameUrl != null) return
            val admittedUrl = admittedMainFrameUrl
            if (admittedUrl != null && admittedUrl.mainFrameMatchKey() != url.mainFrameMatchKey()) {
                view.stopLoading()
                val redirectTarget = classifier.classify(url)
                enqueueNavigation(redirectTarget) { view.loadUrl(redirectTarget.url) }
                return
            }
            pageIsLoading = true
            pageLoadProgress = pageLoadProgress.coerceAtLeast(5)
            omnibox.setText(url)
            admittedMainFrameUrl = url
            activeMainFrameUrl = url
            val target = classifier.classify(url)
            currentTargetKind = target.kind
            if (target.kind == BrowserTargetKind.HnsName) {
                target.displayHost?.let(proxyCoordinator::noteMainFrameHost)
            }
            clearMainFrameHnsStatusUnlessFor(url)
            refreshSecurityState()
            refreshPageProgress()
            refreshTransportWarning()
        }

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val requestUrl = request.url.toString()
            val scheme = request.url.scheme?.lowercase(Locale.US)
            if (isBlockedLoopbackHost(request.url.host)) {
                if (request.isForMainFrame) {
                    Toast.makeText(this@MainActivity, getString(R.string.toast_link_not_supported), Toast.LENGTH_SHORT).show()
                }
                return true
            }
            if (!request.isForMainFrame) {
                return scheme != null && scheme !in SUBFRAME_ALLOWED_SCHEMES
            }
            if (scheme !in WEB_NAVIGATION_SCHEMES) {
                return handleExternalMainFrameNavigation(request.url, request.hasGesture())
            }

            val target = classifier.classify(requestUrl)
            if (target.kind == BrowserTargetKind.Search) {
                Toast.makeText(this@MainActivity, getString(R.string.toast_link_not_supported), Toast.LENGTH_SHORT).show()
                return true
            }
            enqueueNavigation(target) { view.loadUrl(target.url) }
            return true
        }

        override fun shouldInterceptRequest(
            view: WebView,
            request: WebResourceRequest,
        ): WebResourceResponse? {
            assetLoader.shouldInterceptRequest(request.url)?.let { return it }
            if (isBlockedLoopbackHost(request.url.host)) {
                val body = "403 Local Network Request Blocked\n".toByteArray(Charsets.UTF_8)
                return WebResourceResponse(
                    "text/plain",
                    "utf-8",
                    403,
                    "Local Network Request Blocked",
                    mapOf("Cache-Control" to "no-store"),
                    ByteArrayInputStream(body),
                )
            }
            val requestUrl = request.url.toString()
            val target = classifier.classify(requestUrl)
            if (target.kind == BrowserTargetKind.HnsName) {
                val route = target.displayHost
                    ?.let(proxyCoordinator::routeForHnsHost)
                    ?: BrowserProxyRoute.Block
                when (route) {
                    BrowserProxyRoute.Proxy -> return null
                    BrowserProxyRoute.Block -> return blockedHnsProxyResponse()
                    BrowserProxyRoute.CompatibilityInterceptor -> Unit
                }
            }
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
            if (HnsWebViewSslErrorPolicy.canProceed(error, proxyCoordinator)) {
                handler.proceed()
            } else {
                handler.cancel()
            }
        }

        override fun onPageFinished(view: WebView, url: String) {
            if (pendingMainFrameUrl != null) return
            val admittedUrl = admittedMainFrameUrl ?: return
            if (admittedUrl.mainFrameMatchKey() != url.mainFrameMatchKey()) return
            omnibox.setText(url)
            activeMainFrameUrl = url
            admittedMainFrameUrl = url
            val target = classifier.classify(url)
            currentTargetKind = target.kind
            if (target.kind == BrowserTargetKind.HnsName) {
                target.displayHost?.let { host ->
                    proxyCoordinator.noteMainFrameHost(host)
                    proxyCoordinator.takeMainFrameStatus(host)?.let { status ->
                        applyMainFrameHnsStatus(
                            status.statusCode,
                            status.tlsPolicy,
                            status.resolverPolicy,
                            status.securityPath,
                            status.resolutionTraceJson,
                        )
                    }
                }
            }
            pageIsLoading = false
            pageLoadProgress = PAGE_PROGRESS_MAX
            recordHistoryEntry(url, view.title)
            refreshSecurityState()
            refreshPageProgress()
            refreshTransportWarning()
        }

        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            gatewayInterceptionEnabled = false
            proxyCoordinator.suspend()
            pageIsLoading = false
            pageLoadProgress = 0
            refreshSecurityState()
            refreshPageProgress()
            Toast.makeText(
                this@MainActivity,
                getString(R.string.toast_webview_renderer_restarted),
                Toast.LENGTH_SHORT,
            ).show()
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

    private fun handleExternalMainFrameNavigation(uri: Uri, hasUserGesture: Boolean): Boolean {
        val scheme = uri.scheme?.lowercase(Locale.US)
        if (scheme == "about" && uri.toString() == "about:blank") {
            activeMainFrameUrl = uri.toString()
            currentTargetKind = BrowserTargetKind.ExactUrl
            return false
        }
        if (canLaunchExternalNavigation(scheme, hasUserGesture)) {
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

        val fileName = safeDownloadFileName(URLUtil.guessFileName(downloadUrl, contentDisposition, mimeType))
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
                    response.deleteBodyFile()
                }
            }
            mainHandler.post {
                if (activityDestroyed) {
                    return@post
                }
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

    private fun proxyConfigForUrl(url: String?): RustBrowserProxyConfig? =
        url?.let(classifier::classify)?.let(::proxyConfigForTarget)

    private fun proxyConfigForTarget(target: BrowserTarget): RustBrowserProxyConfig? {
        val host = if (target.kind == BrowserTargetKind.HnsName) {
            target.displayHost
        } else {
            null
        }
            ?.trim()
            ?.trimEnd('.')
            ?.lowercase(Locale.US)
            ?.takeIf { it.isNotBlank() }
            ?: return null
        return RustBrowserProxyConfig(
            dataDir = filesDir.absolutePath,
            network = HnsResolutionPreferences.handshakeNetworkId(this),
            scopeHost = host,
            strictHnsMode = HnsResolutionPreferences.strictHnsMode(this),
            dohResolverUrl = HnsResolutionPreferences.dohResolverUrl(this),
            statelessDaneCertificates = HnsResolutionPreferences.statelessDaneCertificates(this),
        )
    }

    private fun currentHnsHostForUrl(url: String?): String? =
        url?.let(classifier::classify)
            ?.takeIf { it.kind == BrowserTargetKind.HnsName }
            ?.displayHost

    private fun isActiveMainFrameRequest(url: String): Boolean {
        val activeUrl = activeMainFrameUrl ?: return false
        return url.mainFrameMatchKey() == activeUrl.mainFrameMatchKey()
    }

    private fun String.mainFrameMatchKey(): String =
        normalizedMainFrameMatchKey(this)

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_LOAD_URL = "com.denuoweb.hnsdane.LOAD_URL"

        private const val SYNC_PROGRESS_MAX = 1000
        private const val PAGE_PROGRESS_MAX = 100
        private const val SYNC_STATUS_POLL_MS = 2_000L
        private const val SECURITY_LABEL_WIDTH_DP = 136
        private const val TOOLBAR_CONTROL_HEIGHT_DP = 48
        private const val HTTP_WARNING_BAR_HEIGHT_DP = 22
        private const val MENU_ICON_BUTTON_SIZE_DP = 55
        private const val MENU_POPUP_WIDTH_DP = MENU_ICON_BUTTON_SIZE_DP * 3
        private const val MENU_ROW_HEIGHT_DP = 55
        private const val MAX_DOWNLOAD_FILE_NAME_CHARS = 120
        private val UNSAFE_DOWNLOAD_FILE_CHARS = Regex("[\\\\/:*?\"<>|\\p{Cntrl}]")
        private val WEB_NAVIGATION_SCHEMES = setOf("http", "https")
        private val SUBFRAME_ALLOWED_SCHEMES = setOf("http", "https", "about", "data", "blob")
        private val NATIVE_GATEWAY_TARGET_KINDS = setOf(
            BrowserTargetKind.HnsName,
            BrowserTargetKind.NativeGateway,
        )
    }
}

private val EXTERNAL_VIEW_SCHEMES = setOf("mailto", "tel", "sms", "geo")

internal fun canLaunchExternalNavigation(scheme: String?, hasUserGesture: Boolean): Boolean =
    hasUserGesture && scheme?.lowercase(Locale.US) in EXTERNAL_VIEW_SCHEMES

internal fun normalizedMainFrameMatchKey(url: String): String {
    val fragmentless = url.trim().substringBefore('#')
    val uri = runCatching { URI(fragmentless) }.getOrNull() ?: return fragmentless
    val scheme = uri.scheme?.lowercase(Locale.US) ?: return fragmentless
    if (scheme != "http" && scheme != "https") {
        return fragmentless
    }
    val host = uri.host
        ?.trim()
        ?.trimEnd('.')
        ?.lowercase(Locale.US)
        ?.takeIf { it.isNotBlank() }
        ?: return fragmentless
    val port = uri.port
    val portPart = when {
        port < 0 -> ""
        scheme == "http" && port == 80 -> ""
        scheme == "https" && port == 443 -> ""
        else -> ":$port"
    }
    val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
    val query = uri.rawQuery?.let { "?$it" }.orEmpty()
    return "$scheme://$host$portPart$path$query"
}

private fun String?.isHttpUrl(): Boolean {
    val value = this?.trim()?.takeIf { it.isNotEmpty() } ?: return false
    return runCatching {
        Uri.parse(value).scheme?.equals("http", ignoreCase = true) == true
    }.getOrDefault(false)
}

internal fun isBlockedLoopbackHost(host: String?): Boolean {
    val normalized = host
        ?.trim()
        ?.removeSurrounding("[", "]")
        ?.trimEnd('.')
        ?.lowercase(Locale.US)
        ?: return false
    if (normalized.length > MAX_NUMERIC_HOST_CHARS) {
        return false
    }
    if (
        normalized == "localhost" ||
        normalized.endsWith(".localhost")
    ) {
        return true
    }

    parseIpv4Literal(normalized)?.let { return isBlockedIpv4(it) }
    val ipv6 = parseIpv6Literal(normalized) ?: return false
    if (ipv6.all { it == 0 } || (ipv6.take(7).all { it == 0 } && ipv6[7] == 1)) {
        return true
    }

    // Cover both IPv4-compatible (::127.0.0.1) and IPv4-mapped
    // (::ffff:127.0.0.1) forms without asking the platform DNS resolver.
    val compatible = ipv6.take(6).all { it == 0 }
    val mapped = ipv6.take(5).all { it == 0 } && ipv6[5] == 0xffff
    if (compatible || mapped) {
        val ipv4 = (ipv6[6].toLong() shl 16) or ipv6[7].toLong()
        return isBlockedIpv4(ipv4)
    }
    return false
}

private fun isBlockedIpv4(address: Long): Boolean {
    val firstOctet = ((address ushr 24) and 0xff).toInt()
    // 0/8 is the current-host network and 127/8 is loopback. Neither should
    // ever be reachable from web content in this browser process.
    return firstOctet == 0 || firstOctet == 127
}

private fun parseIpv4Literal(value: String): Long? {
    if (value.isEmpty()) return null
    val pieces = value.split('.')
    if (pieces.size !in 1..4 || pieces.any(String::isEmpty)) return null
    val numbers = pieces.map { piece -> parseIpv4Number(piece) ?: return null }
    if (numbers.dropLast(1).any { it > 255 }) return null
    val lastBits = 8 * (5 - numbers.size)
    val lastMaximum = (1L shl lastBits) - 1L
    if (numbers.last() > lastMaximum) return null

    var address = numbers.last()
    numbers.dropLast(1).forEachIndexed { index, number ->
        address = address or (number shl (8 * (3 - index)))
    }
    return address
}

private fun parseIpv4Number(piece: String): Long? {
    val (digits, radix) = when {
        piece.startsWith("0x", ignoreCase = true) && piece.length > 2 -> piece.drop(2) to 16
        piece.length > 1 && piece.startsWith('0') -> piece.drop(1) to 8
        else -> piece to 10
    }
    if (digits.isEmpty() || digits.length > 10) return null
    return digits.toLongOrNull(radix)?.takeIf { it in 0..0xffff_ffffL }
}

private fun parseIpv6Literal(value: String): IntArray? {
    if (!value.contains(':') || value.any { it !in "0123456789abcdef:." }) return null
    var expanded = value
    if (expanded.contains('.')) {
        val separator = expanded.lastIndexOf(':')
        if (separator < 0) return null
        val ipv4 = parseIpv4Literal(expanded.substring(separator + 1)) ?: return null
        expanded = expanded.substring(0, separator) +
            ":${((ipv4 ushr 16) and 0xffff).toString(16)}:${(ipv4 and 0xffff).toString(16)}"
    }

    val compression = expanded.indexOf("::")
    if (compression >= 0 && expanded.indexOf("::", compression + 2) >= 0) return null
    val leftText = if (compression >= 0) expanded.substring(0, compression) else expanded
    val rightText = if (compression >= 0) expanded.substring(compression + 2) else ""
    val left = parseIpv6Words(leftText) ?: return null
    val right = parseIpv6Words(rightText) ?: return null
    val words = when {
        compression < 0 && left.size == 8 -> left
        compression >= 0 && left.size + right.size < 8 ->
            left + List(8 - left.size - right.size) { 0 } + right
        else -> return null
    }
    return words.toIntArray()
}

private fun parseIpv6Words(value: String): List<Int>? {
    if (value.isEmpty()) return emptyList()
    val words = value.split(':')
    if (words.any { it.isEmpty() || it.length > 4 }) return null
    return words.map { word -> word.toIntOrNull(16) ?: return null }
}

private const val MAX_NUMERIC_HOST_CHARS = 255

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
