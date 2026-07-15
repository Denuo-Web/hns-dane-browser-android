package com.denuoweb.hnsdane.net

import java.io.File
import java.io.InputStream
import java.util.Locale
import java.util.concurrent.locks.ReentrantReadWriteLock

interface HnsGatewayBridge {
    fun httpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): ByteArray?

    fun httpResponseBodyFile(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): HnsGatewayFileResponse? = null

}

interface HnsSyncBridge {
    fun syncOnce(dataDir: String): String

    fun syncOnce(dataDir: String, network: String): String = syncOnce(dataDir)
}

data class HnsGatewayFileResponse(
    val head: ByteArray,
    val bodyFile: File,
) {
    fun openBodyStream(): InputStream = GatewayResponseBodyStore.openReleasing(bodyFile)

    fun deleteBodyFile() {
        GatewayResponseBodyStore.release(bodyFile)
    }
}

object NativeBridge : HnsGatewayBridge, HnsSyncBridge {
    val isLoaded: Boolean = runCatching {
        System.loadLibrary("hns_dane_browser_ffi")
    }.isSuccess

    fun version(): String = if (isLoaded) {
        nativeVersion()
    } else {
        "rust-core-unavailable"
    }

    fun diagnostics(): String = if (isLoaded) {
        nativeDiagnostics()
    } else {
        """{"core":"unavailable","version":"unavailable","features":[],"securityDefault":"fail-closed"}"""
    }

    fun pruneGatewayResponseBodyFiles(dataDir: String) {
        GatewayResponseBodyStore.prune(dataDir)
    }

    override fun syncOnce(dataDir: String): String = syncOnce(dataDir, DEFAULT_NETWORK)

    override fun syncOnce(dataDir: String, network: String): String = withRuntime(
        dataDir = dataDir,
        network = network,
        unavailable = unavailableSyncJson(network = network),
        createFailure = { nativeSyncOnce(dataDir, network) },
        block = ::nativeRuntimeSyncOnce,
    )

    fun syncStatus(dataDir: String, network: String = DEFAULT_NETWORK): String = withRuntime(
        dataDir = dataDir,
        network = network,
        unavailable = unavailableSyncJson(network = network),
        createFailure = { nativeSyncStatus(dataDir, network) },
        block = ::nativeRuntimeSyncStatus,
    )

    fun clearResolverCache(dataDir: String, network: String = DEFAULT_NETWORK): String = withRuntime(
        dataDir = dataDir,
        network = network,
        unavailable = unavailableSyncJson("rust-core-unavailable", network),
        createFailure = { nativeClearResolverCache(dataDir, network) },
        block = ::nativeRuntimeClearResolverCache,
    )

    fun installHeaderSnapshot(
        dataDir: String,
        snapshotPath: String,
        network: String = DEFAULT_NETWORK,
    ): String = withRuntime(
        dataDir = dataDir,
        network = network,
        unavailable = unavailableSyncJson("rust-core-unavailable", network),
        createFailure = { nativeInstallHeaderSnapshot(dataDir, snapshotPath, network) },
    ) { handle -> nativeRuntimeInstallHeaderSnapshot(handle, snapshotPath) }

    fun resetHeadersFromPeers(dataDir: String, network: String = DEFAULT_NETWORK): String = withRuntime(
        dataDir = dataDir,
        network = network,
        unavailable = unavailableSyncJson("rust-core-unavailable", network),
        createFailure = { nativeResetHeadersFromPeers(dataDir, network) },
        block = ::nativeRuntimeResetHeadersFromPeers,
    )

    fun hnsProofDetails(
        dataDir: String,
        host: String,
        network: String = DEFAULT_NETWORK,
    ): String = withRuntime(
        dataDir = dataDir,
        network = network,
        unavailable = """{"host":"${jsonEscape(host)}","name":null,"network":"${jsonEscape(network)}","nameHash":null,"hnsProof":"error","proofStatus":"error","secure":null,"exists":null,"treeRoot":null,"blockHeight":null,"cacheStatus":"rust_core_unavailable","resourceValueHex":null,"recordTypes":[],"resourceRecords":[],"currentTip":null,"error":"rust-core-unavailable"}""",
        createFailure = { nativeHnsProofDetails(dataDir, host, network) },
    ) { handle -> nativeRuntimeHnsProofDetails(handle, host) }

    override fun httpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): ByteArray? {
        if (!isLoaded) return null
        val headerText = serializeHeaders(headers)
        val controls = gatewayRuntimeControls(headers)
        return withRuntime(
            dataDir = dataDir,
            network = controls.network,
            unavailable = null,
            createFailure = { null },
        ) { handle ->
            nativeRuntimeGatewayHttpResponse(
                handle,
                controls.network,
                controls.strictHnsMode,
                controls.dohResolverUrl,
                controls.statelessDaneCertificates,
                method,
                scheme,
                host,
                port,
                pathAndQuery,
                headerText,
                body,
            )
        }
    }

    override fun httpResponseBodyFile(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): HnsGatewayFileResponse? {
        if (!isLoaded) {
            return null
        }
        val headerText = serializeHeaders(headers)
        val controls = gatewayRuntimeControls(headers)
        val bodyFile = GatewayResponseBodyStore.create(dataDir) ?: return null
        val head = runCatching {
            withRuntime(
                dataDir = dataDir,
                network = controls.network,
                unavailable = null,
                createFailure = { null },
            ) { handle ->
                nativeRuntimeGatewayHttpResponseBodyToFile(
                    handle,
                    controls.network,
                    controls.strictHnsMode,
                    controls.dohResolverUrl,
                    controls.statelessDaneCertificates,
                    method,
                    scheme,
                    host,
                    port,
                    pathAndQuery,
                    headerText,
                    body,
                    bodyFile.absolutePath,
                )
            }
        }.getOrNull()
        if (head == null || !GatewayResponseBodyStore.retainCompleted(bodyFile)) {
            GatewayResponseBodyStore.release(bodyFile)
            return null
        }
        return HnsGatewayFileResponse(head, bodyFile)
    }

    internal fun startRustProxy(config: RustBrowserProxyConfig): LocalBrowserProxyEndpoint? = withRuntime(
        dataDir = config.dataDir,
        network = config.network,
        unavailable = null,
        createFailure = { null },
    ) { runtimeHandle ->
        val bundle = nativeRuntimeStartProxy(
            runtimeHandle,
            config.network,
            config.strictHnsMode,
            config.dohResolverUrl,
            config.statelessDaneCertificates,
            config.scopeHost,
        ) ?: return@withRuntime null
        parseRustProxyEndpointBundle(bundle) ?: run {
            rustProxyHandleFromBundle(bundle)?.let(::nativeProxyDestroy)
            null
        }
    }

    internal fun requestRustProxyStop(endpoint: LocalBrowserProxyEndpoint): Boolean =
        isLoaded && nativeProxyRequestStop(
            endpoint.nativeHandle,
            endpoint.instanceId.sessionId,
            endpoint.instanceId.generation,
        )

    internal fun destroyRustProxy(nativeHandle: Long) {
        if (isLoaded && nativeHandle > 0L) {
            nativeProxyDestroy(nativeHandle)
        }
    }

    internal fun rustProxyMatchesLocalCertificate(
        endpoint: LocalBrowserProxyEndpoint,
        host: String,
        certificateDer: ByteArray,
    ): Boolean = isLoaded && nativeProxyMatchesLocalCertificate(
        endpoint.nativeHandle,
        endpoint.instanceId.sessionId,
        endpoint.instanceId.generation,
        host,
        certificateDer,
    )

    internal fun takeRustProxyMainFrameStatus(
        endpoint: LocalBrowserProxyEndpoint,
        host: String,
    ): LocalBrowserProxyStatus? {
        if (!isLoaded) return null
        val bundle = nativeProxyTakeMainFrameStatus(
            endpoint.nativeHandle,
            endpoint.instanceId.sessionId,
            endpoint.instanceId.generation,
            host,
        ) ?: return null
        return parseRustProxyStatusBundle(bundle, endpoint, host)
    }

    internal fun discardRustProxyMainFrameStatus(
        endpoint: LocalBrowserProxyEndpoint,
        host: String,
    ): Boolean = isLoaded && nativeProxyDiscardMainFrameStatus(
        endpoint.nativeHandle,
        endpoint.instanceId.sessionId,
        endpoint.instanceId.generation,
        host,
    )

    fun closeRuntimes() {
        if (!isLoaded) return
        val writeLock = runtimeLifecycleLock.writeLock()
        writeLock.lock()
        try {
            nativeProxyDestroyAll()
            runtimeHandles.values.forEach(::nativeRuntimeDestroy)
            runtimeHandles.clear()
        } finally {
            writeLock.unlock()
        }
    }

    private fun <T> withRuntime(
        dataDir: String,
        network: String,
        unavailable: T,
        createFailure: () -> T,
        block: (Long) -> T,
    ): T {
        if (!isLoaded) return unavailable
        val canonicalNetwork = canonicalRuntimeNetwork(network)
        val key = RuntimeKey(dataDir, canonicalNetwork)
        val readLock = runtimeLifecycleLock.readLock()
        readLock.lock()
        try {
            runtimeHandles[key]?.let { handle -> return block(handle) }
        } finally {
            readLock.unlock()
        }

        val writeLock = runtimeLifecycleLock.writeLock()
        writeLock.lock()
        try {
            val existing = runtimeHandles[key]
            if (existing != null) return block(existing)
            val created = nativeRuntimeCreate(dataDir, canonicalNetwork)
            if (created == INVALID_RUNTIME_HANDLE) return createFailure()
            runtimeHandles[key] = created
            return block(created)
        } finally {
            writeLock.unlock()
        }
    }

    private external fun nativeVersion(): String

    private external fun nativeDiagnostics(): String

    private external fun nativeRuntimeCreate(dataDir: String, network: String): Long

    private external fun nativeRuntimeDestroy(handle: Long)

    private external fun nativeRuntimeSyncOnce(handle: Long): String

    private external fun nativeRuntimeSyncStatus(handle: Long): String

    private external fun nativeRuntimeClearResolverCache(handle: Long): String

    private external fun nativeRuntimeInstallHeaderSnapshot(handle: Long, snapshotPath: String): String

    private external fun nativeRuntimeResetHeadersFromPeers(handle: Long): String

    private external fun nativeRuntimeHnsProofDetails(handle: Long, host: String): String

    private external fun nativeRuntimeStartProxy(
        handle: Long,
        network: String,
        strictHnsMode: Boolean,
        dohResolverUrl: String,
        statelessDaneCertificates: Boolean,
        scopeRoot: String,
    ): ByteArray?

    private external fun nativeRuntimeGatewayHttpResponse(
        handle: Long,
        network: String,
        strictHnsMode: Boolean,
        dohResolverUrl: String,
        statelessDaneCertificates: Boolean,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        body: ByteArray,
    ): ByteArray?

    private external fun nativeRuntimeGatewayHttpResponseBodyToFile(
        handle: Long,
        network: String,
        strictHnsMode: Boolean,
        dohResolverUrl: String,
        statelessDaneCertificates: Boolean,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        body: ByteArray,
        bodyPath: String,
    ): ByteArray?

    private external fun nativeProxyRequestStop(
        handle: Long,
        sessionId: String,
        generation: Long,
    ): Boolean

    private external fun nativeProxyDestroy(handle: Long)

    private external fun nativeProxyDestroyAll()

    private external fun nativeProxyTakeMainFrameStatus(
        handle: Long,
        sessionId: String,
        generation: Long,
        host: String,
    ): ByteArray?

    private external fun nativeProxyDiscardMainFrameStatus(
        handle: Long,
        sessionId: String,
        generation: Long,
        host: String,
    ): Boolean

    private external fun nativeProxyMatchesLocalCertificate(
        handle: Long,
        sessionId: String,
        generation: Long,
        host: String,
        certificateDer: ByteArray,
    ): Boolean

    private external fun nativeSyncOnce(dataDir: String, network: String): String

    private external fun nativeSyncStatus(dataDir: String, network: String): String

    private external fun nativeClearResolverCache(dataDir: String, network: String): String

    private external fun nativeInstallHeaderSnapshot(
        dataDir: String,
        snapshotPath: String,
        network: String,
    ): String

    private external fun nativeResetHeadersFromPeers(dataDir: String, network: String): String

    private external fun nativeHnsProofDetails(dataDir: String, host: String, network: String): String

    private fun serializeHeaders(headers: List<Pair<String, String>>): String = buildString {
        headers.forEach { (name, value) ->
            append(name)
            append(": ")
            append(value)
            append("\r\n")
        }
    }

    private fun gatewayRuntimeControls(headers: List<Pair<String, String>>): GatewayRuntimeControls {
        var strictHnsMode = false
        var dohResolverUrl = ""
        var statelessDaneCertificates = false
        var network = DEFAULT_NETWORK
        headers.forEach { (name, rawValue) ->
            val value = rawValue.trim()
            when {
                name.equals(HNS_GATEWAY_STRICT_MODE_HEADER, ignoreCase = true) -> {
                    strictHnsMode = strictHnsMode ||
                        value == "1" || value.equals("true", ignoreCase = true)
                }
                name.equals(HNS_GATEWAY_DOH_RESOLVER_HEADER, ignoreCase = true) -> {
                    dohResolverUrl = value
                }
                name.equals(HNS_GATEWAY_STATELESS_DANE_HEADER, ignoreCase = true) -> {
                    statelessDaneCertificates = statelessDaneCertificates ||
                        value == "1" || value.equals("true", ignoreCase = true)
                }
                name.equals(HNS_GATEWAY_NETWORK_HEADER, ignoreCase = true) -> {
                    network = value
                }
            }
        }
        return GatewayRuntimeControls(
            network = canonicalRuntimeNetwork(network),
            strictHnsMode = strictHnsMode,
            dohResolverUrl = dohResolverUrl,
            statelessDaneCertificates = statelessDaneCertificates,
        )
    }

    private fun canonicalRuntimeNetwork(network: String): String =
        when (network.trim().lowercase(Locale.US)) {
            "main", "mainnet" -> "mainnet"
            "test", "testnet" -> "testnet"
            "reg", "regtest" -> "regtest"
            else -> network.trim()
        }

    private fun unavailableSyncJson(
        error: String = "rust-core-unavailable",
        network: String = DEFAULT_NETWORK,
    ): String =
        """{"network":"${jsonEscape(network)}","status":"error","attempted":0,"successful":0,"accepted":0,"failed":0,"peerCount":0,"peerGroups":0,"bestHeight":null,"bestPeerHeight":null,"estimatedTipHeight":null,"resourceCacheEntries":0,"resourceCacheBytes":0,"resourceCacheEvicted":0,"error":"$error","failures":[]}"""

    private fun jsonEscape(value: String): String =
        value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")

    private const val INVALID_RUNTIME_HANDLE = 0L
    private const val DEFAULT_NETWORK = "mainnet"

    private data class RuntimeKey(val dataDir: String, val network: String)

    private data class GatewayRuntimeControls(
        val network: String,
        val strictHnsMode: Boolean,
        val dohResolverUrl: String,
        val statelessDaneCertificates: Boolean,
    )

    private val runtimeLifecycleLock = ReentrantReadWriteLock()
    private val runtimeHandles = mutableMapOf<RuntimeKey, Long>()
}
