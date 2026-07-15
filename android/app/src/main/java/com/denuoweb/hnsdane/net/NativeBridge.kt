package com.denuoweb.hnsdane.net

import java.io.File
import java.io.InputStream
import java.io.OutputStream
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

    fun httpUpgradeTunnel(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        clientInput: InputStream,
        clientOutput: OutputStream,
    ): Boolean = false
}

interface HnsSyncBridge {
    fun syncOnce(dataDir: String): String

    fun syncOnce(dataDir: String, network: String): String = syncOnce(dataDir)
}

interface LocalTlsCertificateProvider {
    fun localTlsCertificate(host: String): LocalTlsCertificate?
}

data class LocalTlsCertificate(
    val certificateDer: ByteArray,
    val privateKeyPkcs8Der: ByteArray,
    val certificateSha256: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LocalTlsCertificate) return false
        return certificateDer.contentEquals(other.certificateDer) &&
            privateKeyPkcs8Der.contentEquals(other.privateKeyPkcs8Der) &&
            certificateSha256.contentEquals(other.certificateSha256)
    }

    override fun hashCode(): Int {
        var result = certificateDer.contentHashCode()
        result = 31 * result + privateKeyPkcs8Der.contentHashCode()
        result = 31 * result + certificateSha256.contentHashCode()
        return result
    }
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

object NativeBridge : HnsGatewayBridge, HnsSyncBridge, LocalTlsCertificateProvider {
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

    override fun localTlsCertificate(host: String): LocalTlsCertificate? = if (isLoaded) {
        nativeLocalTlsCertificate(host)?.let(::parseLocalTlsCertificateBundle)
    } else {
        null
    }

    override fun httpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        body: ByteArray,
    ): ByteArray? = if (isLoaded) {
        nativeGatewayHttpResponse(
            dataDir,
            method,
            scheme,
            host,
            port,
            pathAndQuery,
            serializeHeaders(headers),
            body,
        )
    } else {
        null
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
        val bodyFile = GatewayResponseBodyStore.create(dataDir) ?: return null
        val head = runCatching {
            nativeGatewayHttpResponseBodyToFile(
                dataDir,
                method,
                scheme,
                host,
                port,
                pathAndQuery,
                serializeHeaders(headers),
                body,
                bodyFile.absolutePath,
            )
        }.getOrNull()
        if (head == null || !GatewayResponseBodyStore.retainCompleted(bodyFile)) {
            GatewayResponseBodyStore.release(bodyFile)
            return null
        }
        return HnsGatewayFileResponse(head, bodyFile)
    }

    override fun httpUpgradeTunnel(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headers: List<Pair<String, String>>,
        clientInput: InputStream,
        clientOutput: OutputStream,
    ): Boolean = isLoaded && nativeGatewayHttpUpgradeTunnel(
        dataDir,
        method,
        scheme,
        host,
        port,
        pathAndQuery,
        serializeHeaders(headers),
        clientInput,
        clientOutput,
    )

    internal fun startRustProxy(config: RustBrowserProxyConfig): LocalBrowserProxyEndpoint? = withRuntime(
        dataDir = config.dataDir,
        network = config.network,
        unavailable = null,
        createFailure = { null },
    ) { runtimeHandle ->
        val policyRevision = nativeRuntimeSetPolicy(
            runtimeHandle,
            config.strictHnsMode,
            config.dohResolverUrl,
            config.statelessDaneCertificates,
        )
        if (policyRevision <= 0L) {
            null
        } else {
            val bundle = nativeRuntimeStartProxy(runtimeHandle, config.scopeHost) ?: return@withRuntime null
            parseRustProxyEndpointBundle(bundle) ?: run {
                rustProxyHandleFromBundle(bundle)?.let(::nativeProxyDestroy)
                null
            }
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
        val key = RuntimeKey(dataDir, network)
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
            val created = nativeRuntimeCreate(dataDir, network)
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

    private external fun nativeRuntimeSetPolicy(
        handle: Long,
        strictHnsMode: Boolean,
        dohResolverUrl: String,
        statelessDaneCertificates: Boolean,
    ): Long

    private external fun nativeRuntimeStartProxy(handle: Long, scopeRoot: String): ByteArray?

    private external fun nativeProxyRequestStop(
        handle: Long,
        sessionId: String,
        generation: Long,
    ): Boolean

    private external fun nativeProxyDestroy(handle: Long)

    private external fun nativeProxyDestroyAll()

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

    private external fun nativeLocalTlsCertificate(host: String): ByteArray?

    private external fun nativeGatewayHttpResponse(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        body: ByteArray,
    ): ByteArray?

    private external fun nativeGatewayHttpResponseBodyToFile(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        body: ByteArray,
        bodyPath: String,
    ): ByteArray?

    private external fun nativeGatewayHttpUpgradeTunnel(
        dataDir: String,
        method: String,
        scheme: String,
        host: String,
        port: Int,
        pathAndQuery: String,
        headerText: String,
        clientInput: InputStream,
        clientOutput: OutputStream,
    ): Boolean

    private fun serializeHeaders(headers: List<Pair<String, String>>): String = buildString {
        headers.forEach { (name, value) ->
            append(name)
            append(": ")
            append(value)
            append("\r\n")
        }
    }

    private fun parseLocalTlsCertificateBundle(bundle: ByteArray): LocalTlsCertificate? {
        var offset = 0

        fun readLength(): Int? {
            if (offset + 4 > bundle.size) return null
            val length = (
                ((bundle[offset].toInt() and 0xff) shl 24) or
                    ((bundle[offset + 1].toInt() and 0xff) shl 16) or
                    ((bundle[offset + 2].toInt() and 0xff) shl 8) or
                    (bundle[offset + 3].toInt() and 0xff)
                )
            offset += 4
            if (length < 0 || length > bundle.size - offset) return null
            return length
        }

        fun readBytes(length: Int): ByteArray {
            val value = bundle.copyOfRange(offset, offset + length)
            offset += length
            return value
        }

        val certificateLength = readLength() ?: return null
        val certificateDer = readBytes(certificateLength)
        val keyLength = readLength() ?: return null
        val keyDer = readBytes(keyLength)
        if (offset + LOCAL_TLS_FINGERPRINT_BYTES != bundle.size) return null
        val fingerprint = readBytes(LOCAL_TLS_FINGERPRINT_BYTES)
        return LocalTlsCertificate(certificateDer, keyDer, fingerprint)
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

    private const val LOCAL_TLS_FINGERPRINT_BYTES = 32
    private const val INVALID_RUNTIME_HANDLE = 0L
    private const val DEFAULT_NETWORK = "mainnet"

    private data class RuntimeKey(val dataDir: String, val network: String)

    private val runtimeLifecycleLock = ReentrantReadWriteLock()
    private val runtimeHandles = mutableMapOf<RuntimeKey, Long>()
}
