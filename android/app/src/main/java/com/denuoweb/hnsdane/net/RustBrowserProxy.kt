package com.denuoweb.hnsdane.net

import java.nio.charset.StandardCharsets

internal interface LocalBrowserProxy {
    val endpoint: LocalBrowserProxyEndpoint
    val scopeHost: String

    fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean

    /** Revokes admission and local-certificate trust without waiting for native workers to join. */
    fun requestStop()

    /** Completes the blocking native worker join. This must not run on the Android main thread. */
    fun joinAndDestroy()
}

internal class LocalProxyInstanceId(
    val sessionId: String,
    val generation: Long,
) {
    override fun equals(other: Any?): Boolean =
        other is LocalProxyInstanceId &&
            sessionId == other.sessionId &&
            generation == other.generation

    override fun hashCode(): Int = 31 * sessionId.hashCode() + generation.hashCode()

    override fun toString(): String = "LocalProxyInstanceId([REDACTED])"
}

internal class LocalBrowserProxyEndpoint(
    internal val nativeHandle: Long,
    val port: Int,
    val instanceId: LocalProxyInstanceId,
    val authorization: LoopbackProxyAuthorization,
) {
    override fun toString(): String =
        "LocalBrowserProxyEndpoint(port=$port, instance=[REDACTED], authorization=[REDACTED])"
}

internal class RustBrowserProxyConfig(
    val dataDir: String,
    val network: String,
    val scopeHost: String,
    val strictHnsMode: Boolean,
    val dohResolverUrl: String,
    val statelessDaneCertificates: Boolean,
)

internal interface RustBrowserProxyNativeApi {
    fun start(config: RustBrowserProxyConfig): LocalBrowserProxyEndpoint?

    fun requestStop(endpoint: LocalBrowserProxyEndpoint): Boolean

    fun destroy(nativeHandle: Long)

    fun matchesLocalCertificate(
        endpoint: LocalBrowserProxyEndpoint,
        host: String,
        certificateDer: ByteArray,
    ): Boolean
}

internal object NativeRustBrowserProxyApi : RustBrowserProxyNativeApi {
    override fun start(config: RustBrowserProxyConfig): LocalBrowserProxyEndpoint? =
        NativeBridge.startRustProxy(config)

    override fun requestStop(endpoint: LocalBrowserProxyEndpoint): Boolean =
        NativeBridge.requestRustProxyStop(endpoint)

    override fun destroy(nativeHandle: Long) {
        NativeBridge.destroyRustProxy(nativeHandle)
    }

    override fun matchesLocalCertificate(
        endpoint: LocalBrowserProxyEndpoint,
        host: String,
        certificateDer: ByteArray,
    ): Boolean = NativeBridge.rustProxyMatchesLocalCertificate(endpoint, host, certificateDer)
}

internal class RustBrowserProxy private constructor(
    override val endpoint: LocalBrowserProxyEndpoint,
    override val scopeHost: String,
    private val nativeApi: RustBrowserProxyNativeApi,
) : LocalBrowserProxy {
    private val lifecycleLock = Any()
    private var stopRequested = false
    private var destroyed = false

    override fun matchesLocalCertificate(host: String, certificateDer: ByteArray): Boolean {
        synchronized(lifecycleLock) {
            if (stopRequested || destroyed) return false
        }
        return nativeApi.matchesLocalCertificate(endpoint, host, certificateDer)
    }

    override fun requestStop() {
        val shouldRequest = synchronized(lifecycleLock) {
            if (stopRequested || destroyed) {
                false
            } else {
                stopRequested = true
                true
            }
        }
        if (shouldRequest) {
            nativeApi.requestStop(endpoint)
        }
    }

    override fun joinAndDestroy() {
        requestStop()
        val handle = synchronized(lifecycleLock) {
            if (destroyed) return
            destroyed = true
            endpoint.nativeHandle
        }
        nativeApi.destroy(handle)
    }

    override fun toString(): String =
        "RustBrowserProxy(scope=[REDACTED], endpoint=$endpoint)"

    companion object {
        fun start(
            config: RustBrowserProxyConfig,
            nativeApi: RustBrowserProxyNativeApi = NativeRustBrowserProxyApi,
        ): RustBrowserProxy? = nativeApi.start(config)?.let { endpoint ->
            RustBrowserProxy(endpoint, config.scopeHost, nativeApi)
        }
    }
}

internal fun parseRustProxyEndpointBundle(bundle: ByteArray): LocalBrowserProxyEndpoint? {
    if (bundle.size !in MIN_PROXY_ENDPOINT_BUNDLE_BYTES..MAX_PROXY_ENDPOINT_BUNDLE_BYTES) return null
    val cursor = ProxyEndpointBundleCursor(bundle)
    if (!cursor.readBytes(PROXY_ENDPOINT_MAGIC.size).contentEquals(PROXY_ENDPOINT_MAGIC)) return null
    if (cursor.readUnsignedByte() != PROXY_ENDPOINT_VERSION) return null
    val handle = cursor.readLong()
    val port = cursor.readUnsignedShort()
    val generation = cursor.readLong()
    if (handle <= 0L || port !in 1..65535 || generation <= 0L) return null

    val sessionId = cursor.readAscii(MAX_PROXY_SESSION_BYTES) ?: return null
    val realm = cursor.readAscii(MAX_PROXY_REALM_BYTES) ?: return null
    val username = cursor.readAscii(MAX_PROXY_USERNAME_BYTES) ?: return null
    val password = cursor.readAscii(MAX_PROXY_PASSWORD_BYTES) ?: return null
    if (!cursor.isComplete()) return null

    return LocalBrowserProxyEndpoint(
        nativeHandle = handle,
        port = port,
        instanceId = LocalProxyInstanceId(sessionId, generation),
        authorization = LoopbackProxyAuthorization.createForNative(realm, username, password),
    )
}

internal fun rustProxyHandleFromBundle(bundle: ByteArray): Long? {
    if (bundle.size < PROXY_HANDLE_END_OFFSET) return null
    if (!bundle.copyOfRange(0, PROXY_ENDPOINT_MAGIC.size).contentEquals(PROXY_ENDPOINT_MAGIC)) return null
    if ((bundle[PROXY_ENDPOINT_MAGIC.size].toInt() and 0xff) != PROXY_ENDPOINT_VERSION) return null
    return ProxyEndpointBundleCursor(bundle, PROXY_HANDLE_OFFSET)
        .readLong()
        .takeIf { it > 0L }
}

private class ProxyEndpointBundleCursor(
    private val bytes: ByteArray,
    private var offset: Int = 0,
) {
    fun readUnsignedByte(): Int =
        if (offset < bytes.size) bytes[offset++].toInt() and 0xff else -1

    fun readUnsignedShort(): Int {
        val value = readBytes(2)
        if (value.size != 2) return -1
        return ((value[0].toInt() and 0xff) shl 8) or (value[1].toInt() and 0xff)
    }

    fun readLong(): Long {
        val value = readBytes(8)
        if (value.size != 8) return Long.MIN_VALUE
        var result = 0L
        value.forEach { byte -> result = (result shl 8) or (byte.toLong() and 0xff) }
        return result
    }

    fun readAscii(maxBytes: Int): String? {
        val length = readUnsignedShort()
        if (length !in 1..maxBytes) return null
        val value = readBytes(length)
        if (value.size != length || value.any { byte -> (byte.toInt() and 0xff) !in 0x21..0x7e }) {
            return null
        }
        return String(value, StandardCharsets.US_ASCII)
    }

    fun readBytes(length: Int): ByteArray {
        if (length < 0 || length > bytes.size - offset) return byteArrayOf()
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun isComplete(): Boolean = offset == bytes.size
}

private val PROXY_ENDPOINT_MAGIC = byteArrayOf('H'.code.toByte(), 'N'.code.toByte(), 'S'.code.toByte(), 'P'.code.toByte())
private const val PROXY_ENDPOINT_VERSION = 1
private const val PROXY_HANDLE_OFFSET = 5
private const val PROXY_HANDLE_END_OFFSET = PROXY_HANDLE_OFFSET + 8
private const val MIN_PROXY_ENDPOINT_BUNDLE_BYTES = 35
private const val MAX_PROXY_ENDPOINT_BUNDLE_BYTES = 1024
private const val MAX_PROXY_SESSION_BYTES = 64
private const val MAX_PROXY_REALM_BYTES = 128
private const val MAX_PROXY_USERNAME_BYTES = 64
private const val MAX_PROXY_PASSWORD_BYTES = 256
