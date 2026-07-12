package com.denuoweb.hnsdane.net

import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private val HTTP_HEADER_END = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())

class HnsWebSocketBridge(
    private val dataDir: File,
    private val activeMainFrameUrl: () -> String?,
    private val strictHnsMode: () -> Boolean = { false },
    private val dohResolverUrl: () -> String = { "" },
    private val statelessDaneCertificates: () -> Boolean = { false },
    private val handshakeNetwork: () -> String = { DEFAULT_NETWORK },
    private val enabled: () -> Boolean = { true },
    private val hnsGatewayBridge: HnsGatewayBridge = NativeBridge,
    private val callbackHandler: Handler = Handler(Looper.getMainLooper()),
    private val executor: ExecutorService = Executors.newFixedThreadPool(HnsWebSocketLimits.MAX_ACTIVE_SESSIONS),
    private val writerExecutor: ExecutorService = Executors.newFixedThreadPool(4),
    private val closeScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(),
) : WebViewCompat.WebMessageListener, Closeable {
    private val sessions = ConcurrentHashMap<HnsWebSocketSessionKey, NativeHnsWebSocketSession>()
    private val closed = AtomicBoolean(false)

    override fun onPostMessage(
        view: WebView,
        message: WebMessageCompat,
        sourceOrigin: Uri,
        isMainFrame: Boolean,
        replyProxy: JavaScriptReplyProxy,
    ) {
        if (closed.get() || !enabled() || message.type != WebMessageCompat.TYPE_STRING) {
            return
        }
        val data = message.data ?: return
        if (data.length > HnsWebSocketLimits.MAX_WEB_MESSAGE_CHARS) {
            return
        }
        val payload = runCatching { JSONObject(data) }.getOrNull() ?: return
        val type = payload.optString("type")
        if (type != "open") {
            val trustedSource = runCatching {
                HnsWebSocketRequestPolicy.validateMessageSource(
                    sourceOrigin = sourceOrigin.toString(),
                    activeMainFrameUrl = activeMainFrameUrl(),
                    isMainFrame = isMainFrame,
                )
            }.isSuccess
            if (!trustedSource) {
                return
            }
        }
        when (type) {
            "open" -> openSession(payload, sourceOrigin.toString(), isMainFrame, view)
            "send" -> sendSessionPayload(payload)
            "close" -> closeSession(payload)
        }
    }

    fun closeAll(code: Int = CLOSE_GOING_AWAY, reason: String = "page changed") {
        sessions.values.forEach { it.forceClose(code, reason) }
        sessions.clear()
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            closeAll(CLOSE_GOING_AWAY, "browser shutdown")
            closeScheduler.shutdownNow()
            writerExecutor.shutdownNow()
            executor.shutdownNow()
        }
    }

    private fun openSession(
        payload: JSONObject,
        sourceOrigin: String,
        isMainFrame: Boolean,
        webView: WebView,
    ) {
        val key = HnsWebSocketSessionKey.fromPayload(payload) ?: return
        val id = key.id
        if (id < 0) {
            return
        }
        if (sessions.size >= HnsWebSocketLimits.MAX_ACTIVE_SESSIONS) {
            emitClose(webView, key, CLOSE_ABNORMAL, "too many HNS WebSockets", false)
            return
        }
        val target = runCatching {
            HnsWebSocketRequestPolicy.validate(
                sourceOrigin = sourceOrigin,
                activeMainFrameUrl = activeMainFrameUrl(),
                targetUrl = payload.getString("url"),
                isMainFrame = isMainFrame,
            )
        }.getOrElse { error ->
            emitError(webView, key, error.message ?: "HNS WebSocket blocked")
            emitClose(webView, key, CLOSE_ABNORMAL, error.message ?: "HNS WebSocket blocked", false)
            return
        }
        val session = NativeHnsWebSocketSession(
            key = key,
            target = target,
            protocols = payload.optJSONArray("protocols").stringValues(),
            dataDir = dataDir,
            strictHnsMode = strictHnsMode,
            dohResolverUrl = dohResolverUrl,
            statelessDaneCertificates = statelessDaneCertificates,
            handshakeNetwork = handshakeNetwork,
            hnsGatewayBridge = hnsGatewayBridge,
            executor = executor,
            writerExecutor = writerExecutor,
            closeScheduler = closeScheduler,
            emit = { event -> emit(webView, event) },
            onFinished = { sessions.remove(key) },
        )
        if (sessions.putIfAbsent(key, session) != null) {
            emitClose(webView, key, CLOSE_ABNORMAL, "duplicate HNS WebSocket id", false)
            return
        }
        session.start()
    }

    private fun sendSessionPayload(payload: JSONObject) {
        val session = sessions[HnsWebSocketSessionKey.fromPayload(payload)] ?: return
        when (payload.optString("dataType")) {
            "text" -> session.sendText(payload.optString("data", ""))
            "binary" -> {
                val encoded = payload.optString("data", "")
                if (encoded.length > HnsWebSocketLimits.MAX_OUTBOUND_BINARY_BASE64_CHARS) {
                    session.reject("HNS WebSocket binary message is too large", CLOSE_MESSAGE_TOO_BIG)
                    return
                }
                val bytes = runCatching { Base64.getDecoder().decode(encoded) }
                    .getOrElse {
                        session.reject("HNS WebSocket binary message is malformed")
                        return
                    }
                session.sendBinary(bytes)
            }
            else -> session.sendText(payload.optString("data", ""))
        }
    }

    private fun closeSession(payload: JSONObject) {
        val session = sessions[HnsWebSocketSessionKey.fromPayload(payload)] ?: return
        val code = payload.optInt("code", CLOSE_NORMAL)
        val reason = payload.optString("reason", "")
        if (runCatching { HnsWebSocketFrameCodec.closePayload(code, reason) }.isFailure) {
            session.reject("HNS WebSocket close request is invalid")
            return
        }
        session.close(code, reason)
    }

    private fun emit(webView: WebView, event: JSONObject) {
        val script = "window.__hnsWebSocketDispatch&&window.__hnsWebSocketDispatch(${JSONObject.quote(event.toString())});"
        callbackHandler.post {
            if (!closed.get()) {
                runCatching { webView.evaluateJavascript(script, null) }
            }
        }
    }

    private fun emitError(webView: WebView, key: HnsWebSocketSessionKey, reason: String) {
        emit(webView, key.event("error").put("reason", reason))
    }

    private fun emitClose(webView: WebView, key: HnsWebSocketSessionKey, code: Int, reason: String, wasClean: Boolean) {
        emit(
            webView,
            key.event("close")
                .put("code", code)
                .put("reason", reason)
                .put("wasClean", wasClean),
        )
    }

    companion object {
        const val CLOSE_NORMAL = 1000
        const val CLOSE_GOING_AWAY = 1001
        const val CLOSE_ABNORMAL = 1006
        const val CLOSE_MESSAGE_TOO_BIG = 1009
        const val CLOSE_TRY_AGAIN_LATER = 1013
    }
}

private data class HnsWebSocketSessionKey(
    val pageId: String,
    val id: Int,
) {
    fun event(name: String): JSONObject =
        JSONObject()
            .put("pageId", pageId)
            .put("id", id)
            .put("event", name)

    companion object {
        fun fromPayload(payload: JSONObject): HnsWebSocketSessionKey? {
            val pageId = payload.optString("pageId")
                .trim()
                .takeIf { it.isNotBlank() && it.length <= HnsWebSocketLimits.MAX_PAGE_ID_CHARS }
                ?: return null
            val id = payload.optInt("id", -1).takeIf { it >= 0 } ?: return null
            return HnsWebSocketSessionKey(pageId, id)
        }
    }
}

private class NativeHnsWebSocketSession(
    private val key: HnsWebSocketSessionKey,
    private val target: HnsWebSocketTarget,
    private val protocols: List<String>,
    private val dataDir: File,
    private val strictHnsMode: () -> Boolean,
    private val dohResolverUrl: () -> String,
    private val statelessDaneCertificates: () -> Boolean,
    private val handshakeNetwork: () -> String,
    private val hnsGatewayBridge: HnsGatewayBridge,
    private val executor: ExecutorService,
    private val writerExecutor: ExecutorService,
    private val closeScheduler: ScheduledExecutorService,
    private val emit: (JSONObject) -> Unit,
    private val onFinished: () -> Unit,
) {
    private val finished = AtomicBoolean(false)
    private val closeRequested = AtomicBoolean(false)
    private val writeLock = Any()
    private val outboundQueueLock = Any()
    private var clientWriter: PipedOutputStream? = null
    private var pendingOutboundBytes = 0
    private var pendingOutboundFrames = 0
    @Volatile
    private var opened = false
    private var closeFrameSent = false
    @Volatile
    private var closeTimeout: ScheduledFuture<*>? = null
    private val handshakeKey = websocketKey()
    private val messageAssembler = HnsWebSocketMessageAssembler(
        onMessage = ::emitMessage,
        onFailure = { reason -> fail(reason, HnsWebSocketBridge.CLOSE_MESSAGE_TOO_BIG) },
    )

    fun start() {
        val clientInput = PipedInputStream(PIPE_BUFFER_BYTES)
        val clientOutput = PipedOutputStream(clientInput)
        clientWriter = clientOutput
        val tunnelOutput = HnsWebSocketTunnelOutput(
            onHandshake = ::handleHandshake,
            onFrameBytes = ::handleFrameBytes,
            onFailure = ::fail,
        )

        try {
            executor.execute {
                try {
                    val tunneled = hnsGatewayBridge.httpUpgradeTunnel(
                        dataDir = dataDir.absolutePath,
                        method = "GET",
                        scheme = target.scheme,
                        host = target.host,
                        port = target.port,
                        pathAndQuery = target.pathAndQuery,
                        headers = handshakeHeaders(),
                        clientInput = clientInput,
                        clientOutput = tunnelOutput,
                    )
                    if (!tunneled && !finished.get()) {
                        fail("HNS WebSocket tunnel failed")
                    } else if (!finished.get()) {
                        finishClose(HnsWebSocketBridge.CLOSE_ABNORMAL, "HNS WebSocket closed", false)
                    }
                } catch (error: Exception) {
                    if (!finished.get()) {
                        fail(error.message ?: "HNS WebSocket tunnel failed")
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            runCatching { clientOutput.close() }
            runCatching { clientInput.close() }
            fail("HNS WebSocket tunnel is unavailable", HnsWebSocketBridge.CLOSE_TRY_AGAIN_LATER)
        }
    }

    fun sendText(text: String) {
        val payload = runCatching { HnsWebSocketFrameCodec.textPayload(text) }.getOrElse {
            fail("HNS WebSocket text message is not valid UTF-8")
            return
        }
        writeFrame(HnsWebSocketFrameCodec.OPCODE_TEXT, payload)
    }

    fun sendBinary(bytes: ByteArray) {
        writeFrame(HnsWebSocketFrameCodec.OPCODE_BINARY, bytes)
    }

    fun reject(reason: String, code: Int = HnsWebSocketBridge.CLOSE_ABNORMAL) {
        fail(reason, code)
    }

    fun close(code: Int, reason: String) {
        if (!closeRequested.compareAndSet(false, true)) {
            return
        }
        try {
            writerExecutor.execute {
                val sent = runCatching {
                    val payload = HnsWebSocketFrameCodec.closePayload(code, reason)
                    synchronized(writeLock) {
                        if (finished.get()) {
                            return@synchronized false
                        }
                        val writer = clientWriter ?: return@synchronized false
                        writer.write(HnsWebSocketFrameCodec.encodeClientFrame(HnsWebSocketFrameCodec.OPCODE_CLOSE, payload))
                        writer.flush()
                        closeFrameSent = true
                        true
                    }
                }.getOrDefault(false)
                if (!sent) {
                    fail("HNS WebSocket close send failed")
                    return@execute
                }
                scheduleCloseTimeout()
            }
        } catch (_: RejectedExecutionException) {
            forceClose(code, reason)
        }
    }

    fun forceClose(code: Int, reason: String) {
        runCatching {
            synchronized(writeLock) {
                clientWriter?.close()
                clientWriter = null
            }
        }
        finishClose(code, reason, false)
    }

    private fun writeFrame(opcode: Int, payload: ByteArray) {
        if (finished.get() || closeRequested.get() || !opened) {
            return
        }
        if (payload.size > HnsWebSocketLimits.MAX_MESSAGE_BYTES) {
            fail("HNS WebSocket message is too large", HnsWebSocketBridge.CLOSE_MESSAGE_TOO_BIG)
            return
        }
        if (!reserveOutbound(payload.size)) {
            fail("HNS WebSocket send buffer is full", HnsWebSocketBridge.CLOSE_TRY_AGAIN_LATER)
            return
        }
        try {
            writerExecutor.execute {
                runCatching {
                    synchronized(writeLock) {
                        clientWriter?.write(HnsWebSocketFrameCodec.encodeClientFrame(opcode, payload))
                        clientWriter?.flush()
                    }
                }.onFailure {
                    fail("HNS WebSocket send failed")
                }.also {
                    releaseOutbound(payload.size)
                }
            }
        } catch (_: RuntimeException) {
            releaseOutbound(payload.size)
            fail("HNS WebSocket send failed")
        }
    }

    private fun reserveOutbound(payloadBytes: Int): Boolean =
        synchronized(outboundQueueLock) {
            if (
                pendingOutboundFrames >= HnsWebSocketLimits.MAX_OUTBOUND_QUEUE_FRAMES ||
                pendingOutboundBytes.toLong() + payloadBytes.toLong() > HnsWebSocketLimits.MAX_OUTBOUND_QUEUE_BYTES
            ) {
                false
            } else {
                pendingOutboundFrames += 1
                pendingOutboundBytes += payloadBytes
                true
            }
        }

    private fun releaseOutbound(payloadBytes: Int) {
        synchronized(outboundQueueLock) {
            pendingOutboundFrames = (pendingOutboundFrames - 1).coerceAtLeast(0)
            pendingOutboundBytes = (pendingOutboundBytes - payloadBytes).coerceAtLeast(0)
        }
    }

    private fun handleHandshake(head: ByteArray) {
        val selectedProtocol = runCatching {
            HnsWebSocketHandshakePolicy.validate(head, handshakeKey, protocols)
        }.getOrElse { error ->
            fail(error.message ?: "HNS WebSocket handshake is invalid")
            return
        }
        opened = true
        emit(
            key.event("open")
                .put("protocol", selectedProtocol),
        )
    }

    private fun handleFrameBytes(bytes: ByteArray, offset: Int, length: Int) {
        if (!opened || finished.get()) {
            return
        }
        runCatching {
            frameParser.append(bytes, offset, length)
        }.onFailure { error ->
            fail(error.message ?: "HNS WebSocket frame is malformed")
        }
    }

    private val frameParser = HnsWebSocketFrameParser { frame ->
        when (frame.opcode) {
            HnsWebSocketFrameCodec.OPCODE_TEXT,
            HnsWebSocketFrameCodec.OPCODE_BINARY,
            HnsWebSocketFrameCodec.OPCODE_CONTINUATION,
            -> messageAssembler.accept(frame)
            HnsWebSocketFrameCodec.OPCODE_PING -> writeFrame(HnsWebSocketFrameCodec.OPCODE_PONG, frame.payload)
            HnsWebSocketFrameCodec.OPCODE_CLOSE -> {
                if (runCatching { HnsWebSocketFrameCodec.validateClosePayload(frame.payload) }.isFailure) {
                    fail("HNS WebSocket close frame is malformed")
                } else {
                    val code = HnsWebSocketFrameCodec.closeCode(frame.payload) ?: HnsWebSocketBridge.CLOSE_NORMAL
                    val reason = HnsWebSocketFrameCodec.closeReason(frame.payload)
                    val closeFrameCompleted = runCatching {
                        synchronized(writeLock) {
                            val writer = clientWriter ?: return@runCatching false
                            if (!closeFrameSent) {
                                echoWebSocketClose(writer, frame.payload)
                                closeFrameSent = true
                            }
                            writer.close()
                            clientWriter = null
                            true
                        }
                    }.getOrDefault(false)
                    finishClose(code, reason, closeFrameCompleted)
                }
            }
        }
    }

    private fun emitMessage(opcode: Int, payload: ByteArray) {
        val event = JSONObject()
            .put("pageId", key.pageId)
            .put("id", key.id)
            .put("event", "message")
        if (opcode == HnsWebSocketFrameCodec.OPCODE_TEXT) {
            event.put("dataType", "text")
            event.put("data", payload.toString(Charsets.UTF_8))
        } else {
            event.put("dataType", "binary")
            event.put("data", Base64.getEncoder().encodeToString(payload))
        }
        emit(event)
    }

    private fun fail(reason: String) {
        fail(reason, HnsWebSocketBridge.CLOSE_ABNORMAL)
    }

    private fun fail(reason: String, code: Int) {
        if (finished.get()) {
            return
        }
        emit(key.event("error").put("reason", reason))
        finishClose(code, reason, false)
    }

    private fun finishClose(code: Int, reason: String, wasClean: Boolean) {
        if (!finished.compareAndSet(false, true)) {
            return
        }
        closeTimeout?.cancel(false)
        closeTimeout = null
        runCatching {
            synchronized(writeLock) {
                clientWriter?.close()
                clientWriter = null
            }
        }
        synchronized(outboundQueueLock) {
            pendingOutboundFrames = 0
            pendingOutboundBytes = 0
        }
        emit(
            key.event("close")
                .put("code", code)
                .put("reason", reason)
                .put("wasClean", wasClean),
        )
        onFinished()
    }

    private fun scheduleCloseTimeout() {
        if (finished.get()) {
            return
        }
        closeTimeout = try {
            closeScheduler.schedule(
                {
                    fail("HNS WebSocket close handshake timed out")
                },
                CLOSE_HANDSHAKE_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
        } catch (_: RejectedExecutionException) {
            forceClose(HnsWebSocketBridge.CLOSE_ABNORMAL, "HNS WebSocket close handshake unavailable")
            null
        }
    }

    private fun handshakeHeaders(): List<Pair<String, String>> {
        val headers = mutableListOf(
            "Host" to target.hostHeader(),
            "Origin" to target.origin,
            "Upgrade" to "websocket",
            "Connection" to "Upgrade",
            "Sec-WebSocket-Key" to handshakeKey,
            "Sec-WebSocket-Version" to "13",
        )
        if (protocols.isNotEmpty()) {
            headers += "Sec-WebSocket-Protocol" to protocols.joinToString(", ")
        }
        if (strictHnsMode()) {
            headers += HNS_GATEWAY_STRICT_MODE_HEADER to "1"
        }
        dohResolverUrl().takeIf { it.isNotBlank() }?.let { resolver ->
            headers += HNS_GATEWAY_DOH_RESOLVER_HEADER to resolver
        }
        if (statelessDaneCertificates()) {
            headers += HNS_GATEWAY_STATELESS_DANE_HEADER to "1"
        }
        handshakeNetwork()
            .takeUnless { it.equals(DEFAULT_NETWORK, ignoreCase = true) }
            ?.let { headers += HNS_GATEWAY_NETWORK_HEADER to it }
        return headers
    }

    private fun HnsWebSocketTarget.hostHeader(): String {
        val bracketedHost = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        val defaultPort = if (scheme.equals("wss", ignoreCase = true)) 443 else 80
        return if (port == defaultPort) bracketedHost else "$bracketedHost:$port"
    }

    private fun websocketKey(): String {
        val bytes = ByteArray(16)
        SECURE_RANDOM.nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }

    private companion object {
        const val PIPE_BUFFER_BYTES = 64 * 1024
        const val CLOSE_HANDSHAKE_TIMEOUT_SECONDS = 5L
        val SECURE_RANDOM = java.security.SecureRandom()
    }
}

internal class HnsWebSocketTunnelOutput(
    private val onHandshake: (ByteArray) -> Unit,
    private val onFrameBytes: (ByteArray, Int, Int) -> Unit,
    private val onFailure: (String) -> Unit,
) : OutputStream() {
    private val handshake = ByteArrayOutputStream()
    private var handshakeComplete = false
    private var failed = false

    override fun write(b: Int) {
        val byte = byteArrayOf(b.toByte())
        write(byte, 0, byte.size)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0 || failed) {
            return
        }
        if (handshakeComplete) {
            onFrameBytes(b, off, len)
            return
        }

        require(off >= 0 && len >= 0 && off <= b.size - len) { "invalid output buffer range" }
        val maximumBuffered = HnsWebSocketLimits.MAX_HANDSHAKE_BYTES + HTTP_HEADER_END.size
        val bufferedLength = minOf(len, maximumBuffered - handshake.size())
        if (bufferedLength > 0) {
            handshake.write(b, off, bufferedLength)
        }
        val bytes = handshake.toByteArray()
        val headEnd = headerEnd(bytes)
        if (headEnd < 0) {
            if (handshake.size() > HnsWebSocketLimits.MAX_HANDSHAKE_BYTES || bufferedLength < len) {
                failOversizedHandshake()
            }
            return
        }

        val frameOffset = headEnd + HTTP_HEADER_END.size
        if (frameOffset > HnsWebSocketLimits.MAX_HANDSHAKE_BYTES) {
            failOversizedHandshake()
            return
        }
        val head = bytes.copyOfRange(0, frameOffset)
        handshakeComplete = true
        onHandshake(head)
        if (bytes.size > frameOffset) {
            onFrameBytes(bytes, frameOffset, bytes.size - frameOffset)
        }
        if (bufferedLength < len) {
            onFrameBytes(b, off + bufferedLength, len - bufferedLength)
        }
    }

    private fun failOversizedHandshake() {
        failed = true
        handshake.reset()
        onFailure("HNS WebSocket handshake response is too large")
    }

    private fun headerEnd(bytes: ByteArray): Int {
        for (index in 0..(bytes.size - HTTP_HEADER_END.size)) {
            if (HTTP_HEADER_END.indices.all { offset -> bytes[index + offset] == HTTP_HEADER_END[offset] }) {
                return index
            }
        }
        return -1
    }
}

private data class HnsWebSocketHandshakeResponse(
    val status: Int,
    val headers: List<Pair<String, String>>,
) {
    fun header(name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    fun headerValues(name: String): List<String> =
        headers.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }

    companion object {
        fun parse(bytes: ByteArray): HnsWebSocketHandshakeResponse {
            require(bytes.size <= HnsWebSocketLimits.MAX_HANDSHAKE_BYTES && bytes.endsWith(HTTP_HEADER_END)) {
                "HNS WebSocket response head is malformed"
            }
            val text = bytes.toString(StandardCharsets.ISO_8859_1)
            val lines = text.split("\r\n").filter { it.isNotEmpty() }
            val statusParts = lines.firstOrNull()?.split(' ', limit = 3).orEmpty()
            require(
                statusParts.size >= 2 &&
                    statusParts[0] == "HTTP/1.1" &&
                    statusParts[1].length == 3 &&
                    statusParts[1].all(Char::isDigit),
            ) {
                "HNS WebSocket status line is invalid"
            }
            val status = statusParts[1].toIntOrNull()
                ?: throw IllegalArgumentException("HNS WebSocket status line is invalid")
            val headers = lines.drop(1).map { line ->
                val separator = line.indexOf(':')
                require(separator > 0) { "HNS WebSocket response header is malformed" }
                val name = line.substring(0, separator)
                val value = line.substring(separator + 1).trim()
                require(isWebSocketProtocolToken(name) && value.none(::isInvalidHttpHeaderValueCharacter)) {
                    "HNS WebSocket response header is malformed"
                }
                name to value
            }
            return HnsWebSocketHandshakeResponse(status, headers)
        }
    }
}

private fun ByteArray.endsWith(suffix: ByteArray): Boolean =
    size >= suffix.size && suffix.indices.all { index -> this[size - suffix.size + index] == suffix[index] }

internal fun echoWebSocketClose(output: OutputStream, payload: ByteArray) {
    HnsWebSocketFrameCodec.validateClosePayload(payload)
    output.write(HnsWebSocketFrameCodec.encodeClientFrame(HnsWebSocketFrameCodec.OPCODE_CLOSE, payload))
    output.flush()
}

internal object HnsWebSocketHandshakePolicy {
    fun validate(responseBytes: ByteArray, requestKey: String, offeredProtocols: List<String>): String {
        val response = HnsWebSocketHandshakeResponse.parse(responseBytes)
        require(response.status == 101) { "HNS WebSocket tunnel returned HTTP ${response.status}" }
        require(response.hasHeaderToken("Upgrade", "websocket")) { "HNS WebSocket Upgrade header is invalid" }
        require(response.hasHeaderToken("Connection", "upgrade")) { "HNS WebSocket Connection header is invalid" }

        val accepts = response.headerValues("Sec-WebSocket-Accept")
        require(accepts.size == 1 && accepts.single() == expectedAccept(requestKey)) {
            "HNS WebSocket accept value is invalid"
        }
        require(response.headerValues("Sec-WebSocket-Extensions").all { it.isBlank() }) {
            "HNS WebSocket extensions are unsupported"
        }

        val selected = response.headerValues("Sec-WebSocket-Protocol")
        require(selected.size <= 1) { "HNS WebSocket selected multiple protocols" }
        val protocol = selected.singleOrNull()?.trim().orEmpty()
        require(protocol.isEmpty() || protocol in offeredProtocols) {
            "HNS WebSocket selected an unoffered protocol"
        }
        return protocol
    }

    private fun HnsWebSocketHandshakeResponse.hasHeaderToken(name: String, expected: String): Boolean =
        headerValues(name)
            .flatMap { it.split(',') }
            .any { it.trim().equals(expected, ignoreCase = true) }

    private fun expectedAccept(requestKey: String): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(
            (requestKey + WEB_SOCKET_GUID).toByteArray(StandardCharsets.US_ASCII),
        )
        return Base64.getEncoder().encodeToString(digest)
    }

    private const val WEB_SOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
}

private fun JSONArray?.stringValues(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return (0 until length())
        .mapNotNull { index -> optString(index).trim().takeIf { it.isNotEmpty() } }
        .filter { it.length <= HnsWebSocketLimits.MAX_PROTOCOL_CHARS && isWebSocketProtocolToken(it) }
        .distinctBy { it.lowercase(Locale.US) }
        .take(HnsWebSocketLimits.MAX_PROTOCOLS)
}

private fun isWebSocketProtocolToken(value: String): Boolean {
    if (value.isEmpty()) {
        return false
    }
    return value.all { char ->
        char.code in 0x21..0x7e && char !in HTTP_TOKEN_SEPARATORS
    }
}

private fun isInvalidHttpHeaderValueCharacter(char: Char): Boolean =
    char != '\t' && (char.code < 0x20 || char.code == 0x7f)

private const val DEFAULT_NETWORK = "mainnet"

private val HTTP_TOKEN_SEPARATORS = setOf('(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t')
