package com.denuoweb.hnsdane.net

import com.denuoweb.hnsdane.core.BrowserWebSocketScopePolicySource

/** Installs the complete WebSocket scope policy emitted by shared Rust. */
internal object HnsProxyWebSocketPolicy {
    fun script(source: BrowserWebSocketScopePolicySource): String =
        source.webSocketScopePolicyScript()
            ?.takeIf { it.isNotBlank() }
            ?: FAIL_CLOSED_SCRIPT

    /** A missing native policy must disable WebSockets, never weaken namespace isolation. */
    private val FAIL_CLOSED_SCRIPT =
        """
(function() {
  'use strict';
  if (window.__hnsProxyWebSocketPolicyInstalled) return;
  window.__hnsProxyWebSocketPolicyInstalled = true;
  window.__hnsRustNamespacePolicyUnavailable = true;
  function BlockedWebSocket() {
    throw new DOMException('Shared namespace policy is unavailable.', 'SecurityError');
  }
  window.WebSocket = BlockedWebSocket;
})();
        """.trimIndent()
}
