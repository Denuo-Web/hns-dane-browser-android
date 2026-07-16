package com.denuoweb.hnsdane.core

/** Browser namespace decisions returned by the shared Rust resolver policy. */
enum class BrowserNamespaceClass {
    Hns,
    Icann,
    NativeGateway,
    Invalid,
    Unavailable,
}

fun interface BrowserNamespacePolicy {
    fun classifyHost(host: String): BrowserNamespaceClass
}

fun interface BrowserWebSocketScopePolicySource {
    /** Returns the complete document-start policy emitted by shared Rust. */
    fun webSocketScopePolicyScript(): String?
}

enum class NativeGatewayHostDecision {
    Required,
    Direct,
    Block,
}

/**
 * Android routing helpers around the shared Rust namespace decision.
 *
 * This object deliberately contains no IANA list, special-use suffix list, or
 * independent HNS classification algorithm. An unavailable or malformed Rust
 * result is kept distinct so production callers can fail closed.
 */
object HnsHostPolicy {
    fun nativeGatewayDecision(
        host: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): NativeGatewayHostDecision =
        when (namespacePolicy.classifyHost(host)) {
            BrowserNamespaceClass.Hns,
            BrowserNamespaceClass.NativeGateway,
            -> NativeGatewayHostDecision.Required
            BrowserNamespaceClass.Icann -> NativeGatewayHostDecision.Direct
            BrowserNamespaceClass.Invalid,
            BrowserNamespaceClass.Unavailable,
            -> NativeGatewayHostDecision.Block
        }

    fun requiresHnsResolution(
        host: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): Boolean = namespacePolicy.classifyHost(host) == BrowserNamespaceClass.Hns

    fun requiresNativeGatewayResolution(
        host: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): Boolean = nativeGatewayDecision(host, namespacePolicy) == NativeGatewayHostDecision.Required

    fun isNativeGatewayHost(
        host: String,
        namespacePolicy: BrowserNamespacePolicy,
    ): Boolean = namespacePolicy.classifyHost(host) == BrowserNamespaceClass.NativeGateway
}
