package com.denuoweb.hnsdane.core

/** Fixed test double; production namespace rules remain exclusively in Rust. */
internal class FixedBrowserNamespacePolicy(
    private val classifications: Map<String, BrowserNamespaceClass>,
    private val defaultClass: BrowserNamespaceClass = BrowserNamespaceClass.Invalid,
) : BrowserNamespacePolicy {
    override fun classifyHost(host: String): BrowserNamespaceClass =
        classifications[host] ?: defaultClass
}

internal val TEST_BROWSER_NAMESPACE_POLICY: BrowserNamespacePolicy =
    FixedBrowserNamespacePolicy(
        classifications =
            buildMap {
                listOf(
                    "appassets.androidplatform.net",
                    "example.com",
                    "discord.gg",
                    "example.zip",
                    "example.museum",
                    "example.arpa",
                    "example.xn--p1ai",
                    "example.google",
                    "localhost",
                    "example",
                    "invalid",
                    "local",
                    "test",
                    "app.alt",
                    "foo.example",
                    "foo.internal",
                    "foo.invalid",
                    "foo.local",
                    "foo.localhost",
                    "foo.onion",
                    "foo.test",
                ).forEach { put(it, BrowserNamespaceClass.Icann) }
                put("dane-test.denuoweb.com", BrowserNamespaceClass.NativeGateway)
                put("dane-test.denuoweb.com.", BrowserNamespaceClass.NativeGateway)
            },
        defaultClass = BrowserNamespaceClass.Hns,
    )
