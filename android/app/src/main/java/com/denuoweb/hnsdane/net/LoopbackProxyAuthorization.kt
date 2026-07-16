package com.denuoweb.hnsdane.net

import java.nio.charset.StandardCharsets
import java.util.Base64

/** Credentials and challenge scope for one native loopback proxy generation. */
class LoopbackProxyAuthorization private constructor(
    val realm: String,
    val username: String,
    val password: String,
) {
    private val credentials = "$username:$password".toByteArray(StandardCharsets.UTF_8)

    fun authorizationHeaderValue(): String =
        "Basic " + Base64.getEncoder().encodeToString(credentials)

    fun matchesChallenge(host: String, challengeRealm: String): Boolean =
        host.trim().removeSurrounding("[", "]").equals(LOOPBACK, ignoreCase = true) &&
            challengeRealm == realm

    companion object {
        private const val LOOPBACK = "127.0.0.1"

        internal fun createForTest(
            realm: String,
            username: String,
            password: String,
        ): LoopbackProxyAuthorization = LoopbackProxyAuthorization(realm, username, password)

        internal fun createForNative(
            realm: String,
            username: String,
            password: String,
        ): LoopbackProxyAuthorization = LoopbackProxyAuthorization(realm, username, password)
    }
}
