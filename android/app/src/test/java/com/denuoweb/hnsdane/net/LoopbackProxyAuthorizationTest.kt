package com.denuoweb.hnsdane.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LoopbackProxyAuthorizationTest {
    @Test
    fun emitsTheNativeProxyBasicCredential() {
        val authorization = LoopbackProxyAuthorization.createForTest(
            realm = "hns-loopback-test",
            username = "browser",
            password = "secret",
        )

        assertEquals("Basic YnJvd3NlcjpzZWNyZXQ=", authorization.authorizationHeaderValue())
    }

    @Test
    fun challengeMustMatchTheExactLoopbackHostAndRealm() {
        val authorization = LoopbackProxyAuthorization.createForTest(
            realm = "hns-loopback-test",
            username = "browser",
            password = "secret",
        )

        assertTrue(authorization.matchesChallenge("127.0.0.1", "hns-loopback-test"))
        assertTrue(authorization.matchesChallenge("[127.0.0.1]", "hns-loopback-test"))
        assertFalse(authorization.matchesChallenge("localhost", "hns-loopback-test"))
        assertFalse(authorization.matchesChallenge("127.0.0.1", "other-realm"))
    }
}
