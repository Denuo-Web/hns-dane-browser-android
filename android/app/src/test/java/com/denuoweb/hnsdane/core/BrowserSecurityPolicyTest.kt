package com.denuoweb.hnsdane.core

import org.junit.Assert.assertEquals
import org.junit.Test

class BrowserSecurityPolicyTest {
    @Test
    fun normalWebTargetsUseWebPkiEvenWhenProxyIsUnavailable() {
        assertEquals(
            SecurityState.WebPkiOnly,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.ExactUrl,
                proxyAvailable = false,
                syncStatusJson = null,
            ),
        )
    }

    @Test
    fun hnsTargetsRequireProxyAvailability() {
        assertEquals(
            SecurityState.ProofUnavailable,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = false,
                syncStatusJson = """{"status":"up_to_date"}""",
            ),
        )
    }

    @Test
    fun hnsTargetsShowLoadingWhenSyncIsReadyButPageIsNotVerified() {
        for (status in listOf("synced", "up_to_date")) {
            assertEquals(
                status,
                SecurityState.Loading,
                BrowserSecurityPolicy.state(
                    targetKind = BrowserTargetKind.HnsName,
                    proxyAvailable = true,
                    syncStatusJson = """{"status":"$status"}""",
                ),
            )
        }
    }

    @Test
    fun hnsTargetsStaySyncingWhenPeerHeightIsStillAhead() {
        assertEquals(
            SecurityState.Syncing,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"synced","bestHeight":93344,"bestPeerHeight":335684}""",
            ),
        )
    }

    @Test
    fun hnsTargetsStaySyncingWhenEstimatedTipIsStillAhead() {
        assertEquals(
            SecurityState.Syncing,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"synced","bestHeight":92000,"bestPeerHeight":null,"estimatedTipHeight":335684}""",
            ),
        )
    }

    @Test
    fun mainFrameHnsGatewayFailureOverridesReadySyncState() {
        assertEquals(
            SecurityState.ValidationFailed,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"up_to_date"}""",
                mainFrameHnsStatusCode = 502,
            ),
        )
    }

    @Test
    fun mainFrameHnsGatewaySuccessCanShowVerifiedBeforeNextSyncSnapshot() {
        assertEquals(
            SecurityState.HnsVerified,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
            ),
        )
    }

    @Test
    fun mainFrameHnsGatewaySuccessShowsDaneVerifiedWhenNativeReportsDane() {
        assertEquals(
            SecurityState.DaneVerified,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsTlsPolicy = HnsPageTlsPolicy.Dane,
            ),
        )
    }

    @Test
    fun nativeGatewayIcannDaneHostCanShowDaneVerified() {
        assertEquals(
            SecurityState.DaneVerified,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.NativeGateway,
                proxyAvailable = false,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsTlsPolicy = HnsPageTlsPolicy.Dane,
            ),
        )
    }

    @Test
    fun nativeGatewayIcannWebPkiFallbackShowsWebPkiOnly() {
        assertEquals(
            SecurityState.WebPkiOnly,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.NativeGateway,
                proxyAvailable = false,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsTlsPolicy = HnsPageTlsPolicy.WebPkiFallback,
            ),
        )
    }

    @Test
    fun mainFrameHnsGatewaySuccessShowsDaneCompatibilityForDohResolvedDane() {
        assertEquals(
            SecurityState.DaneCompatibility,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsTlsPolicy = HnsPageTlsPolicy.Dane,
                mainFrameHnsResolverPolicy = HnsPageResolverPolicy.HnsDohCompatibility,
            ),
        )
    }

    @Test
    fun explicitSecurityPathsSelectExactSuccessfulState() {
        val expectations = mapOf(
            HnsPageSecurityPath.DaneAuthoritativeDoh to SecurityState.DaneViaAuthoritativeDoh,
            HnsPageSecurityPath.DaneAuthoritativeDns53 to SecurityState.DaneViaAuthoritativeDns53,
            HnsPageSecurityPath.DaneThirdPartyDoh to SecurityState.DaneViaThirdPartyDoh,
            HnsPageSecurityPath.StatelessDane to SecurityState.StatelessDane,
            HnsPageSecurityPath.DaneIcannDoh to SecurityState.DaneViaIcannDoh,
            HnsPageSecurityPath.HnsAuthoritativeDoh to SecurityState.HnsViaAuthoritativeDoh,
            HnsPageSecurityPath.HnsAuthoritativeDns53 to SecurityState.HnsViaAuthoritativeDns53,
            HnsPageSecurityPath.HnsThirdPartyDoh to SecurityState.HnsViaThirdPartyDoh,
        )

        expectations.forEach { (path, expectedState) ->
            assertEquals(
                path.name,
                expectedState,
                BrowserSecurityPolicy.state(
                    targetKind = BrowserTargetKind.HnsName,
                    proxyAvailable = true,
                    syncStatusJson = """{"status":"idle"}""",
                    mainFrameHnsStatusCode = 200,
                    mainFrameHnsSecurityPath = path,
                ),
            )
        }
    }

    @Test
    fun explicitSecurityPathTakesPrecedenceOverLegacySuccessHeaders() {
        assertEquals(
            SecurityState.StatelessDane,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsTlsPolicy = HnsPageTlsPolicy.WebPkiFallback,
                mainFrameHnsResolverPolicy = HnsPageResolverPolicy.HnsDohCompatibility,
                mainFrameHnsSecurityPath = HnsPageSecurityPath.StatelessDane,
            ),
        )
    }

    @Test
    fun gatewayFailureTakesPrecedenceOverExplicitSecurityPath() {
        assertEquals(
            SecurityState.ValidationFailed,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"up_to_date"}""",
                mainFrameHnsStatusCode = 502,
                mainFrameHnsSecurityPath = HnsPageSecurityPath.DaneAuthoritativeDoh,
            ),
        )
    }

    @Test
    fun mainFrameHnsGatewaySuccessShowsMixedPolicyForWebPkiFallback() {
        assertEquals(
            SecurityState.MixedPolicy,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsTlsPolicy = HnsPageTlsPolicy.WebPkiFallback,
            ),
        )
    }

    @Test
    fun mainFrameHnsGatewaySuccessShowsHnsCompatibilityForDohResolvedHttp() {
        assertEquals(
            SecurityState.HnsCompatibility,
            BrowserSecurityPolicy.state(
                targetKind = BrowserTargetKind.HnsName,
                proxyAvailable = true,
                syncStatusJson = """{"status":"idle"}""",
                mainFrameHnsStatusCode = 200,
                mainFrameHnsResolverPolicy = HnsPageResolverPolicy.HnsDohCompatibility,
            ),
        )
    }

    @Test
    fun hnsTargetsShowProofUnavailableForSyncFailures() {
        for (status in listOf("error", "seed_failed", "peer_failed")) {
            assertEquals(
                status,
                SecurityState.ProofUnavailable,
                BrowserSecurityPolicy.state(
                    targetKind = BrowserTargetKind.HnsName,
                    proxyAvailable = true,
                    syncStatusJson = """{"status":"$status"}""",
                ),
            )
        }
    }

    @Test
    fun hnsTargetsRemainSyncingForUnknownOrInitialStatus() {
        for (statusJson in listOf(null, """{"status":"idle"}""", """{"status":"status"}""")) {
            assertEquals(
                SecurityState.Syncing,
                BrowserSecurityPolicy.state(
                    targetKind = BrowserTargetKind.HnsName,
                    proxyAvailable = true,
                    syncStatusJson = statusJson,
                ),
            )
        }
    }
}
