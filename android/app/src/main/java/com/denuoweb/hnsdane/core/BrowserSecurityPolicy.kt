package com.denuoweb.hnsdane.core

object BrowserSecurityPolicy {
    fun state(
        targetKind: BrowserTargetKind?,
        proxyAvailable: Boolean,
        syncStatusJson: String?,
        mainFrameHnsStatusCode: Int? = null,
        mainFrameHnsTlsPolicy: HnsPageTlsPolicy? = null,
        mainFrameHnsResolverPolicy: HnsPageResolverPolicy? = null,
        mainFrameHnsSecurityPath: HnsPageSecurityPath? = null,
    ): SecurityState {
        if (targetKind != BrowserTargetKind.HnsName && targetKind != BrowserTargetKind.NativeGateway) {
            return SecurityState.WebPkiOnly
        }
        if (mainFrameHnsStatusCode?.let { it in 400..599 } == true) {
            return SecurityState.ValidationFailed
        }
        if (mainFrameHnsStatusCode?.let { it in 200..299 } == true) {
            mainFrameHnsSecurityPath?.let { securityPath ->
                return securityPath.securityState()
            }
            if (mainFrameHnsTlsPolicy == HnsPageTlsPolicy.Dane) {
                if (mainFrameHnsResolverPolicy == HnsPageResolverPolicy.HnsDohCompatibility) {
                    return SecurityState.DaneCompatibility
                }
                return SecurityState.DaneVerified
            }
            if (mainFrameHnsTlsPolicy == HnsPageTlsPolicy.WebPkiFallback) {
                if (targetKind == BrowserTargetKind.NativeGateway) {
                    return SecurityState.WebPkiOnly
                }
                return SecurityState.MixedPolicy
            }
            if (targetKind == BrowserTargetKind.NativeGateway) {
                return SecurityState.WebPkiOnly
            }
            if (mainFrameHnsResolverPolicy == HnsPageResolverPolicy.HnsDohCompatibility) {
                return SecurityState.HnsCompatibility
            }
            return SecurityState.HnsVerified
        }
        if (!proxyAvailable && targetKind == BrowserTargetKind.HnsName) {
            return SecurityState.ProofUnavailable
        }
        if (targetKind == BrowserTargetKind.NativeGateway) {
            return SecurityState.Loading
        }
        if (
            syncStatusJson.hasSyncStatus("error") ||
            syncStatusJson.hasSyncStatus("seed_failed") ||
            syncStatusJson.hasSyncStatus("peer_failed")
        ) {
            return SecurityState.ProofUnavailable
        }
        if (
            !syncStatusJson.isBehindPeerHeight() &&
            (syncStatusJson.hasSyncStatus("synced") || syncStatusJson.hasSyncStatus("up_to_date"))
        ) {
            return SecurityState.Loading
        }

        return SecurityState.Syncing
    }

    private fun HnsPageSecurityPath.securityState(): SecurityState =
        when (this) {
            HnsPageSecurityPath.DaneAuthoritativeDoh -> SecurityState.DaneViaAuthoritativeDoh
            HnsPageSecurityPath.DaneAuthoritativeDns53 -> SecurityState.DaneViaAuthoritativeDns53
            HnsPageSecurityPath.DaneThirdPartyDoh -> SecurityState.DaneViaThirdPartyDoh
            HnsPageSecurityPath.StatelessDane -> SecurityState.StatelessDane
            HnsPageSecurityPath.DaneIcannDoh -> SecurityState.DaneViaIcannDoh
            HnsPageSecurityPath.HnsAuthoritativeDoh -> SecurityState.HnsViaAuthoritativeDoh
            HnsPageSecurityPath.HnsAuthoritativeDns53 -> SecurityState.HnsViaAuthoritativeDns53
            HnsPageSecurityPath.HnsThirdPartyDoh -> SecurityState.HnsViaThirdPartyDoh
        }

    private fun String?.hasSyncStatus(status: String): Boolean =
        this?.contains("\"status\":\"$status\"") == true

    private fun String?.isBehindPeerHeight(): Boolean {
        val json = this ?: return false
        val best = json.longField("bestHeight") ?: return false
        val target = json.longField("bestPeerHeight")
            ?: json.longField("estimatedTipHeight")
            ?: return false
        return target > best
    }

    private fun String.longField(name: String): Long? {
        val pattern = """"$name"\s*:\s*(null|-?\d+)""".toRegex()
        val value = pattern.find(this)?.groupValues?.getOrNull(1) ?: return null
        return value.takeUnless { it == "null" }?.toLongOrNull()
    }
}
