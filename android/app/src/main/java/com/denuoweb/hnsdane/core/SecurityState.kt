package com.denuoweb.hnsdane.core

enum class SecurityState {
    Syncing,
    Loading,
    HnsVerified,
    HnsCompatibility,
    HnsViaAuthoritativeDoh,
    HnsViaAuthoritativeDns53,
    HnsViaP2pDnsRelay,
    HnsViaThirdPartyDoh,
    DaneVerified,
    DaneCompatibility,
    DaneViaAuthoritativeDoh,
    DaneViaAuthoritativeDns53,
    DaneViaP2pDnsRelay,
    DaneViaThirdPartyDoh,
    StatelessDane,
    DaneViaIcannDoh,
    WebPkiOnly,
    MixedPolicy,
    ValidationFailed,
    ProofUnavailable,
}

enum class HnsPageTlsPolicy {
    Dane,
    WebPkiFallback,
}

enum class HnsPageResolverPolicy {
    HnsDohCompatibility,
}

enum class HnsPageSecurityPath {
    DaneAuthoritativeDoh,
    DaneAuthoritativeDns53,
    DaneThirdPartyDoh,
    StatelessDane,
    DaneIcannDoh,
    HnsAuthoritativeDoh,
    HnsAuthoritativeDns53,
    HnsThirdPartyDoh,
    DaneP2pDnsRelay,
    HnsP2pDnsRelay,
    ;

    companion object {
        fun fromHeaderValue(value: String?): HnsPageSecurityPath? =
            when (value?.trim()?.lowercase()) {
                "dane-authoritative-doh" -> DaneAuthoritativeDoh
                "dane-authoritative-dns53" -> DaneAuthoritativeDns53
                "dane-third-party-doh" -> DaneThirdPartyDoh
                "stateless-dane" -> StatelessDane
                "dane-icann-doh" -> DaneIcannDoh
                "hns-authoritative-doh" -> HnsAuthoritativeDoh
                "hns-authoritative-dns53" -> HnsAuthoritativeDns53
                "hns-third-party-doh" -> HnsThirdPartyDoh
                "dane-p2p-dns-relay" -> DaneP2pDnsRelay
                "hns-p2p-dns-relay" -> HnsP2pDnsRelay
                else -> null
            }
    }
}
