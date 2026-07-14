package com.denuoweb.hnsdane.core

enum class SecurityState {
    Syncing,
    Loading,
    HnsVerified,
    HnsCompatibility,
    HnsViaAuthoritativeDoh,
    HnsViaAuthoritativeDns53,
    HnsViaThirdPartyDoh,
    DaneVerified,
    DaneCompatibility,
    DaneViaAuthoritativeDoh,
    DaneViaAuthoritativeDns53,
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
                else -> null
            }
    }
}
