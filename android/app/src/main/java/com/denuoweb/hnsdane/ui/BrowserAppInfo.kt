package com.denuoweb.hnsdane.ui

internal object BrowserAppInfo {
    const val APP_NAME = "HNS DANE Browser"
    const val PUBLISHER_NAME = "Denuo Web, LLC"
    const val LICENSE_NAME = "PolyForm Noncommercial 1.0.0"
    const val LICENSE_SUMMARY =
        "HNS DANE Browser is source-available under the PolyForm Noncommercial License 1.0.0. Noncommercial use, study, modification, and redistribution are allowed under the license. Commercial use requires separate written permission from Denuo Web, LLC."
    const val USER_AGREEMENT =
        "This is an experimental Handshake-first browser with local HNS proofs, RFC 8484 DoH transport, and DNSSEC/DANE diagnostics. HNS resolution, DNSSEC validation, DANE checks, compatibility fallback, and sync may fail closed or be incomplete. The app is provided without warranty, is not a financial service, and donations are optional and unlock no features."
    const val PRIVACY_POLICY_URL =
        "https://denuoweb.com/work/hns-dane-browser/privacy"
    const val PRIVACY_POLICY_SUMMARY =
        "HNS DANE Browser does not include ads, analytics SDKs, or developer-operated accounts. It stores browsing history, cookies, download records, settings, diagnostics, and HNS sync/cache data locally on the device. It sends network requests needed for browser functionality to websites you visit, HNS peers, DNS seeds, authoritative nameservers, RFC 9461-discovered authoritative DoH endpoints, and, in compatibility mode only, an HNS DoH resolver after local/direct resolution fails. Strict HNS mode disables the third-party HNS DoH fallback. Local browsing data can be cleared from Settings."
    const val HNS_DONATION_ADDRESS = "hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh"
    const val HNS_DONATION_URI =
        "handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh?label=Denuo%20Web%20HNS%20DANE%20Browser&message=HNS%20DANE%20Browser%20donation"
    const val SOURCE_CODE_URL = "https://github.com/Denuo-Web/hns-dane-browser-android"
}
