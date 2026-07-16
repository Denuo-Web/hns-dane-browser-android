import Foundation
import Network
import WebKit

@MainActor
final class PersistentWebKitProfile {
    static let profileIdentifierKey = "browser.webKitProfileIdentifier.v1"

    let dataStore: WKWebsiteDataStore

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let identifier = Self.loadOrCreateIdentifier(defaults: defaults)
        dataStore = WKWebsiteDataStore(forIdentifier: identifier)
    }

    /// Installs one authenticated global proxy. There is deliberately no API that clears the
    /// configuration to a direct route: stale configurations fail closed while no WebView exists.
    func install(proxy endpoint: BrowserProxyEndpoint) throws {
        guard endpoint.isNumericIPv4Loopback,
              let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw BrowserCoreError.invalidProxyEndpoint
        }

        let loopback = NWEndpoint.hostPort(
            host: NWEndpoint.Host("127.0.0.1"),
            port: port
        )
        var configuration = ProxyConfiguration(
            httpCONNECTProxy: loopback,
            tlsOptions: nil
        )
        configuration.allowFailover = false
        configuration.matchDomains = []
        configuration.excludedDomains = []
        configuration.applyCredential(
            username: endpoint.username,
            password: endpoint.password
        )
        dataStore.proxyConfigurations = [configuration]
    }

    func makeHardenedConfiguration() -> WKWebViewConfiguration {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = dataStore
        configuration.userContentController = WKUserContentController()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        configuration.mediaTypesRequiringUserActionForPlayback = .all
        configuration.allowsAirPlayForMediaPlayback = false
        configuration.allowsInlineMediaPlayback = false
        configuration.suppressesIncrementalRendering = false
        return configuration
    }

    private static func loadOrCreateIdentifier(defaults: UserDefaults) -> UUID {
        if let stored = defaults.string(forKey: profileIdentifierKey),
           let identifier = UUID(uuidString: stored) {
            return identifier
        }
        let identifier = UUID()
        defaults.set(identifier.uuidString, forKey: profileIdentifierKey)
        return identifier
    }
}
