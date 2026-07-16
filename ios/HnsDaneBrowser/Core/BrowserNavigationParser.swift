import Foundation

struct BrowserNavigationParser {
    let canonicalizeHost: (String) throws -> String
    let classifyCanonicalHost: (String) throws -> BrowserHostKind
    let hnsRootForCanonicalHost: (String) throws -> String

    func parse(_ rawValue: String) throws -> BrowserDestination {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw BrowserCoreError.invalidAddress("Enter an address.") }
        guard trimmed.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            throw BrowserCoreError.invalidAddress("Enter a complete web or Handshake address.")
        }

        let explicitScheme = trimmed.range(
            of: #"^[A-Za-z][A-Za-z0-9+.-]*://"#,
            options: .regularExpression
        ) != nil
        let candidate = explicitScheme ? trimmed : "https://\(trimmed)"
        guard var components = URLComponents(string: candidate),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              components.user == nil,
              components.password == nil,
              let extractedHost = components.host,
              !extractedHost.isEmpty else {
            throw BrowserCoreError.unsupportedAddress
        }

        let canonicalHost = try canonicalizeHost(extractedHost)
        let hostKind = try classifyCanonicalHost(canonicalHost)
        let scope: BrowserProxyScope
        switch hostKind {
        case .handshake:
            scope = .handshakeRoot(try hnsRootForCanonicalHost(canonicalHost))
        case .icann:
            scope = .icann
        case .search:
            throw BrowserCoreError.invalidAddress("The address host is invalid.")
        }

        components.scheme = scheme
        guard let url = components.url else {
            throw BrowserCoreError.invalidAddress("The address is malformed.")
        }
        return BrowserDestination(
            url: url,
            canonicalHost: canonicalHost,
            hostKind: hostKind,
            proxyScope: scope
        )
    }
}
