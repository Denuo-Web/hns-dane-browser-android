import XCTest
@testable import HnsDaneBrowser

final class BrowserNavigationParserTests: XCTestCase {
    func testExplicitURLPreservesPathAndClassifiesExtractedHost() throws {
        var classified: [String] = []
        let parser = BrowserNavigationParser(
            canonicalizeHost: { $0.lowercased() },
            classifyCanonicalHost: {
                classified.append($0)
                return .icann
            },
            hnsRootForCanonicalHost: { _ in XCTFail("ICANN must not derive HNS root"); return "" }
        )

        let destination = try parser.parse("https://WWW.Example.COM/docs/page?q=1")

        XCTAssertEqual(destination.url.absoluteString, "https://WWW.Example.COM/docs/page?q=1")
        XCTAssertEqual(destination.canonicalHost, "www.example.com")
        XCTAssertEqual(destination.proxyScope, .icann)
        XCTAssertEqual(classified, ["www.example.com"])
    }

    func testBareHostAndPathDefaultsToHTTPSAndUsesRustDerivedRoot() throws {
        let parser = BrowserNavigationParser(
            canonicalizeHost: { $0.lowercased() },
            classifyCanonicalHost: { _ in .handshake },
            hnsRootForCanonicalHost: { _ in "woodburn" }
        )

        let destination = try parser.parse("Nathan.Woodburn/docs")

        XCTAssertEqual(destination.url.absoluteString, "https://Nathan.Woodburn/docs")
        XCTAssertEqual(destination.canonicalHost, "nathan.woodburn")
        XCTAssertEqual(destination.proxyScope, .handshakeRoot("woodburn"))
    }

    func testCanonicalRustHostDrivesUnicodeScopeAndStatusIdentity() throws {
        var extractedHost: String?
        let parser = BrowserNavigationParser(
            canonicalizeHost: {
                extractedHost = $0
                return "xn--bcher-kva"
            },
            classifyCanonicalHost: { host in
                XCTAssertEqual(host, "xn--bcher-kva")
                return .handshake
            },
            hnsRootForCanonicalHost: { host in
                XCTAssertEqual(host, "xn--bcher-kva")
                return host
            }
        )

        let destination = try parser.parse("https://bücher/")

        XCTAssertNotNil(extractedHost)
        XCTAssertEqual(destination.canonicalHost, "xn--bcher-kva")
        XCTAssertEqual(destination.proxyScope, .handshakeRoot("xn--bcher-kva"))
    }

    func testSearchTextAndUnsupportedSchemesFailClosed() {
        let parser = BrowserNavigationParser(
            canonicalizeHost: { $0 },
            classifyCanonicalHost: { _ in .search },
            hnsRootForCanonicalHost: { _ in "" }
        )

        XCTAssertThrowsError(try parser.parse("two words"))
        XCTAssertThrowsError(try parser.parse("file:///tmp/page.html"))
    }
}
