import XCTest
@testable import HnsDaneBrowser

final class MainFrameAdmissionPolicyTests: XCTestCase {
    private let policy = MainFrameAdmissionPolicy()

    func testSameScopeAllowsNativeNavigation() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        XCTAssertEqual(
            policy.evaluate(activeScope: scope, destinationScope: scope, httpMethod: "POST"),
            .allow
        )
    }

    func testCrossScopeGetRotates() {
        XCTAssertEqual(
            policy.evaluate(
                activeScope: .handshakeRoot("woodburn"),
                destinationScope: .icann,
                httpMethod: "GET"
            ),
            .rotateProxy
        )
    }

    func testCrossScopePostCannotBeReplayed() {
        XCTAssertEqual(
            policy.evaluate(
                activeScope: .icann,
                destinationScope: .handshakeRoot("woodburn"),
                httpMethod: "POST"
            ),
            .blockNonIdempotentReplay
        )
    }
}

final class NavigationReplayPolicyTests: XCTestCase {
    private let policy = NavigationReplayPolicy()

    func testGetAndHeadCanBeReplayedAcrossLifecycleRotation() {
        XCTAssertTrue(policy.allowsAutomaticReplay(httpMethod: "GET"))
        XCTAssertTrue(policy.allowsAutomaticReplay(httpMethod: "head"))
        XCTAssertTrue(policy.allowsAutomaticReplay(httpMethod: nil))
    }

    func testRequestBodiesAreNeverAutomaticallyReplayed() {
        XCTAssertFalse(policy.allowsAutomaticReplay(httpMethod: "POST"))
        XCTAssertFalse(policy.allowsAutomaticReplay(httpMethod: "PUT"))
        XCTAssertFalse(policy.allowsAutomaticReplay(httpMethod: "PATCH"))
        XCTAssertFalse(policy.allowsAutomaticReplay(httpMethod: "DELETE"))
    }
}
