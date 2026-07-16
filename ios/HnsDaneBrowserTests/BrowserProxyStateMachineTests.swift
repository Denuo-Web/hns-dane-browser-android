import XCTest
@testable import HnsDaneBrowser

final class BrowserProxyStateMachineTests: XCTestCase {
    func testSameHnsRootReusesExactLiveGeneration() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = BrowserProxyStateMachine()

        XCTAssertEqual(machine.queueNavigation(scope: scope), [])
        XCTAssertEqual(machine.resume(), [.startProxy(1, scope)])
        XCTAssertEqual(
            machine.proxyStarted(epoch: 1, scope: scope, succeeded: true),
            [.publishCandidateAndAdmitWebView(1, scope)]
        )
        machine.navigationAdmitted(epoch: 1, scope: scope)

        XCTAssertEqual(
            machine.queueNavigation(scope: scope),
            [.admitThroughActiveProxy(1, scope)]
        )
        XCTAssertEqual(machine.phase, .active(1, scope))
    }

    func testCrossRootNavigationRevokesBeforeReplacementStart() {
        let first = BrowserProxyScope.handshakeRoot("woodburn")
        let second = BrowserProxyScope.handshakeRoot("2d")
        var machine = makeActiveMachine(scope: first)

        XCTAssertEqual(
            machine.queueNavigation(scope: second),
            [.revokeWebView, .requestStopActiveProxy, .startProxy(2, second)]
        )
        XCTAssertEqual(machine.phase, .starting(2, second))
    }

    func testHnsToIcannNavigationDropsAuthorizedRoot() {
        let hns = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = makeActiveMachine(scope: hns)

        XCTAssertEqual(
            machine.queueNavigation(scope: .icann),
            [.revokeWebView, .requestStopActiveProxy, .startProxy(2, .icann)]
        )
    }

    func testNewestScopeWinsWhileStartIsInFlight() {
        let first = BrowserProxyScope.handshakeRoot("woodburn")
        let latest = BrowserProxyScope.handshakeRoot("2d")
        var machine = BrowserProxyStateMachine()
        _ = machine.queueNavigation(scope: first)
        XCTAssertEqual(machine.resume(), [.startProxy(1, first)])

        XCTAssertEqual(machine.queueNavigation(scope: latest), [])
        XCTAssertEqual(
            machine.proxyStarted(epoch: 1, scope: first, succeeded: true),
            [.disposeStaleProxyThenStart(2, latest)]
        )
        XCTAssertEqual(machine.phase, .starting(2, latest))
    }

    func testSuspensionRejectsLateCandidateAndDoesNotRestart() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = BrowserProxyStateMachine()
        _ = machine.queueNavigation(scope: scope)
        _ = machine.resume()

        XCTAssertEqual(machine.suspend(retaining: scope), [.revokeWebView])
        XCTAssertEqual(
            machine.proxyStarted(epoch: 1, scope: scope, succeeded: true),
            [.disposeStaleProxy]
        )
        XCTAssertEqual(machine.phase, .suspended)
    }

    func testSuspensionClearsScopeForDiscardedUnsafeNavigation() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = BrowserProxyStateMachine()
        _ = machine.queueNavigation(scope: scope)
        _ = machine.resume()

        XCTAssertEqual(machine.suspend(retaining: nil), [.revokeWebView])
        XCTAssertNil(machine.pendingScope)
        XCTAssertEqual(machine.resume(), [])
        XCTAssertEqual(machine.phase, .idle)
    }

    func testOldCandidateDoesNotChaseNewStartAfterResume() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = BrowserProxyStateMachine()
        _ = machine.queueNavigation(scope: scope)
        XCTAssertEqual(machine.resume(), [.startProxy(1, scope)])
        XCTAssertEqual(machine.suspend(retaining: scope), [.revokeWebView])
        XCTAssertEqual(machine.resume(), [.startProxy(3, scope)])

        XCTAssertEqual(
            machine.proxyStarted(epoch: 1, scope: scope, succeeded: true),
            [.disposeStaleProxy]
        )
        XCTAssertEqual(machine.phase, .starting(3, scope))
    }

    func testDestroyedStateSurvivesLateSuccessfulCandidate() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = BrowserProxyStateMachine()
        _ = machine.queueNavigation(scope: scope)
        _ = machine.resume()
        XCTAssertEqual(machine.destroy(), [.revokeWebView])

        XCTAssertEqual(
            machine.proxyStarted(epoch: 1, scope: scope, succeeded: true),
            [.disposeStaleProxy]
        )
        XCTAssertEqual(machine.phase, .destroyed)
    }

    func testRendererTerminationRevokesAndFreshensGeneration() {
        let scope = BrowserProxyScope.handshakeRoot("woodburn")
        var machine = makeActiveMachine(scope: scope)

        XCTAssertEqual(
            machine.rendererTerminated(retaining: scope),
            [.revokeWebView, .requestStopActiveProxy, .startProxy(3, scope)]
        )
        XCTAssertEqual(machine.phase, .starting(3, scope))
    }

    private func makeActiveMachine(scope: BrowserProxyScope) -> BrowserProxyStateMachine {
        var machine = BrowserProxyStateMachine()
        _ = machine.queueNavigation(scope: scope)
        _ = machine.resume()
        _ = machine.proxyStarted(epoch: 1, scope: scope, succeeded: true)
        machine.navigationAdmitted(epoch: 1, scope: scope)
        return machine
    }
}
