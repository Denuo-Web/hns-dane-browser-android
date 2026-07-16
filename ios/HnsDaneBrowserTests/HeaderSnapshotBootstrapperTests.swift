import Foundation
import XCTest
@testable import HnsDaneBrowser

final class HeaderSnapshotBootstrapperTests: XCTestCase {
    func testExactSnapshotInstallsOnceAndMarksSuccess() throws {
        let suite = "HeaderSnapshotBootstrapperTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let decompressor = FakeSnapshotDecompressor()
        let runtime = FakeRuntime(hostKind: .icann)
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("gzip")
        let bootstrapper = HeaderSnapshotBootstrapper(
            resourceURL: { source },
            defaults: defaults,
            decompressor: decompressor
        )

        try bootstrapper.installIfNeeded(into: runtime)

        XCTAssertEqual(decompressor.calls, 1)
        XCTAssertEqual(decompressor.lastExpectedBytes, 70_800_287)
        XCTAssertNotNil(runtime.installedSnapshotPath)
        XCTAssertTrue(defaults.bool(forKey: HeaderSnapshotBootstrapper.installedMarkerKey))

        try bootstrapper.installIfNeeded(into: runtime)
        XCTAssertEqual(decompressor.calls, 1)
    }

    func testMissingSnapshotFailsBeforeRuntimeInstall() {
        let suite = "HeaderSnapshotBootstrapperTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let runtime = FakeRuntime(hostKind: .icann)
        let bootstrapper = HeaderSnapshotBootstrapper(
            resourceURL: { nil },
            defaults: defaults,
            decompressor: FakeSnapshotDecompressor()
        )

        XCTAssertThrowsError(try bootstrapper.installIfNeeded(into: runtime))
        XCTAssertNil(runtime.installedSnapshotPath)
        XCTAssertFalse(defaults.bool(forKey: HeaderSnapshotBootstrapper.installedMarkerKey))
    }
}

private final class FakeSnapshotDecompressor: HeaderSnapshotDecompressing {
    var calls = 0
    var lastExpectedBytes: UInt64?

    func decompress(source: URL, destination: URL, expectedBytes: UInt64) throws {
        calls += 1
        lastExpectedBytes = expectedBytes
        guard FileManager.default.createFile(atPath: destination.path, contents: Data([0])) else {
            throw HeaderSnapshotBootstrapError.unableToCreateTemporaryFile
        }
    }
}
