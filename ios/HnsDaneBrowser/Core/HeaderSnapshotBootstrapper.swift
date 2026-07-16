import Foundation

protocol HeaderSnapshotDecompressing {
    func decompress(
        source: URL,
        destination: URL,
        expectedBytes: UInt64
    ) throws
}

enum HeaderSnapshotBootstrapError: LocalizedError {
    case bundledSnapshotMissing
    case unableToCreateTemporaryFile
    case gzipOpenFailed
    case gzipReadFailed(String)
    case unexpectedSize(expected: UInt64, actual: UInt64)

    var errorDescription: String? {
        switch self {
        case .bundledSnapshotMissing:
            return "The bundled Handshake header snapshot is missing."
        case .unableToCreateTemporaryFile:
            return "A private temporary header snapshot could not be created."
        case .gzipOpenFailed:
            return "The bundled Handshake header snapshot could not be opened."
        case .gzipReadFailed(let message):
            return "The bundled Handshake header snapshot is corrupt: \(message)"
        case .unexpectedSize(let expected, let actual):
            return "The header snapshot size was \(actual) bytes; expected \(expected)."
        }
    }
}

struct ZlibHeaderSnapshotDecompressor: HeaderSnapshotDecompressing {
    private let chunkBytes = 64 * 1_024

    func decompress(
        source: URL,
        destination: URL,
        expectedBytes: UInt64
    ) throws {
        let stream = source.path.withCString { path in
            "rb".withCString { mode in
                gzopen(path, mode)
            }
        }
        guard let stream else { throw HeaderSnapshotBootstrapError.gzipOpenFailed }
        defer { gzclose(stream) }

        guard FileManager.default.createFile(
            atPath: destination.path,
            contents: nil,
            attributes: [.protectionKey: FileProtectionType.complete]
        ) else {
            throw HeaderSnapshotBootstrapError.unableToCreateTemporaryFile
        }

        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }

        var buffer = [UInt8](repeating: 0, count: chunkBytes)
        var copied: UInt64 = 0
        while true {
            let count: Int32 = buffer.withUnsafeMutableBytes { bytes in
                gzread(stream, bytes.baseAddress, UInt32(bytes.count))
            }
            if count < 0 {
                var errorNumber: Int32 = Z_OK
                let pointer = gzerror(stream, &errorNumber)
                let message = pointer.map(String.init(cString:)) ?? "zlib error \(errorNumber)"
                throw HeaderSnapshotBootstrapError.gzipReadFailed(message)
            }
            if count == 0 { break }

            let next = copied + UInt64(count)
            guard next <= expectedBytes else {
                throw HeaderSnapshotBootstrapError.unexpectedSize(
                    expected: expectedBytes,
                    actual: next
                )
            }
            try output.write(contentsOf: Data(buffer.prefix(Int(count))))
            copied = next
        }
        try output.synchronize()

        guard copied == expectedBytes else {
            throw HeaderSnapshotBootstrapError.unexpectedSize(
                expected: expectedBytes,
                actual: copied
            )
        }
    }
}

final class HeaderSnapshotBootstrapper {
    static let expectedUncompressedBytes: UInt64 = 70_800_287
    static let installedMarkerKey = "browser.headerSnapshot.mainnet.height300000.v1"

    private let resourceURL: () -> URL?
    private let defaults: UserDefaults
    private let fileManager: FileManager
    private let decompressor: HeaderSnapshotDecompressing

    init(
        resourceURL: @escaping () -> URL? = {
            Bundle.main.url(
                forResource: "hns_headers_300000.snapshot",
                withExtension: "gzip"
            )
        },
        defaults: UserDefaults = .standard,
        fileManager: FileManager = .default,
        decompressor: HeaderSnapshotDecompressing = ZlibHeaderSnapshotDecompressor()
    ) {
        self.resourceURL = resourceURL
        self.defaults = defaults
        self.fileManager = fileManager
        self.decompressor = decompressor
    }

    /// A missing, truncated, oversized, corrupt, or rejected first-run snapshot is fatal. The app
    /// does not admit a WebView until this operation succeeds.
    func installIfNeeded(into runtime: BrowserRuntime) throws {
        if defaults.bool(forKey: Self.installedMarkerKey) { return }

        guard let compressedURL = resourceURL() else {
            throw HeaderSnapshotBootstrapError.bundledSnapshotMissing
        }

        let temporaryDirectory = fileManager.temporaryDirectory
            .appendingPathComponent("hns-browser-bootstrap", isDirectory: true)
        try fileManager.createDirectory(
            at: temporaryDirectory,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete]
        )
        let snapshotURL = temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("snapshot")
        defer { try? fileManager.removeItem(at: snapshotURL) }

        try decompressor.decompress(
            source: compressedURL,
            destination: snapshotURL,
            expectedBytes: Self.expectedUncompressedBytes
        )
        try runtime.installHeaderSnapshot(at: snapshotURL.path)
        defaults.set(true, forKey: Self.installedMarkerKey)
    }
}
