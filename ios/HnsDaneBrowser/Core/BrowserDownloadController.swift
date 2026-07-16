import Foundation
import WebKit

@MainActor
protocol BrowserDownloadControllerDelegate: AnyObject {
    func downloadController(_ controller: BrowserDownloadController, didFinishAt url: URL)
    func downloadController(_ controller: BrowserDownloadController, didFail error: Error)
}

@MainActor
final class BrowserDownloadController: NSObject, WKDownloadDelegate {
    weak var delegate: BrowserDownloadControllerDelegate?
    var authenticationHandler: ((URLAuthenticationChallenge, @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) -> Void)?

    private var destinations: [ObjectIdentifier: URL] = [:]
    private var reservedDestinations: Set<URL> = []

    func attach(_ download: WKDownload) {
        download.delegate = self
    }

    func download(
        _ download: WKDownload,
        decideDestinationUsing response: URLResponse,
        suggestedFilename: String,
        completionHandler: @escaping (URL?) -> Void
    ) {
        do {
            let destination = try makeDestination(suggestedFilename: suggestedFilename)
            destinations[ObjectIdentifier(download)] = destination
            completionHandler(destination)
        } catch {
            delegate?.downloadController(self, didFail: error)
            completionHandler(nil)
        }
    }

    func downloadDidFinish(_ download: WKDownload) {
        guard let destination = destinations.removeValue(forKey: ObjectIdentifier(download)) else {
            return
        }
        reservedDestinations.remove(destination)
        delegate?.downloadController(self, didFinishAt: destination)
    }

    func download(
        _ download: WKDownload,
        didFailWithError error: Error,
        resumeData: Data?
    ) {
        if let destination = destinations.removeValue(forKey: ObjectIdentifier(download)) {
            reservedDestinations.remove(destination)
        }
        delegate?.downloadController(self, didFail: error)
    }

    func download(
        _ download: WKDownload,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let authenticationHandler else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        authenticationHandler(challenge, completionHandler)
    }

    private func makeDestination(suggestedFilename: String) throws -> URL {
        let fileManager = FileManager.default
        guard let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw BrowserCoreError.runtimeUnavailable("Downloads directory is unavailable")
        }
        let downloads = documents.appendingPathComponent("Downloads", isDirectory: true)
        try fileManager.createDirectory(
            at: downloads,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        )

        let safeName = safeFilename(from: suggestedFilename)
        let original = downloads.appendingPathComponent(safeName, isDirectory: false)
        if isAvailable(original, fileManager: fileManager) {
            reservedDestinations.insert(original)
            return original
        }

        let stem = original.deletingPathExtension().lastPathComponent
        let extensionName = original.pathExtension
        for suffix in 1...9_999 {
            let filename = extensionName.isEmpty
                ? "\(stem)-\(suffix)"
                : "\(stem)-\(suffix).\(extensionName)"
            let candidate = downloads.appendingPathComponent(filename, isDirectory: false)
            if isAvailable(candidate, fileManager: fileManager) {
                reservedDestinations.insert(candidate)
                return candidate
            }
        }
        let fallback = downloads.appendingPathComponent(UUID().uuidString, isDirectory: false)
        reservedDestinations.insert(fallback)
        return fallback
    }

    private func safeFilename(from suggestedFilename: String) -> String {
        let normalized = suggestedFilename.precomposedStringWithCanonicalMapping
        let lastComponent = (normalized as NSString).lastPathComponent
        let hasControl = normalized.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0)
        }
        let isUnsafe = normalized.isEmpty
            || normalized == "."
            || normalized == ".."
            || normalized != lastComponent
            || normalized.contains("/")
            || normalized.contains("\\")
            || normalized.utf8.count > 180
            || hasControl
        return isUnsafe ? "download-\(UUID().uuidString)" : normalized
    }

    private func isAvailable(_ url: URL, fileManager: FileManager) -> Bool {
        !reservedDestinations.contains(url) && !fileManager.fileExists(atPath: url.path)
    }
}
