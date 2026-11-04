// Minimal secure updater (scripts/sign-release.sh, docs/releasing.md).
//
// Decisions this updater makes explicitly:
//   * Detached signature: the sibling file `<manifest>.sig` holds the base64
//     of the raw 64-byte Ed25519 signature over the exact manifest bytes.
//   * The manifest bytes are verified BEFORE any JSON parsing, so a tampered
//     manifest never reaches the decoder.
//   * No Sparkle and no third-party package: CryptoKit `Curve25519.Signing`
//     (a system framework) is the only crypto.
//   * The updater never installs anything: it downloads the dmg to a temp
//     directory, checks its SHA-256, and hands the file to the caller, which
//     reveals it in Finder. Nothing from the dmg is ever executed.
//   * Privacy: one plain GET per file, `User-Agent: Auxesis/<version>`, no
//     cookies, no bearer token, no personal data.
//   * Bounded downloads: the manifest and the detached signature are
//     streamed and aborted past a hard cap (64 KiB / 1 KiB); a `Content-Length`
//     larger than the cap is rejected before the body is read. The dmg is
//     streamed straight to disk and the task is cancelled as soon as the
//     received bytes exceed the signed `dmgSize` (itself capped at 2 GiB), so a
//     hostile feed host cannot exhaust the app's memory. The dmg file is
//     deleted on any failure.
import CryptoKit
import Foundation

// MARK: - Wire types

/// One signed release manifest. The signature is over the exact bytes of the
/// JSON document that encodes this value.
public struct ReleaseManifest: Codable, Equatable, Sendable {
    public let version: String
    public let build: Int
    public let minOS: String
    public let dmgURL: URL
    public let dmgSHA256: String
    /// Exact size of the dmg in bytes. Signed, so a hostile host cannot make
    /// the app accept more (or fewer) bytes than the release key approved.
    public let dmgSize: Int
    public let minAllowedBuild: Int

    public init(
        version: String, build: Int, minOS: String,
        dmgURL: URL, dmgSHA256: String, dmgSize: Int, minAllowedBuild: Int
    ) {
        self.version = version
        self.build = build
        self.minOS = minOS
        self.dmgURL = dmgURL
        self.dmgSHA256 = dmgSHA256
        self.dmgSize = dmgSize
        self.minAllowedBuild = minAllowedBuild
    }
}

/// A verified, downloaded update. The dmg sits in a temp directory; nothing
/// has been run and no admin rights have been requested.
public struct AvailableUpdate: Equatable, Sendable {
    public let version: String
    public let build: Int
    public let dmgFile: URL

    public init(version: String, build: Int, dmgFile: URL) {
        self.version = version
        self.build = build
        self.dmgFile = dmgFile
    }
}

public enum UpdateCheckResult: Equatable, Sendable {
    case upToDate(installedBuild: Int)
    case available(AvailableUpdate)
}

public enum UpdateError: Error, Equatable, Sendable {
    case insecureURL(String)
    case httpStatus(Int)
    case badSignature
    case malformedManifest
    case unsupportedOS(required: String, current: String)
    case belowMinAllowedBuild(installed: Int, minAllowed: Int, offered: Int)
    case hashMismatch
    case network(String)
}

/// Bounded-download rejections are reported as `.network` messages: the
/// exhaustive `UpdateError` switch that renders the alert lives in
/// `AuxesisMac/CheckForUpdates.swift`. The messages are the strings the alert
/// shows verbatim.
enum UpdateLimit {
    static let manifestTooLarge: UpdateError =
        .network("The update manifest is larger than the 64 KiB limit, so it was rejected.")
    static let signatureTooLarge: UpdateError =
        .network("The update signature is larger than the 1 KiB limit, so it was rejected.")
    static let dmgTooLarge: UpdateError =
        .network("The update disk image is larger than the signed size, so it was rejected.")
    static let dmgSizeMismatch: UpdateError =
        .network("The update disk image did not match the signed size (it was deleted).")
}

// MARK: - Updater

/// Checks a signed https feed. Manual by default; the app owns the UI.
public final class Updater {
    /// The single production feed. Tests inject their own URL through `Config`.
    public static let feedURL = URL(string: "https://updates.auxesis.app/release.json")!

    // TODO(owner): release key — replace this placeholder with the production
    // Ed25519 public key (base64 of 32 bytes) before the first signed release.
    // Generate one with `scripts/sign-release.sh generate <path>`.
    public static let pinnedPublicKeyBase64 = "cGxhY2Vob2xkZXItdGVzdC1rZXktMzItYnl0ZXMhISE="

    /// Hard cap on the manifest document (64 KiB).
    static let maxManifestBytes = 64 * 1024
    /// Hard cap on the detached signature document (1 KiB).
    static let maxSignatureBytes = 1024
    /// Absolute cap on a dmg, independent of the signed `dmgSize` (2 GiB).
    static let maxDmgBytes = 2 * 1024 * 1024 * 1024

    /// Test-only override. Internal so production code outside this module
    /// cannot repoint the feed or swap the pinned key.
    struct Config {
        var manifestURL: URL
        var publicKey: Data
        var installedBuild: Int
        var currentOS: OperatingSystemVersion
        var userAgent: String
        var downloadDirectory: URL
        var session: URLSession
        var handOff: (URL) -> Void

        init(
            manifestURL: URL,
            publicKey: Data,
            installedBuild: Int,
            currentOS: OperatingSystemVersion,
            userAgent: String,
            downloadDirectory: URL,
            session: URLSession,
            handOff: @escaping (URL) -> Void
        ) {
            self.manifestURL = manifestURL
            self.publicKey = publicKey
            self.installedBuild = installedBuild
            self.currentOS = currentOS
            self.userAgent = userAgent
            self.downloadDirectory = downloadDirectory
            self.session = session
            self.handOff = handOff
        }
    }

    private let config: Config

    init(config: Config) {
        self.config = config
    }

    /// The app's updater: production feed, pinned key, cookieless session.
    public static func live(
        installedBuild: Int,
        appVersion: String,
        handOff: @escaping (URL) -> Void
    ) -> Updater {
        Updater(config: Config(
            manifestURL: feedURL,
            publicKey: Data(base64Encoded: pinnedPublicKeyBase64) ?? Data(),
            installedBuild: installedBuild,
            currentOS: ProcessInfo.processInfo.operatingSystemVersion,
            userAgent: "Auxesis/\(appVersion)",
            // Each download gets a fresh 0700 directory directly under the
            // system temp directory, avoiding a predictable shared path.
            downloadDirectory: FileManager.default.temporaryDirectory,
            session: makeSession(),
            handOff: handOff))
    }

    /// An ephemeral, cookieless session. Redirects are allowed only to https.
    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 600
        return URLSession(configuration: config, delegate: HTTPSRedirectGuard(), delegateQueue: nil)
    }

    /// Fetch the manifest and its detached signature, verify, then parse.
    @MainActor
    public func checkForUpdates() async throws -> UpdateCheckResult {
        guard isHTTPS(config.manifestURL) else {
            throw UpdateError.insecureURL(config.manifestURL.absoluteString)
        }
        // Both documents are capped while streaming; a too-large manifest is
        // rejected before the signature is even requested.
        let manifestData = try await fetchSmall(
            config.manifestURL, cap: Self.maxManifestBytes, tooLarge: UpdateLimit.manifestTooLarge)
        let signatureData = try await fetchSmall(
            config.manifestURL.appendingPathExtension("sig"),
            cap: Self.maxSignatureBytes, tooLarge: UpdateLimit.signatureTooLarge)
        // Signature first: the decoder must never see unverified bytes.
        try verify(signatureBase64: signatureData, message: manifestData)

        let manifest: ReleaseManifest
        do {
            manifest = try JSONDecoder().decode(ReleaseManifest.self, from: manifestData)
        } catch {
            throw UpdateError.malformedManifest
        }
        guard isHTTPS(manifest.dmgURL) else {
            throw UpdateError.insecureURL(manifest.dmgURL.absoluteString)
        }
        if manifest.build <= config.installedBuild {
            return .upToDate(installedBuild: config.installedBuild)
        }
        if config.installedBuild < manifest.minAllowedBuild,
           manifest.build < manifest.minAllowedBuild {
            throw UpdateError.belowMinAllowedBuild(
                installed: config.installedBuild,
                minAllowed: manifest.minAllowedBuild,
                offered: manifest.build)
        }
        guard let required = Self.parseOSVersion(manifest.minOS) else {
            throw UpdateError.malformedManifest
        }
        if !Self.osVersion(config.currentOS, atLeast: required) {
            throw UpdateError.unsupportedOS(
                required: manifest.minOS,
                current: Self.describe(config.currentOS))
        }
        // A zero or negative size is malformed; the absolute 2 GiB cap holds
        // even when the release key signed a bigger number.
        guard manifest.dmgSize > 0 else { throw UpdateError.malformedManifest }
        guard manifest.dmgSize <= Self.maxDmgBytes else { throw UpdateLimit.dmgTooLarge }

        let downloadDirectory = config.downloadDirectory
            .appendingPathComponent("AuxesisUpdate-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: downloadDirectory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
        } catch {
            throw UpdateError.network(error.localizedDescription)
        }
        let file = downloadDirectory.appendingPathComponent("Auxesis-\(manifest.build).dmg")
        let downloaded: URL
        do {
            downloaded = try await streamDownload(
                manifest.dmgURL, to: file, maxBytes: manifest.dmgSize)
        } catch {
            try? FileManager.default.removeItem(at: downloadDirectory)
            throw error
        }
        let size = (try? FileManager.default.attributesOfItem(atPath: downloaded.path))?[.size] as? NSNumber
        guard size?.intValue == manifest.dmgSize else {
            try? FileManager.default.removeItem(at: downloadDirectory)
            throw UpdateLimit.dmgSizeMismatch
        }
        let expected = manifest.dmgSHA256.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let actual: String
        do {
            actual = try Self.sha256Hex(ofFile: downloaded)
        } catch {
            try? FileManager.default.removeItem(at: downloadDirectory)
            throw UpdateError.network(error.localizedDescription)
        }
        guard actual == expected else {
            try? FileManager.default.removeItem(at: downloadDirectory)
            throw UpdateError.hashMismatch
        }
        config.handOff(downloaded)
        return .available(AvailableUpdate(version: manifest.version, build: manifest.build, dmgFile: downloaded))
    }

    // MARK: - Steps

    /// Stream a small document (manifest or signature) into memory, aborting
    /// as soon as it passes `cap`. A `Content-Length` above the cap is refused
    /// before the body is read at all.
    private func fetchSmall(_ url: URL, cap: Int, tooLarge: UpdateError) async throws -> Data {
        guard isHTTPS(url) else { throw UpdateError.insecureURL(url.absoluteString) }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(config.userAgent, forHTTPHeaderField: "User-Agent")
        do {
            let (bytes, response) = try await config.session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw UpdateError.network("non-HTTP response")
            }
            guard http.statusCode == 200 else { throw UpdateError.httpStatus(http.statusCode) }
            if let final = http.url, !isHTTPS(final) {
                throw UpdateError.insecureURL(final.absoluteString)
            }
            if let lengthText = http.value(forHTTPHeaderField: "Content-Length"),
               let length = Int(lengthText), length > cap {
                throw tooLarge
            }
            var data = Data()
            data.reserveCapacity(min(cap, 1 << 16))
            for try await byte in bytes {
                guard data.count < cap else { throw tooLarge }
                data.append(byte)
            }
            return data
        } catch let error as UpdateError {
            throw error
        } catch {
            throw UpdateError.network(error.localizedDescription)
        }
    }

    /// Stream the dmg straight to `destination`; never buffered in memory. The
    /// download task is cancelled the moment it passes `maxBytes`, and the file
    /// is removed on any failure.
    private func streamDownload(_ url: URL, to destination: URL, maxBytes: Int) async throws -> URL {
        guard isHTTPS(url) else { throw UpdateError.insecureURL(url.absoluteString) }
        let downloader = BoundedDownloader(
            destination: destination, maxBytes: maxBytes, userAgent: config.userAgent)
        do {
            return try await downloader.download(url, configuration: config.session.configuration)
        } catch let error as UpdateError {
            try? FileManager.default.removeItem(at: destination)
            throw error
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw UpdateError.network(error.localizedDescription)
        }
    }

    private func verify(signatureBase64: Data, message: Data) throws {
        let text = String(decoding: signatureBase64, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let signature = Data(base64Encoded: text), signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: config.publicKey),
              key.isValidSignature(signature, for: message)
        else {
            throw UpdateError.badSignature
        }
    }

    static func sha256Hex(ofFile url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            guard let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func isHTTPS(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https"
    }

    static func parseOSVersion(_ text: String) -> OperatingSystemVersion? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard let major = parts.first.flatMap({ Int($0) }), major >= 0 else { return nil }
        let minor = parts.count > 1 ? (Int(parts[1]) ?? 0) : 0
        let patch = parts.count > 2 ? (Int(parts[2]) ?? 0) : 0
        return OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: patch)
    }

    static func osVersion(_ current: OperatingSystemVersion, atLeast required: OperatingSystemVersion) -> Bool {
        if current.majorVersion != required.majorVersion { return current.majorVersion > required.majorVersion }
        if current.minorVersion != required.minorVersion { return current.minorVersion > required.minorVersion }
        return current.patchVersion >= required.patchVersion
    }

    static func describe(_ version: OperatingSystemVersion) -> String {
        "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }
}

/// Allows an https redirect and refuses anything else: the feed must never be
/// downgraded to http mid-flight.
private final class HTTPSRedirectGuard: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(request.url?.scheme?.lowercased() == "https" ? request : nil)
    }
}

/// Streams a download to a file and cancels the task as soon as the received
/// bytes exceed `maxBytes`. It never buffers the body in memory: the system
/// writes it to a temp file and this delegate moves it into place only after
/// the response is a 200 over https and the size is within the cap.
private final class BoundedDownloader: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let destination: URL
    private let maxBytes: Int64
    private let userAgent: String
    private let lock = NSLock()
    private var finished = false
    private var continuation: CheckedContinuation<URL, Error>?
    private var session: URLSession?

    init(destination: URL, maxBytes: Int, userAgent: String) {
        self.destination = destination
        self.maxBytes = Int64(maxBytes)
        self.userAgent = userAgent
    }

    func download(_ url: URL, configuration: URLSessionConfiguration) async throws -> URL {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
            self.session = session
            session.downloadTask(with: request).resume()
        }
    }

    private func finish(_ result: Result<URL, Error>) {
        lock.lock()
        if finished {
            lock.unlock()
            return
        }
        finished = true
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        session?.invalidateAndCancel()
        continuation?.resume(with: result)
    }

    func urlSession(
        _ session: URLSession, downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        if totalBytesWritten > maxBytes {
            downloadTask.cancel()
            finish(.failure(UpdateLimit.dmgTooLarge))
        }
    }

    func urlSession(
        _ session: URLSession, downloadTask: URLSessionDownloadTask,
        didFinishDownloadingTo location: URL
    ) {
        guard let http = downloadTask.response as? HTTPURLResponse else {
            finish(.failure(UpdateError.network("non-HTTP response")))
            return
        }
        guard http.statusCode == 200 else {
            finish(.failure(UpdateError.httpStatus(http.statusCode)))
            return
        }
        if let final = http.url, final.scheme?.lowercased() != "https" {
            finish(.failure(UpdateError.insecureURL(final.absoluteString)))
            return
        }
        // Progress callbacks can be coalesced; refuse a temp file that is over
        // the cap even if `didWriteData` never saw the overshoot.
        if let attributes = try? FileManager.default.attributesOfItem(atPath: location.path),
           let size = attributes[.size] as? NSNumber, size.int64Value > maxBytes {
            finish(.failure(UpdateLimit.dmgTooLarge))
            return
        }
        do {
            // The destination is inside a fresh private directory and must
            // not exist. Never unlink a path supplied by the filesystem.
            try FileManager.default.moveItem(at: location, to: destination)
        } catch {
            finish(.failure(UpdateError.network(error.localizedDescription)))
            return
        }
        finish(.success(destination))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error {
            finish(.failure(UpdateError.network(error.localizedDescription)))
        } else {
            finish(.failure(UpdateError.network("download ended without a file")))
        }
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(request.url?.scheme?.lowercased() == "https" ? request : nil)
    }
}

// MARK: - Opt-in daily check (default OFF)

/// The manual check is the default. Automatic checking is opt-in and stores
/// only a boolean and a timestamp in `UserDefaults` — no personal data.
public struct UpdatePreferences {
    public static let dailyCheckEnabledKey = "updates.dailyCheckEnabled"
    public static let lastCheckAtKey = "updates.lastCheckAt"
    public static let checkInterval: TimeInterval = 24 * 60 * 60

    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public var dailyCheckEnabled: Bool {
        get { defaults.bool(forKey: Self.dailyCheckEnabledKey) }
        nonmutating set { defaults.set(newValue, forKey: Self.dailyCheckEnabledKey) }
    }

    public var lastCheckAt: Date? {
        get { defaults.object(forKey: Self.lastCheckAtKey) as? Date }
        nonmutating set { defaults.set(newValue, forKey: Self.lastCheckAtKey) }
    }

    public func shouldCheckDaily(now: Date = Date()) -> Bool {
        Self.shouldCheck(enabled: dailyCheckEnabled, lastCheckAt: lastCheckAt, now: now)
    }

    /// Pure decision, so it can be tested without touching `UserDefaults`.
    public static func shouldCheck(enabled: Bool, lastCheckAt: Date?, now: Date) -> Bool {
        guard enabled else { return false }
        guard let lastCheckAt else { return true }
        return now.timeIntervalSince(lastCheckAt) >= checkInterval
    }
}
