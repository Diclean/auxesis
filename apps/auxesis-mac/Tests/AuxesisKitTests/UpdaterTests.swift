// Updater tests. Every one runs against a URLProtocol stub: no packets,
// no real feed, no real dmg.
import CryptoKit
import Foundation
import Testing
@testable import AuxesisKit

private let updateFeedURL = URL(string: "https://updates.test/release.json")!
private let updateDmgURL = URL(string: "https://updates.test/Auxesis.dmg")!

/// Serves exact-URL responses and records what a session asked for.
final class UpdateURLProtocol: URLProtocol {
    struct Record: Equatable {
        let url: String
        let method: String
        let userAgent: String?
        let cookie: String?
        let authorization: String?
    }

    nonisolated(unsafe) private static var responses: [String: (Int, Data, [String: String])] = [:]
    nonisolated(unsafe) private static var _records: [Record] = []
    private static let lock = NSLock()

    static func reset() {
        lock.withLock {
            responses = [:]
            _records = []
        }
    }

    static func serve(
        _ url: String, status: Int = 200, headers: [String: String] = [:], _ data: Data
    ) {
        lock.withLock { responses[url] = (status, data, headers) }
    }

    static var records: [Record] { lock.withLock { _records } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let record = Record(
            url: request.url?.absoluteString ?? "",
            method: request.httpMethod ?? "GET",
            userAgent: request.value(forHTTPHeaderField: "User-Agent"),
            cookie: request.value(forHTTPHeaderField: "Cookie"),
            authorization: request.value(forHTTPHeaderField: "Authorization"))
        let served = Self.lock.withLock { () -> (Int, Data, [String: String]) in
            Self._records.append(record)
            return Self.responses[record.url] ?? (404, Data(), [:])
        }
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        let response = HTTPURLResponse(
            url: url, statusCode: served.0, httpVersion: nil, headerFields: served.2)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: served.1)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@objcMembers @MainActor final class UpdaterTests: XCTestCase {
    // MARK: - Setup helpers

    private func tempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-updater-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func makeManifest(
        build: Int = 42,
        minAllowedBuild: Int = 1,
        minOS: String = "14.0",
        version: String = "1.2.3",
        dmg: Data,
        dmgURL: URL = updateDmgURL,
        dmgSize: Int? = nil,
        signingKey: Curve25519.Signing.PrivateKey  // gitleaks:allow
    ) throws -> (manifest: Data, signature: Data) {
        let object: [String: Any] = [
            "version": version,
            "build": build,
            "minOS": minOS,
            "dmgURL": dmgURL.absoluteString,
            "dmgSHA256": sha256Hex(dmg),
            "dmgSize": dmgSize ?? dmg.count,
            "minAllowedBuild": minAllowedBuild,
        ]
        let manifest = try JSONSerialization.data(withJSONObject: object)
        let signature = try signingKey.signature(for: manifest)
        return (manifest, Data(signature.base64EncodedString().utf8))
    }

    private func serve(
        manifest: Data,
        signature: Data,
        dmg: Data,
        manifestHeaders: [String: String] = [:],
        dmgHeaders: [String: String] = [:],
        dmgURL: URL = updateDmgURL,
        feed: URL = updateFeedURL
    ) {
        UpdateURLProtocol.serve(feed.absoluteString, headers: manifestHeaders, manifest)
        UpdateURLProtocol.serve(
            feed.appendingPathExtension("sig").absoluteString, signature)
        UpdateURLProtocol.serve(dmgURL.absoluteString, headers: dmgHeaders, dmg)
    }

    private func makeUpdater(
        publicKey: Curve25519.Signing.PublicKey,
        installedBuild: Int,
        directory: URL,
        manifestURL: URL = updateFeedURL,
        currentOS: OperatingSystemVersion = OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0),
        handOff: @escaping (URL) -> Void = { _ in }
    ) -> Updater {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [UpdateURLProtocol.self]
        let session = URLSession(configuration: config)
        return Updater(config: Updater.Config(
            manifestURL: manifestURL,
            publicKey: publicKey.rawRepresentation,
            installedBuild: installedBuild,
            currentOS: currentOS,
            userAgent: "Auxesis/1.2.3",
            downloadDirectory: directory,
            session: session,
            handOff: handOff))
    }

    private func assertRejected(_ updater: Updater, _ expected: UpdateError) async {
        do {
            let result = try await updater.checkForUpdates()
            XCTFail("expected \(expected), got \(result)")
        } catch let error as UpdateError {
            XCTAssertEqual(error, expected)
        } catch {
            XCTFail("expected \(expected), got \(error)")
        }
    }

    private func dmgLeftovers(in directory: URL) -> [String] {
        let root = URL(fileURLWithPath: directory.path, isDirectory: true)
        let enumerator = FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: nil)
        return (enumerator?.allObjects as? [URL] ?? [])
            .filter { $0.pathExtension == "dmg" }
            .map(\.path)
    }

    // MARK: - The acceptance cases

    func testValidNewerReleaseIsAcceptedAndDmgHashMatches() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("a-real-looking-dmg".utf8)
        let (manifest, signature) = try makeManifest(dmg: dmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        var handedOff: URL?
        let updater = makeUpdater(
            publicKey: key.publicKey, installedBuild: 1, directory: dir,
            handOff: { handedOff = $0 })

        let result = try await updater.checkForUpdates()

        guard case .available(let update) = result else {
            XCTFail("expected an available update, got \(result)")
            return
        }
        XCTAssertEqual(update.version, "1.2.3")
        XCTAssertEqual(update.build, 42)
        XCTAssertEqual(try Data(contentsOf: update.dmgFile), dmg)
        XCTAssertEqual(handedOff?.path, update.dmgFile.path)
        XCTAssertTrue(FileManager.default.fileExists(atPath: update.dmgFile.path))
        let mode = (try FileManager.default.attributesOfItem(
            atPath: update.dmgFile.deletingLastPathComponent().path)[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(mode, 0o700, "the handoff directory must be private")
    }

    // MARK: - Bounded downloads

    func testOversizedManifestIsRejectedBeforeSignatureCheck() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        // One byte past the 64 KiB cap, with no Content-Length to lean on.
        let oversized = Data(repeating: 0x20, count: Updater.maxManifestBytes + 1)
        UpdateURLProtocol.serve(updateFeedURL.absoluteString, oversized)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, UpdateLimit.manifestTooLarge)
        let urls = UpdateURLProtocol.records.map(\.url)
        XCTAssertFalse(
            urls.contains(updateFeedURL.appendingPathExtension("sig").absoluteString),
            "a too-large manifest must be rejected before the signature is fetched")
        XCTAssertFalse(urls.contains(updateDmgURL.absoluteString))
    }

    func testManifestContentLengthOverCapIsRejectedEarly() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        // A small body that lies about being far over the cap.
        let small = Data("{}".utf8)
        UpdateURLProtocol.serve(
            updateFeedURL.absoluteString,
            headers: ["Content-Length": String(Updater.maxManifestBytes * 16)],
            small)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, UpdateLimit.manifestTooLarge)
        let urls = UpdateURLProtocol.records.map(\.url)
        XCTAssertFalse(urls.contains(updateFeedURL.appendingPathExtension("sig").absoluteString))
    }

    func testDmgLargerThanDeclaredSizeIsRejectedAndFileDeleted() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("this body is longer than the declared size".utf8)
        let (manifest, signature) = try makeManifest(dmg: dmg, dmgSize: 4, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, UpdateLimit.dmgTooLarge)
        XCTAssertTrue(dmgLeftovers(in: dir).isEmpty, "an oversized dmg must be deleted")
    }

    func testDmgSmallerThanDeclaredSizeIsRejectedAndFileDeleted() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("short".utf8)
        let (manifest, signature) = try makeManifest(dmg: dmg, dmgSize: 5000, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, UpdateLimit.dmgSizeMismatch)
        XCTAssertTrue(dmgLeftovers(in: dir).isEmpty, "a short dmg must be deleted")
    }

    func testDmgSizeOverAbsoluteCapIsRejectedWithoutDownloading() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("small".utf8)
        let (manifest, signature) = try makeManifest(
            dmg: dmg, dmgSize: Updater.maxDmgBytes + 1, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, UpdateLimit.dmgTooLarge)
        XCTAssertFalse(UpdateURLProtocol.records.map(\.url).contains(updateDmgURL.absoluteString))
        XCTAssertTrue(dmgLeftovers(in: dir).isEmpty)
    }

    func testTamperedManifestIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let (manifest, signature) = try makeManifest(dmg: dmg, signingKey: key)
        var tampered = manifest
        tampered.append(0x20)
        serve(manifest: tampered, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, .badSignature)
        XCTAssertTrue(UpdateURLProtocol.records.allSatisfy { $0.url != updateDmgURL.absoluteString })
    }

    func testWrongKeyIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let signingKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let (manifest, signature) = try makeManifest(dmg: dmg, signingKey: signingKey)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: otherKey.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, .badSignature)
    }

    func testDowngradeIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let (manifest, signature) = try makeManifest(build: 5, version: "0.9.0", dmg: dmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)

        let sameBuild = makeUpdater(publicKey: key.publicKey, installedBuild: 5, directory: dir)
        let sameResult = try await sameBuild.checkForUpdates()
        XCTAssertEqual(sameResult, .upToDate(installedBuild: 5))

        let older = makeUpdater(publicKey: key.publicKey, installedBuild: 9, directory: dir)
        let olderResult = try await older.checkForUpdates()
        XCTAssertEqual(olderResult, .upToDate(installedBuild: 9))
        XCTAssertTrue(UpdateURLProtocol.records.allSatisfy { $0.url != updateDmgURL.absoluteString })
    }

    func testReplayedOldSignedManifestBelowMinAllowedBuildIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let (manifest, signature) = try makeManifest(
            build: 10, minAllowedBuild: 100, version: "0.9.0", dmg: dmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 5, directory: dir)

        await assertRejected(
            updater, .belowMinAllowedBuild(installed: 5, minAllowed: 100, offered: 10))
    }

    func testHttpFeedURLIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let httpFeed = URL(string: "http://updates.test/release.json")!
        let updater = makeUpdater(
            publicKey: key.publicKey, installedBuild: 1, directory: dir, manifestURL: httpFeed)

        await assertRejected(updater, .insecureURL(httpFeed.absoluteString))
        XCTAssertTrue(UpdateURLProtocol.records.isEmpty, "an http feed must not be dialled at all")
    }

    func testHttpDmgURLIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let httpDmg = URL(string: "http://updates.test/Auxesis.dmg")!
        let (manifest, signature) = try makeManifest(dmg: dmg, dmgURL: httpDmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg, dmgURL: httpDmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, .insecureURL(httpDmg.absoluteString))
        XCTAssertTrue(UpdateURLProtocol.records.allSatisfy { $0.url != httpDmg.absoluteString })
    }

    func testDmgHashMismatchIsRejectedAndFileDeleted() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let expectedDmg = Data("the-dmg-the-manifest-describes".utf8)
        // Same length, different bytes: the size check passes and SHA-256 fails.
        let servedDmg = Data(repeating: 0x41, count: expectedDmg.count)
        let (manifest, signature) = try makeManifest(dmg: expectedDmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: servedDmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, .hashMismatch)
        XCTAssertTrue(
            dmgLeftovers(in: dir).isEmpty,
            "a mismatched dmg must be deleted, found \(dmgLeftovers(in: dir))")
    }

    func testMinOSAboveCurrentOSIsRejected() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let (manifest, signature) = try makeManifest(minOS: "15.0", dmg: dmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        await assertRejected(updater, .unsupportedOS(required: "15.0", current: "14.0.0"))
    }

    // MARK: - Privacy

    func testRequestsCarryOnlyThePlainUserAgent() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        UpdateURLProtocol.reset()
        let key = Curve25519.Signing.PrivateKey()
        let dmg = Data("dmg".utf8)
        let (manifest, signature) = try makeManifest(dmg: dmg, signingKey: key)
        serve(manifest: manifest, signature: signature, dmg: dmg)
        let updater = makeUpdater(publicKey: key.publicKey, installedBuild: 1, directory: dir)

        _ = try await updater.checkForUpdates()

        XCTAssertFalse(UpdateURLProtocol.records.isEmpty)
        for record in UpdateURLProtocol.records {
            XCTAssertEqual(record.method, "GET")
            XCTAssertEqual(record.userAgent, "Auxesis/1.2.3")
            XCTAssertNil(record.cookie, "no cookies on an update request")
            XCTAssertNil(record.authorization, "no bearer token on the update feed")
        }
    }

    // MARK: - Opt-in daily check

    func testDailyCheckIsOffByDefaultAndOnlyAfterADay() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertFalse(UpdatePreferences.shouldCheck(enabled: false, lastCheckAt: nil, now: now))
        XCTAssertTrue(UpdatePreferences.shouldCheck(enabled: true, lastCheckAt: nil, now: now))
        XCTAssertFalse(UpdatePreferences.shouldCheck(
            enabled: true, lastCheckAt: now.addingTimeInterval(-3600), now: now))
        XCTAssertTrue(UpdatePreferences.shouldCheck(
            enabled: true, lastCheckAt: now.addingTimeInterval(-90_000), now: now))
    }
}
