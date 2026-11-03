// C2c: the worker loop. A fake in-process auxd, no socket; the loop is driven
// one cycle at a time so no test sleeps.
import XCTest
@testable import AuxesisKit
import Foundation

@objcMembers @MainActor final class ExtractionWorkerTests: XCTestCase {
    private let loopback = URL(string: "http://127.0.0.1:2893")!

    private func makeWorker(
        _ fake: FakeDocsAuxd,
        onEvent: @escaping (ExtractionEvent) -> Void = { _ in }
    ) -> ExtractionWorker {
        ExtractionWorker(client: fake, baseURL: loopback, onEvent: onEvent)
    }

    private func claimed(_ hash: String, size: Int) -> PendingDocument {
        PendingDocument(hash: hash, mime: "application/pdf", size: size)
    }

    func testClaimsFetchesAndPostsOncePerDocument() async throws {
        let fake = FakeDocsAuxd()
        let pdf = try DocsFixtures.textPDF(DocsFixtures.invoiceLine)
        fake.pendingResult = .success([claimed(DocsFixtures.hashA, size: pdf.count)])
        fake.blobs = [DocsFixtures.hashA: .success(pdf)]
        let worker = makeWorker(fake)
        let delay = await worker.runOneCycle()

        XCTAssertEqual(fake.pendingCalls, [1], "one document at a time")
        XCTAssertEqual(fake.blobCalls, [DocsFixtures.hashA])
        XCTAssertEqual(fake.posts.count, 1, "posted once per document")
        XCTAssertEqual(fake.posts.first?.sha256, DocsFixtures.hashA)
        XCTAssertEqual(fake.posts.first?.extractor, .pdfText)
        XCTAssertTrue(fake.posts.first?.text.contains("TOTAL TTC 42,00") ?? false)
        XCTAssertEqual(worker.posted, 1)
        XCTAssertEqual(delay, 0, "keep draining while auxd has work")
    }

    func testEmptyQueueIdles() async {
        let fake = FakeDocsAuxd()
        let worker = makeWorker(fake)
        let delay = await worker.runOneCycle()
        XCTAssertEqual(delay, ExtractionWorker.idleInterval)
        XCTAssertTrue(fake.posts.isEmpty)
    }

    func testUnauthorizedBacksOffWithoutPosting() async {
        let fake = FakeDocsAuxd()
        fake.pendingResult = .failure(AuxdError.unauthorized)
        let worker = makeWorker(fake)
        let first = await worker.runOneCycle()
        XCTAssertEqual(first, ExtractionBackoff.initial)
        XCTAssertEqual(worker.lastFailure, "unauthorized")
        XCTAssertTrue(fake.posts.isEmpty)
        XCTAssertTrue(fake.blobCalls.isEmpty)
        let second = await worker.runOneCycle()
        XCTAssertGreaterThan(second, first, "the backoff grows")
    }

    func testBlobNotFoundSkipsAndNeverPostsUnclaimedText() async {
        let fake = FakeDocsAuxd()
        fake.pendingResult = .success([claimed(DocsFixtures.hashA, size: 11)])
        // No blob registered: the fake answers 404 — the claim has lapsed.
        let worker = makeWorker(fake)
        let delay = await worker.runOneCycle()
        XCTAssertEqual(delay, ExtractionWorker.idleInterval)
        XCTAssertTrue(fake.posts.isEmpty, "no text is posted for an unclaimed hash")
        XCTAssertEqual(fake.blobCalls, [DocsFixtures.hashA])
    }

    func testPostNotFoundDropsTheTextAsUnclaimed() async throws {
        let fake = FakeDocsAuxd()
        let pdf = try DocsFixtures.textPDF(DocsFixtures.invoiceLine)
        fake.pendingResult = .success([claimed(DocsFixtures.hashA, size: pdf.count)])
        fake.blobs = [DocsFixtures.hashA: .success(pdf)]
        fake.postResult = .failure(AuxdError.http(status: 404, body: ""))
        let worker = makeWorker(fake)
        let delay = await worker.runOneCycle()
        XCTAssertEqual(worker.posted, 0)
        XCTAssertEqual(delay, ExtractionWorker.idleInterval)
    }

    func testPostConflictDropsTheTextAsUnclaimed() async throws {
        let fake = FakeDocsAuxd()
        let pdf = try DocsFixtures.textPDF(DocsFixtures.invoiceLine)
        fake.pendingResult = .success([claimed(DocsFixtures.hashA, size: pdf.count)])
        fake.blobs = [DocsFixtures.hashA: .success(pdf)]
        fake.postResult = .failure(AuxdError.http(status: 409, body: ""))
        let worker = makeWorker(fake)
        let delay = await worker.runOneCycle()
        XCTAssertEqual(worker.posted, 0)
        XCTAssertEqual(delay, ExtractionWorker.idleInterval)
    }

    func testMalformedHashIsNeverFetchedOrPosted() async {
        let fake = FakeDocsAuxd()
        fake.pendingResult = .success([
            PendingDocument(hash: "not-a-hash", mime: "application/pdf", size: 4)
        ])
        let worker = makeWorker(fake)
        _ = await worker.runOneCycle()
        XCTAssertTrue(fake.blobCalls.isEmpty)
        XCTAssertTrue(fake.posts.isEmpty)
    }

    func testOversizeDocumentPostsNoneWithoutFetchingTheBlob() async {
        let fake = FakeDocsAuxd()
        fake.pendingResult = .success([
            claimed(DocsFixtures.hashB, size: DocumentExtractor.maxInputBytes + 1)
        ])
        let worker = makeWorker(fake)
        _ = await worker.runOneCycle()
        XCTAssertTrue(fake.blobCalls.isEmpty, "the blob is never fetched")
        XCTAssertEqual(fake.posts.count, 1)
        XCTAssertEqual(fake.posts.first?.extractor, ExtractionKind.none)
        XCTAssertEqual(fake.posts.first?.text, "")
        XCTAssertEqual(worker.posted, 1)
    }

    func testPoisonDocumentIsAnsweredNoneAfterThreeAttempts() async {
        let fake = FakeDocsAuxd()
        fake.pendingResult = .success([claimed(DocsFixtures.hashA, size: 1234)])
        fake.blobs = [DocsFixtures.hashA: .failure(AuxdError.transport("boom"))]
        let worker = makeWorker(fake)
        _ = await worker.runOneCycle()
        _ = await worker.runOneCycle()
        _ = await worker.runOneCycle()
        XCTAssertEqual(fake.blobCalls.count, ExtractionWorker.maxAttemptsPerDocument)
        XCTAssertTrue(fake.posts.isEmpty, "no answer before the third failure")

        // The fourth cycle must stop retrying and let the queue move on.
        let delay = await worker.runOneCycle()
        XCTAssertEqual(delay, 0)
        XCTAssertEqual(fake.posts.count, 1)
        XCTAssertEqual(fake.posts.first?.extractor, ExtractionKind.none)
        XCTAssertEqual(fake.posts.first?.text, "")
        XCTAssertEqual(worker.posted, 1)
    }

    func testBackoffSequenceIsPinned() {
        let delays = (1...8).map { ExtractionBackoff.delay(attempt: $0) }
        XCTAssertEqual(delays, [5, 10, 20, 40, 80, 160, 300, 300])
        XCTAssertEqual(ExtractionBackoff.delay(attempt: 0), 0)
    }

    func testStartRefusesEveryOffLoopbackEndpoint() {
        let fake = FakeDocsAuxd()
        for url in [
            URL(string: "http://evil.example.com:2893"),
            URL(string: "https://127.0.0.1:2893"),
            URL(string: "http://127.0.0.1.evil.example.com:2893"),
            nil,
        ] {
            let worker = ExtractionWorker(client: fake, baseURL: url)
            XCTAssertFalse(worker.start(), "refused: \(url?.absoluteString ?? "nil")")
            XCTAssertFalse(worker.isRunning)
        }
    }

    func testStartOnLoopbackRunsTheLoopAndStops() {
        let fake = FakeDocsAuxd()
        let gate = Gate()
        let worker = ExtractionWorker(
            client: fake, baseURL: loopback, sleeper: { _ in await gate.wait() })
        XCTAssertTrue(worker.start())
        XCTAssertTrue(worker.isRunning)
        XCTAssertTrue(waitUntil { !fake.pendingCalls.isEmpty })
        worker.stop()
        XCTAssertFalse(worker.isRunning)
        gate.open()
    }

    func testEventsCarryOnlyAHashPrefixNeverTheText() async throws {
        let fake = FakeDocsAuxd()
        let pdf = try DocsFixtures.textPDF(DocsFixtures.invoiceLine)
        fake.pendingResult = .success([claimed(DocsFixtures.hashA, size: pdf.count)])
        fake.blobs = [DocsFixtures.hashA: .success(pdf)]
        let recorder = EventRecorder()
        let worker = makeWorker(fake, onEvent: { recorder.record($0) })
        _ = await worker.runOneCycle()

        let posted = recorder.events.compactMap { event -> (String, ExtractionKind)? in
            if case let .posted(prefix, extractor) = event { return (prefix, extractor) }
            return nil
        }.first
        guard let posted else { return XCTFail("no posted event") }
        XCTAssertEqual(posted.0, String(DocsFixtures.hashA.prefix(8)))
        XCTAssertEqual(posted.1, .pdfText)
        XCTAssertFalse(recorder.events.contains { "\($0)".contains("TOTAL") })
        XCTAssertFalse(recorder.events.contains { "\($0)".contains("Exemple") })
    }

    // MARK: - Source proofs

    /// The extractor and the worker take no network API at all, and they log
    /// nothing (no `print`, no `NSLog`, no `os_log`), so no extracted text can
    /// be written to a log from either file.
    func testExtractorAndWorkerContainNoNetworkAPIAndNoLogging() throws {
        for name in ["DocumentExtractor.swift", "ExtractionWorker.swift"] {
            let source = try Self.source(name)
            XCTAssertFalse(source.isEmpty, "\(name) was not read")
            for forbidden in [
                "URLSession", "import Network", "NWConnection", "CFNetwork",
                "print(", "NSLog(", "os_log(", "Logger(",
            ] {
                XCTAssertFalse(
                    source.contains(forbidden),
                    "\(forbidden) must not appear in \(name)")
            }
        }
    }

    private static func source(_ name: String) throws -> String {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // AuxesisKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // apps/auxesis-mac
            .appendingPathComponent("Sources/AuxesisKit/\(name)")
        return try String(contentsOf: url, encoding: .utf8)
    }
}
