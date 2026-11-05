import XCTest
@testable import AuxesisKit

/// The Documents page model over a fake client, and the real client's
/// three docs routes over `RecordingURLProtocol` (no socket). Fictional data.
@objcMembers @MainActor final class DocumentsPageTests: XCTestCase {
    private static let list = #"""
    [{"hash":"aaaaaaaaaaaa","kind":"receipt","issued_on":"2025-09-30","number":"REC-2025-0007","total":"120.00 EUR","vat":"20.00 EUR","client":null,"checks":[],"status":"read"},
     {"hash":"bbbbbbbbbbbb","kind":null,"issued_on":null,"number":null,"total":null,"vat":null,"client":null,"checks":[],"status":"waiting for reading"},
     {"hash":"cccccccccccc","kind":"invoice","issued_on":"2025-10-02","number":"FAC-2025-0042","total":"1440.00 EUR","vat":"240.00 EUR","client":{"id":7,"name":"Nordwind Studio SARL","archived":true},"checks":[{"name":"totals","state":"pass"}],"status":"read"}]
    """#

    private func rows() throws -> [DocumentRow] {
        try JSONDecoder().decode([DocumentRow].self, from: Data(Self.list.utf8))
    }

    func testTheListMapsOnlyTheRouteFieldsNewestFirst() async throws {
        let fake = FakeDocs(rows: try rows())
        let model = DocumentsPageModel(client: fake)
        await model.reload()
        guard case .loaded(let shown) = model.load else { return XCTFail("\(model.load)") }
        XCTAssertEqual(shown.map(\.hash), ["cccccccccccc", "aaaaaaaaaaaa", "bbbbbbbbbbbb"], "dated newest first, undated last")
        XCTAssertEqual(model.clients.map(\.displayName), ["Nordwind Studio SARL", "Atelier Cobalt"])
        let (invoice, receipt, waiting) = (shown[0], shown[1], shown[2])
        XCTAssertEqual(DocumentsPageModel.dateText(invoice, language: .en), "Oct 2, 2025")
        XCTAssertEqual(DocumentsPageModel.dateText(invoice, language: .fr), "2 oct. 2025")
        XCTAssertEqual(DocumentsPageModel.dateText(waiting, language: .en), "", "an unread row has no date yet, not a dash")
        XCTAssertEqual(DocumentsPageModel.documentText(invoice, language: .en), "Invoice FAC-2025-0042")
        XCTAssertEqual(DocumentsPageModel.documentText(receipt, language: .fr), "Reçu REC-2025-0007")
        XCTAssertEqual(DocumentsPageModel.documentText(waiting, language: .en), "Not read yet")
        XCTAssertEqual(DocumentsPageModel.clientText(invoice, language: .en), "Nordwind Studio SARL (archived)")
        XCTAssertEqual(DocumentsPageModel.clientText(receipt, language: .en), "No client")
        XCTAssertEqual(DocumentsPageModel.clientText(receipt, language: .fr), "Sans client")
        XCTAssertFalse(waiting.isRead)
    }

    /// One date style for the table and the export fields, amounts as
    /// local currency, and the unread row says so instead of dashes.
    func testDatesAmountsAndTheUnreadRowFollowTheLanguage() throws {
        let row = { (total: String?, status: String) in
            let json = #"{"hash":"dddddddddddd","kind":null,"issued_on":null,"number":null,"total":"# + (total.map { "\"\($0)\"" } ?? "null") + #","client":null,"status":""# + status + #""}"#
            return try JSONDecoder().decode(DocumentRow.self, from: Data(json.utf8))
        }
        // Foundation writes narrow and plain no-break spaces in FR; compare on plain spaces.
        let amount = { (total: String?, language: Language) in
            try DocumentsPageModel.amountText(row(total, "read"), language: language)
                .replacingOccurrences(of: "\u{202F}", with: " ").replacingOccurrences(of: "\u{00A0}", with: " ")
        }
        XCTAssertEqual(try amount("1240.00 EUR", .en), "€1,240.00")
        XCTAssertEqual(try amount("1240.00 EUR", .fr), "1 240,00 €")
        XCTAssertEqual(try amount("1196.00 GBP", .en), "£1,196.00")
        XCTAssertTrue(try amount("1196.00 GBP", .fr).hasPrefix("1 196,00 £"), try amount("1196.00 GBP", .fr))
        XCTAssertEqual(try amount("-12.05 EUR", .en), "-€12.05")
        XCTAssertEqual(try amount("2500.00 XQZ", .en), "2,500.00 XQZ", "unknown code: grouped number plus the raw code")
        XCTAssertEqual(try amount("2500.00 XQZ", .fr), "2 500,00 XQZ")
        XCTAssertEqual(try amount("2500.00", .fr), "2 500,00", "no code: the number alone")
        XCTAssertEqual(try amount("n/a EUR", .en), "n/a EUR", "unparseable stays as written")

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "Europe/Paris")!
        let first = calendar.date(from: DateComponents(year: 2026, month: 9, day: 1))!
        let paris = calendar.timeZone
        XCTAssertEqual(DocumentsPageModel.dayText(first, language: .en, timeZone: paris), "Sep 1, 2026")
        XCTAssertEqual(DocumentsPageModel.dayText(first, language: .fr, timeZone: paris), "1 sept. 2026")
        let dated = try JSONDecoder().decode(DocumentRow.self, from: Data(#"{"hash":"eeeeeeeeeeee","kind":"invoice","issued_on":"2026-10-14","number":"X-1","total":null,"client":null,"status":"read"}"#.utf8))
        XCTAssertEqual(DocumentsPageModel.dateText(dated, language: .en), "Oct 14, 2026")
        XCTAssertEqual(DocumentsPageModel.dateText(dated, language: .fr), "14 oct. 2026")
        XCTAssertEqual(DocumentsPageModel.amountText(dated, language: .en), "—", "a read row missing only its amount keeps the dash")

        let unread = try row(nil, "waiting for reading")
        XCTAssertEqual(DocumentsPageModel.documentText(unread, language: .en), "Not read yet")
        XCTAssertEqual(DocumentsPageModel.documentText(unread, language: .fr), "Pas encore lu")
        XCTAssertEqual(DocumentsPageModel.dateText(unread, language: .en), "")
        XCTAssertEqual(DocumentsPageModel.amountText(unread, language: .en), "")
        XCTAssertFalse(unread.isRead, "the client menu stays disabled")
        // Read, but nothing came out of it (a scan): said plainly, still linkable by hand.
        let scan = try JSONDecoder().decode(DocumentRow.self, from: Data(#"{"hash":"ffffffffffff","kind":"other","issued_on":null,"number":null,"total":null,"client":null,"status":"read"}"#.utf8))
        XCTAssertEqual(DocumentsPageModel.documentText(scan, language: .en), "No details found")
        XCTAssertEqual(DocumentsPageModel.documentText(scan, language: .fr), "Aucun détail trouvé")
        XCTAssertEqual(DocumentsPageModel.dateText(scan, language: .en), "")
        XCTAssertEqual(DocumentsPageModel.amountText(scan, language: .en), "")
        XCTAssertTrue(scan.isRead)
    }

    func testTheFilterAsksAuxdForThatSlice() async throws {
        let fake = FakeDocs(rows: try rows())
        let model = DocumentsPageModel(client: fake)
        await model.reload()
        XCTAssertEqual(fake.asked, [.all], "the first load asks for everything")

        // Setting the filter starts its own reload on the main actor. Wait for
        // that reload to reach the client instead of asking it again by hand:
        // a second, awaited reload would race it, and both call the client off
        // the main actor.
        model.filter = .unlinked
        let unlinked = await waitForRequests([.all, .unlinked], from: fake)
        XCTAssertEqual(unlinked, [.all, .unlinked], "the filter's reload asks for the unlinked slice")
        model.filter = .client(7)
        let client = await waitForRequests([.all, .unlinked, .client(7)], from: fake)
        XCTAssertEqual(client, [.all, .unlinked, .client(7)], "the filter's reload asks for that client's slice")
        XCTAssertTrue(client.contains(.unlinked) && client.last == .client(7), "\(client)")

        let empty = FakeDocs(rows: [])
        let none = DocumentsPageModel(client: empty)
        await none.reload()
        XCTAssertEqual(none.load, .loaded([]))
    }

    func testLinkAndUnlinkCallTheRouteThenReload() async throws {
        let fake = FakeDocs(rows: try rows())
        let model = DocumentsPageModel(client: fake)
        await model.reload()
        guard case .loaded(let shown) = model.load else { return XCTFail() }
        await model.link(shown[1], to: 7)
        await model.link(shown[0], to: nil)
        await model.link(shown[1], to: nil)  // already has no client: nothing to write
        XCTAssertEqual(fake.links.map(\.0), ["aaaaaaaaaaaa", "cccccccccccc"])
        XCTAssertEqual(fake.links.map(\.1), [7, nil])
        XCTAssertEqual(fake.asked.count, 3, "each link reloads the list")
        XCTAssertNil(model.problem)
        XCTAssertNil(model.linking)

        fake.failure = AuxdError.http(status: 409, body: #"{"error":{"code":"docs_link_refused","message":"not read"}}"#)
        await model.link(shown[1], to: 7)
        XCTAssertEqual(model.problem, .notRead)
        XCTAssertEqual(L10n.ui(model.problem!.key, .en), "This receipt is still being read. Try again in a minute.")
    }

    func testExportBuildsTheRequestAndReportsTheFolder() async throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "Europe/Paris")!
        let day = { (text: String) in ISO8601DateFormatter().date(from: text)! }
        let request = DocumentsExport(from: day("2025-08-31T22:30:00Z"), to: day("2025-09-30T12:00:00Z"),
                                      client: 7, out: URL(fileURLWithPath: "/tmp/Exports"), calendar: calendar)
        XCTAssertEqual(request.queryItems.map { "\($0.name)=\($0.value!)" },
                       ["from=2025-09-01", "to=2025-09-30", "client=7", "out=/tmp/Exports"], "local days, not UTC")
        XCTAssertNil(DocumentsExport(from: Date(), to: Date(), client: nil, out: URL(fileURLWithPath: "/tmp"))
            .queryItems.first { $0.name == "client" })

        let fake = FakeDocs(rows: [])
        fake.exportAnswer = .written(folder: "/tmp/Exports/auxesis-receipts-2025-09-01-2025-09-30", rows: 3, missing: 1)
        let model = DocumentsPageModel(client: fake)
        // Dates picked backwards are put in order.
        await model.export(from: day("2025-09-30T10:00:00Z"), to: day("2025-09-01T10:00:00Z"), client: nil, into: URL(fileURLWithPath: "/tmp/Exports"))
        XCTAssertEqual(fake.exports.first?.from, "2025-09-01")
        XCTAssertEqual(fake.exports.first?.to, "2025-09-30")
        XCTAssertEqual(model.exportedText(language: .en), "3 receipts exported, with their originals and a CSV.")
        XCTAssertFalse(model.exporting)

        fake.exportAnswer = .empty
        await model.export(from: Date(), to: Date(), client: nil, into: URL(fileURLWithPath: "/tmp"))
        XCTAssertEqual(model.exportedText(language: .fr), "Aucun reçu sur cette période. Rien n’a été écrit.")
    }

    func testErrorsMapToThePagesWords() {
        let http = { (status: Int, code: String) in
            AuxdError.http(status: status, body: #"{"error":{"code":"\#(code)","message":"x"}}"#)
        }
        XCTAssertEqual(DocumentsProblem(AuxdError.transport("Could not connect")), .offline)
        XCTAssertEqual(DocumentsProblem(http(404, "docs_link_refused")), .gone)
        XCTAssertEqual(DocumentsProblem(http(409, "docs_export_exists")), .exportExists)
        XCTAssertEqual(DocumentsProblem(http(400, "docs_export_refused")), .exportRefused)
        XCTAssertEqual(DocumentsProblem(http(500, "docs_list_failed")), .failed)
        XCTAssertEqual(DocumentsProblem(AuxdError.unauthorized), .failed)
        XCTAssertEqual(DocumentsProblem(CancellationError()), .failed)
    }

    func testAnOfflineDaemonShowsTheOfflineState() async {
        let fake = FakeDocs(rows: [])
        fake.failure = AuxdError.transport("Could not connect to the server.")
        let model = DocumentsPageModel(client: fake)
        await model.reload()
        XCTAssertEqual(model.load, .failed(.offline))
        XCTAssertEqual(L10n.ui(.docsErrOffline, .en), "Auxesis isn't running. Start it from the menu bar, then try again.")
    }

    func testTheRealClientCallsTheThreeRoutes() async throws {
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("auxesis-docs-page-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        let client = AuxdClient(endpoint: AuxdEndpoint(baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
                                                       tokenFile: tokenFile, lockPID: nil, source: "test"),
                                requestTimeout: 5, configuration: config)
        RecordingURLProtocol.respond { request in
            let path = request.url!.path
            let body = path == "/v1/docs" ? Self.list
                : path.hasSuffix("/export") ? #"{"status":"written","folder":"/tmp/A & B/x","rows":2,"missing":0}"#
                : #"{"hash":"aaaaaaaaaaaa","party_id":null}"#
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!, Data(body.utf8))
        }
        let listed = try await client.documents(.unlinked)
        XCTAssertEqual(listed.count, 3)
        try await client.linkDocument(hash: "aaaaaaaaaaaa", client: 7)
        try await client.linkDocument(hash: "aaaaaaaaaaaa", client: nil)
        let answer = try await client.exportDocuments(DocumentsExport(
            from: Date(), to: Date(), client: nil, out: URL(fileURLWithPath: "/tmp/A & B")))
        XCTAssertEqual(answer, .written(folder: "/tmp/A & B/x", rows: 2, missing: 0))
        let urls = RecordingURLProtocol.recorded.map { "\($0.method) \($0.url)" }
        XCTAssertEqual(urls[0], "GET http://127.0.0.1:2893/v1/docs?limit=500&unlinked=true")
        XCTAssertEqual(urls[1], "POST http://127.0.0.1:2893/v1/docs/aaaaaaaaaaaa/party?party=7")
        XCTAssertEqual(urls[2], "POST http://127.0.0.1:2893/v1/docs/aaaaaaaaaaaa/party?party=none")
        XCTAssertTrue(urls[3].hasPrefix("POST http://127.0.0.1:2893/v1/docs/export?from="), urls[3])
        XCTAssertTrue(urls[3].hasSuffix("&out=/tmp/A%20%26%20B"), "the & in a folder name stays in the value: \(urls[3])")
    }
}

/// Wait for the fake to record exactly `expected` requests. The filter starts
/// its reload in a `Task` on the main actor, and that task only runs when the
/// test yields; `waitUntil` spins the run loop without suspending, so it would
/// time out while the main actor is held by the test. Sleep between reads.
@MainActor
private func waitForRequests(_ expected: [DocumentsFilter], from fake: FakeDocs,
                             timeout: TimeInterval = 5) async -> [DocumentsFilter] {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline, fake.asked != expected {
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
    return fake.asked
}

/// Records the calls it receives. The model's async reloads run the client off
/// the main actor, so its state is lock-protected: a bare array read from the
/// test while a reload appends to it is a race, and on CI that race killed the
/// whole test process (exit 1, no failing assertion printed).
private final class FakeDocs: DocumentsClient {
    let rows: [DocumentRow]
    private let lock = NSLock()
    private var _failure: Error?
    private var _exportAnswer: DocumentsExportResult = .empty
    private var _asked: [DocumentsFilter] = []
    private var _links: [(String, Int64?)] = []
    private var _exports: [DocumentsExport] = []

    init(rows: [DocumentRow]) { self.rows = rows }

    var failure: Error? {
        get { lock.withLock { _failure } }
        set { lock.withLock { _failure = newValue } }
    }
    var exportAnswer: DocumentsExportResult {
        get { lock.withLock { _exportAnswer } }
        set { lock.withLock { _exportAnswer = newValue } }
    }
    var asked: [DocumentsFilter] { lock.withLock { _asked } }
    var links: [(String, Int64?)] { lock.withLock { _links } }
    var exports: [DocumentsExport] { lock.withLock { _exports } }

    func documents(_ filter: DocumentsFilter) async throws -> [DocumentRow] {
        try lock.withLock {
            _asked.append(filter)
            if let _failure { throw _failure }
            return rows
        }
    }
    func linkDocument(hash: String, client: Int64?) async throws {
        try lock.withLock {
            if let _failure { throw _failure }
            _links.append((hash, client))
        }
    }
    func exportDocuments(_ request: DocumentsExport) async throws -> DocumentsExportResult {
        try lock.withLock {
            _exports.append(request)
            if let _failure { throw _failure }
            return _exportAnswer
        }
    }
    func clients() async throws -> [ClientSummary] {
        [ClientSummary(id: 7, displayName: "Nordwind Studio SARL"), ClientSummary(id: 9, displayName: "Atelier Cobalt")]
    }
}
