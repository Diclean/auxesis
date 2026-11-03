// Today (M2): the live client's `GET /v1/brief/today` and the Today state on a
// daemon without that route, over a stubbed URL protocol. No socket, no
// fixture daemon, no real token: the token file lives in a temp home.
import Foundation
import Testing
@testable import AuxesisKit

/// The stub's answer. A free function: the URL protocol calls it off the main actor.
private func stubReply(_ request: URLRequest, _ status: Int, _ body: String = "") -> (HTTPURLResponse, Data) {
    let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
    return (response, Data(body.utf8))
}

/// The JSON body a stubbed request carried (URLProtocol sees it as a stream).
private func bodyJSON(_ request: URLRequest) -> [String: String] {
    var data = request.httpBody ?? Data()
    if data.isEmpty, let stream = request.httpBodyStream {
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 1024)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
    }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: String] ?? [:]
}

/// Bodies seen by the stub, off the main actor.
private final class BodyLog: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: [String: String]] = [:]
    func set(_ path: String, _ body: [String: String]) { lock.withLock { items[path] = body } }
    func get(_ path: String) -> [String: String]? { lock.withLock { items[path] } }
}

@objcMembers @MainActor final class TodayClientTests: XCTestCase {
    private let day = "2026-10-13"

    private func tempHome() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-today-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// A client on the mock URLProtocol, with a bearer token in a temp home.
    private func mockClient(home: URL) throws -> AuxdClient {
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
            tokenFile: tokenFile, lockPID: nil, source: "test")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        return AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)
    }

    /// Runs an async call to completion on the main run loop.
    private func resolve<T>(_ operation: @escaping () async throws -> T) throws -> T {
        let box = ResultBox()
        Task {
            do { box.set(.success(try await operation())) }
            catch { box.set(.failure(error)) }
        }
        XCTAssertTrue(waitUntil { box.result != nil })
        return try box.result!.get() as! T
    }

    // MARK: - GET /v1/brief/today

    func testTodayBriefDecodesTheStoredBriefWithTheBearerToken() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            stubReply(request, 200, #"{"day":"2026-10-13","written_at":"08:00","events":[{"title":"Call","start":"15:00"}],"mail":[{"sender":"Jonas Weber","subject":"Slot"}],"mail_truncated":true}"#)
        }
        let client = try mockClient(home: home)

        let brief = try resolve { try await client.todayBrief() }

        XCTAssertEqual(brief?.day, day)
        XCTAssertEqual(brief?.writtenAt, "08:00")
        XCTAssertEqual(brief?.events, [BriefEvent(title: "Call", start: "15:00")])
        XCTAssertEqual(brief?.notes, [])
        XCTAssertEqual(brief?.mail?.count, 1)
        XCTAssertEqual(brief?.mailTruncated, true)
        guard let record = RecordingURLProtocol.recorded.last else { return XCTFail("no request was sent") }
        XCTAssertEqual(record.method, "GET")
        XCTAssertTrue(record.url.hasSuffix("/v1/brief/today"))
        XCTAssertEqual(record.authorization, "Bearer deadbeef")
    }

    func testA404IsTheEmptyStateNotAnError() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in stubReply(request, 404, #"{"error":"not_found"}"#) }
        let client = try mockClient(home: home)

        XCTAssertNil(try resolve { try await client.todayBrief() })
    }

    func testAnEmptyBodyIsTheEmptyStateToo() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in stubReply(request, 200) }
        let client = try mockClient(home: home)

        XCTAssertNil(try resolve { try await client.todayBrief() })
    }

    func testA401IsThrownSoTheAuthPathSeesIt() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in stubReply(request, 401) }
        let client = try mockClient(home: home)

        XCTAssertThrowsError(try resolve { try await client.todayBrief() }) { error in
            XCTAssertEqual(error as? AuxdError, .unauthorized)
        }
    }

    // MARK: - Possible new clients

    func testProspectsDecodeAndAMissingFieldIsEmpty() throws {
        let with = #"{"day":"2026-10-13","prospects":[{"account":"work","name":"","email":"a@b.test","reason":"referral","date":"Wed, 14 Oct 2026 09:00:00 +0000"}]}"#
        let brief = try JSONDecoder().decode(DailyBrief.self, from: Data(with.utf8))
        XCTAssertEqual(brief.prospects.count, 1)
        XCTAssertEqual(brief.prospects.first?.title, "a@b.test", "no name: the address leads")
        XCTAssertEqual(brief.prospects.first?.reasonKey, .prospectReferral)
        XCTAssertEqual(brief.prospects.first?.shortDate(.en, timeZone: TimeZone(identifier: "UTC")!), "14 Oct, 09:00")
        let without = try JSONDecoder().decode(DailyBrief.self, from: Data(#"{"day":"2026-10-13"}"#.utf8))
        XCTAssertEqual(without.prospects, [])
    }

    func testAddAndIgnorePostTheAccountAndAddressAndA404IsGone() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        let bodies = BodyLog()
        RecordingURLProtocol.respond { request in
            let path = request.url?.path ?? ""
            bodies.set(path, bodyJSON(request))
            switch path {
            case "/v1/brief/prospects/add": return stubReply(request, 200, #"{"status":"added","party_id":7}"#)
            case "/v1/brief/prospects/ignore": return stubReply(request, 200, #"{"status":"ignored"}"#)
            default: return stubReply(request, 404, #"{"error":"prospect_unknown"}"#)
            }
        }
        let client = try mockClient(home: home)

        XCTAssertEqual(try resolve { try await client.resolveProspect(account: "work", email: "a@b.test", add: true) }, .added(partyID: 7))
        XCTAssertEqual(bodies.get("/v1/brief/prospects/add"), ["account": "work", "email": "a@b.test"])
        XCTAssertEqual(try resolve { try await client.resolveProspect(account: "work", email: "c@d.test", add: false) }, .ignored)
        XCTAssertEqual(bodies.get("/v1/brief/prospects/ignore"), ["account": "work", "email": "c@d.test"])
        XCTAssertEqual(RecordingURLProtocol.recorded.last?.method, "POST")

        RecordingURLProtocol.respond { request in stubReply(request, 404, #"{"error":"prospect_unknown"}"#) }
        XCTAssertEqual(try resolve { try await client.resolveProspect(account: "work", email: "a@b.test", add: true) }, .gone)
    }

    func testAnActionRemovesTheRowAndAnErrorKeepsItWithOneLine() throws {
        let fixture = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: fixture, language: .en), client: fixture)
        shell.loadToday()
        XCTAssertTrue(waitUntil { shell.today.value != nil })
        guard case .brief(let brief)? = shell.today.value, let first = brief.prospects.first else {
            return XCTFail("the fixture suggests prospects")
        }
        shell.resolveProspect(first, add: true)
        XCTAssertTrue(waitUntil { shell.prospectsBusy.isEmpty && Self.prospects(shell).count == brief.prospects.count - 1 })
        XCTAssertFalse(Self.prospects(shell).contains(first))
        shell.resolveProspect(Self.prospects(shell)[0], add: false)
        XCTAssertTrue(waitUntil { Self.prospects(shell).count == brief.prospects.count - 2 })
        XCTAssertNil(shell.prospectFailed)

        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            request.httpMethod == "GET"
                ? stubReply(request, 200, #"{"day":"\#(TodayPresentation.day(Date()))","prospects":[{"account":"work","email":"a@b.test","reason":"quote"}]}"#)
                : stubReply(request, 500)
        }
        let client = try mockClient(home: home)
        let live = ShellModel(store: Store(transport: client, language: .en), client: client)
        live.loadToday()
        XCTAssertTrue(waitUntil { Self.prospects(live).count == 1 })
        live.resolveProspect(Self.prospects(live)[0], add: true)
        XCTAssertTrue(waitUntil { live.prospectFailed != nil })
        XCTAssertEqual(Self.prospects(live).count, 1, "an error keeps the row")
    }

    private static func prospects(_ shell: ShellModel) -> [BriefProspect] {
        if case .brief(let brief)? = shell.today.value { return brief.prospects }
        return []
    }

    // MARK: - Today on a daemon without the read route

    /// The bug the owner saw on the real daemon: a run writes today's brief,
    /// the re-read still answers 404, and the page must not say "No brief yet"
    /// under "Today's brief is written." No fixture involved.
    func testAfterARunWritesOnADaemonWithoutTheReadRouteNoEmptySentenceShows() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            switch (request.httpMethod ?? "GET", request.url?.path ?? "") {
            case ("GET", "/v1/brief/today"): return stubReply(request, 404, #"{"error":"not_found"}"#)
            case ("GET", "/v1/jobs"): return stubReply(request, 200, "[]")
            case ("POST", "/v1/brief/run"): return stubReply(request, 200, #"{"status":"written","brief":null}"#)
            default: return stubReply(request, 500)
            }
        }
        let client = try mockClient(home: home)
        let shell = ShellModel(store: Store(transport: client, language: .en), client: client)
        var loads = 0
        let loaded = shell.$today.dropFirst().sink { _ in loads += 1 }
        defer { loaded.cancel() }

        shell.loadToday()
        XCTAssertTrue(waitUntil { loads == 1 })
        XCTAssertEqual(shell.today.value, .empty(nextRun: "08:00"))
        XCTAssertTrue(shell.showsTodayEmptySentence, "before any run the sentence is right")

        shell.runBriefNow()
        XCTAssertTrue(waitUntil { loads == 2 }, "the run re-reads Today")
        XCTAssertEqual(shell.briefRunNote, .briefRunWritten)
        XCTAssertEqual(shell.today.value, .empty(nextRun: "08:00"), "this daemon still answers 404 on the read")
        XCTAssertFalse(shell.showsTodayEmptySentence)
    }
}
