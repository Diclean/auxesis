import XCTest
@testable import AuxesisKit
import Foundation

/// The Mac bridge, app side (A2b-app). Fakes, a recording poster and the shared
/// `RecordingURLProtocol` only: no network, no EventKit, no Vision, no prompt.
@objcMembers @MainActor final class BridgeTests: XCTestCase {
    private func request(_ name: String) throws -> BridgeRequest {
        guard let request = BridgeRequest.decode(try Fixtures.data(name)) else {
            throw BridgeFailure(code: "test", message: "fixture did not decode: \(name)")
        }
        return request
    }

    private func postedObject(_ poster: RecordingBridgePoster) -> [String: Any]? {
        guard let body = poster.calls.first?.body,
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        else { return nil }
        return object
    }

    private func temporaryHome() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-bridge-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// A client on a mock URLProtocol. The test seam builds no system bridge.
    private func mockClient(home: URL) throws -> AuxdClient {
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
            tokenFile: tokenFile, lockPID: nil, source: "test")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        return AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)
    }

    // MARK: - Decoding

    func testARealFrameIsARequestAndALedgerEchoIsNot() async throws {
        let requestData = try Fixtures.data("bridge-request-create.json")
        let decoded = BridgeRequest.decode(requestData)
        XCTAssertEqual(decoded?.id, "8f14e45f-ea0b-4a3c-9a1e-2b7c5d6e0f11")
        XCTAssertEqual(decoded?.op, "eventkit.create_event")

        // The ledger re-emits the journal row as `type:"bridge.request"` with
        // its fields under `payload`: no top-level id, so not a request.
        let echo = try Fixtures.data("bridge-ledger-echo.json")
        XCTAssertNil(BridgeRequest.decode(echo))
        XCTAssertEqual(BridgeFrame.route(echo), .event(.other("bridge.request")))

        if case .request(let routed) = BridgeFrame.route(requestData) {
            XCTAssertEqual(routed.op, "eventkit.create_event")
        } else {
            XCTFail("a real frame must route as a bridge request")
        }
        XCTAssertEqual(BridgeFrame.route(Data("not json".utf8)), .skip)
    }

    func testARequestIdThatIsNotAUUIDIsIgnored() async throws {
        let bad = Data(#"{"type":"bridge.request","id":"not-a-uuid","op":"x","args":{}}"#.utf8)
        XCTAssertNil(BridgeRequest.decode(bad))
        let short = Data(#"{"type":"bridge.request","id":"8f14e45fea0b4a3c9a1e2b7c5d6e0f11","op":"x","args":{}}"#.utf8)
        XCTAssertNil(BridgeRequest.decode(short))
        let good = Data(#"{"type":"bridge.request","id":"8f14e45f-ea0b-4a3c-9a1e-2b7c5d6e0f11","op":"x","args":{}}"#.utf8)
        XCTAssertNotNil(BridgeRequest.decode(good))
    }

    // MARK: - eventkit.create_event

    func testCreateEventPostsTheExactResultBody() async throws {
        let writer = FakeEventWriter()
        writer.result = BridgeEventResult(eventId: "evt-1", calendar: "Travail")
        let poster = RecordingBridgePoster()
        let log = RecordingBridgeLog()
        let handler = BridgeHandler(writer: writer, recognizer: FakeTextRecognizer(), answers: poster, log: log)

        await handler.handle(try request("bridge-request-create.json"))

        XCTAssertEqual(poster.calls.count, 1)
        XCTAssertEqual(poster.calls.first?.id, "8f14e45f-ea0b-4a3c-9a1e-2b7c5d6e0f11")
        let object = postedObject(poster)
        XCTAssertEqual(object?["ok"] as? Bool, true)
        let result = object?["result"] as? [String: Any]
        XCTAssertEqual(result?["event_id"] as? String, "evt-1")
        XCTAssertEqual(result?["calendar"] as? String, "Travail")
        XCTAssertEqual(writer.createdTitles, ["Déjeuner avec Camille Exemple"])
        XCTAssertEqual(writer.createdCalendars, ["Travail"])
        XCTAssertEqual(writer.createdLocations, ["Café de la Gare"])
        XCTAssertEqual(log.lines.first, "eventkit.create_event 8f14e45f-ea0b-4a3c-9a1e-2b7c5d6e0f11 ok")
    }

    func testUpdateEventDispatchesTheEventId() async throws {
        let writer = FakeEventWriter()
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(writer: writer, recognizer: FakeTextRecognizer(), answers: poster, log: RecordingBridgeLog())

        await handler.handle(try request("bridge-request-update.json"))

        XCTAssertEqual(writer.updatedEventIds, ["evt-42"])
        XCTAssertEqual(writer.updatedTitles, ["Déjeuner déplacé avec Camille Exemple"])
        let result = postedObject(poster)?["result"] as? [String: Any]
        XCTAssertEqual(result?["event_id"] as? String, "evt-1")
        XCTAssertEqual(result?["calendar"] as? String, "Travail")
    }

    func testInvalidCreateArgumentsAreRejected() async throws {
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster,
            log: RecordingBridgeLog())
        // Missing start/end: the daemon should have refused it first.
        let bad = BridgeRequest(
            id: "11111111-1111-4111-8111-111111111111", op: "eventkit.create_event",
            args: Data(#"{"title":"x"}"#.utf8))

        await handler.handle(bad)

        XCTAssertEqual(postedObject(poster)?["error"] as? String, "invalid_args")
    }

    // MARK: - vision.ocr

    func testOCRIsUnavailableUntilWaveC() async throws {
        let recognizer = FakeTextRecognizer()
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: recognizer, answers: poster,
            log: RecordingBridgeLog())

        await handler.handle(try request("bridge-request-ocr.json"))

        let object = postedObject(poster)
        XCTAssertEqual(object?["ok"] as? Bool, false)
        XCTAssertEqual(object?["error"] as? String, "ocr_unavailable")
        XCTAssertTrue(recognizer.requested.isEmpty, "no fetch, no Vision, no network")
    }

    func testInvalidSHA256IsRejectedBeforeAnyFetch() async throws {
        let recognizer = FakeTextRecognizer()
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: recognizer, answers: poster,
            log: RecordingBridgeLog(), ocrAvailable: true)
        let bad = BridgeRequest(
            id: "22222222-2222-4222-8222-222222222222", op: "vision.ocr",
            args: Data(#"{"sha256":"NOT-64-LOWERCASE-HEX"}"#.utf8))

        await handler.handle(bad)

        XCTAssertEqual(postedObject(poster)?["error"] as? String, "invalid_args")
        XCTAssertTrue(recognizer.requested.isEmpty)
    }

    func testOCRPostsTheLinesAndPagesShape() async throws {
        let recognizer = FakeTextRecognizer()
        recognizer.result = VisionOCRResult(
            lines: [
                VisionOCRLine(
                    text: "Facture",
                    confidence: 0.97,
                    box: VisionOCRBox(x: 0.1, y: 0.2, width: 0.3, height: 0.4)),
                VisionOCRLine(
                    text: "Camille Exemple",
                    confidence: 0.91,
                    box: VisionOCRBox(x: 0.1, y: 0.5, width: 0.5, height: 0.1)),
            ],
            pages: 2)
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: recognizer, answers: poster,
            log: RecordingBridgeLog(), ocrAvailable: true)

        await handler.handle(try request("bridge-request-ocr.json"))

        let result = postedObject(poster)?["result"] as? [String: Any]
        XCTAssertEqual(result?["pages"] as? Int, 2)
        let lines = result?["lines"] as? [[String: Any]]
        XCTAssertEqual(lines?.count, 2)
        XCTAssertEqual(lines?.first?["text"] as? String, "Facture")
        XCTAssertEqual(lines?.first?["confidence"] as? Double, 0.97)
        let box = lines?.first?["box"] as? [String: Any]
        XCTAssertEqual(box?["x"] as? Double, 0.1)
        XCTAssertEqual(box?["height"] as? Double, 0.4)
        XCTAssertEqual(recognizer.requested, [String(repeating: "a", count: 64)])
    }

    func testOCRAccessDeniedIsTyped() async throws {
        let recognizer = FakeTextRecognizer()
        recognizer.error = BridgeFailure.accessDenied
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: recognizer, answers: poster,
            log: RecordingBridgeLog(), ocrAvailable: true)

        await handler.handle(try request("bridge-request-ocr.json"))

        XCTAssertEqual(postedObject(poster)?["error"] as? String, "access_denied")
    }

    func testAResultOverTheBodyCapAnswersResultTooLarge() async throws {
        let recognizer = FakeTextRecognizer()
        recognizer.result = VisionOCRResult(
            lines: [
                VisionOCRLine(
                    text: String(repeating: "x", count: 1_100_000), confidence: 0.9,
                    box: VisionOCRBox(x: 0, y: 0, width: 1, height: 1))
            ],
            pages: 1)
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: recognizer, answers: poster,
            log: RecordingBridgeLog(), ocrAvailable: true)

        await handler.handle(try request("bridge-request-ocr.json"))

        XCTAssertEqual(poster.calls.count, 1)
        XCTAssertEqual(postedObject(poster)?["error"] as? String, "result_too_large")
        let size = poster.calls.first?.body.count ?? 0
        XCTAssertTrue(size <= BridgeBodyCap.bytes, "the answer must stay under 1 MiB, got \(size)")
    }

    // MARK: - Refusals

    func testUnknownOpIsUnsupported() async throws {
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster,
            log: RecordingBridgeLog())
        let request = BridgeRequest(id: "op-1", op: "calendar.delete", args: Data("{}".utf8))

        await handler.handle(request)

        let object = postedObject(poster)
        XCTAssertEqual(object?["ok"] as? Bool, false)
        XCTAssertEqual(object?["error"] as? String, "unsupported_op")
        XCTAssertNotNil(object?["message"] as? String)
    }

    func testAccessDeniedIsTyped() async throws {
        let writer = FakeEventWriter()
        writer.error = BridgeFailure.accessDenied
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(writer: writer, recognizer: FakeTextRecognizer(), answers: poster, log: RecordingBridgeLog())

        await handler.handle(try request("bridge-request-create.json"))

        let object = postedObject(poster)
        XCTAssertEqual(object?["ok"] as? Bool, false)
        XCTAssertEqual(object?["error"] as? String, "access_denied")
    }

    func testAWriterThrowBecomesAValueFreeErrorAnswer() async throws {
        let writer = FakeEventWriter()
        writer.error = NSError(
            domain: "test", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "CANARY_EVENT_VALUE"])
        let poster = RecordingBridgePoster()
        let log = RecordingBridgeLog()
        let handler = BridgeHandler(writer: writer, recognizer: FakeTextRecognizer(), answers: poster, log: log)

        await handler.handle(try request("bridge-request-create.json"))

        let object = postedObject(poster)
        XCTAssertEqual(object?["ok"] as? Bool, false)
        XCTAssertEqual(object?["error"] as? String, "op_failed")
        let message = object?["message"] as? String ?? ""
        XCTAssertFalse(message.contains("CANARY_EVENT_VALUE"), "an error value must not leak: \(message)")
        for line in log.lines {
            XCTAssertFalse(line.contains("CANARY_EVENT_VALUE"), "an error value reached the log: \(line)")
        }
    }

    // MARK: - Answer exactly once

    func testADuplicateFrameAnswersOnce() async throws {
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster,
            log: RecordingBridgeLog())
        let request = try self.request("bridge-request-create.json")

        await handler.handle(request)
        await handler.handle(request)

        XCTAssertEqual(poster.calls.count, 1)
    }

    func testAReplayedIdIsPrunedAfterTenMinutes() async throws {
        let clock = TestClock(Date(timeIntervalSince1970: 1_000))
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster,
            log: RecordingBridgeLog(), now: { clock.now })
        let request = try self.request("bridge-request-create.json")

        await handler.handle(request)
        await handler.handle(request)
        XCTAssertEqual(poster.calls.count, 1)
        clock.advance(601)
        await handler.handle(request)
        XCTAssertEqual(poster.calls.count, 2, "past the daemon's retention the id is retired")
    }

    func testA404IsDroppedQuietly() async throws {
        let poster = RecordingBridgePoster()
        poster.status = 404
        let log = RecordingBridgeLog()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster, log: log)

        await handler.handle(try request("bridge-request-create.json"))

        XCTAssertEqual(poster.calls.count, 1, "the one answer is still attempted")
        XCTAssertEqual(log.lines.count, 1)
        XCTAssertTrue(log.lines[0].contains("dropped"), log.lines[0])
    }

    func testAConflictIsLoggedAndDropped() async throws {
        let poster = RecordingBridgePoster()
        poster.status = 409
        let log = RecordingBridgeLog()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster, log: log)

        await handler.handle(try request("bridge-request-create.json"))

        XCTAssertEqual(poster.calls.count, 1, "the one answer is still attempted")
        XCTAssertEqual(log.lines.count, 1)
        XCTAssertTrue(log.lines[0].contains("dropped"), log.lines[0])
    }

    // MARK: - No value in the log

    func testLogLinesCarryNoArgumentOrResultValue() async throws {
        let recognizer = FakeTextRecognizer()
        recognizer.result = VisionOCRResult(
            lines: [
                VisionOCRLine(
                    text: "CANARY_OCR_TEXT", confidence: 0.9,
                    box: VisionOCRBox(x: 0, y: 0, width: 1, height: 1))
            ],
            pages: 1)
        let poster = RecordingBridgePoster()
        let log = RecordingBridgeLog()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: recognizer, answers: poster, log: log,
            ocrAvailable: true)

        await handler.handle(try request("bridge-request-create.json"))
        await handler.handle(try request("bridge-request-ocr.json"))

        XCTAssertEqual(log.lines.count, 2)
        XCTAssertTrue(log.lines[0].hasPrefix("eventkit.create_event"), log.lines[0])
        XCTAssertTrue(log.lines[1].hasPrefix("vision.ocr"), log.lines[1])
        for line in log.lines {
            for canary in ["Camille Exemple", "Café de la Gare", "+33612345678", "CANARY_OCR_TEXT"] {
                XCTAssertFalse(line.contains(canary), "a value reached the log: \(line)")
            }
        }
    }

    // MARK: - Pure rules

    func testRFC3339NormalisesSeparatorCaseAndFraction() async throws {
        let canonical = RFC3339.date("2030-03-04T09:00:00Z")
        XCTAssertNotNil(canonical)
        XCTAssertEqual(RFC3339.date("2030-03-04 09:00:00z"), canonical, "space and lower-case z")
        XCTAssertEqual(RFC3339.date("2030-03-04t09:00:00Z"), canonical, "lower-case t")
        XCTAssertNotNil(RFC3339.date("2030-03-04T09:00:00.250Z"), "fractional seconds")
        XCTAssertNil(RFC3339.date("yesterday"))
    }

    func testSHA256ShapeIsExactly64LowercaseHex() async throws {
        XCTAssertTrue(BridgeSHA256.isValid(String(repeating: "a", count: 64)))
        XCTAssertTrue(BridgeSHA256.isValid(String(repeating: "0", count: 64)))
        XCTAssertFalse(BridgeSHA256.isValid(String(repeating: "A", count: 64)))
        XCTAssertFalse(BridgeSHA256.isValid(String(repeating: "a", count: 63)))
        XCTAssertFalse(BridgeSHA256.isValid(String(repeating: "g", count: 64)))
    }

    func testCalendarSelectionNeverFallsBackForAMissingName() async throws {
        XCTAssertEqual(BridgeCalendarSelection.select(named: nil, titles: ["Home"]), .defaultCalendar)
        XCTAssertEqual(
            BridgeCalendarSelection.select(named: "Travail", titles: ["Home", "Travail"]), .named(1))
        XCTAssertEqual(
            BridgeCalendarSelection.select(named: "Absent", titles: ["Home", "Travail"]), .missing)
    }

    func testEventTimesMustBeStrictlyOrdered() async throws {
        let start = Date(timeIntervalSince1970: 100)
        XCTAssertTrue(BridgeTimes.ordered(start: start, end: Date(timeIntervalSince1970: 200)))
        XCTAssertFalse(BridgeTimes.ordered(start: start, end: start))
        XCTAssertFalse(BridgeTimes.ordered(start: start, end: Date(timeIntervalSince1970: 50)))
    }

    // MARK: - The EventKit-free write plan

    /// The writer checks the live event against the
    /// facts the write's approval rested on. A guest added, or a calendar
    /// moved, refuses the write; unchanged, the write goes out.
    func testTheWriterRefusesAWriteWhoseFactsChanged() {
        let expected = BridgeExpectations(calendarID: "cal-home", attendees: 0)
        XCTAssertEqual(
            BridgeWriteFacts.decide(
                liveCalendarID: "cal-home", liveAttendees: 0, recurring: false, expected: expected),
            .save)
        XCTAssertEqual(
            BridgeWriteFacts.decide(
                liveCalendarID: "cal-home", liveAttendees: 1, recurring: false, expected: expected),
            .factsChanged)
        XCTAssertEqual(
            BridgeWriteFacts.decide(
                liveCalendarID: "cal-shared", liveAttendees: 0, recurring: false, expected: expected),
            .factsChanged)
        // No expectations: a write that already had the owner's card is not
        // checked twice.
        XCTAssertEqual(
            BridgeWriteFacts.decide(
                liveCalendarID: "cal-shared", liveAttendees: 3, recurring: false, expected: nil),
            .save)
    }

    /// A recurring event, or a detached occurrence of
    /// one, never takes the approval-free path. EventKit's lookup can return
    /// the first occurrence, not the one the copy saw, so the check and the
    /// save could land on another occurrence.
    func testTheWriterRefusesARecurringEvent() {
        let expected = BridgeExpectations(calendarID: "cal-home", attendees: 0)
        XCTAssertEqual(
            BridgeWriteFacts.decide(
                liveCalendarID: "cal-home", liveAttendees: 0, recurring: true, expected: expected),
            .factsChanged)
        // Even with no facts to check, a recurring event is not a free write:
        // it stays behind the owner's card.
        XCTAssertEqual(
            BridgeWriteFacts.decide(
                liveCalendarID: "cal-home", liveAttendees: 0, recurring: true, expected: nil),
            .save)
    }

    /// The daemon's expectations reach the writer.
    func testTheBridgeHandsTheExpectedFactsToTheWriter() async throws {
        let request = BridgeRequest(
            id: "req-1", op: "eventkit.update_event",
            args: jsonObject([
                "event_id": "evt-42",
                "expected_calendar_id": "cal-home",
                "expected_attendees": 0,
            ]))
        let writer = FakeEventWriter()
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: writer, recognizer: FakeTextRecognizer(), answers: poster)
        await handler.handle(request)
        XCTAssertEqual(
            writer.updatedExpectations.first,
            BridgeExpectations(calendarID: "cal-home", attendees: 0))
        // Half the facts proves nothing: the write is refused, not checked
        // halfway.
        let half = BridgeRequest(
            id: "req-2", op: "eventkit.update_event",
            args: jsonObject(["event_id": "evt-42", "expected_calendar_id": "cal-home"]))
        await handler.handle(half)
        XCTAssertEqual(writer.updatedExpectations.count, 1, "no write without both facts")
        let bodies = poster.calls.map { String(data: $0.body, encoding: .utf8) ?? "" }
        XCTAssertTrue(bodies.last?.contains("invalid_args") == true, bodies.last ?? "")
    }

    private func jsonObject(_ value: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: value)) ?? Data()
    }

    private func plan(
        _ request: BridgeWriteRequest,
        existing: BridgeWritePlanner.Existing? = nil,
        names: [String] = ["Home"]
    ) -> Result<BridgeEventPlan, BridgeFailure> {
        BridgeWritePlanner.plan(request, existing: existing, calendarNames: names)
    }

    private func createArgs(
        calendar: String? = nil, title: String = "Réunion",
        start: String = "2030-03-04T09:00:00Z", end: String = "2030-03-04T10:00:00Z"
    ) -> CreateEventArgs {
        CreateEventArgs(
            calendar: calendar, title: title, start: start, end: end,
            location: nil, notes: nil, url: nil)
    }

    private func updateArgs(
        calendar: String? = nil, title: String? = nil,
        start: String? = nil, end: String? = nil
    ) -> UpdateEventArgs {
        UpdateEventArgs(
            eventId: "evt-42", calendar: calendar, title: title,
            start: start, end: end, location: nil, notes: nil, url: nil,
            expectedCalendarID: nil, expectedAttendees: nil)
    }

    private func existingEvent() -> BridgeWritePlanner.Existing {
        BridgeWritePlanner.Existing(
            title: "Réunion",
            start: RFC3339.date("2030-03-04T09:00:00Z")!,
            end: RFC3339.date("2030-03-04T10:00:00Z")!,
            location: "Salle 1", notes: "notes", url: "https://example.test/x")
    }

    func testCreatePlanUsesTheDefaultCalendarForNoOrABlankName() {
        // CAL-BLANK-CREATE: a blank field is the absent field, never a title.
        for name in [nil, "", "   ", "\t\n"] as [String?] {
            guard case .success(let value) = plan(.create(createArgs(calendar: name))) else {
                return XCTFail("create with calendar \(String(describing: name)) must plan")
            }
            XCTAssertEqual(value.calendar, .defaultCalendar)
            XCTAssertEqual(value.title, "Réunion")
            XCTAssertEqual(value.start, RFC3339.date("2030-03-04T09:00:00Z")!)
        }

        guard case .success(let named) = plan(.create(createArgs(calendar: "Home"))) else {
            return XCTFail("a found calendar must plan")
        }
        XCTAssertEqual(named.calendar, .named(0))
    }

    func testCreatePlanRefusesAMissingNamedCalendar() {
        for name in ["Absent", "Home ", "primary"] {
            XCTAssertEqual(
                plan(.create(createArgs(calendar: name))), .failure(.calendarNotFound), name)
        }
    }

    func testUpdatePlanKeepsTheEventWhenNoCalendarIsGiven() {
        guard case .success(let value) = plan(.update(updateArgs(title: "Nouveau")), existing: existingEvent()) else {
            return XCTFail("update with no calendar must plan")
        }
        XCTAssertEqual(value.calendar, .unchanged)
        XCTAssertEqual(value.title, "Nouveau")
        // Untouched fields survive the merge.
        XCTAssertEqual(value.location, "Salle 1")
        XCTAssertEqual(value.notes, "notes")
        XCTAssertEqual(value.url, "https://example.test/x")
    }

    func testUpdatePlanRefusesAMissingNamedCalendar() {
        for name in ["Absent", "", "   ", "primary"] {
            XCTAssertEqual(
                plan(
                    .update(updateArgs(calendar: name, title: "Nouveau")),
                    existing: existingEvent()),
                .failure(.calendarNotFound), name)
        }
    }

    func testUpdatePlanRefusesMergedTimesThatDoNotOrder() {
        // Only the start moves past the existing end: the merged pair is bad.
        XCTAssertEqual(
            plan(.update(updateArgs(start: "2030-03-04T11:00:00Z")), existing: existingEvent()),
            .failure(.invalidArgs))
        // Only the end moves before the existing start.
        XCTAssertEqual(
            plan(.update(updateArgs(end: "2030-03-04T08:00:00Z")), existing: existingEvent()),
            .failure(.invalidArgs))
    }

    func testCreatePlanRefusesUnorderedOrUnparseableTimes() {
        XCTAssertEqual(
            plan(.create(createArgs(start: "2030-03-04T10:00:00Z", end: "2030-03-04T09:00:00Z"))),
            .failure(.invalidArgs))
        XCTAssertEqual(plan(.create(createArgs(start: "yesterday"))), .failure(.invalidArgs))
    }

    func testARejectedPlanProducesNoFieldsToApply() {
        // The planner returns a failure, never a partial plan: there is nothing
        // for the writer to apply, so the cached event cannot be left dirty.
        let result = plan(
            .update(updateArgs(calendar: "Absent", title: "Nouveau")), existing: existingEvent())
        if case .success = result { XCTFail("a rejected plan must not produce fields") }
        XCTAssertEqual(result, .failure(.calendarNotFound))
    }

    // MARK: - No argument canary in the log, on every path

    func testNoArgumentCanaryReachesTheLogOnSuccessErrorOr401() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)

        let canaries = ["CANARY_TITLE_Camille", "CANARY_NOTES_+33612345678"]
        let args = Data(
            #"{"title":"CANARY_TITLE_Camille","notes":"CANARY_NOTES_+33612345678","start":"2030-03-04T09:00:00Z","end":"2030-03-04T09:30:00Z"}"#
                .utf8)
        let canaryRequest = BridgeRequest(
            id: "8f14e45f-ea0b-4a3c-9a1e-2b7c5d6e0f11", op: "eventkit.create_event", args: args)

        // Success path.
        let successLog = RecordingBridgeLog()
        let success = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(),
            answers: RecordingBridgePoster(), log: successLog)
        await success.handle(canaryRequest)

        // Error path: the writer throws with a canary in its own message.
        let writer = FakeEventWriter()
        writer.error = BridgeFailure(code: "access_denied", message: "CANARY_TITLE_Camille")
        let errorLog = RecordingBridgeLog()
        let error = BridgeHandler(
            writer: writer, recognizer: FakeTextRecognizer(),
            answers: RecordingBridgePoster(), log: errorLog)
        await error.handle(canaryRequest)

        // 401 path, through the real answer POST.
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            (HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!, Data())
        }
        let authLog = RecordingBridgeLog()
        let auth = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(),
            answers: client, log: authLog)
        await auth.handle(canaryRequest)

        XCTAssertFalse(successLog.lines.isEmpty)
        XCTAssertFalse(errorLog.lines.isEmpty)
        XCTAssertFalse(authLog.lines.isEmpty)
        for line in successLog.lines + errorLog.lines + authLog.lines {
            for canary in canaries {
                XCTAssertFalse(line.contains(canary), "a value reached the log: \(line)")
            }
        }
    }

    // MARK: - Socket wiring

    func testYieldDispatchesARequestAndSurfacesNoEvent() async throws {
        let poster = RecordingBridgePoster()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: poster,
            log: RecordingBridgeLog())
        let data = try Fixtures.data("bridge-request-create.json")
        let stream = AsyncThrowingStream<WireEvent, Error> { continuation in
            AuxdClient.yield(data, to: continuation, bridge: handler)
            continuation.finish()
        }

        var events: [WireEvent] = []
        for try await event in stream { events.append(event) }

        XCTAssertTrue(events.isEmpty, "a bridge request must not surface as a WireEvent")
        XCTAssertTrue(waitUntil { poster.calls.count == 1 }, "the handler must answer the frame")
    }

    func testYieldSurfacesALedgerEchoAsAnEvent() async throws {
        let echo = try Fixtures.data("bridge-ledger-echo.json")
        let stream = AsyncThrowingStream<WireEvent, Error> { continuation in
            AuxdClient.yield(echo, to: continuation, bridge: nil)
            continuation.finish()
        }

        var events: [WireEvent] = []
        for try await event in stream { events.append(event) }

        XCTAssertEqual(events, [.other("bridge.request")])
    }

    // MARK: - POST /v1/bridge/{id}

    func testPostBridgeAnswerUsesTheExactPathAndBearer() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer deadbeef")
            return (
                HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                Data(#"{"ok":true}"#.utf8))
        }
        let id = "8f14e45f-ea0b-4a3c-9a1e-2b7c5d6e0f11"

        let status = try await client.postBridgeAnswer(
            id: id, body: Data(#"{"ok":true,"result":{}}"#.utf8))

        XCTAssertEqual(status, 200)
        let record = try XCTUnwrapOptional(RecordingURLProtocol.recorded.last)
        XCTAssertEqual(record.url, "http://127.0.0.1:2893/v1/bridge/\(id)")
        XCTAssertEqual(record.method, "POST")
        XCTAssertEqual(record.authorization, "Bearer deadbeef")
    }

    func testPostBridgeAnswer404And409AreDroppedQuietly() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }

        for status in [404, 409] {
            RecordingURLProtocol.respond { request in
                (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, Data())
            }
            let log = RecordingBridgeLog()
            let handler = BridgeHandler(
                writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: client, log: log)

            await handler.handle(try request("bridge-request-create.json"))

            XCTAssertEqual(log.lines.count, 1, "status \(status)")
            XCTAssertTrue(log.lines[0].contains("dropped"), "status \(status): \(log.lines[0])")
        }
    }

    func testPostBridgeAnswer401LogsAnAuthFailureWithoutValues() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            (HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!, Data())
        }
        let log = RecordingBridgeLog()
        let handler = BridgeHandler(
            writer: FakeEventWriter(), recognizer: FakeTextRecognizer(), answers: client, log: log)

        await handler.handle(try request("bridge-request-create.json"))

        XCTAssertEqual(log.lines.count, 1)
        XCTAssertTrue(log.lines[0].contains("auth_failed"), log.lines[0])
        for canary in ["Camille Exemple", "Café de la Gare", "+33612345678"] {
            XCTAssertFalse(log.lines[0].contains(canary), log.lines[0])
        }
    }

    func testDocumentBytesRejectsANonSHA256BeforeAnyRequest() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let client = try mockClient(home: home)
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            XCTFail("an invalid sha256 must not build a request: \(request.url?.absoluteString ?? "")")
            return (
                HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!,
                Data())
        }

        do {
            _ = try await client.documentBytes(sha256: "not-a-hash")
            XCTFail("an invalid sha256 must be refused")
        } catch let error as AuxdError {
            XCTAssertEqual(error, .badURL)
        }
        XCTAssertTrue(RecordingURLProtocol.recorded.isEmpty)
    }
}

// MARK: - Fakes

private final class FakeEventWriter: EventWriter {
    var result = BridgeEventResult(eventId: "evt-1", calendar: "Travail")
    var error: Error?
    private(set) var createdTitles: [String] = []
    private(set) var createdCalendars: [String?] = []
    private(set) var createdLocations: [String?] = []
    private(set) var updatedEventIds: [String] = []
    private(set) var updatedTitles: [String?] = []
    private(set) var updatedExpectations: [BridgeExpectations?] = []

    func createEvent(
        calendar: String?, title: String, start: String, end: String,
        location: String?, notes: String?, url: String?
    ) async throws -> BridgeEventResult {
        createdTitles.append(title)
        createdCalendars.append(calendar)
        createdLocations.append(location)
        if let error { throw error }
        return result
    }

    func updateEvent(
        eventId: String, calendar: String?, title: String?, start: String?,
        end: String?, location: String?, notes: String?, url: String?,
        expected: BridgeExpectations?
    ) async throws -> BridgeEventResult {
        updatedEventIds.append(eventId)
        updatedTitles.append(title)
        updatedExpectations.append(expected)
        if let error { throw error }
        return result
    }
}

private final class FakeTextRecognizer: TextRecognizer {
    var result = VisionOCRResult(lines: [], pages: 1)
    var error: Error?
    private(set) var requested: [String] = []

    func recognize(sha256: String) async throws -> VisionOCRResult {
        requested.append(sha256)
        if let error { throw error }
        return result
    }
}

private final class RecordingBridgePoster: BridgeAnswerPosting {
    private let lock = NSLock()
    private var stored: [(id: String, body: Data)] = []
    var status = 200

    var calls: [(id: String, body: Data)] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func postBridgeAnswer(id: String, body: Data) async throws -> Int {
        lock.withLock { stored.append((id, body)) }
        return status
    }
}

private final class RecordingBridgeLog: BridgeLogging {
    private let lock = NSLock()
    private var stored: [String] = []

    var lines: [String] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func log(op: String, id: String, outcome: String) {
        lock.lock()
        stored.append("\(op) \(id) \(outcome)")
        lock.unlock()
    }
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ start: Date) { value = start }

    var now: Date {
        lock.withLock { value }
    }

    func advance(_ seconds: TimeInterval) {
        lock.withLock { value = value.addingTimeInterval(seconds) }
    }
}
