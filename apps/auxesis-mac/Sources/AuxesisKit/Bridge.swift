// The Mac bridge, app side (`docs/phase1.md` §3, work order A2b-app).
//
// `auxd` cannot call EventKit or Vision; this app can. The daemon publishes one
// `bridge.request` frame on the existing authenticated `/v1/events` WebSocket
// and waits, bounded, for `POST /v1/bridge/{id}`. This file decodes the frame,
// dispatches the op to a protocol (tests use fakes), and posts exactly one
// answer.
//
// Privacy rule: an argument value or a result value (a title, a note, OCR text)
// never reaches a log line. Only op, id and outcome are logged.
import Dispatch
import Foundation
import Vision
import os

/// Whether the app may run `vision.ocr`. The daemon route that serves the
/// document bytes (`GET /v1/documents/{sha256}/bytes`) lands in Wave C; until
/// then `vision.ocr` answers `ocr_unavailable` with no network call. Wave C
/// flips this to `true`; the recogniser below is already in place.
public let visionOCRIsAvailable = false

// MARK: - Request frame

/// One real `bridge.request` frame from `/v1/events`.
///
/// The store broadcaster also re-emits each journal row with its kind as
/// `type`; a `bridge.request` row then arrives with its fields nested under
/// `payload` and no top-level `id`. [`decode`] requires a top-level UUID `id`,
/// so a ledger echo (or a value frame) is never mistaken for a request.
public struct BridgeRequest: Equatable {
    public let id: String
    public let op: String
    /// The `args` object, re-serialised so the per-op decoders can read it.
    public let args: Data

    public init(id: String, op: String, args: Data) {
        self.id = id
        self.op = op
        self.args = args
    }

    /// Decode a frame, or `nil` when it is not a request (a ledger echo, a
    /// value frame, a non-UUID id, malformed JSON).
    public static func decode(_ data: Data) -> BridgeRequest? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["type"] as? String == "bridge.request",
              let id = object["id"] as? String, isUUID(id),
              let op = object["op"] as? String, !op.isEmpty
        else { return nil }
        let args = object["args"] as? [String: Any] ?? [:]
        guard let argsData = try? JSONSerialization.data(withJSONObject: args) else { return nil }
        return BridgeRequest(id: id, op: op, args: argsData)
    }

    /// The daemon mints a 36-character UUID v4; anything else is not a request.
    static func isUUID(_ text: String) -> Bool {
        text.count == 36 && UUID(uuidString: text) != nil
    }
}

/// How one raw `/v1/events` frame is routed (pure, so a test can pin it).
public enum BridgeFrameRoute: Equatable {
    /// A real request (top-level `id`): hand it to the bridge handler.
    case request(BridgeRequest)
    /// A normal app frame.
    case event(WireEvent)
    /// Unparseable: skip, exactly as `WireEventDecoder` did before.
    case skip
}

public enum BridgeFrame {
    /// Route one raw frame. A bridge request is not also a `WireEvent`; a
    /// ledger echo (no top-level `id`) falls through to the event decoder.
    public static func route(_ data: Data) -> BridgeFrameRoute {
        if let request = BridgeRequest.decode(data) { return .request(request) }
        if let event = try? WireEventDecoder.decode(data) { return .event(event) }
        return .skip
    }
}

// MARK: - Failures and results

/// One op refusal the app hands back to `auxd`. The message never carries an
/// argument or a result value.
public struct BridgeFailure: Error, Equatable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    /// The app has no EventKit access; it never prompts on its own.
    public static let accessDenied = BridgeFailure(
        code: "access_denied",
        message: "Auxesis has no access to Calendars")
    /// The op is not one this app knows.
    public static let unsupportedOp = BridgeFailure(
        code: "unsupported_op",
        message: "this op is not supported by the app")
    /// OCR needs `GET /v1/documents/{sha256}/bytes`, which lands in Wave C.
    public static let ocrUnavailable = BridgeFailure(
        code: "ocr_unavailable",
        message: "OCR is not available yet")
    /// A named calendar does not exist: never silently fall back to the default.
    public static let calendarNotFound = BridgeFailure(
        code: "calendar_not_found",
        message: "no calendar with that title")
    /// The answer would exceed the daemon's 1 MiB body cap.
    public static let resultTooLarge = BridgeFailure(
        code: "result_too_large",
        message: "the result is too large to return")
    /// A refusal with no more specific code: never an error value.
    public static let failed = BridgeFailure(
        code: "op_failed",
        message: "the op could not run")
    /// Malformed args the daemon should have refused first.
    public static let invalidArgs = BridgeFailure(
        code: "invalid_args",
        message: "the arguments are not valid for this op")
    /// The live event no longer matches the facts the write rested on: a guest
    /// was added, or the event moved to another calendar (CAL-DEFAULT-ID r1).
    /// Nothing was written: the owner decides.
    public static let factsChanged = BridgeFailure(
        code: "facts_changed",
        message: "the event's calendar or its guests changed")
}

/// The facts a write's approval rested on (CAL-DEFAULT-ID r1).
///
/// The daemon's copy of the calendar said the event sits on a calendar and
/// has no guest. The copy may be stale, so the app checks the live event
/// against these facts before it saves anything.
public struct BridgeExpectations: Equatable {
    /// The id of the calendar the event must still sit on.
    public var calendarID: String
    /// The guest count the event must still have.
    public var attendees: Int

    public init(calendarID: String, attendees: Int) {
        self.calendarID = calendarID
        self.attendees = attendees
    }
}

/// What the writer does with the live event's facts (CAL-DEFAULT-ID r1).
public enum BridgeWriteFacts: Equatable {
    /// The live event still matches what the copy said: the write goes out.
    case save
    /// The live event no longer matches: nothing is saved.
    case factsChanged

    /// The writer's one decision on the approval-free path: the live event
    /// must still sit on the same calendar with the same guest count. A guest
    /// added, or a calendar moved, refuses the write. A recurring event
    /// refuses it too (CAL-DEFAULT-ID r2): EventKit's lookup can return the
    /// first occurrence, not the one the copy saw, so the check and the save
    /// could land on another one.
    ///
    /// No expectations, no check: a write that already had the owner's card
    /// is not checked twice, and a recurring update stays behind that card
    /// (the security review's "keep recurring updates approval-gated").
    public static func decide(
        liveCalendarID: String, liveAttendees: Int, recurring: Bool,
        expected: BridgeExpectations?
    ) -> BridgeWriteFacts {
        guard let expected else { return .save }
        if recurring { return .factsChanged }
        let same = expected.calendarID == liveCalendarID && expected.attendees == liveAttendees
        return same ? .save : .factsChanged
    }
}

/// One EventKit write result: `{event_id, calendar}` (`phase1.md` §3).
public struct BridgeEventResult: Equatable {
    public let eventId: String
    public let calendar: String

    public init(eventId: String, calendar: String) {
        self.eventId = eventId
        self.calendar = calendar
    }

    public var json: [String: Any] {
        ["event_id": eventId, "calendar": calendar]
    }
}

/// One normalized Vision box (origin bottom-left, unit square).
public struct VisionOCRBox: Equatable {
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }

    public var json: [String: Any] {
        ["x": x, "y": y, "width": width, "height": height]
    }
}

public struct VisionOCRLine: Equatable {
    public let text: String
    public let confidence: Double
    public let box: VisionOCRBox

    public init(text: String, confidence: Double, box: VisionOCRBox) {
        self.text = text
        self.confidence = confidence
        self.box = box
    }

    public var json: [String: Any] {
        ["text": text, "confidence": confidence, "box": box.json]
    }
}

/// `vision.ocr` result: `{lines:[{text, confidence, box}], pages}`.
public struct VisionOCRResult: Equatable {
    public let lines: [VisionOCRLine]
    public let pages: Int

    public init(lines: [VisionOCRLine], pages: Int) {
        self.lines = lines
        self.pages = pages
    }

    public var json: [String: Any] {
        ["lines": lines.map(\.json), "pages": pages]
    }
}

// MARK: - Test seams

/// EventKit write seam: tests use a fake and never touch the owner's calendar.
///
/// Not main-actor isolated: the bridge runs these off the main actor so a slow
/// EventKit save cannot stall the UI.
public protocol EventWriter: AnyObject {
    func createEvent(
        calendar: String?, title: String, start: String, end: String,
        location: String?, notes: String?, url: String?
    ) async throws -> BridgeEventResult
    /// `expected` are the facts the write's approval rested on (CAL-DEFAULT-ID
    /// r1): the writer refuses the write, without saving, when the live event
    /// no longer matches them.
    func updateEvent(
        eventId: String, calendar: String?, title: String?, start: String?,
        end: String?, location: String?, notes: String?, url: String?,
        expected: BridgeExpectations?
    ) async throws -> BridgeEventResult
}

/// Vision seam: tests use a fake and never run OCR.
public protocol TextRecognizer: AnyObject {
    func recognize(sha256: String) async throws -> VisionOCRResult
}

/// Reads one registry document's bytes from auxd
/// (`GET /v1/documents/{sha256}/bytes`, local token).
public protocol DocumentBytesFetching: AnyObject {
    func documentBytes(sha256: String) async throws -> Data
}

/// Posts one answer to `POST /v1/bridge/{id}` and reports the HTTP status.
/// Throws only when the request never reached the daemon.
public protocol BridgeAnswerPosting: AnyObject {
    func postBridgeAnswer(id: String, body: Data) async throws -> Int
}

/// Where bridge outcomes are logged: op, id and outcome only, never a value.
public protocol BridgeLogging: AnyObject {
    func log(op: String, id: String, outcome: String)
}

/// Default logger. Every interpolation is `.public` on purpose: the strings are
/// an op name, a UUID and an outcome word, never an argument or a result.
public final class OSLogBridgeLogger: BridgeLogging {
    private let logger = Logger(subsystem: "app.auxesis.mac", category: "bridge")

    public init() {}

    public func log(op: String, id: String, outcome: String) {
        logger.info(
            "bridge op=\(op, privacy: .public) id=\(id, privacy: .public) outcome=\(outcome, privacy: .public)"
        )
    }
}

/// The daemon caps an answer body at 1 MiB; an OCR line set can reach it.
enum BridgeBodyCap {
    static let bytes = 1024 * 1024
}

/// The one sha256 shape the daemon accepts: 64 lowercase hex characters.
enum BridgeSHA256 {
    static func isValid(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        guard bytes.count == 64 else { return false }
        return bytes.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }
}

/// `phase1.md` §3: an event's end is strictly after its start, also after a
/// partial update merged new times onto an existing event.
enum BridgeTimes {
    static func ordered(start: Date, end: Date) -> Bool { end > start }
}

/// The create/update calendar rule, kept pure: a nil name uses the store's
/// default (create) or keeps the event in place (update); a named calendar must
/// match an exact title, otherwise the op is `calendar_not_found`.
enum BridgeCalendarSelection: Equatable {
    case named(Int)
    case defaultCalendar
    case missing

    static func select(named name: String?, titles: [String]) -> BridgeCalendarSelection {
        guard let name else { return .defaultCalendar }
        guard let index = titles.firstIndex(of: name) else { return .missing }
        return .named(index)
    }
}

/// Which calendar a write targets. `.defaultCalendar` is create-only;
/// `.unchanged` is update-only.
enum BridgeCalendarChoice: Equatable {
    case defaultCalendar
    case named(Int)
    case unchanged
}

/// The final fields a write applies, plus its calendar. No EventKit type here:
/// the whole decision is testable, and the writer only copies this onto an
/// EKEvent after it has succeeded.
struct BridgeEventPlan: Equatable {
    var title: String
    var start: Date
    var end: Date
    var location: String?
    var notes: String?
    var url: String?
    var calendar: BridgeCalendarChoice
}

/// One write request, decoded and free of EventKit.
enum BridgeWriteRequest: Equatable {
    case create(CreateEventArgs)
    case update(UpdateEventArgs)
}

/// The one EventKit-free decision for both bridge write ops. Every new value,
/// including the merged start/end and the target calendar, is computed and
/// validated here before any EKEvent is touched, so a rejected request can
/// never leave a dirty cached event.
enum BridgeWritePlanner {
    /// The existing event's fields, as the update path sees them.
    struct Existing: Equatable {
        var title: String
        var start: Date
        var end: Date
        var location: String?
        var notes: String?
        var url: String?
    }

    static func plan(
        _ request: BridgeWriteRequest,
        existing: Existing?,
        calendarNames: [String]
    ) -> Result<BridgeEventPlan, BridgeFailure> {
        switch request {
        case .create(let args):
            return create(args, calendarNames: calendarNames)
        case .update(let args):
            guard let existing else { return .failure(.invalidArgs) }
            return update(args, existing: existing, calendarNames: calendarNames)
        }
    }

    private static func create(
        _ args: CreateEventArgs, calendarNames: [String]
    ) -> Result<BridgeEventPlan, BridgeFailure> {
        guard let start = RFC3339.date(args.start), let end = RFC3339.date(args.end),
              BridgeTimes.ordered(start: start, end: end) else {
            return .failure(.invalidArgs)
        }
        return calendar(args.calendar, calendarNames: calendarNames, forUpdate: false).map { choice in
            BridgeEventPlan(
                title: args.title, start: start, end: end,
                location: args.location, notes: args.notes, url: args.url, calendar: choice)
        }
    }

    private static func update(
        _ args: UpdateEventArgs, existing: Existing, calendarNames: [String]
    ) -> Result<BridgeEventPlan, BridgeFailure> {
        var title = existing.title
        var start = existing.start
        var end = existing.end
        var location = existing.location
        var notes = existing.notes
        var url = existing.url
        if let value = args.title { title = value }
        if let value = args.start {
            guard let date = RFC3339.date(value) else { return .failure(.invalidArgs) }
            start = date
        }
        if let value = args.end {
            guard let date = RFC3339.date(value) else { return .failure(.invalidArgs) }
            end = date
        }
        if let value = args.location { location = value }
        if let value = args.notes { notes = value }
        if let value = args.url { url = value }
        // A partial update can cross the merged times: check the result, not
        // just the fields the caller happened to send.
        guard BridgeTimes.ordered(start: start, end: end) else { return .failure(.invalidArgs) }
        return calendar(args.calendar, calendarNames: calendarNames, forUpdate: true).map { choice in
            BridgeEventPlan(
                title: title, start: start, end: end,
                location: location, notes: notes, url: url, calendar: choice)
        }
    }

    /// nil is the default for create and "unchanged" for update; a named
    /// calendar must exist. On a create, an empty or whitespace-only name is
    /// the same as no name: the store's default. On an update, a blank name
    /// still names a calendar and fails closed (#397).
    private static func calendar(
        _ name: String?, calendarNames: [String], forUpdate: Bool
    ) -> Result<BridgeCalendarChoice, BridgeFailure> {
        let blank = name?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true
        if !forUpdate, blank {
            return .success(.defaultCalendar)
        }
        guard let name else { return .success(forUpdate ? .unchanged : .defaultCalendar) }
        switch BridgeCalendarSelection.select(named: name, titles: calendarNames) {
        case .named(let index):
            return .success(.named(index))
        case .defaultCalendar, .missing:
            return .failure(.calendarNotFound)
        }
    }
}

// MARK: - The handler

/// Runs one bridge request and answers it exactly once.
public actor BridgeHandler {
    private let writer: EventWriter
    private let recognizer: TextRecognizer
    private let answers: BridgeAnswerPosting?
    private let log: BridgeLogging
    /// Whether `vision.ocr` may run; see [`visionOCRIsAvailable`].
    private let ocrAvailable: Bool
    /// Injectable so a test can advance past the retention window.
    private let now: () -> Date
    /// Ids answered or in flight, with when: a replay answers once, until the
    /// daemon's own 10-minute retention has expired (then a replay is a 404).
    private var seen: [String: Date] = [:]

    private static let seenTTL: TimeInterval = 600

    public init(
        writer: EventWriter,
        recognizer: TextRecognizer,
        answers: BridgeAnswerPosting?,
        log: BridgeLogging = OSLogBridgeLogger(),
        ocrAvailable: Bool = visionOCRIsAvailable,
        now: @escaping () -> Date = { Date() }
    ) {
        self.writer = writer
        self.recognizer = recognizer
        self.answers = answers
        self.log = log
        self.ocrAvailable = ocrAvailable
        self.now = now
    }

    /// Run one request and post exactly one answer. A repeated id is ignored
    /// inside the retention window.
    public func handle(_ request: BridgeRequest) async {
        let now = self.now()
        pruneSeen(now)
        guard seen[request.id] == nil else { return }
        seen[request.id] = now
        let (answer, outcome) = await run(request)
        await post(request, answer, outcome: outcome)
    }

    private func pruneSeen(_ now: Date) {
        let cutoff = now.addingTimeInterval(-Self.seenTTL)
        seen = seen.filter { $0.value > cutoff }
    }

    private func run(_ request: BridgeRequest) async -> (BridgeAnswer, String) {
        switch request.op {
        case "eventkit.create_event":
            guard let args = try? JSONDecoder().decode(CreateEventArgs.self, from: request.args) else {
                return (.failure(.invalidArgs), BridgeFailure.invalidArgs.code)
            }
            do {
                let result = try await writer.createEvent(
                    calendar: args.calendar, title: args.title, start: args.start,
                    end: args.end, location: args.location, notes: args.notes, url: args.url)
                return (.result(result.json), "ok")
            } catch let failure as BridgeFailure {
                return (.failure(failure), failure.code)
            } catch {
                return (.failure(.failed), BridgeFailure.failed.code)
            }
        case "eventkit.update_event":
            guard let args = try? JSONDecoder().decode(UpdateEventArgs.self, from: request.args) else {
                return (.failure(.invalidArgs), BridgeFailure.invalidArgs.code)
            }
            // The expected facts travel as a pair: half of them proves nothing,
            // and a write is never checked halfway (CAL-DEFAULT-ID r1).
            if (args.expectedCalendarID == nil) != (args.expectedAttendees == nil) {
                return (.failure(.invalidArgs), BridgeFailure.invalidArgs.code)
            }
            do {
                let result = try await writer.updateEvent(
                    eventId: args.eventId, calendar: args.calendar, title: args.title,
                    start: args.start, end: args.end, location: args.location,
                    notes: args.notes, url: args.url, expected: args.expectations)
                return (.result(result.json), "ok")
            } catch let failure as BridgeFailure {
                return (.failure(failure), failure.code)
            } catch {
                return (.failure(.failed), BridgeFailure.failed.code)
            }
        case "vision.ocr":
            // Wave C flips the flag; until then there is no route to fetch the
            // bytes, so fail closed before touching the network or Vision.
            guard ocrAvailable else {
                return (.failure(.ocrUnavailable), BridgeFailure.ocrUnavailable.code)
            }
            guard let args = try? JSONDecoder().decode(OcrArgs.self, from: request.args),
                  BridgeSHA256.isValid(args.sha256) else {
                return (.failure(.invalidArgs), BridgeFailure.invalidArgs.code)
            }
            do {
                let result = try await recognizer.recognize(sha256: args.sha256)
                return (.result(result.json), "ok")
            } catch let failure as BridgeFailure {
                return (.failure(failure), failure.code)
            } catch {
                return (.failure(.failed), BridgeFailure.failed.code)
            }
        default:
            return (.failure(.unsupportedOp), BridgeFailure.unsupportedOp.code)
        }
    }

    private func post(_ request: BridgeRequest, _ answer: BridgeAnswer, outcome: String) async {
        guard let answers else {
            log.log(op: request.op, id: request.id, outcome: "no_route")
            return
        }
        do {
            var body = try answer.encoded()
            var finalOutcome = outcome
            if body.count > BridgeBodyCap.bytes {
                body = try BridgeAnswer.failure(.resultTooLarge).encoded()
                finalOutcome = BridgeFailure.resultTooLarge.code
            }
            let status = try await answers.postBridgeAnswer(id: request.id, body: body)
            switch status {
            case 200..<300:
                log.log(op: request.op, id: request.id, outcome: finalOutcome)
            case 404, 409:
                // Already answered or timed out: log and drop, never retry.
                log.log(op: request.op, id: request.id, outcome: "dropped")
            case 401:
                // The local bearer token was refused; never a value.
                log.log(op: request.op, id: request.id, outcome: "auth_failed")
            default:
                log.log(op: request.op, id: request.id, outcome: "rejected")
            }
        } catch {
            log.log(op: request.op, id: request.id, outcome: "unreachable")
        }
    }
}

/// The exact answer body for `POST /v1/bridge/{id}`.
public enum BridgeAnswer {
    case result([String: Any])
    case failure(BridgeFailure)

    public func encoded() throws -> Data {
        let object: [String: Any]
        switch self {
        case .result(let value):
            object = ["ok": true, "result": value]
        case .failure(let failure):
            object = ["ok": false, "error": failure.code, "message": failure.message]
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}

// MARK: - Real Vision recogniser

/// Real recogniser: fetch the registry bytes with the local token, then run one
/// accurate `VNRecognizeTextRequest` on a background queue. Images only: PDF
/// page splitting is Wave C, together with the document-bytes route.
public final class VisionDocumentRecognizer: TextRecognizer {
    private let fetch: DocumentBytesFetching

    public init(fetch: DocumentBytesFetching) {
        self.fetch = fetch
    }

    public func recognize(sha256: String) async throws -> VisionOCRResult {
        guard BridgeSHA256.isValid(sha256) else { throw BridgeFailure.invalidArgs }
        let data = try await fetch.documentBytes(sha256: sha256)
        return try await Self.recognizeOnVisionQueue(data)
    }

    /// The Vision request runs on a background queue, not on the caller's
    /// executor: OCR is CPU-heavy and must not block an actor or the main thread.
    private static func recognizeOnVisionQueue(_ data: Data) async throws -> VisionOCRResult {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<VisionOCRResult, Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                do { continuation.resume(returning: try recognizeSync(data)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private static func recognizeSync(_ data: Data) throws -> VisionOCRResult {
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = true
        request.recognitionLanguages = ["en-US", "fr-FR"]
        let handler = VNImageRequestHandler(data: data, options: [:])
        try handler.perform([request])
        let lines = (request.results ?? []).compactMap { observation -> VisionOCRLine? in
            guard let candidate = observation.topCandidates(1).first else { return nil }
            let box = observation.boundingBox
            return VisionOCRLine(
                text: candidate.string,
                confidence: Double(candidate.confidence),
                box: VisionOCRBox(
                    x: Double(box.origin.x), y: Double(box.origin.y),
                    width: Double(box.size.width), height: Double(box.size.height)))
        }
        return VisionOCRResult(lines: lines, pages: 1)
    }
}

// MARK: - Args and times

struct CreateEventArgs: Decodable, Equatable {
    let calendar: String?
    let title: String
    let start: String
    let end: String
    let location: String?
    let notes: String?
    let url: String?
}

struct UpdateEventArgs: Decodable, Equatable {
    let eventId: String
    let calendar: String?
    let title: String?
    let start: String?
    let end: String?
    let location: String?
    let notes: String?
    let url: String?
    /// The facts the write's approval rested on (CAL-DEFAULT-ID r1).
    let expectedCalendarID: String?
    let expectedAttendees: Int?

    enum CodingKeys: String, CodingKey {
        case eventId = "event_id"
        case calendar, title, start, end, location, notes, url
        case expectedCalendarID = "expected_calendar_id"
        case expectedAttendees = "expected_attendees"
    }

    /// The expectations the writer checks, when the daemon sent them.
    var expectations: BridgeExpectations? {
        guard let expectedCalendarID, let expectedAttendees else { return nil }
        return BridgeExpectations(calendarID: expectedCalendarID, attendees: expectedAttendees)
    }
}

private struct OcrArgs: Decodable {
    let sha256: String
}

/// RFC 3339 times the daemon validated (`chrono` also accepts fractional
/// seconds, so both forms are read). Normalising first tolerates a space
/// separator and lower-case `t`/`z` some producers emit.
enum RFC3339 {
    static func normalize(_ text: String) -> String {
        text.replacingOccurrences(of: " ", with: "T").uppercased()
    }

    static func date(_ text: String) -> Date? {
        let normalized = normalize(text)
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let date = plain.date(from: normalized) { return date }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: normalized)
    }
}
