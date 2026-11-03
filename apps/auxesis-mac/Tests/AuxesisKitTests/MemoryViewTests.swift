// MEM-UI-1: the memory page's wire shapes and its three actions. No network:
// the daemon is the fixture, and the one real client is driven through the
// recording URL protocol.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class MemoryViewTests: XCTestCase {
    /// The daemon's exact answer: four groups, three of them empty, and one
    /// pending suggestion.
    private let viewJSON = """
    {"agent":"main",
     "groups":[{"key":"about_you","items":[{"id":"1","text":"Short mails, first names","source":"learned from a mail","saved_at":"2026-10-20T08:30:00Z","editable":true}]},
               {"key":"people","items":[]},
               {"key":"rules","items":[]},
               {"key":"other","items":[]}],
     "suggestions":[{"id":"s-12","text":"Camille wants Léa copied on quotes","source":"learned from a mail","created_at":"2026-10-27T08:30:00Z"}]}
    """

    /// A daemon that answers with one fixed snapshot.
    func testThePageReadsTheChiefsMemory() {
        XCTAssertEqual(MemoryPageModel.agent, "aux")
    }

    private final class StubMemory: MemoryClient {
        let snapshot: MemorySnapshot
        init(snapshot: MemorySnapshot) { self.snapshot = snapshot }
        func memorySnapshot(agent: String) async throws -> MemorySnapshot { snapshot }
        func updateMemory(agent: String, item: String, text: String) async throws -> MemoryFact {
            snapshot.groups["about_you"]![0]
        }
        func forgetMemory(agent: String, item: String) async throws {}
        func acceptMemorySuggestion(agent: String, suggestion: String) async throws -> MemoryFact {
            snapshot.groups["about_you"]![0]
        }
        func rejectMemorySuggestion(agent: String, suggestion: String) async throws {}
    }

    /// Answers the first read, then fails every read after it.
    private final class FailingReread: MemoryClient {
        let snapshot: MemorySnapshot
        var reads = 0
        init(snapshot: MemorySnapshot) { self.snapshot = snapshot }
        func memorySnapshot(agent: String) async throws -> MemorySnapshot {
            reads += 1
            if reads > 1 { throw URLError(.cannotConnectToHost) }
            return snapshot
        }
        func updateMemory(agent: String, item: String, text: String) async throws -> MemoryFact {
            snapshot.groups["about_you"]![0]
        }
        func forgetMemory(agent: String, item: String) async throws {}
        func acceptMemorySuggestion(agent: String, suggestion: String) async throws -> MemoryFact {
            snapshot.groups["about_you"]![0]
        }
        func rejectMemorySuggestion(agent: String, suggestion: String) async throws {}
    }

    /// A save that lands but whose re-read fails says so at page level.
    func testAFailedReadAfterASaveIsNeverSilent() async throws {
        let first = await page()
        let snapshot = try XCTUnwrapOptional(first.snapshot)
        let model = MemoryPageModel(client: FailingReread(snapshot: snapshot))
        await model.load()
        let fact = try XCTUnwrapOptional(model.facts(in: .aboutYou).first)
        model.beginEdit(fact)
        model.draft = "Short mails"
        await model.saveEdit()
        XCTAssertNotNil(model.problem, "the failed re-read must show a reason")
        XCTAssertNil(model.problemItem, "it is a page-level problem, shown above the sections")
    }

    /// A row problem never hides a later page-level one.
    func testAPageProblemAfterARowProblemIsShownAtPageLevel() async throws {
        let first = await page()
        let snapshot = try XCTUnwrapOptional(first.snapshot)
        let model = MemoryPageModel(client: FailingReread(snapshot: snapshot))
        await model.load()
        let fact = try XCTUnwrapOptional(model.facts(in: .aboutYou).first)
        model.beginEdit(fact)
        model.draft = "   "
        await model.saveEdit()
        XCTAssertEqual(model.problemItem, fact.id, "an empty save is a row problem")
        model.askForget(fact)
        XCTAssertNil(model.problemItem, "asking to forget clears the row problem")
        await model.load()
        XCTAssertNotNil(model.problem)
        XCTAssertNil(model.problemItem, "the failed read is shown at page level")
    }

    private func page() async -> MemoryPageModel {
        let model = MemoryPageModel(client: FixtureDaemon(scenario: .team))
        await model.load()
        return model
    }

    func testTheViewDecodesWithEmptyGroupsAndSuggestions() throws {
        let snapshot = try JSONDecoder().decode(MemorySnapshot.self, from: Data(viewJSON.utf8))
        XCTAssertEqual(snapshot.agent, "main")
        XCTAssertEqual(snapshot.groups.count, 4)
        XCTAssertEqual(snapshot.groups["people"], [])
        XCTAssertEqual(snapshot.groups["rules"], [])
        XCTAssertEqual(snapshot.groups["other"], [])
        let fact = try XCTUnwrapOptional(snapshot.groups["about_you"]?.first)
        XCTAssertEqual(fact.id, "1")
        XCTAssertEqual(fact.source, "learned from a mail")
        XCTAssertEqual(fact.savedAt, "2026-10-20T08:30:00Z")
        XCTAssertTrue(fact.editable)
        XCTAssertEqual(snapshot.suggestions.count, 1)
        XCTAssertEqual(snapshot.suggestions.first?.id, "s-12")
    }

    /// The page shows the four sections in a fixed order, empty ones included
    /// (MEM-EMPTY-STATE): a section with no fact says so instead of vanishing.
    func testEverySectionStaysAndSaysWhenItIsEmpty() async throws {
        let snapshot = try JSONDecoder().decode(MemorySnapshot.self, from: Data(viewJSON.utf8))
        let model = MemoryPageModel(client: StubMemory(snapshot: snapshot))
        await model.load()
        XCTAssertEqual(model.visibleSections, [.aboutYou, .rules, .people, .other])
        XCTAssertEqual(model.facts(in: .aboutYou).count, 1)
        XCTAssertEqual(model.facts(in: .people).count, 0)
        XCTAssertEqual(model.facts(in: .other).count, 0)
        XCTAssertFalse(model.showsEmptyLine(in: .aboutYou), "a section with a fact shows no empty line")
        for section in MemorySection.displayOrder where section != .aboutYou {
            XCTAssertTrue(model.showsEmptyLine(in: section), "\(section.rawValue) has no fact: it says so")
        }
    }

    /// Every section shows its empty line while it holds no fact, and hides it
    /// as soon as one lands (MEM-EMPTY-STATE).
    func testEachSectionShowsItsEmptyLineUntilItHasOneFact() async throws {
        for section in MemorySection.displayOrder {
            let empty = MemoryPageModel(client: StubMemory(snapshot: MemorySnapshot(agent: "aux", groups: [:], suggestions: [])))
            await empty.load()
            XCTAssertTrue(empty.showsEmptyLine(in: section), "\(section.rawValue) with no fact shows its empty line")

            let filled = MemoryPageModel(client: StubMemory(snapshot: MemorySnapshot(
                agent: "aux", groups: [section.rawValue: [MemoryFact(id: "1", text: "A fact")]], suggestions: [])))
            await filled.load()
            XCTAssertFalse(filled.showsEmptyLine(in: section), "\(section.rawValue) with a fact hides its empty line")
        }
    }

    /// The empty line says the same thing in both languages (MEM-EMPTY-STATE).
    func testTheEmptyLineIsWrittenInEnglishAndFrench() {
        XCTAssertEqual(
            L10n.ui(.memorySectionEmpty, .en),
            "Nothing yet — tell Aux in chat, e.g. “I prefer meetings after 10”.")
        XCTAssertEqual(
            L10n.ui(.memorySectionEmpty, .fr),
            "Rien pour l’instant — dites-le à Aux dans le chat, p. ex. « Je préfère les rendez-vous après 10 h ».")
        XCTAssertNotEqual(L10n.ui(.memorySectionEmpty, .en), L10n.ui(.memorySectionEmpty, .fr))
    }

    /// French typography: the spaces inside the guillemets and in "10 h" are
    /// no-break (U+00A0), so the line never breaks inside a guillemet or
    /// between the number and its unit.
    func testTheFrenchEmptyLineKeepsItsNoBreakSpaces() {
        let fr = L10n.ui(.memorySectionEmpty, .fr)
        XCTAssertTrue(fr.contains("\u{00A0}"), "the French line keeps its no-break spaces")
        XCTAssertFalse(fr.contains("« "), "no plain space after the opening guillemet")
        XCTAssertFalse(fr.contains(" »"), "no plain space before the closing guillemet")
        XCTAssertFalse(fr.contains("10 h"), "no plain space between 10 and h")
    }

    func testEditSendsTheTextAndTheRowShowsIt() async throws {
        let model = await page()
        let fact = try XCTUnwrapOptional(model.facts(in: .aboutYou).first)
        model.beginEdit(fact)
        model.draft = "  Short mails, first names  "
        await model.saveEdit()
        XCTAssertEqual(model.facts(in: .aboutYou).first?.text, "Short mails, first names")
        XCTAssertNil(model.editing)
    }

    /// The first click only asks; the second one forgets.
    func testForgetAsksFirstThenRemovesTheRow() async throws {
        let model = await page()
        let fact = try XCTUnwrapOptional(model.facts(in: .aboutYou).first)
        model.askForget(fact)
        XCTAssertEqual(model.confirming, fact.id)
        XCTAssertEqual(model.facts(in: .aboutYou).count, 1, "the first click only asks")
        await model.forget(fact)
        XCTAssertTrue(model.facts(in: .aboutYou).isEmpty)
        XCTAssertNil(model.confirming)
    }

    /// "Remember" and "No" both take the row away.
    func testRememberAndNoRemoveTheSuggestion() async throws {
        let model = await page()
        let suggestion = try XCTUnwrapOptional(model.suggestions.first)
        await model.decide(suggestion, keep: true)
        XCTAssertTrue(model.suggestions.isEmpty, "the suggestion row is gone")
        XCTAssertTrue(model.facts(in: .other).contains { $0.text == suggestion.text })

        let other = await page()
        let second = try XCTUnwrapOptional(other.suggestions.first)
        await other.decide(second, keep: false)
        XCTAssertTrue(other.suggestions.isEmpty)
    }

    /// At most five suggestions are shown.
    func testAtMostFiveSuggestionsAreShown() async {
        let model = await page()
        XCTAssertLessThanOrEqual(model.suggestions.count, MemoryPageModel.suggestionLimit)
    }

    /// The edit leaves the Mac as a PATCH with the text alone.
    func testTheEditIsAPatchWithTheTextAlone() async throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-memory-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
            tokenFile: tokenFile, lockPID: nil, source: "test")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        let client = AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)

        var body = Data()
        RecordingURLProtocol.reset()
        RecordingURLProtocol.respond { request in
            body = RecordingURLProtocol.body(of: request)
            let answer = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (answer, Data(#"{"id":"1","text":"New","source":"you told Aux","editable":true}"#.utf8))
        }
        defer { RecordingURLProtocol.reset() }

        let fact = try await client.updateMemory(agent: "main", item: "1", text: "New")
        XCTAssertEqual(fact.text, "New")
        let record = try XCTUnwrapOptional(RecordingURLProtocol.recorded.first)
        XCTAssertEqual(record.method, "PATCH")
        XCTAssertEqual(record.url, "http://127.0.0.1:2893/v1/agents/main/memory/1")
        XCTAssertEqual(String(data: body, encoding: .utf8), #"{"text":"New"}"#)
    }
}

/// The body of a recorded request: URLSession hands it over as a stream.
extension RecordingURLProtocol {
    static func body(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}
