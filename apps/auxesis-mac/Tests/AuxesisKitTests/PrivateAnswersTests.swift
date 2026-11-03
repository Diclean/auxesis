// Private answers (PRIV-ANSWERS-UI): the JSON shape, newest first, hidden when
// empty, dismiss removes on 204 and on 404 and keeps a failure visible, and
// nothing is persisted. No network: the model is fed by a fake source.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class PrivateAnswersTests: XCTestCase {
    private let wire = #"[{"id":"8","received_at":"2026-10-15T10:02:00.000001+00:00","answer":"Second"},{"id":"7","received_at":"2026-10-15T09:41:07.123456+00:00","answer":"First\nline two"}]"#

    func testDecodesTheDaemonShape() throws {
        let answers = try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8))
        XCTAssertEqual(answers.map(\.id), ["8", "7"])
        XCTAssertEqual(answers[1].answer, "First\nline two")
        XCTAssertEqual(answers[1].clock(in: TimeZone(identifier: "UTC")!), "09:41")
        XCTAssertEqual(try JSONDecoder().decode([PrivateAnswer].self, from: Data("[]".utf8)), [])
    }

    func testAMalformedTimeIsRejectedNotShownAsNow() {
        let bad = Data(#"[{"id":"1","received_at":"yesterday","answer":"x"}]"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode([PrivateAnswer].self, from: bad))
    }

    func testPollsEveryTenSeconds() {
        XCTAssertEqual(PrivateAnswersModel.interval, 10_000_000_000)
    }

    func testShowsNewestFirst() async throws {
        let fake = FakeAnswers(Array(try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8)).reversed()))
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        XCTAssertEqual(model.answers.map(\.id), ["8", "7"])
        XCTAssertFalse(model.isEmpty)
    }

    func testHidesWhenEmpty() async {
        let fake = FakeAnswers([])
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        XCTAssertTrue(model.isEmpty)
    }

    func testDismissRemovesTheAnswerOn204() async throws {
        let fake = FakeAnswers(try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8)))
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        await model.dismiss(model.answers[0])
        XCTAssertEqual(fake.removed, ["8"])
        XCTAssertEqual(model.answers.map(\.id), ["7"])
        XCTAssertNil(model.dismissFailedID)
    }

    func testDismissRemovesTheAnswerOn404() async throws {
        let fake = FakeAnswers(try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8)))
        fake.removeError = AuxdError.http(status: 404, body: "")
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        await model.dismiss(model.answers[0])
        XCTAssertEqual(model.answers.map(\.id), ["7"])
        XCTAssertNil(model.dismissFailedID)
    }

    func testAFailedDismissKeepsTheAnswerAndSaysSo() async throws {
        let fake = FakeAnswers(try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8)))
        fake.removeError = AuxdError.http(status: 500, body: "")
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        await model.dismiss(model.answers[0])
        XCTAssertEqual(model.answers.count, 2)
        XCTAssertEqual(model.dismissFailedID, "8")
    }

    func testADismissedAnswerStaysGoneAcrossPolls() async throws {
        let fake = FakeAnswers(try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8)))
        fake.keepsRemoved = true
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        await model.dismiss(model.answers[0])
        await model.refresh()
        XCTAssertEqual(model.answers.map(\.id), ["7"], "a poll that races the dismiss must not bring it back")
    }

    func testNothingIsPersisted() async throws {
        let before = Set(UserDefaults.standard.dictionaryRepresentation().keys)
        let fake = FakeAnswers(try JSONDecoder().decode([PrivateAnswer].self, from: Data(wire.utf8)))
        let model = PrivateAnswersModel(fetch: fake.fetch, remove: fake.remove)
        await model.refresh()
        await model.dismiss(model.answers[0])
        XCTAssertEqual(Set(UserDefaults.standard.dictionaryRepresentation().keys), before)
        XCTAssertEqual(fake.fetches, 1, "the model reads only through its source, nothing else")
        XCTAssertEqual(fake.removed, ["8"])
    }
}

/// A daemon stand-in: holds the answers, records the calls, fails on demand.
@MainActor
private final class FakeAnswers {
    var answers: [PrivateAnswer]
    var removeError: Error?
    var keepsRemoved = false
    var fetches = 0
    var removed: [String] = []

    init(_ answers: [PrivateAnswer]) { self.answers = answers }

    func fetch() async throws -> [PrivateAnswer] {
        fetches += 1
        return answers
    }

    func remove(_ id: String) async throws {
        if let removeError { throw removeError }
        removed.append(id)
        if !keepsRemoved { answers.removeAll { $0.id == id } }
    }
}
