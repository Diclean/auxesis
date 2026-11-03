// The sidebar footer: how many requests left the Mac today. The number comes
// from the run receipts the privacy record page shows, counted by the local
// day. It never claims more than the record holds: a run that stayed on this
// Mac is not counted, and a record that could not be read says so.
import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class PrivacyCountTests: XCTestCase {
    /// The one line under the sidebar: the number, in plain words.
    func testTheFooterCountsTheRequestsThatLeftTheMacToday() {
        XCTAssertEqual(PrivacyRecordCounter.label(.count(12), .en), "12 requests left the Mac today")
        XCTAssertEqual(PrivacyRecordCounter.label(.count(1), .en), "1 request left the Mac today")
        XCTAssertEqual(PrivacyRecordCounter.label(.count(0), .en), "No request left the Mac today")
    }

    /// No number yet is not a failure: the line waits for the record instead
    /// of saying "unavailable" forever.
    func testNoNumberYetIsNotTheUnavailableLine() {
        XCTAssertEqual(PrivacyRecordCounter.label(.loading, .en), "Requests that left the Mac today")
        XCTAssertEqual(PrivacyRecordCounter.label(.unavailable, .en), "Request count unavailable")
        XCTAssertNotEqual(PrivacyRecordCounter.label(.loading, .en), PrivacyRecordCounter.label(.unavailable, .en))
    }

    func testTheFrenchLineSaysTheSameThing() {
        XCTAssertEqual(PrivacyRecordCounter.label(.count(12), .fr), "12 requêtes ont quitté ce Mac aujourd’hui")
        XCTAssertEqual(PrivacyRecordCounter.label(.count(1), .fr), "1 requête a quitté ce Mac aujourd’hui")
        XCTAssertEqual(PrivacyRecordCounter.label(.count(0), .fr), "Aucune requête n’a quitté ce Mac aujourd’hui")
        XCTAssertEqual(PrivacyRecordCounter.label(.loading, .fr), "Requêtes ayant quitté ce Mac aujourd’hui")
        XCTAssertEqual(PrivacyRecordCounter.label(.unavailable, .fr), "Nombre de requêtes indisponible")
    }

    /// Only today's records that reached outside count: a run that stayed on
    /// this Mac is not a run that left, and a record without a day is never
    /// attributed to today.
    func testOnlyTodaysRecordsThatReachedOutsideAreCounted() {
        let receipts = [
            Receipt(runId: "a", agent: "aux", started: "2026-10-24 09:00:00", hostsContacted: ["api.example.test"]),
            Receipt(runId: "b", agent: "aux", started: "2026-10-24 10:00:00", hostsContacted: []),
            Receipt(runId: "c", agent: "aux", started: "2026-10-23 10:00:00", hostsContacted: ["api.example.test"]),
            Receipt(runId: "d", agent: "aux", started: nil, hostsContacted: ["api.example.test"])
        ]
        XCTAssertEqual(PrivacyRecordCounter.count(receipts, day: "2026-10-24"), 1)
        XCTAssertEqual(PrivacyRecordCounter.state(read: .loaded, receipts: receipts, day: "2026-10-24"), .count(1))
        XCTAssertEqual(PrivacyRecordCounter.state(read: .loading, receipts: receipts, day: "2026-10-24"), .loading)
        XCTAssertEqual(PrivacyRecordCounter.state(read: .unavailable, receipts: receipts, day: "2026-10-24"), .unavailable)
    }

    /// A local brain is on this Mac: a run that only reached `127.0.0.1`
    /// (the Ollama preset) never left, so it is not counted.
    func testARunThatStayedOnThisMacIsNotCounted() {
        let receipts = [
            Receipt(runId: "a", agent: "aux", started: "2026-10-24 09:00:00", hostsContacted: ["127.0.0.1"]),
            Receipt(runId: "b", agent: "aux", started: "2026-10-24 09:10:00", hostsContacted: ["http://localhost:11434/v1"]),
            Receipt(runId: "c", agent: "aux", started: "2026-10-24 09:20:00", hostsContacted: ["::1"]),
            Receipt(runId: "d", agent: "aux", started: "2026-10-24 09:30:00", hostsContacted: ["[::1]:11434"]),
            Receipt(runId: "e", agent: "aux", started: "2026-10-24 09:40:00", hostsContacted: ["127.0.0.1", "api.example.test"]),
            Receipt(runId: "f", agent: "aux", started: "2026-10-24 09:50:00", hostsContacted: [])
        ]
        XCTAssertEqual(PrivacyRecordCounter.count(receipts, day: "2026-10-24"), 1)
        XCTAssertFalse(PrivacyRecordCounter.reachedOutside(["127.0.0.1", "localhost", "::1", "[::1]:11434"]))
        XCTAssertTrue(PrivacyRecordCounter.reachedOutside(["127.0.0.1", "api.example.test"]))
    }

    /// An octet is digits only: `Int("+0")` is 0, so a signed octet would make
    /// "127.+0.0.1" look like this Mac. It is an outside host, so the run
    /// that reached it is counted.
    func testAHostWithASignedOctetIsNotLoopback() {
        let receipts = [
            Receipt(runId: "a", agent: "aux", started: "2026-10-24 09:00:00", hostsContacted: ["127.+0.0.1"])
        ]
        XCTAssertFalse(PrivacyRecordCounter.isLoopback("127.+0.0.1"), "a signed octet is not an octet")
        XCTAssertFalse(PrivacyRecordCounter.isLoopback("127.-1.0.1"), "a negative octet is not an octet")
        XCTAssertTrue(PrivacyRecordCounter.reachedOutside(["127.+0.0.1"]))
        XCTAssertEqual(PrivacyRecordCounter.count(receipts, day: "2026-10-24"), 1)
    }

    /// The store says when the record was read, and when it could not be.
    func testTheStoreTellsARecordItReadFromOneItCouldNotRead() {
        let transport = FakeTransport()
        transport.receiptsResult = .success([
            Receipt(runId: "run-a", agent: "aux", started: "2026-10-24 09:00:00", hostsContacted: ["api.example.test"])
        ])
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.privacyRecordRead == .loaded && store.receipts.count == 1 }, "the record was read")
        store.stop()

        let failing = FakeTransport()
        failing.receiptsResult = .failure(AuxdError.http(status: 404, body: "{}"))
        let other = Store(transport: failing)
        other.start()
        XCTAssertTrue(waitUntil { other.privacyRecordRead == .unavailable }, "the record could not be read")
        other.stop()
    }

    /// The per-agent read (thread selection) must not say the count is
    /// unavailable: only the snapshot read decides that.
    func testAFailedAgentReadKeepsTheKnownCount() {
        let transport = FakeTransport()
        transport.receiptsResult = .success([
            Receipt(runId: "run-a", agent: "scout", started: "2026-10-24 09:00:00", hostsContacted: ["api.example.test"])
        ])
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.privacyRecordRead == .loaded && store.receipts.count == 1 }, "the record was read")
        transport.receiptsResult = .failure(AuxdError.http(status: 404, body: "{}"))
        let failuresBefore = store.failedReceiptReads
        store.selectAgent("mail")
        XCTAssertTrue(waitUntil { transport.receiptsCalls.contains { $0.agent == "mail" } }, "the agent's receipts were read")
        // The failed read is handled on the main actor: wait for the store to
        // have handled it (the counter moves after the catch) instead of
        // draining the run loop for a fixed time. A sleep would read the
        // state *before* the failure landed, which is the same `.loaded` the
        // assertion below wants — the test would pass without proving
        // anything.
        XCTAssertTrue(waitUntil { store.failedReceiptReads > failuresBefore }, "the failed agent read was handled")
        XCTAssertEqual(store.privacyRecordRead, .loaded, "a failed agent read must not hide the count")
        store.stop()
    }

    /// A live `run.finished` frame moves the count: the footer counts the
    /// runs of today, not only the ones the snapshot already knew.
    func testALiveRunFrameMovesTheCount() {
        let day = TodayPresentation.day(Date())
        let transport = FakeTransport()
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.privacyRecordRead == .loaded }, "the record was read")
        XCTAssertEqual(PrivacyRecordCounter.count(store.receipts, day: day), 0)
        transport.emit(.runFinished(Receipt(runId: "run-live", agent: "scout", started: "\(day) 09:00:00", hostsContacted: ["api.example.test"])))
        XCTAssertTrue(waitUntil { store.receipts.count == 1 }, "the frame was received")
        XCTAssertEqual(PrivacyRecordCounter.count(store.receipts, day: day), 1)
        store.stop()
    }

    /// Midnight: the footer counts the day it is drawn on, so the number is
    /// the new day's without reopening the app.
    func testTheFooterCountsTheDayItIsDrawnOn() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let before = calendar.date(from: DateComponents(year: 2026, month: 10, day: 24, hour: 23, minute: 59))!
        let after = calendar.date(from: DateComponents(year: 2026, month: 10, day: 25, hour: 0, minute: 1))!
        let receipts = [Receipt(runId: "a", agent: "scout", started: "2026-10-24 23:59:30", hostsContacted: ["api.example.test"])]
        XCTAssertEqual(PrivacyRecordCounter.state(read: .loaded, receipts: receipts, now: before, calendar: calendar), .count(1))
        XCTAssertEqual(PrivacyRecordCounter.state(read: .loaded, receipts: receipts, now: after, calendar: calendar), .count(0))
    }
}
