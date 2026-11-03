import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class PrivacyRecordTests: XCTestCase {
    func testInspectorMapsReceiptToContractFieldsInOrderAndStartsAsSent() {
        let receipt = Receipt(
            runId: "run-1", agent: "scout", started: "2026-10-07 09:00:00",
            finished: "2026-10-07 09:00:12", hostsContacted: ["api.example.test"]
        )
        let inspector = RequestInspectorModel(receipt: receipt)

        XCTAssertEqual(inspector.visibleSections, [.sent, .destination, .agentAndSkill, .coverage])
        XCTAssertFalse(inspector.isRestored)
        XCTAssertEqual(inspector.value(for: .sent), "2026-10-07 09:00:00 · 12 s")
        XCTAssertEqual(inspector.value(for: .destination), "Host recorded for run: api.example.test")
        XCTAssertEqual(inspector.value(for: .agentAndSkill), "scout")
        XCTAssertEqual(inspector.value(for: .coverage), "Counts by kind only; original values are never kept in this record.")
        XCTAssertFalse(inspector.visibleSections.contains(.exactRequest))
        XCTAssertFalse(inspector.visibleSections.contains(.restored))
        XCTAssertFalse(inspector.visibleSections.contains(.whatCameBack))
        XCTAssertFalse(inspector.visibleSections.contains(.retentionClaim))
        XCTAssertEqual(inspector.value(for: .whatCameBack), "Not kept: unavailable, not missing")
    }

    func testInspectorShowsRecordedTriggerSkillHostsAndReplacementCounts() {
        let receipt = Receipt(
            runId: "run-2", agent: "scout", trigger: "agent_delegation", skills: ["research"],
            replacedValues: ["email": 2, "phone": 1],
            hostsContacted: ["api.example.test", "docs.example.test"]
        )
        let inspector = RequestInspectorModel(receipt: receipt)
        XCTAssertTrue(inspector.value(for: .destination).contains("api.example.test, docs.example.test"))
        XCTAssertEqual(inspector.value(for: .agentAndSkill), "scout · research")
        XCTAssertEqual(inspector.value(for: .trigger), "Agent delegation")
        XCTAssertEqual(inspector.value(for: .replaced), "email ×2, phone ×1")
        XCTAssertEqual(inspector.visibleSections, [.destination, .agentAndSkill, .trigger, .replaced, .coverage])
    }

    func testOldReceiptRowsKeepNewEvidenceUnavailable() throws {
        let data = #"{"run_id":"old","agent":"scout","status":"done"}"#.data(using: .utf8)!
        let receipt = try JSONDecoder().decode(Receipt.self, from: data)
        XCTAssertNil(receipt.trigger)
        XCTAssertTrue(receipt.skills.isEmpty)
        XCTAssertTrue(receipt.replacedValues.isEmpty)
    }

    func testInspectorKeepsMissingEvidenceAndFailureStatesExplicit() {
        let incomplete = RequestInspectorModel(receipt: Receipt(runId: "fallback", agent: "mail", receiptError: true))
        XCTAssertEqual(incomplete.value(for: .destination), "unavailable")
        XCTAssertEqual(incomplete.value(for: .trigger), "unavailable")
        XCTAssertEqual(incomplete.failureState, .recordUnavailable)

        let transformFailure = RequestInspectorModel(transformationFailure: "Filter failed")
        XCTAssertEqual(transformFailure.failureState, .transformationFailed(reason: "Filter failed"))
        XCTAssertFalse(transformFailure.canRestore)
        XCTAssertFalse(transformFailure.isRestored)
    }

    func testPrivacyListFiltersReceiptsByAgentAndDay() {
        let rows = [
            Receipt(runId: "a", agent: "scout", started: "2026-10-24 09:00:00"),
            Receipt(runId: "b", agent: "mail", started: "2026-10-24 10:00:00"),
            Receipt(runId: "c", agent: "scout", started: "2026-10-23 10:00:00")
        ]
        XCTAssertEqual(PrivacyRecordListModel.filtered(rows, agent: "scout", day: "2026-10-24").map(\.runId), ["a"])
    }
}
