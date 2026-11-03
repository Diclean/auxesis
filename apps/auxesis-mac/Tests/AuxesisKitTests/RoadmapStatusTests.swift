// The task-timeline status words: one explicit receipt -> roadmap
// correspondence, the eight French roadmap words, and the rule that a status
// outside the roadmap stays visible instead of being masked as a known one.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class RoadmapStatusTests: XCTestCase {
    // MARK: Explicit receipt -> displayed status

    func testEveryKnownReceiptStatusMapsToItsRoadmapWord() {
        XCTAssertEqual(RoadmapStatus(receipt: .done), .done)
        XCTAssertEqual(RoadmapStatus(receipt: .doneUnverified), .doneUnverified)
        XCTAssertEqual(RoadmapStatus(receipt: .pausedNeedsYou), .needsYou)
        XCTAssertEqual(RoadmapStatus(receipt: .stoppedBudget), .paused)
        XCTAssertEqual(RoadmapStatus(receipt: .failed), .failed)
    }

    func testReceiptMappingIsExplicitlyDifferentForDoneAndUnverified() {
        // The two "done" receipts must not collapse into one displayed word:
        // done_unverified has its own roadmap status.
        XCTAssertNotEqual(RoadmapStatus(receipt: .done), RoadmapStatus(receipt: .doneUnverified))
    }

    func testTheEightRoadmapWordsInFrench() {
        XCTAssertEqual(RoadmapStatus.waiting.label(.fr), "en attente")
        XCTAssertEqual(RoadmapStatus.preparing.label(.fr), "en préparation")
        XCTAssertEqual(RoadmapStatus.running.label(.fr), "en cours")
        XCTAssertEqual(RoadmapStatus.needsYou.label(.fr), "en attente de toi")
        XCTAssertEqual(RoadmapStatus.done.label(.fr), "terminé")
        XCTAssertEqual(RoadmapStatus.doneUnverified.label(.fr), "terminé, à vérifier")
        XCTAssertEqual(RoadmapStatus.failed.label(.fr), "échoué")
        XCTAssertEqual(RoadmapStatus.paused.label(.fr), "en pause")
    }

    func testEachRoadmapWordIsDistinct() {
        let words = [
            RoadmapStatus.waiting, .preparing, .running, .needsYou,
            .done, .doneUnverified, .failed, .paused,
        ].map { $0.label(.fr) }
        XCTAssertEqual(Set(words).count, 8, "each roadmap status needs its own word: \(words)")
    }

    // MARK: An unknown status stays visible (no mask)

    func testUnknownReceiptStatusIsKeptAndNamed() throws {
        let receipt = try JSONDecoder().decode(
            Receipt.self,
            from: Data(#"{"run_id":"r1","agent":"a","status":"needs_a_nap"}"#.utf8)
        )
        let status = RoadmapStatus(receipt: receipt.status)
        XCTAssertEqual(status, .unknown("needs_a_nap"))
        let word = status.label(.fr)
        XCTAssertTrue(word.contains("needs_a_nap"), "the raw token must stay visible: \(word)")
        XCTAssertTrue(word.contains("inconnu"), word)
        XCTAssertFalse(word.contains("terminé"), "an unknown status is never masked as done: \(word)")
    }

    func testEmptyUnknownTokenStillSaysUnknown() {
        XCTAssertEqual(RoadmapStatus.unknown("  ").label(.fr), "état inconnu")
        XCTAssertEqual(RoadmapStatus.unknown("").label(.en), "unknown state")
    }

    // MARK: English + problem hint

    func testEnglishWordsArePresentAndPlain() {
        for status in [RoadmapStatus.waiting, .preparing, .running, .needsYou, .done, .doneUnverified, .failed, .paused] {
            XCTAssertFalse(status.label(.en).isEmpty)
        }
        XCTAssertEqual(RoadmapStatus.needsYou.label(.en), "waiting for you")
        XCTAssertEqual(RoadmapStatus.paused.label(.en), "paused")
    }

    func testProblemStatusesNeedAttention() {
        XCTAssertTrue(RoadmapStatus.failed.isProblem)
        XCTAssertTrue(RoadmapStatus.needsYou.isProblem)
        XCTAssertTrue(RoadmapStatus.paused.isProblem)
        XCTAssertFalse(RoadmapStatus.done.isProblem)
        XCTAssertFalse(RoadmapStatus.doneUnverified.isProblem)
        XCTAssertFalse(RoadmapStatus.unknown("x").isProblem)
    }
}
