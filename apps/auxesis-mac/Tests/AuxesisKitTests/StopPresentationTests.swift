import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class StopPresentationTests: XCTestCase {
    func testBannerShowsPresentAndMissingEvidenceWithoutInventingValues() throws {
        var calendar = Calendar(identifier: .gregorian)
        guard let timeZone = TimeZone(secondsFromGMT: 0) else { return XCTFail("UTC time zone") }
        calendar.timeZone = timeZone
        guard let requested = calendar.date(from: DateComponents(year: 2026, month: 10, day: 24, hour: 9, minute: 14, second: 2)),
              let acknowledged = calendar.date(from: DateComponents(year: 2026, month: 10, day: 24, hour: 9, minute: 14, second: 3))
        else { return XCTFail("fixture timestamps") }

        XCTAssertEqual(
            StopBannerModel(requestedAt: requested, acknowledgedAt: acknowledged, unknownOutcomeCount: 2, timeZone: timeZone).text,
            "Stop requested 09:14:02 · acknowledged by auxd 09:14:03 · 2 outcomes unknown"
        )
        XCTAssertEqual(
            StopBannerModel(requestedAt: nil, acknowledgedAt: nil, unknownOutcomeCount: nil).text,
            "Stop requested time unavailable · acknowledgement time unavailable · unknown outcome count unavailable"
        )
    }

    func testReportMapsTheFourContractGroupsFromOnlyKnownCounts() {
        let report = StopReportModel(unknownOutcomeCount: 3, cancelledSends: 1)

        XCTAssertEqual(report.groups.map(\.title), [
            "Outcome unknown", "Stopped mid-work, partial kept", "Cancelled before leaving", "Held, not deleted"
        ])
        XCTAssertEqual(report.groups.map(\.detail), [
            "3 outcomes unknown", "Unavailable", "1 pending send cancelled", "Unavailable"
        ])
        XCTAssertFalse(report.groups[0].canCheckStatus)
        XCTAssertEqual(report.groups[0].checkStatusDisabledReason, "Not available yet")
        XCTAssertTrue(report.resumeSemantics.contains("does not send or replay"))
        XCTAssertEqual(report.leftSummary, "Unavailable")
        XCTAssertEqual(report.stayedSummary, "Unavailable")
    }

    func testStoppedStateHasAnActionDisabledReason() {
        XCTAssertEqual(StopActionState.disabledReason(stopped: true), "Stopped (read-only). Resume to use actions.")
        XCTAssertNil(StopActionState.disabledReason(stopped: false))
    }
}
