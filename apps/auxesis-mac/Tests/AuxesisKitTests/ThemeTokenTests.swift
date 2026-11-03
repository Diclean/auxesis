// Token sanity: the values in Theme.swift are the frozen design contract.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ThemeTokenTests: XCTestCase {
    func testTypeScaleIsTheContractScale() {
        XCTAssertEqual(
            [Theme.Text.caption, Theme.Text.meta, Theme.Text.ui, Theme.Text.body, Theme.Text.title, Theme.Text.heading],
            [11, 12, 13, 14, 17, 24]
        )
        XCTAssertEqual(
            [Theme.Weight.regular, Theme.Weight.medium, Theme.Weight.semibold, Theme.Weight.strong, Theme.Weight.bold],
            [400, 500, 600, 600, 600]
        )
        XCTAssertEqual([Theme.Text.lead, Theme.Text.secondary, Theme.Text.detailTitleTracking, Theme.Text.leadLineHeight], [16, 12.5, -0.3, 1.5])
    }

    func testLayoutFollowsThePrototype() {
        XCTAssertEqual(Theme.sidebarWidth, 288)
        XCTAssertEqual(Theme.inspectorWidth, 360)
        XCTAssertEqual(Theme.barHeight, 52)
        XCTAssertEqual(Theme.hairline, 1)
        // The conversation and its composer share one 640-pt column.
        XCTAssertEqual([Theme.columnWidth, Theme.composerWidth], [640, 640])
    }

    func testSpacingAndCornerTokensFollowContractV3() {
        XCTAssertEqual([Theme.controlRadius, Theme.popoverRadius, Theme.proposalRadius], [6, 8, 10])
        XCTAssertEqual([Theme.rowVerticalPadding, Theme.rowHorizontalPadding], [10, 18])
        XCTAssertEqual([Theme.detailTopPadding, Theme.detailSidePadding, Theme.sectionGap], [28, 36, 26])
        XCTAssertEqual([Theme.labelValueGap, Theme.hairline, Theme.shadowY, Theme.shadowBlur], [7, 1, 12, 32])
        XCTAssertEqual([Theme.shadowLightOpacity, Theme.shadowDarkOpacity], [0.22, 0.60])
    }

    func testTheTileBreathesOnlyWhileWorking() {
        XCTAssertTrue(Motion.tileBreathes(working: true, stopped: false, reduceMotion: false))
        XCTAssertFalse(Motion.tileBreathes(working: true, stopped: false, reduceMotion: true))
        XCTAssertFalse(Motion.tileBreathes(working: true, stopped: true, reduceMotion: false))
        XCTAssertFalse(Motion.tileBreathes(working: false, stopped: false, reduceMotion: false))
    }
}
