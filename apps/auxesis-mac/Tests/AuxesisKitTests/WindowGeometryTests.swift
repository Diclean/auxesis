// Window geometry: the main window is never zero-sized and never parked fully
// off-screen. Pure rect math (AppKit bottom-left coordinates), so `swift test`
// covers it without a window.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class WindowGeometryTests: XCTestCase {
    /// A 1440x900 Mac screen, visible area with no menu bar carved out.
    private let screen = CGRect(x: 0, y: 0, width: 1440, height: 900)

    func testZeroSizedWindowGetsTheDefaultSizeCentred() {
        let frame = WindowGeometry.fit(current: .zero, screen: screen)
        XCTAssertEqual(frame.size, WindowGeometry.defaultSize)
        XCTAssertEqual(frame.midX, screen.midX, accuracy: 0.5)
        XCTAssertEqual(frame.midY, screen.midY, accuracy: 0.5)
    }

    func testTinyWindowNeverGoesBelowTheMinimum() {
        let frame = WindowGeometry.fit(
            current: CGRect(x: 10, y: 10, width: 320, height: 200),
            screen: screen
        )
        XCTAssertEqual(frame.size, WindowGeometry.defaultSize)
        XCTAssertGreaterThanOrEqual(frame.width, WindowGeometry.minimumSize.width)
        XCTAssertGreaterThanOrEqual(frame.height, WindowGeometry.minimumSize.height)
        XCTAssertEqual(frame.origin, CGPoint(x: 10, y: 10))
    }

    func testOffScreenWindowIsPulledBackOntoTheScreen() {
        let frame = WindowGeometry.fit(
            current: CGRect(x: 5000, y: 5000, width: 1000, height: 700),
            screen: screen
        )
        let visible = frame.intersection(screen)
        XCTAssertFalse(visible.isNull)
        XCTAssertGreaterThanOrEqual(visible.width, 200)
        XCTAssertGreaterThanOrEqual(visible.height, 80)
    }

    func testWindowBiggerThanTheScreenIsClampedToIt() {
        let small = CGRect(x: 0, y: 0, width: 1000, height: 700)
        let frame = WindowGeometry.fit(
            current: CGRect(x: -50, y: -50, width: 2000, height: 1600),
            screen: small
        )
        XCTAssertEqual(frame.width, 1000)
        XCTAssertEqual(frame.height, 700)
        XCTAssertTrue(small.contains(frame))
    }

    func testBigWindowAlreadyOnScreenIsKeptExactly() {
        let current = CGRect(x: 100, y: 100, width: 1200, height: 800)
        XCTAssertEqual(WindowGeometry.fit(current: current, screen: screen), current)
    }

    func testWindowCrossingTheScreenEdgeIsClampedInside() {
        let frame = WindowGeometry.fit(
            current: CGRect(x: -400, y: -300, width: 1000, height: 700),
            screen: screen
        )
        XCTAssertGreaterThanOrEqual(frame.minX, screen.minX)
        XCTAssertGreaterThanOrEqual(frame.minY, screen.minY)
        XCTAssertLessThanOrEqual(frame.maxX, screen.maxX)
        XCTAssertLessThanOrEqual(frame.maxY, screen.maxY)
    }
}
