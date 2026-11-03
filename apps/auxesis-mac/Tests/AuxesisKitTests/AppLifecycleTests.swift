// Lifecycle rule: closing the main window keeps Auxesis running in the menu
// bar; only an explicit Quit ends it. Pure function, so `swift test` covers it
// without launching AppKit.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class AppLifecycleTests: XCTestCase {
    func testClosingTheLastWindowDoesNotTerminateTheApp() {
        XCTAssertFalse(AppLifecycle.shouldTerminateAfterLastWindowClosed())
    }
}
