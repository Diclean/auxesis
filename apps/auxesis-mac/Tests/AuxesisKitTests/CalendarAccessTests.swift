import EventKit
import XCTest
@testable import AuxesisKit

/// Calendar access alone decides whether the brief's calendar is read; a
/// missing Reminders grant must never hide the owner's meetings.
@objcMembers @MainActor final class CalendarAccessTests: XCTestCase {
    func testCalendarAccessAloneAuthorizesWhateverRemindersSay() {
        XCTAssertEqual(SystemAppleEventKit.access(events: .fullAccess), .authorized)
        XCTAssertEqual(SystemAppleEventKit.access(events: .denied), .denied)
        XCTAssertEqual(SystemAppleEventKit.access(events: .restricted), .restricted)
        XCTAssertEqual(SystemAppleEventKit.access(events: .notDetermined), .notDetermined)
        XCTAssertEqual(SystemAppleEventKit.access(events: .writeOnly), .notDetermined)
    }
}
