import EventKit
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class AppleEventKitTests: XCTestCase {
    @MainActor
    func testFakeProviderKeepsTestsAwayFromRealCalendarsAndReminders() async throws {
        let fake = FakeEventKit()
        XCTAssertEqual(fake.access, .authorized)
        let result = try await fake.requestAccessAndRead()
        XCTAssertTrue(result.authorized)
        XCTAssertEqual(result.events.count, 1)
        XCTAssertEqual(result.reminders.first?.completed, false)
        XCTAssertTrue(fake.didRequest)
    }

    @MainActor
    func testUnavailableAccessProducesEmptySnapshotWithoutRealPermissionPrompt() async throws {
        let fake = FakeEventKit(granted: false)
        let result = try await fake.requestAccessAndRead()
        XCTAssertFalse(result.authorized)
        XCTAssertTrue(result.events.isEmpty)
        XCTAssertTrue(result.reminders.isEmpty)
    }

    func testSnapshotFiltersTheDateWindowCapsItemsAndRemovesControlsAndBidi() {
        let now = ISO8601DateFormatter().date(from: "2026-10-08T12:00:00Z")!
        let events = [
            AppleEventItem(title: "OK\u{202e}\u{0007}", start: "2026-10-08T13:00:00Z", end: "2026-10-08T14:00:00Z", calendar: "Main", location: "Hall\u{2066}A\u{2069}"),
            AppleEventItem(title: "Old", start: "2026-10-01T13:00:00Z", end: "2026-10-01T14:00:00Z", calendar: "Main", location: nil),
        ]
        let reminders = [AppleReminderItem(title: "Soon", due: "2026-10-09T00:00:00Z", list: "Home", completed: false)]
        let result = AppleEventKitSnapshot(authorized: true, events: events, reminders: reminders)
            .boundedAndCleaned(now: now, calendar: Calendar(identifier: .gregorian))
        XCTAssertEqual(result.events.count, 1)
        XCTAssertEqual(result.events[0].title, "OK")
        XCTAssertEqual(result.events[0].location, "HallA")
        XCTAssertEqual(result.reminders.count, 1)
    }

    /// The published event keeps its id and an explicit guest list.
    func testSnapshotKeepsTheEventIdAndItsGuestList() throws {
        let now = ISO8601DateFormatter().date(from: "2026-10-08T12:00:00Z")!
        let event = AppleEventItem(title: "Call", start: "2026-10-08T13:00:00Z", end: "2026-10-08T14:00:00Z",
            calendar: "Main", location: nil, id: "E1", attendees: [])
        let result = AppleEventKitSnapshot(authorized: true, events: [event], reminders: [])
            .boundedAndCleaned(now: now, calendar: Calendar(identifier: .gregorian))
        XCTAssertEqual(result.events[0].id, "E1")
        XCTAssertEqual(result.events[0].attendees, [])
        let json = String(data: try JSONEncoder().encode(result.events[0]), encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains(#""attendees":[]"#), json)
    }

    /// CAL-DEFAULT-ID: the publisher names the owner's default calendar and
    /// fills each event's id and guest list, from a fake store: no real
    /// EventKit, ever.
    @MainActor
    func testPublisherFillsTheDefaultCalendarIdAndTheEventFactsFromTheFakeStore() async throws {
        let publisher = SystemAppleEventKit(reader: FakeEventKitReader())
        let snapshot = try await publisher.requestAccessAndRead()
        XCTAssertEqual(snapshot.defaultCalendarID, "cal-default")
        let event = try XCTUnwrapOptional(snapshot.events.first)
        XCTAssertEqual(event.id, "E1")
        XCTAssertEqual(event.calendarID, "cal-default")
        XCTAssertEqual(event.attendees, [])
        let json = String(data: try JSONEncoder().encode(snapshot), encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains(#""default_calendar_id":"cal-default""#), json)
    }

    /// CAL-COMPLETE-DEDUP: the app keeps at most 100 events and says when it
    /// cut the list, so the daemon never reads a cut copy as the whole
    /// calendar. Exactly 100 is complete, 101 is truncated.
    func testSnapshotKeepsOneHundredEventsAndSaysWhenTheListWasCut() throws {
        let now = ISO8601DateFormatter().date(from: "2026-10-08T12:00:00Z")!
        let calendar = Calendar(identifier: .gregorian)
        let events = (0..<101).map { index in
            AppleEventItem(title: "Busy \(index)", start: "2026-10-08T13:00:00Z",
                end: "2026-10-08T14:00:00Z", calendar: "Main", location: nil)
        }
        let cut = AppleEventKitSnapshot(authorized: true, events: events, reminders: [])
            .boundedAndCleaned(now: now, calendar: calendar)
        XCTAssertTrue(cut.eventsTruncated)
        XCTAssertEqual(cut.events.count, 100)
        let json = String(data: try JSONEncoder().encode(cut), encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains(#""events_truncated":true"#), json)

        let full = AppleEventKitSnapshot(authorized: true, events: Array(events.prefix(100)), reminders: [])
            .boundedAndCleaned(now: now, calendar: calendar)
        XCTAssertFalse(full.eventsTruncated)
        XCTAssertEqual(full.events.count, 100)
    }
}

/// A fake EventKit: the publisher reads its events, their guest lists and the
/// owner's default calendar id from here, never from the owner's calendars.
@MainActor private final class FakeEventKitReader: AppleEventKitReading {
    var eventAccess: EKAuthorizationStatus { .fullAccess }
    var reminderAccess: EKAuthorizationStatus { .fullAccess }
    func requestEventAccess() async throws -> Bool { true }
    func requestReminderAccess() async throws -> Bool { true }
    var defaultCalendarID: String? { "cal-default" }

    func events(from start: Date, to end: Date) -> [AppleEventItem] {
        [AppleEventItem(title: "Call", start: Self.iso(start), end: Self.iso(end),
            calendar: "Home", location: nil, calendarID: "cal-default", allDay: false,
            id: "E1", attendees: [])]
    }
    func reminders(from start: Date, to end: Date) async -> [AppleReminderItem] { [] }

    private static func iso(_ date: Date) -> String { ISO8601DateFormatter().string(from: date) }
}

@MainActor private final class FakeEventKit: AppleEventKitProviding {
    private let granted: Bool
    private(set) var didRequest = false
    init(granted: Bool = true) { self.granted = granted }
    var access: AppleEventKitAccess { granted ? .authorized : .denied }
    func requestAccessAndRead() async throws -> AppleEventKitSnapshot {
        didRequest = true
        guard granted else { return AppleEventKitSnapshot(authorized: false, events: [], reminders: []) }
        return AppleEventKitSnapshot(authorized: true,
            events: [AppleEventItem(title: "Réunion", start: "2026-10-08T09:00:00Z", end: "2026-10-08T10:00:00Z", calendar: "Travail", location: nil)],
            reminders: [AppleReminderItem(title: "Appeler", due: "2026-10-09T09:00:00Z", list: "Personnel", completed: false)])
    }
    func readIfAuthorized() async throws -> AppleEventKitSnapshot {
        try await requestAccessAndRead()
    }
}
