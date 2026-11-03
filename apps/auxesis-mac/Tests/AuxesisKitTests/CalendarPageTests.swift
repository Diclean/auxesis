import XCTest
@testable import AuxesisKit

/// CAL-PAGE-1: the Calendar page, its sync line and the login-item toggle.
/// Fake EventKit and a fake login item only: no real calendar, no macOS change.
@objcMembers @MainActor final class CalendarPageTests: XCTestCase {
    private let iso = ISO8601DateFormatter()
    private var paris: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "Europe/Paris")!
        return calendar
    }

    func testTheSnapshotCarriesItsCaptureFactsInUTC() throws {
        let now = iso.date(from: "2026-10-16T21:59:00Z")!  // 23:59 in Paris
        let read = AppleEventKitSnapshot(authorized: true, events: [], reminders: [], capturedAt: iso.string(from: now))
            .boundedAndCleaned(now: now, calendar: paris)
        XCTAssertEqual(read.capturedAt, "2026-10-16T21:59:00Z")
        XCTAssertEqual(read.coversFrom, "2026-10-15T22:00:00Z", "the start of the Paris day, in UTC")
        XCTAssertEqual(read.coversTo, "2026-10-23T22:00:00Z", "8 days later")
        let json = String(decoding: try JSONEncoder().encode(read), as: UTF8.self)
        for key in ["\"captured_at\"", "\"covers_from\"", "\"covers_to\""] {
            XCTAssertTrue(json.contains(key), "\(key) in \(json)")
        }
        // Published after midnight: the second pass keeps what was read.
        let published = read.boundedAndCleaned(now: iso.date(from: "2026-10-16T22:01:00Z")!, calendar: paris)
        XCTAssertEqual(published.coversFrom, read.coversFrom)
        XCTAssertEqual(published.coversTo, read.coversTo)
        XCTAssertEqual(published.capturedAt, read.capturedAt)
    }

    func testTheSyncLineSaysFreshStaleOrNotShared() throws {
        let now = iso.date(from: "2026-10-20T10:00:00Z")!
        let zone = TimeZone(identifier: "Europe/Paris")!
        let fresh = try status(#"{"shared":true,"updated_at":"2026-10-20T09:58:00Z","covers_from":null,"covers_to":null,"fresh":true}"#)
        XCTAssertEqual(CalendarSyncLine(fresh), .fresh(iso.date(from: "2026-10-20T09:58:00Z")!))
        XCTAssertEqual(CalendarSyncLine(fresh).text(now: now, language: .en, timeZone: zone), "Updated 2 min ago")
        XCTAssertEqual(CalendarSyncLine(fresh).text(now: now, language: .fr, timeZone: zone), "Mis à jour il y a 2 min")

        let stale = try status(#"{"shared":true,"updated_at":"2026-10-16T16:33:00Z","covers_from":null,"covers_to":null,"fresh":false}"#)
        XCTAssertTrue(CalendarSyncLine(stale).isStale)
        XCTAssertEqual(CalendarSyncLine(stale).text(now: now, language: .en, timeZone: zone), "Not updated since Fri 16 Oct, 18:33")

        let legacy = try status(#"{"shared":true,"updated_at":null,"covers_from":null,"covers_to":null,"fresh":false}"#)
        XCTAssertEqual(CalendarSyncLine(legacy), .unknown)
        XCTAssertTrue(CalendarSyncLine(legacy).isStale, "an old copy with no capture time is never shown as fresh")

        let none = try status(#"{"shared":false,"updated_at":null,"covers_from":null,"covers_to":null,"fresh":false}"#)
        XCTAssertEqual(CalendarSyncLine(none), .notShared)
        XCTAssertEqual(CalendarSyncLine(nil), .unknown, "no answer from auxd is not fresh either")
    }

    func testRefreshNowRunsOneCycleAndGroupsTheEventsByDay() async {
        let kit = PageKit()
        var published: [AppleEventKitSnapshot] = []
        let model = CalendarPageModel(
            refresher: CalendarAutoRefresher(kit: kit, isReady: { true }, publish: { published.append($0) }, sleeper: { _ in }),
            status: { CalendarSyncStatus(shared: true, updatedAt: Date(), fresh: true) },
            login: FakeLoginItem())
        await model.refreshNow()
        XCTAssertEqual(published.count, 1, "one cycle publishes once")
        XCTAssertEqual(kit.reads, 1)
        XCTAssertEqual(model.line, .fresh(model.status!.updatedAt!))
        let days = model.days(calendar: .current)
        XCTAssertEqual(days.map { $0.events.map(\.title) }, [["Studio call", "Invoice review"], ["Site visit"]])
    }

    func testTheLoginItemIsOffByDefaultAndShowsTheMacOSState() {
        let login = FakeLoginItem()
        let model = CalendarPageModel(
            refresher: CalendarAutoRefresher(kit: PageKit(), isReady: { true }, publish: { _ in }),
            status: { throw URLError(.cannotConnectToHost) },
            login: login)
        XCTAssertEqual(model.loginItem, .off)
        XCTAssertEqual(login.calls, [], "nothing registers until the owner turns it on")
        login.next = .requiresApproval
        model.setLoginItem(true)
        XCTAssertEqual(login.calls, [true])
        XCTAssertEqual(model.loginItem, .requiresApproval, "macOS's answer, not the switch's")
        login.fail = true
        model.setLoginItem(false)
        XCTAssertTrue(model.loginItemFailed)
        XCTAssertEqual(model.loginItem, .requiresApproval)
    }

    func testAllDayEventsSayAllDayNotMidnight() throws {
        let item = { (start: String, end: String) in
            AppleEventItem(title: "Invoice due", start: start, end: end, calendar: "Work", location: nil)
        }
        // Midnight to midnight in Paris, including EventKit's minute-precision 23:59 end.
        for end in ["2026-10-21T22:00:00Z", "2026-10-21T21:59:59Z", "2026-10-21T21:59:00Z"] {
            let allDay = item("2026-10-20T22:00:00Z", end)
            XCTAssertTrue(allDay.isAllDay(calendar: paris), end)
            XCTAssertEqual(allDay.timeText(language: .en, calendar: paris), "All day")
            XCTAssertEqual(allDay.timeText(language: .fr, calendar: paris), "Toute la journée")
        }
        let timed = item("2026-10-21T07:30:00Z", "2026-10-21T08:00:00Z")
        XCTAssertFalse(timed.isAllDay(calendar: paris))
        XCTAssertEqual(timed.timeText(language: .en, calendar: paris), "09:30–10:00")
        XCTAssertFalse(item("2026-10-20T22:00:00Z", "2026-10-20T22:00:00Z").isAllDay(calendar: paris), "no length, not all day")
        XCTAssertFalse(item("2026-10-20T22:00:00Z", "2026-10-21T10:00:00Z").isAllDay(calendar: paris), "ends at noon")

        let flagged = try decodedEvent(
            title: "Invoice due", start: "2026-10-21T08:30:00Z", end: "2026-10-21T09:00:00Z", allDay: true
        )
        XCTAssertEqual(flagged.timeText(language: .en, calendar: paris), "All day")
        XCTAssertEqual(flagged.timeText(language: .fr, calendar: paris), "Toute la journée")

        let explicitlyTimed = try decodedEvent(
            title: "Long shift", start: "2026-10-20T22:00:00Z", end: "2026-10-21T21:59:00Z", allDay: false
        )
        XCTAssertFalse(explicitlyTimed.isAllDay(calendar: paris), "an API flag wins over the boundary fallback")
    }

    func testDuplicateCalendarRowsCollapseByTitleAndTimeAcrossCalendars() throws {
        let start = "2026-10-20T22:00:00Z"
        let end = "2026-10-21T09:00:00Z"
        let laterEnd = "2026-10-21T10:00:00Z"
        let events = [
            try decodedEvent(title: "Heure d'hiver", start: start, end: end, calendar: "Work", calendarID: "work"),
            try decodedEvent(title: "Heure d'hiver", start: start, end: end, calendar: "Work", calendarID: "work"),
            try decodedEvent(title: "Heure d'hiver", start: start, end: end, calendar: "Personal", calendarID: "personal"),
            try decodedEvent(title: "Imported holiday", start: start, end: end, calendar: "Imported"),
            try decodedEvent(title: "Imported holiday", start: start, end: end, calendar: "Archive"),
            try decodedEvent(title: "Heure d'hiver", start: start, end: laterEnd, calendar: "Work", calendarID: "work"),
        ]
        let snapshot = AppleEventKitSnapshot(
            authorized: true, events: events, reminders: [], coversFrom: start, coversTo: "2026-10-28T22:00:00Z")

        let rows = CalendarPageModel.days(in: snapshot, calendar: paris).flatMap(\.events)
        XCTAssertEqual(rows.count, 3)
        XCTAssertEqual(rows.filter { $0.title == "Heure d'hiver" }.count, 2,
                       "exact matches collapse across calendars while different times remain")
        XCTAssertEqual(rows.filter { $0.title == "Imported holiday" }.count, 1,
                       "without calendar IDs, title and times identify a duplicate across calendars")
    }

    func testAllDayHolidayDuplicatesCollapseAcrossCalendarsOnTheSameLocalDay() throws {
        let first = try decodedEvent(
            title: "Jour férié", start: "2026-10-20T22:00:00Z", end: "2026-10-21T22:00:00Z",
            calendar: "Public Holidays", calendarID: "public", allDay: true
        )
        let second = try decodedEvent(
            title: "Jour férié", start: "2026-10-21T00:00:00Z", end: "2026-10-22T00:00:00Z",
            calendar: "Fêtes", calendarID: "holidays", allDay: true
        )
        let snapshot = AppleEventKitSnapshot(authorized: true, events: [first, second], reminders: [])

        let rows = CalendarPageModel.days(in: snapshot, calendar: paris).flatMap(\.events)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.calendar, "Public Holidays", "the first calendar remains the source")
    }

    func testRefreshNowSaysWhyItFailed() async {
        var ready = true
        var fail = false
        let kit = PageKit()
        var shared = true
        let model = CalendarPageModel(
            refresher: CalendarAutoRefresher(kit: kit, isReady: { ready }, publish: { _ in if fail { throw URLError(.badServerResponse) } }),
            status: { CalendarSyncStatus(shared: shared, updatedAt: Date(), fresh: true) },
            login: FakeLoginItem())

        await model.refreshNow()
        XCTAssertNil(model.problem)
        XCTAssertNil(model.problemText(language: .en))
        XCTAssertFalse(model.needsCalendarAccess)

        ready = false
        await model.refreshNow()
        XCTAssertEqual(model.problemText(language: .en), "Couldn't refresh: Auxesis isn't running. Start it from the menu bar.")
        XCTAssertEqual(model.problemText(language: .fr), "Actualisation impossible : Auxesis n’est pas lancé. Lancez-le depuis la barre des menus.")
        XCTAssertFalse(model.snapshot?.events.isEmpty ?? true, "the local read still shows")

        ready = true
        fail = true
        await model.refreshNow()
        XCTAssertEqual(model.problemText(language: .en), "Couldn't refresh: Aux didn't get the update. Try again.")
        XCTAssertFalse(model.needsCalendarAccess)

        fail = false
        kit.granted = false
        await model.refreshNow()
        XCTAssertEqual(model.problem, .noAccess)
        XCTAssertEqual(model.problemText(language: .en), "Couldn't refresh: Calendar access is off. Turn it on in Settings.")
        XCTAssertTrue(model.needsCalendarAccess, "Open Settings replaces Refresh now")

        // Not shared already says so: Open Settings, and no red line twice.
        shared = false
        await model.refreshNow()
        XCTAssertEqual(model.line, .notShared)
        XCTAssertTrue(model.needsCalendarAccess)
        XCTAssertNil(model.problemText(language: .en))

        kit.granted = true
        shared = true
        await model.refreshNow()
        XCTAssertNil(model.problem, "a published cycle clears the red line")
        XCTAssertFalse(model.needsCalendarAccess)
    }

    func testRefreshNowJoinsTheCycleAlreadyRunning() async {
        let kit = PageKit()
        kit.gated = true
        var published = 0
        let refresher = CalendarAutoRefresher(kit: kit, isReady: { true }, publish: { _ in published += 1 })
        let loop = Task { await refresher.refreshOnce() }
        while kit.reads == 0 { await Task.yield() }
        let now = Task { await refresher.refreshOnce() }
        for _ in 0..<20 { await Task.yield() }
        kit.release()
        let outcomes = [await loop.value, await now.value]
        XCTAssertEqual(outcomes, [.published, .published])
        XCTAssertEqual(kit.reads, 1, "one read for both")
        XCTAssertEqual(published, 1, "one publish for both")
        kit.gated = false
        await refresher.refreshOnce()
        XCTAssertEqual(kit.reads, 2, "the next request starts a new cycle")
    }

    func testTheLoginItemIsReReadWhenTheAppComesBack() {
        let login = FakeLoginItem()
        let model = CalendarPageModel(
            refresher: CalendarAutoRefresher(kit: PageKit(), isReady: { true }, publish: { _ in }),
            status: { throw URLError(.cannotConnectToHost) },
            login: login)
        login.state = .requiresApproval
        model.reloadLoginItem()
        XCTAssertEqual(model.loginItem, .requiresApproval)
        login.state = .enabled  // approved in System Settings
        model.reloadLoginItem()
        XCTAssertEqual(model.loginItem, .enabled)
    }

    func testDayHeadingsStartWithACapital() {
        let day = iso.date(from: "2026-10-20T22:00:00Z")!  // Wed 21 Oct, Paris
        let later = iso.date(from: "2026-10-24T10:00:00Z")!
        XCTAssertEqual(CalendarDay.title(day, language: .fr, calendar: paris, now: later), "Mercredi 21 octobre")
        XCTAssertEqual(CalendarDay.title(day, language: .en, calendar: paris, now: later), "Wednesday 21 October")
        XCTAssertEqual(CalendarDay.title(day, language: .fr, calendar: paris, now: day), "Aujourd’hui · Mercredi 21 octobre")
    }

    func testThePageAndItsRefresherDoNotKeepEachOtherAlive() {
        weak var weakRefresher: CalendarAutoRefresher?
        weak var weakModel: CalendarPageModel?
        do {
            let refresher = CalendarAutoRefresher(kit: PageKit(), isReady: { true }, publish: { _ in })
            let model = CalendarPageModel(refresher: refresher, status: { throw URLError(.unknown) }, login: FakeLoginItem())
            weakRefresher = refresher
            weakModel = model
        }
        XCTAssertNil(weakModel)
        XCTAssertNil(weakRefresher)
    }

    private func status(_ json: String) throws -> CalendarSyncStatus {
        try JSONDecoder().decode(CalendarSyncStatus.self, from: Data(json.utf8))
    }

    private func decodedEvent(
        title: String, start: String, end: String, calendar: String = "Work",
        calendarID: String? = nil, allDay: Bool? = nil
    ) throws -> AppleEventItem {
        var value: [String: Any] = ["title": title, "start": start, "end": end,
                                    "calendar": calendar, "location": NSNull()]
        if let calendarID { value["calendar_id"] = calendarID }
        if let allDay { value["all_day"] = allDay }
        return try JSONDecoder().decode(AppleEventItem.self, from: JSONSerialization.data(withJSONObject: value))
    }
}

@MainActor private final class PageKit: AppleEventKitProviding {
    private(set) var reads = 0
    var granted = true
    /// Holds each read until `release()`, to overlap two refreshes.
    var gated = false
    private var waiting: CheckedContinuation<Void, Never>?
    var access: AppleEventKitAccess { granted ? .authorized : .denied }
    func requestAccessAndRead() async throws -> AppleEventKitSnapshot { try await readIfAuthorized() }
    func release() { waiting?.resume(); waiting = nil }
    func readIfAuthorized() async throws -> AppleEventKitSnapshot {
        reads += 1
        if gated { await withCheckedContinuation { waiting = $0 } }
        let day = Calendar.current.startOfDay(for: Date())
        let at = { (hours: Double) in ISO8601DateFormatter().string(from: day.addingTimeInterval(hours * 3600)) }
        return AppleEventKitSnapshot(authorized: true, events: [
            AppleEventItem(title: "Site visit", start: at(24 + 10), end: at(24 + 11), calendar: "Work", location: nil),
            AppleEventItem(title: "Invoice review", start: at(15), end: at(16), calendar: "Work", location: nil),
            AppleEventItem(title: "Studio call", start: at(9), end: at(10), calendar: "Work", location: nil),
        ], reminders: [], capturedAt: ISO8601DateFormatter().string(from: Date()))
    }
}

private final class FakeLoginItem: LoginItemControlling {
    var state: LoginItemState = .off
    var next: LoginItemState = .enabled
    var fail = false
    private(set) var calls: [Bool] = []
    func setEnabled(_ on: Bool) throws {
        calls.append(on)
        if fail { throw URLError(.unknown) }
        state = on ? next : .off
    }
}
