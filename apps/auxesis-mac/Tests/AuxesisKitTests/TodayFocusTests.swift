import Foundation
import Testing
@testable import AuxesisKit

/// TODAY-SHAPE-1: the focus line and "What matters first", by plain rules.
@objcMembers @MainActor final class TodayFocusTests: XCTestCase {
    private let utc: Calendar = { var c = Calendar(identifier: .gregorian); c.timeZone = TimeZone(identifier: "UTC")!; return c }()
    /// 2026-11-04 09:00 UTC.
    private var now: Date { utc.date(from: DateComponents(year: 2026, month: 11, day: 4, hour: 9))! }
    private let card = (id: "ap-1", headline: "Reply to Jonas Weber", agent: "mail", at: nil) as TodayFocusApproval
    private let failing = PlannedJob(id: 4, agent: "mail", name: "Inbox sweep", schedule: "daily 07:30",
                                     health: .failing, reason: "Inbox sweep failed at 07:32")
    private let late = PlannedJob(id: 3, agent: "documents", name: "File receipts", schedule: "daily 07:00", health: .late)
    private let fine = PlannedJob(id: 1, agent: "aux", name: "Morning brief", schedule: "daily 08:00", health: .ok)
    private let mail = [BriefMail(sender: "Camille Exemple", subject: "Newest"), BriefMail(sender: "Hosting Test", subject: "Oldest")]

    private func brief(_ events: [BriefEvent]? = [], mail: [BriefMail]? = [], truncated: Bool = false) -> DailyBrief {
        DailyBrief(day: "2026-11-04", writtenAt: "08:00", events: events, mail: mail, mailTruncated: truncated)
    }
    private func line(_ brief: DailyBrief, _ cards: [TodayFocusApproval] = [], jobs: [PlannedJob] = []) -> TodayFocusLine {
        TodayFocus.line(approvals: cards, jobs: jobs, brief: brief, now: now, calendar: utc)
    }
    private func top(_ brief: DailyBrief, _ cards: [TodayFocusApproval] = [], jobs: [PlannedJob] = []) -> [TodayTopItem] {
        TodayFocus.top(approvals: cards, jobs: jobs, brief: brief, now: now, language: .en, calendar: utc)
    }

    func testPrecedenceApprovalsThenJobsThenEventThenMailThenCalm() {
        let all = brief([BriefEvent(title: "Dentist", start: "10:30", end: "11:00")], mail: mail)
        XCTAssertEqual(line(all, [card, card], jobs: [failing]), .waiting(count: 2))
        XCTAssertEqual(line(all, jobs: [late, failing]), .jobFailed(name: "Inbox sweep"))
        XCTAssertEqual(line(all, jobs: [fine, late]), .jobLate(name: "File receipts"))
        XCTAssertEqual(line(all, jobs: [fine]), .eventSoon(title: "Dentist", start: "10:30"))
        XCTAssertEqual(line(brief(mail: mail), jobs: [fine]), .unread(count: 2, atLeast: false))
        XCTAssertEqual(line(brief(mail: mail, truncated: true)), .unread(count: 2, atLeast: true))
        XCTAssertEqual(line(brief(nil, mail: nil)), .calm)
        // A disabled or unknown job never needs you.
        let off = PlannedJob(id: 9, agent: "mail", name: "Off", schedule: "daily", enabled: false, health: .failing)
        let new = PlannedJob(id: 8, agent: "mail", name: "New", schedule: "daily", health: .unknown)
        XCTAssertEqual(line(brief(), jobs: [off, new, fine]), .calm)
        XCTAssertTrue(top(brief(), jobs: [off, new, fine]).isEmpty)
        XCTAssertEqual(line(brief()).text(.fr), "Rien ne vous attend pour l’instant.")
    }

    func testOnlyAnUpcomingTimedEventWithinTwoHoursIsSoon() {
        XCTAssertEqual(line(brief([BriefEvent(title: "Edge", start: "11:00")])), .eventSoon(title: "Edge", start: "11:00"))
        for event in [BriefEvent(title: "Later", start: "11:01"), BriefEvent(title: "Started", start: "08:59"),
                      BriefEvent(title: "Due", allDay: true), BriefEvent(title: "Odd", start: "soon")] {
            XCTAssertEqual(line(brief([event])), .calm, event.title)
        }
        let two = [BriefEvent(title: "B", start: "10:45"), BriefEvent(title: "A", start: "9:30")]
        XCTAssertEqual(line(brief(two)), .eventSoon(title: "A", start: "9:30"))
    }

    func testTopThreeFollowsThePrecedenceAndStopsAtThree() {
        let all = brief([BriefEvent(title: "Call", start: "15:00", end: "15:30")], mail: mail)
        let rows = top(all, [card], jobs: [late, failing])
        XCTAssertEqual(rows.map(\.action), [.openApproval("ap-1"), .openJob(4), .openJob(3)])
        XCTAssertEqual(rows.map(\.mark), [.waits, .failed, .late])
        XCTAssertEqual(rows.map(\.evidence), ["Mail", "Mail · Inbox sweep failed at 07:32", "Documents · daily 07:00"])
        let dated = (id: "ap-2", headline: "Send quote", agent: "mail", at: now.addingTimeInterval(-600)) as TodayFocusApproval
        XCTAssertTrue(top(brief(), [dated])[0].evidence.hasPrefix("Mail · since "))
    }

    func testTopShowsTheNextEventOfTheDayAndTheOldestUnread() {
        // Not within 2 h, so not the focus, but still the day's next event.
        let all = brief([BriefEvent(title: "Past", start: "08:00"), BriefEvent(title: "Call", start: "15:00", end: "15:30")], mail: mail)
        XCTAssertEqual(line(all), .unread(count: 2, atLeast: false))
        let rows = top(all)
        XCTAssertEqual(rows.map(\.action), [.openCalendar, .openMail])
        XCTAssertEqual(rows.map(\.title), ["Call", "Oldest"])
        XCTAssertTrue(rows[0].evidence.hasPrefix("Today · 15:00"), rows[0].evidence)
        XCTAssertEqual(rows[1].evidence, "Oldest unread · from Hosting Test")
        XCTAssertEqual(rows.map(\.mark), [nil, nil])
    }

    /// The fixture daemon has one scenario per focus state.
    func testFixtureScenariosExerciseEveryFocusState() async throws {
        let ten = Calendar.current.date(bySettingHour: 10, minute: 0, second: 0, of: Date())!
        var seen: [FixtureDaemon.Scenario: TodayFocusLine] = [:]
        for scenario in [FixtureDaemon.Scenario.team, .todayJob, .todayEvent, .todayMail, .todayCalm] {
            let daemon = FixtureDaemon(scenario: scenario, now: ten)
            let cards = try await daemon.pendingApprovals().map { (id: $0.id, headline: $0.headline, agent: $0.agent, at: nil) as TodayFocusApproval }
            let jobs = try await daemon.plannedJobs()
            let written = try await daemon.todayBrief()
            guard case .brief(let today) = TodayPresentation.make(brief: written, today: TodayPresentation.day(ten))
            else { return XCTFail("no brief for \(scenario)") }
            seen[scenario] = TodayFocus.line(approvals: cards, jobs: jobs, brief: today, now: ten)
        }
        guard case .waiting(let count)? = seen[.team] else { return XCTFail("team: no waiting card") }
        XCTAssertGreaterThan(count, 0)
        XCTAssertEqual(seen[.todayJob], .jobFailed(name: "Inbox sweep"))
        XCTAssertEqual(seen[.todayEvent], .eventSoon(title: "Call with Jonas Weber", start: "10:40"))
        XCTAssertEqual(seen[.todayMail], .unread(count: 7, atLeast: false))
        XCTAssertEqual(seen[.todayCalm], .calm)
    }
}
