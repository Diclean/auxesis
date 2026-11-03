// Today (M2): the brief of the day. Events by time, the brief's degradation
// lines kept, the empty state when today has no brief, and the run button
// against the fixture daemon. No network.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class TodayTests: XCTestCase {
    private let day = "2026-10-13"

    func testTodayQueueGroupsFollowContractOrderAndMissingBriefHasEmptyState() {
        let groups = TodayQueueModel.groups(waiting: 2, dueToday: 1, sinceYouLeft: 4, runningNow: 3)
        XCTAssertEqual(groups.map(\.kind), [.waiting, .dueToday, .sinceYouLeft, .runningNow])
        XCTAssertEqual(groups.map(\.count), [2, 1, 4, 3])
        XCTAssertEqual(TodayPresentation.make(brief: nil, today: day), .empty(nextRun: "08:00"))
    }

    func testBriefChecksBlockAlwaysHasUnavailableSourceStatesWithoutInventedFreshness() {
        let brief = DailyBrief(day: day, events: nil, mail: nil)
        let block = TodayBriefChecks.block(for: brief)
        XCTAssertEqual(block.heading, .whatBriefChecked)
        XCTAssertEqual(block.checks.map(\.source), [.todayCalendar, .todayMail, .todayWeather])
        XCTAssertEqual(block.checks.map(\.state), [.unavailable, .unavailable, .notChecked])
        XCTAssertTrue(block.checks.allSatisfy { $0.note == nil })
    }

    func testVanishedWaitingSelectionFallsBackToBrief() {
        let resolved = TodayQueueModel.resolvedSelection(.waiting("gone"), waitingIDs: [], ledgerIDs: [], agentIDs: [])
        XCTAssertEqual(resolved, .brief)
    }

    func testEventsAreSortedAllDayFirstThenByTime() {
        let brief = DailyBrief(day: day, events: [
            BriefEvent(title: "Call", start: "15:00", end: "15:30"),
            BriefEvent(title: "No time"),
            BriefEvent(title: "Review", start: "10:30"),
            BriefEvent(title: "Due", allDay: true),
            BriefEvent(title: "Early", start: "8:45"),
        ], mail: [])
        guard case .brief(let shown) = TodayPresentation.make(brief: brief, today: day) else {
            return XCTFail("today's brief is shown")
        }
        XCTAssertEqual(shown.events?.map(\.title), ["Due", "Early", "Review", "Call", "No time"])
    }

    /// The 10-25 owner brief: two calendars, straight vs curly apostrophe,
    /// stored as 00:00–23:59 without the all-day flag.
    func testUnflaggedMidnightToMidnightCopiesWithCurlyApostropheShowOnceAllDay() {
        let brief = DailyBrief(day: day, events: [
            BriefEvent(title: "Heure d'hiver", start: "00:00", end: "23:59"),
            BriefEvent(title: "Heure d\u{2019}hiver", start: "00:00", end: "23:59"),
            BriefEvent(title: "Heure d'été", start: "09:00", end: "10:00"),
        ], mail: [])
        guard case .brief(let shown) = TodayPresentation.make(brief: brief, today: day) else {
            return XCTFail("today's brief is shown")
        }
        XCTAssertEqual(shown.events?.map(\.title), ["Heure d'hiver", "Heure d'été"])
        XCTAssertEqual(shown.events?.map { CalendarEventPresentation.timeText(for: $0, language: .en) }, ["All day", "09:00–10:00"])
    }

    func testTodayUsesSharedAllDayFormattingAndDeduplicatesCalendarCopies() {
        let brief = DailyBrief(day: day, events: [
            BriefEvent(title: "Fête", allDay: true),
            BriefEvent(title: "Fête", allDay: true),
            BriefEvent(title: "Review", start: "10:00", end: "10:30"),
            BriefEvent(title: "Review", start: "10:00", end: "10:30"),
        ], mail: [])
        guard case .brief(let shown) = TodayPresentation.make(brief: brief, today: day) else {
            return XCTFail("today's brief is shown")
        }
        XCTAssertEqual(shown.events?.map(\.title), ["Fête", "Review"])
        XCTAssertEqual(shown.events?.map { CalendarEventPresentation.timeText(for: $0, language: .en) }, ["All day", "10:00–10:30"])
    }

    func testDegradationLinesAreShownAndMissingSourcesStayMissing() {
        let brief = DailyBrief(day: day, events: nil, mail: [BriefMail(sender: "Jonas Weber", subject: "Slot")],
                               notes: ["Calendar: not available.", " ", "Weather: no city set yet."])
        guard case .brief(let shown) = TodayPresentation.make(brief: brief, today: day) else {
            return XCTFail("today's brief is shown")
        }
        XCTAssertEqual(shown.notes, ["Calendar: not available.", "Weather: no city set yet."])
        XCTAssertNil(shown.events, "a calendar that could not be read is not an empty day")
        XCTAssertEqual(shown.mail?.count, 1)
    }

    func testEmptyStateWhenNoBriefOrOnlyYesterdays() {
        XCTAssertEqual(TodayPresentation.make(brief: nil, today: day), .empty(nextRun: "08:00"))
        let yesterday = DailyBrief(day: "2026-10-12", events: [], mail: [])
        XCTAssertEqual(TodayPresentation.make(brief: yesterday, today: day), .empty(nextRun: "08:00"))
        let jobs = [PlannedJob(id: 1, agent: "aux", name: "Morning brief", schedule: "daily 07:30")]
        XCTAssertEqual(TodayPresentation.make(brief: nil, today: day, jobs: jobs), .empty(nextRun: "07:30"))
        let odd = [PlannedJob(id: 1, agent: "aux", name: "Morning brief", schedule: "after Camille's reply")]
        XCTAssertEqual(TodayPresentation.nextRunTime(odd), "08:00")
    }

    func testBriefDecodesWhenDefaultedKeysAreAbsent() throws {
        // No `notes`, no `all_day`, no `written_at`: a brief the daemon wrote
        // without those keys must still decode, not show "failed".
        let brief = try JSONDecoder().decode(DailyBrief.self, from: Data(
            #"{"day":"2026-10-13","events":[{"title":"Call","start":"15:00"},{"title":"No time"}],"mail":[]}"#.utf8))
        XCTAssertEqual(brief.day, day)
        XCTAssertNil(brief.writtenAt)
        XCTAssertEqual(brief.notes, [])
        XCTAssertEqual(brief.events, [BriefEvent(title: "Call", start: "15:00"), BriefEvent(title: "No time")])
        XCTAssertEqual(brief.mail, [])

        let due = try JSONDecoder().decode(BriefEvent.self, from: Data(#"{"title":"Due","all_day":true}"#.utf8))
        XCTAssertTrue(due.allDay)
        XCTAssertNil(due.start)
        let untimed = try JSONDecoder().decode(BriefEvent.self, from: Data(#"{"title":"Plain"}"#.utf8))
        XCTAssertFalse(untimed.allDay)
    }

    func testTheEmptySentenceIsHiddenOnceARunWroteOrFoundTodaysBrief() {
        // Written by this run: the re-read may still answer empty, but the
        // sentence "No brief yet today" must not sit under "written".
        XCTAssertFalse(ShellModel.showsEmptySentence(afterRun: .briefRunWritten))
        XCTAssertFalse(ShellModel.showsEmptySentence(afterRun: .briefRunAlready))
        XCTAssertTrue(ShellModel.showsEmptySentence(afterRun: nil))
        XCTAssertTrue(ShellModel.showsEmptySentence(afterRun: .briefRunFailed))
        XCTAssertTrue(ShellModel.showsEmptySentence(afterRun: .briefRunQuiet))
    }

    func testRunStatusesMapToPlainNotes() {
        XCTAssertEqual(ShellModel.briefNote("written"), .briefRunWritten)
        XCTAssertEqual(ShellModel.briefNote("already_today"), .briefRunAlready)
        XCTAssertEqual(ShellModel.briefNote("skipped_quiet_hours"), .briefRunQuiet)
        XCTAssertEqual(ShellModel.briefNote("source_unavailable"), .briefRunNoSource)
        XCTAssertEqual(ShellModel.briefNote("something_new"), .briefRunFailed)
    }

    func testFixtureShowsTheBriefAndRunFillsTheEmptyDay() {
        let team = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: team, language: .en), client: team)
        shell.loadToday()
        XCTAssertTrue(waitUntil { shell.today.value != nil })
        guard case .brief(let brief)? = shell.today.value else { return XCTFail("the fixture brief") }
        XCTAssertEqual(brief.events?.first?.title, "Invoice NW-2026-031 due")
        XCTAssertEqual(brief.notes, ["Weather: no city set yet."])

        let empty = FixtureDaemon(scenario: .empty)
        let fresh = ShellModel(store: Store(transport: empty, language: .en), client: empty)
        fresh.loadToday()
        XCTAssertTrue(waitUntil { fresh.today.value != nil })
        XCTAssertEqual(fresh.today.value, .empty(nextRun: "08:00"))
        fresh.runBriefNow()
        XCTAssertTrue(waitUntil { fresh.briefRunNote != nil })
        XCTAssertEqual(fresh.briefRunNote, .briefRunWritten)
        XCTAssertTrue(waitUntil { if case .brief? = fresh.today.value { return true } else { return false } })
    }

    func testTodayCopyHasFrenchPeers() {
        for key in [UIKey.today, .todayEmpty, .todayRun, .briefRunWritten, .briefRunFailed] {
            XCTAssertNotEqual(L10n.ui(key, .fr), L10n.ui(key, .en), "\(key) has no French")
        }
        XCTAssertEqual(L10n.uf(.todayEmpty, .en, "08:00"), "No brief yet today. The next one runs at 08:00.")
    }
}
