// Sidebar v5: the row's second line, the local search and the
// two-row privacy footer. Pure rules, so no window and no service.
import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class SidebarV5Tests: XCTestCase {
    private func row(
        _ member: TeamMember, line: String, tone: LineTone = .muted, count: Int = 0, working: Bool = false
    ) -> TeamRowModel {
        TeamRowModel(member: member, line: line, tone: tone, time: nil, timeIsLive: false, count: count, unread: false, working: working)
    }

    private func entry(_ member: TeamMember, line: String, count: Int = 0, working: Bool = false, what: String? = nil) -> SidebarEntry {
        let model = row(member, line: line, count: count, working: working)
        return SidebarEntry(
            row: model, badge: MessengerText.needsYou(count, .en),
            status: SidebarText.status(row: model, waitingWhat: what, language: .en),
            role: SidebarText.role(member, .en)
        )
    }

    // MARK: status line

    func testEachStateSaysItInWords() {
        let waiting = SidebarText.status(row: row(.mail, line: "x", count: 1), waitingWhat: "reply to Mira", language: .en)
        XCTAssertEqual(waiting, SidebarStatus(kind: .waiting, text: "Waiting on you: reply to Mira"))
        let working = SidebarText.status(row: row(.calendar, line: "Finding 3 slots · 2 of 3", working: true), waitingWhat: nil, language: .en)
        XCTAssertEqual(working, SidebarStatus(kind: .working, text: "Finding 3 slots · 2 of 3"))
        let idle = SidebarText.status(row: row(.clients, line: "Notes for Sample Studio"), waitingWhat: nil, language: .en)
        XCTAssertEqual(idle, SidebarStatus(kind: .idle, text: "Idle · last: Notes for Sample Studio"))
        let stopped = SidebarText.status(row: row(.documents, line: "Paused by Stop", tone: .halt), waitingWhat: nil, language: .en)
        XCTAssertEqual(stopped, SidebarStatus(kind: .stopped, text: "Paused by Stop"))
    }

    func testWhatNeedsYouIsNeverHiddenBehindATaskName() {
        let both = SidebarText.status(row: row(.mail, line: "Sorting · 1 of 4", count: 2, working: true), waitingWhat: "send the quote", language: .en)
        XCTAssertEqual(both.kind, .waiting)
        let noName = SidebarText.status(row: row(.mail, line: "x", count: 1), waitingWhat: "  ", language: .en)
        XCTAssertEqual(noName.text, "Waiting on you")
    }

    func testAnAgentWithNoMessageIsIdleNotAFakeLastLine() {
        let status = SidebarText.status(row: row(.mail, line: L10n.ui(.roleMail, .en)), waitingWhat: nil, language: .en)
        XCTAssertEqual(status.text, "Idle")
    }

    func testBadgeNamesTheCountWithWords() {
        XCTAssertNil(entry(.mail, line: "x").badge)
        XCTAssertEqual(entry(.mail, line: "x", count: 1).badge, "Needs you")
        XCTAssertEqual(entry(.mail, line: "x", count: 3).badge, "3 need you")
    }

    func testRolesAreShortAndEveryAgentHasOne() {
        XCTAssertEqual(SidebarText.role(.mail, .en), "inbox, drafts")
        for member in TeamMember.all { XCTAssertNotNil(SidebarText.role(member, .fr), member.id) }
    }

    // MARK: search

    private var entries: [SidebarEntry] {
        [
            entry(.aux, line: "3 things need you today"),
            entry(.mail, line: "Reply to Mira about Tuesday", count: 1),
            entry(.calendar, line: "Finding 3 slots · 2 of 3", working: true),
            entry(.clients, line: "Notes for Sample Studio"),
        ]
    }

    func testSearchMatchesNameAndLastLineIgnoringCaseAndAccents() {
        func names(_ query: String) -> [String] { SidebarSearch.filter(entries, query: query).map(\.row.member.name) }
        XCTAssertEqual(names("mail"), ["Mail"])
        XCTAssertEqual(names("TUESDAY"), ["Mail"])
        XCTAssertEqual(names("sample studio"), ["Clients"])
        XCTAssertEqual(names("studio sample"), ["Clients"], "every word must match, in any order")
        XCTAssertEqual(names("mirá"), ["Mail"])
        XCTAssertEqual(names("zzz"), [])
    }

    func testEmptyOrBlankSearchKeepsEveryRow() {
        XCTAssertEqual(SidebarSearch.filter(entries, query: "").count, 4)
        XCTAssertEqual(SidebarSearch.filter(entries, query: "   ").count, 4)
    }

    func testSearchDoesNotMatchTheStatusPrefix() {
        XCTAssertEqual(SidebarSearch.filter(entries, query: "idle").count, 0)
        XCTAssertEqual(SidebarSearch.filter(entries, query: "waiting on").count, 0)
    }

    // MARK: footer

    private func receipt(_ id: String, day: String, hosts: [String]) -> Receipt {
        Receipt(runId: id, agent: "aux", started: "\(day) 09:00:00", hostsContacted: hosts)
    }

    private func delegation(steps: [DelegationStep]) -> Delegation {
        Delegation(id: "d", agent: "mail", ask: "x", at: "2026-10-28 08:00:00", state: .done, steps: steps)
    }

    private var noon: Date {
        var parts = DateComponents(year: 2026, month: 10, day: 28, hour: 12)
        parts.calendar = Calendar.current
        return parts.date!
    }

    func testFooterCountsRequestsAndStayedStepsFromTodaysRecord() {
        let iso = ISO8601DateFormatter()
        let today = iso.string(from: noon)
        let yesterday = iso.string(from: noon.addingTimeInterval(-86_400))
        let steps = [
            DelegationStep(text: "a", at: today, state: .done, place: .stayed),
            DelegationStep(text: "b", at: today, state: .done, place: .stayed),
            DelegationStep(text: "c", at: today, state: .done, place: .left),
            DelegationStep(text: "d", at: today, state: .done, place: nil),
            DelegationStep(text: "e", at: yesterday, state: .done, place: .stayed),
            DelegationStep(text: "f", at: nil, state: .done, place: .stayed),
        ]
        let footer = SidebarText.footer(
            read: .loaded, receipts: [receipt("a", day: TodayPresentation.day(noon), hosts: ["api.example.test"])],
            delegations: [delegation(steps: steps)], now: noon, language: .en
        )
        XCTAssertEqual(footer.requests, "1 request left the Mac today")
        XCTAssertEqual(footer.stayed, "2 steps handled by a local brain today", "unknown place, unknown time and other days are not counted as handled")
    }

    func testFooterSaysNothingRatherThanClaimingWithoutData() {
        let footer = SidebarText.footer(read: .loading, receipts: [], delegations: [], now: noon, language: .en)
        XCTAssertNil(footer.requests)
        XCTAssertNil(footer.stayed)
        let failed = SidebarText.footer(read: .unavailable, receipts: [], delegations: [], now: noon, language: .en)
        XCTAssertEqual(failed.requests, "Request count unavailable")
        XCTAssertNil(failed.stayed)
        let none = SidebarText.footer(read: .loaded, receipts: [], delegations: [], now: noon, language: .en)
        XCTAssertEqual(none.requests, "No request left the Mac today")
        XCTAssertNil(none.stayed)
    }

    /// Wording rules: no absolute or legal claims anywhere in the sidebar copy.
    func testSidebarCopyUsesNoBannedWords() {
        let banned = ["100", "never leaves", "never leave", "gdpr", "rgpd", "anonym", "leak-free", "sans fuite", "stayed", "resté"]
        var lines: [String] = []
        for language in Language.allCases {
            for key in [UIKey.sidebarSearch, .sidebarSearchClear, .sidebarNoMatch, .sidebarTeam, .sidebarWaitingOn, .sidebarIdle,
                        .sidebarIdleLast, .sidebarStayedOne, .sidebarRoleAux, .sidebarRoleMail, .sidebarRoleCalendar,
                        .sidebarRoleClients, .sidebarRoleDocuments] {
                lines.append(L10n.ui(key, language))
            }
            lines.append(L10n.uf(.sidebarStayedMany, language, 12))
            for state in [PrivacyRecordCount.loading, .unavailable, .count(0), .count(1), .count(7)] {
                lines.append(PrivacyRecordCounter.label(state, language))
            }
        }
        for line in lines {
            for word in banned { XCTAssertFalse(line.lowercased().contains(word), "\(line) contains \(word)") }
        }
    }

    // MARK: daemon `where` field and ⌘F state

    /// The per-step `where` the daemon sends: "local" stayed, "out" left, anything
    /// else or nothing is not counted as stayed.
    func testOnlyAStepWhoseWhereIsLocalCountsAsStayed() throws {
        let at = ISO8601DateFormatter().string(from: noon)
        let steps = ["local", "out", "elsewhere", ""].map {
            #"{"text":"s","at":"\#(at)","state":"done","where":"\#($0)"}"#
        } + [#"{"text":"s","at":"\#(at)","state":"done"}"#]
        let json = #"{"id":"d","agent":"mail","ask":"x","at":"\#(at)","state":"done","steps":[\#(steps.joined(separator: ","))]}"#
        let delegation = try JSONDecoder().decode(Delegation.self, from: Data(json.utf8))
        XCTAssertEqual(delegation.steps.map(\.place), [.stayed, .left, nil, nil, nil])
        let footer = SidebarText.footer(read: .loaded, receipts: [], delegations: [delegation], now: noon, language: .en)
        XCTAssertEqual(footer.stayed, "1 step handled by a local brain today")
    }

    func testFindOpensACollapsedSidebarThenFocusesAndEscReturns() {
        let shell = ShellModel(store: Store(transport: FixtureDaemon(scenario: .team), language: .en), client: nil)
        shell.sidebarVisible = false
        shell.requestSearchFocus()
        XCTAssertTrue(shell.sidebarVisible)
        XCTAssertTrue(shell.sidebarOpenedBySearch)
        XCTAssertTrue(shell.consumeSearchFocus(), "a search that mounts after the request still takes focus")
        XCTAssertFalse(shell.consumeSearchFocus(), "focus is taken once; a plain reopen never grabs it")
        shell.endSearch()
        XCTAssertFalse(shell.sidebarVisible)
        XCTAssertFalse(shell.sidebarOpenedBySearch)
    }

    func testEscLeavesTheSidebarAloneWhenFindDidNotOpenIt() {
        let shell = ShellModel(store: Store(transport: FixtureDaemon(scenario: .team), language: .en), client: nil)
        XCTAssertTrue(shell.sidebarVisible)
        shell.requestSearchFocus()
        XCTAssertFalse(shell.sidebarOpenedBySearch)
        shell.endSearch()
        XCTAssertTrue(shell.sidebarVisible)
        // Closing by hand forgets the ⌘F opening.
        shell.sidebarVisible = false
        shell.requestSearchFocus()
        shell.sidebarVisible = false
        XCTAssertFalse(shell.sidebarOpenedBySearch)
    }
}
