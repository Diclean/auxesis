// The restyle's view-models are pure decisions: rail search, row previews,
// day chips and quoted replies. Locked here so the layout can't drift into
// inventing data (a quote is only a real previous owner message; a day chip
// only for a real timestamp).
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class PresentationTests: XCTestCase {
    private func agent(_ name: String, status: String = "", state: AgentState = .idle) -> Agent {
        Agent(
            id: name, name: name, hue: AgentHues.index(for: name),
            glyph: String(name.prefix(1)).uppercased(),
            state: state, status: status, threadKey: name
        )
    }

    private func message(
        _ id: String,
        _ author: Author,
        _ text: String,
        ts: Int64 = 1_700_000_000_000
    ) -> ChatMessage {
        ChatMessage(
            id: id, threadKey: "scout", author: author, ts: ts,
            blocks: [.text(text)]
        )
    }

    // MARK: Rail search

    func testRailSearchIsCaseAndAccentInsensitive() {
        let agents = [agent("Elodie"), agent("scout"), agent("Max")]
        XCTAssertEqual(RailSearch.filter(agents, query: "elo").map(\.name), ["Elodie"])
        XCTAssertEqual(RailSearch.filter(agents, query: "ÉLODIE").map(\.name), ["Elodie"])
        XCTAssertEqual(RailSearch.filter(agents, query: "  ").count, 3)
        XCTAssertTrue(RailSearch.filter(agents, query: "zzz").isEmpty)
    }

    func testRowPreviewUsesRealStatusThenState() {
        let working = agent("scout", status: "reading mail", state: .working)
        XCTAssertEqual(AgentRow.preview(for: working, .en), "reading mail")
        XCTAssertEqual(AgentRow.preview(for: working, .fr), "reading mail")
        let idle = agent("scout", status: "  ", state: .idle)
        XCTAssertEqual(AgentRow.preview(for: idle, .fr), L10n.t(.stateIdle, .fr))
        XCTAssertEqual(AgentRow.preview(for: idle, .en), "idle")
    }

    // MARK: Day chips

    func testDayStampTodayYesterdayAndOlder() {
        let now = Date(timeIntervalSince1970: 1_700_000_000) // 2023-11-14 22:13 UTC
        let tz = TimeZone(identifier: "UTC")!
        XCTAssertNil(DayStamp.label(for: 0, now: now, .fr, timeZone: tz))
        XCTAssertNil(DayStamp.label(for: -5, now: now, .fr, timeZone: tz))
        XCTAssertEqual(
            DayStamp.label(for: 1_699_999_000_000, now: now, .fr, timeZone: tz),
            L10n.t(.dayToday, .fr)
        )
        XCTAssertEqual(
            DayStamp.label(for: 1_699_913_600_000, now: now, .en, timeZone: tz),
            L10n.t(.dayYesterday, .en)
        )
        let older = DayStamp.label(for: 1_699_827_200_000, now: now, .en, timeZone: tz)
        XCTAssertNotNil(older)
        XCTAssertNotEqual(older, L10n.t(.dayToday, .en))
        XCTAssertNotEqual(older, L10n.t(.dayYesterday, .en))
    }

    func testConversationRowsChipOncePerDay() {
        let tz = TimeZone(identifier: "UTC")!
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let messages = [
            message("1", .you, "first", ts: 1_699_827_200_000),   // day -2
            message("2", .agent("scout"), "second", ts: 1_699_913_600_000), // day -1
            message("3", .agent("scout"), "third", ts: 1_699_916_000_000),  // still day -1
            message("4", .you, "fourth", ts: 1_699_999_000_000),   // today
        ]
        let rows = Conversation.rows(messages, now: now, .en, timeZone: tz)
        XCTAssertEqual(rows.map(\.dayLabel), ["Nov 12", L10n.t(.dayYesterday, .en), nil, L10n.t(.dayToday, .en)])
    }

    func testUnknownTimestampsGetNoDayChip() {
        let rows = Conversation.rows(
            [message("1", .you, "hello", ts: 0), message("2", .agent("scout"), "hi", ts: 0)],
            .en
        )
        XCTAssertEqual(rows.map(\.dayLabel), [nil, nil])
    }

    // MARK: Clock honesty (breaker survivor M8)

    func testClockNeverFabricatesAnHourForUnknownTimestamps() {
        XCTAssertEqual(Clock.hhmm(0), "", "ts 0 is unknown, not 00:00")
        XCTAssertEqual(Clock.hhmm(-5), "")
        XCTAssertFalse(Clock.hhmm(0).contains(":"))
        let real = Clock.hhmm(1_700_000_000_000)
        XCTAssertNotNil(real.range(of: #"^\d{2}:\d{2}$"#, options: .regularExpression), "real timestamps still render")
    }

    // MARK: Quoted replies

    func testQuoteIsTheRealPreviousOwnerMessage() {
        let messages = [
            message("1", .you, "Please summarise the inbox"),
            message("2", .agent("scout"), "Here it is"),
        ]
        let rows = Conversation.rows(messages, .en)
        XCTAssertNil(rows[0].quoted)
        XCTAssertEqual(rows[1].quoted?.id, "1")
        XCTAssertEqual(rows[1].quoted?.text, "Please summarise the inbox")
    }

    func testNoQuoteWhenPreviousIsNotTheOwnerOrTextIsEmpty() {
        let chain = [
            message("1", .agent("scout"), "first"),
            message("2", .agent("scout"), "second"),
            message("3", .tool, "tool result"),
            message("4", .agent("scout"), "third"),
        ]
        let rows = Conversation.rows(chain, .en)
        XCTAssertNil(rows[1].quoted)
        XCTAssertNil(rows[2].quoted)
        XCTAssertNil(rows[3].quoted)

        let emptyOwner = [
            message("1", .you, ""),
            message("2", .agent("scout"), "answer"),
        ]
        XCTAssertNil(Conversation.rows(emptyOwner, .en)[1].quoted)
    }
}
