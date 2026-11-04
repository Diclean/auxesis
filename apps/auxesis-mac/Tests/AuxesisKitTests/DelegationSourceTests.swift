// A delegated ask carries its source, and the app
// matches on that field instead of on the ask's words. A row stored before
// the field existed keeps the old text match.
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class DelegationSourceTests: XCTestCase {
    private let ask = "List the quote requests in the inbox."

    private func row(_ id: String, _ text: String, _ at: Int64, source: String? = nil) -> ChatMessage {
        var message = ChatMessage(
            id: id,
            threadKey: "mail",
            author: .you,
            ts: at,
            blocks: [.text(text)]
        )
        message.source = source
        return message
    }

    private func delegation() -> Delegation {
        Delegation(id: "d1", agent: "mail", ask: ask, at: "2027-01-15 08:00:00", state: .done)
    }

    /// The owner's bubbles, by row id.
    private func owned(_ items: [ThreadItem]) -> [String] {
        items.flatMap { item -> [String] in
            guard case .group(let group) = item, group.voice == .owner else { return [] }
            return group.entries.compactMap { if case .message(let message) = $0 { return message.id } else { return nil } }
        }
    }

    /// The grey delegation lines, by delegation id.
    private func handoffs(_ items: [ThreadItem]) -> [String] {
        items.flatMap { item -> [String] in
            guard case .group(let group) = item, group.voice == .handoff else { return [] }
            return group.entries.compactMap { if case .handoff(let delegation) = $0 { return delegation.id } else { return nil } }
        }
    }

    private func timeline(_ messages: [ChatMessage]) -> [ThreadItem] {
        ThreadTimeline.build(agent: "mail", messages: messages, delegations: [delegation()], approvals: [])
    }

    func testAnAskStoredBeforeTheFieldKeepsItsTextMatchBesideANewOne() {
        // Two delegations: the first one's row was stored before the field
        // existed, the second one carries it. Each is claimed once.
        let first = Delegation(id: "d1", agent: "mail", ask: "First ask.", at: "2027-01-15 08:00:00", state: .done)
        let second = Delegation(id: "d2", agent: "mail", ask: "Second ask.", at: "2027-01-15 08:01:00", state: .done)
        let old = row("40", "First ask.", 1_800_000_000_000)
        let new = row("41", "Second ask.", 1_800_000_060_000, source: "delegation")
        let items = ThreadTimeline.build(agent: "mail", messages: [old, new], delegations: [first, second], approvals: [])
        XCTAssertEqual(owned(items), [], "neither ask is the owner's")
        XCTAssertEqual(handoffs(items), ["d1", "d2"])
    }

    func testADelegatedAskWithTheSourceFieldIsTheEventLineNotAnOwnerBubble() {
        let delegated = row("40", ask, 1_800_000_000_000, source: "delegation")
        let items = timeline([delegated])
        XCTAssertEqual(owned(items), [], "Aux's words are never the owner's")
        XCTAssertEqual(handoffs(items), ["d1"], "the grey delegation line shows them")
    }

    func testTheOwnersOwnWordsWithTheSameWordsKeepTheirBubble() {
        let delegated = row("40", ask, 1_800_000_000_000, source: "delegation")
        let mine = row("42", ask, 1_800_000_002_000)
        let items = timeline([delegated, mine])
        XCTAssertEqual(owned(items), ["42"], "the owner typed the same words and keeps them")
        XCTAssertEqual(handoffs(items), ["d1"])
    }

    func testARowStoredBeforeTheFieldKeepsTheOldTextMatch() {
        let stored = row("40", ask + "\n", 1_800_000_000_000)
        let mine = row("42", ask, 1_800_000_002_000)
        let items = timeline([stored, mine])
        XCTAssertEqual(owned(items), ["42"], "one row per ask, as before")
        XCTAssertEqual(handoffs(items), ["d1"])
    }

    func testAnUnknownSourceIsAnOrdinaryMessage() {
        let other = row("40", ask, 1_800_000_000_000, source: "owner")
        let items = timeline([other])
        XCTAssertEqual(owned(items), ["40"], "an unknown source is never hidden")
    }

    /// The live path: the `message.new` frame carries the
    /// source, and the app keeps it when it rebuilds the row. A delegated ask
    /// whose stored text is not the ask (an ask over 8 KiB is truncated) must
    /// still be the grey delegation line, not an owner bubble, until the
    /// thread reloads.
    func testTheLiveFrameKeepsItsSourceAndShowsTheDelegationLine() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = Store(transport: transport, language: .fr)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.selectedAgentName == "scout" })

        var live = ChatMessage(
            id: "40",
            threadKey: "7",
            author: .you,
            ts: 1_800_000_000_000,
            blocks: [.text("List the quote requests in the")]
        )
        live.source = "delegation"
        transport.emit(.messageNew(live))
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == "40" } }, "the live row is stored")

        let row = store.messages.first { $0.id == "40" }
        XCTAssertEqual(row?.source, "delegation", "the live row keeps its source")

        let items = ThreadTimeline.build(
            agent: "scout",
            messages: store.messages,
            delegations: [Delegation(
                id: "d1", agent: "scout", ask: "List the quote requests in the inbox.",
                at: "2027-01-15 08:00:00", state: .done
            )],
            approvals: []
        )
        XCTAssertFalse(owned(items).contains("40"), "Aux's ask is never the owner's bubble")
        XCTAssertEqual(handoffs(items), ["d1"], "the grey delegation line shows it")
        store.stop()
    }

    func testTheSourceFieldIsDecodedAndCarried() throws {
        let json = """
        {"id":40,"thread_id":7,"role":"user","content":"Ask","at":"2027-01-15 08:00:00","source":"delegation"}
        """
        let decoded = try JSONDecoder().decode(MessageJson.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.source, "delegation")
        let message = Mapper.message(from: decoded, threadKey: "mail", agentName: "mail")
        XCTAssertEqual(message.source, "delegation")
        XCTAssertEqual(message.author, .you, "the role never changes")
    }
}
