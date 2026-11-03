import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class ConversationsTests: XCTestCase {
    private func summary(_ id: Int64, _ at: String, _ title: String = "a chat") -> ConversationSummary {
        ConversationSummary(id: id, title: title, updatedAt: at)
    }

    func testOrderingCapAndEmptyState() {
        let items = [
            summary(1, "2026-10-01 09:00:00"), summary(3, "2026-10-03 09:00:00"),
            summary(2, "2026-10-02 09:00:00"), summary(4, "not a timestamp"),
            summary(5, "2026-10-03 09:00:00"),
        ]
        XCTAssertEqual(ConversationList.ordered(items).map(\.id), [5, 3, 2, 1, 4],
                       "newest first, id descending on a tie, an unreadable time last")
        let many = (0..<55).map { summary(Int64($0 + 1), String(format: "2026-10-01 00:00:%02d", $0)) }
        XCTAssertEqual(ConversationList.ordered(many).map(\.id), (6...55).reversed().map { $0 })
        XCTAssertTrue(ConversationList.rows(.loaded([])).isEmpty)
        XCTAssertEqual(ConversationList.title(summary(1, "", "  "), language: .en), "Untitled conversation")
    }

    func testSelectingAListedConversationOpensThatSession() {
        let transport = FakeTransport()
        transport.conversationsResult = .success([summary(7, "2026-10-02 09:00:00", "Plan the Q4 workshop")])
        transport.messagesByThread = [
            "aux": MessagesPage(thread: SessionJson(id: 9, agent: "aux"), messages: []),
            "7": MessagesPage(
                thread: SessionJson(id: 7, agent: "aux"),
                messages: [MessageJson(id: 70, threadId: 7, role: "user", content: "Plan the Q4 workshop",
                                       at: "2026-10-02 09:00:00")]),
        ]
        let shell = ShellModel(store: Store(transport: transport, language: .en), client: nil)
        shell.start()
        XCTAssertTrue(waitUntil { shell.store.phase == .live && ConversationList.rows(shell.store.conversations).count == 1 })

        shell.openConversation(session: 7)
        XCTAssertTrue(shell.conversationPresented)
        XCTAssertEqual(shell.conversationAgent, "aux")
        XCTAssertTrue(waitUntil { shell.store.selectedConversationId == 7 && shell.store.messages.count == 1 })
        XCTAssertTrue(transport.calls.contains("messages:7"), "the listed session is read, not the current one")
    }
}
