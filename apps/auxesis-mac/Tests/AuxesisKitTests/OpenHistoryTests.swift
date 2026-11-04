// An agent conversation opens on its existing history, never on
// the empty welcome, and a sidebar row says the real last line of its thread.
//
// Root cause of the empty Aux (owner's app): "New chat" (POST /v1/threads/aux/new)
// makes an empty session the agent's current thread; the old session, with its
// messages, stays stored but was never read again. A live check that starts a
// new chat on the owner's daemon leaves the app on the welcome screen.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class OpenHistoryTests: XCTestCase {
    private func page(id: Int64, agent: String, count: Int) -> MessagesPage {
        let messages = (0..<count).map { index in
            MessageJson(
                id: id * 100 + Int64(index), threadId: id, role: index % 2 == 0 ? "user" : "assistant",
                content: "Line \(index)", preview: "Line \(index)",
                at: "2026-10-27 09:\(String(format: "%02d", index)):00"
            )
        }
        return MessagesPage(
            thread: SessionJson(id: id, agent: agent, createdAt: "2026-10-27 08:00:0\(id % 10)"),
            messages: messages
        )
    }

    private func open(_ transport: FakeTransport) -> ShellModel {
        let shell = ShellModel(store: Store(transport: transport, language: .en), client: nil)
        shell.start()
        return shell
    }

    func testTheFirstWindowOpensOnTheAuxHistory() {
        let transport = FakeTransport()
        transport.messagesResult = .success(page(id: 5, agent: "aux", count: 18))
        let shell = open(transport)
        XCTAssertTrue(waitUntil { shell.store.phase == .live })
        XCTAssertEqual(shell.store.selectedAgentName, "aux")
        XCTAssertEqual(shell.store.messages.count, 18, "the 18 stored messages are shown, not the welcome")
    }

    func testANewChatSessionStillOpensOnTheLastConversation() {
        let transport = FakeTransport()
        // Session 9 is the empty one "New chat" started; 8 belongs to Mail; 7 holds Aux's 18 messages.
        transport.messagesByThread = [
            "aux": MessagesPage(thread: SessionJson(id: 9, agent: "aux", createdAt: "2026-10-28 08:00:00"), messages: []),
            "8": page(id: 8, agent: "mail", count: 3),
            "7": page(id: 7, agent: "aux", count: 18),
        ]
        let shell = open(transport)
        XCTAssertTrue(waitUntil { shell.store.conversation.count == 19 }, "got \(shell.store.conversation.count)")
        XCTAssertTrue(shell.store.messages.isEmpty, "the current session is still the new, empty one")
        let items = ThreadTimeline.build(
            agent: "aux", messages: shell.store.conversation, delegations: [], approvals: [],
            threadStartedAt: shell.store.threadStartedAt(for: "aux")
        )
        XCTAssertFalse(items.isEmpty, "the thread is drawn, not the welcome")
        XCTAssertEqual(shell.store.conversation[18].text, L10n.ui(.newChatDivider, .en), "the new chat starts under the old one")
    }

    func testAnotherAgentsSessionIsNeverShownAsHistory() {
        let transport = FakeTransport()
        transport.messagesByThread = [
            "aux": MessagesPage(thread: SessionJson(id: 4, agent: "aux", createdAt: "2026-10-28 08:00:00"), messages: []),
            "3": page(id: 3, agent: "mail", count: 2),
            "2": page(id: 2, agent: "clients", count: 2),
            "1": page(id: 1, agent: "calendar", count: 2),
        ]
        let shell = open(transport)
        XCTAssertTrue(waitUntil { shell.store.phase == .live })
        XCTAssertTrue(waitUntil(timeout: 1) { !shell.store.earlierMessages.isEmpty } == false)
        XCTAssertTrue(shell.store.conversation.isEmpty, "no Aux session exists: the welcome is right")
    }

    // MARK: Sidebar last line

    private func message(_ id: Int64, _ role: String, _ text: String, _ at: String, preview: String? = nil) -> MessageJson {
        MessageJson(id: id, threadId: 1, role: role, content: text, preview: preview, at: at)
    }

    func testTheSidebarSaysTheLastLineNotAuxAnswered() {
        let transport = FakeTransport()
        transport.agentsResult = .success([])
        transport.messagesByThread = [
            "aux": MessagesPage(thread: SessionJson(id: 1, agent: "aux", createdAt: "2026-10-27 08:00:00"), messages: [
                message(1, "user", "Please keep the afternoon free.", "2026-10-27 09:00:00",
                        preview: "Please keep the afternoon free."),
                message(2, "assistant", "Done.\nI moved the 15:00 review.", "2026-10-27 09:01:00",
                        preview: "Done."),
            ]),
            "mail": MessagesPage(thread: SessionJson(id: 2, agent: "mail", createdAt: "2026-10-27 08:00:00"), messages: [
                message(3, "assistant", "Drafted a reply to Jonas.", "2026-10-27 09:02:00",
                        preview: "Drafted a reply to Jonas."),
                message(4, "user", "  Send it tomorrow,\n  not today. ", "2026-10-27 09:03:00",
                        preview: "Send it tomorrow,"),
                message(5, "tool", "exit 0", "2026-10-27 09:04:00"),
            ]),
        ]
        let shell = open(transport)
        XCTAssertTrue(waitUntil { shell.store.previews["mail"] != nil && shell.store.previews["aux"] != nil })
        XCTAssertEqual(shell.row(for: .aux).line, "Done.", "first line of the last message, one line")
        XCTAssertEqual(shell.row(for: .mail).line, "You: Send it tomorrow,", "the owner's last words say You:, tool rows never count")
        XCTAssertNotNil(shell.row(for: .mail).time, "the row keeps the time of that message")
    }

    func testAnAgentWithNoMessageKeepsItsRoleLine() {
        let transport = FakeTransport()
        transport.messagesByThread = ["clients": MessagesPage(thread: nil, messages: [])]
        let shell = open(transport)
        XCTAssertTrue(waitUntil { shell.store.phase == .live })
        XCTAssertFalse(shell.row(for: .clients).line.isEmpty)
        XCTAssertFalse(shell.row(for: .clients).line.hasPrefix("You:"))
    }

    // CHAT-SELECT-TEST: picking a conversation in the sidebar reads that
    // thread. The sidebar's List calls `shell.go(.agent(id))`, which selects
    // the agent in the store (`Store.selectAgent`); the store then loads that
    // thread — the messages of the selected thread arrive, in order, and a
    // thread whose current session is empty still opens on the agent's last
    // conversation.
    func testSelectingAnAgentInTheSidebarLoadsItsThreadInOrder() {
        let transport = FakeTransport()
        transport.agentsResult = .success([])
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        transport.messagesByThread = [
            "mail": page(id: 4, agent: "mail", count: 3),
        ]
        let shell = open(transport)
        XCTAssertTrue(waitUntil { shell.store.phase == .live })
        XCTAssertTrue(shell.store.messages.isEmpty, "no thread is open yet")

        // The sidebar row: the same call the sidebar's List makes.
        shell.go(.agent("mail"))

        XCTAssertTrue(waitUntil { shell.store.messages.count == 3 }, "got \(shell.store.messages.count)")
        XCTAssertEqual(
            shell.store.messages.map(\.text),
            ["Line 0", "Line 1", "Line 2"],
            "the selected thread reads in order, oldest first"
        )

        // A thread whose current session is empty (a "New chat" session) opens
        // on the agent's last conversation: its earlier messages load, in order.
        transport.messagesByThread["calendar"] = MessagesPage(
            thread: SessionJson(id: 6, agent: "calendar", createdAt: "2026-10-27 08:00:06"), messages: []
        )
        transport.messagesByThread["5"] = page(id: 5, agent: "calendar", count: 2)
        shell.go(.agent("calendar"))

        XCTAssertTrue(waitUntil { shell.store.earlierMessages.count == 2 }, "got \(shell.store.earlierMessages.count)")
        XCTAssertEqual(
            shell.store.earlierMessages.map(\.text),
            ["Line 0", "Line 1"],
            "the earlier messages of that thread load in order"
        )
        XCTAssertEqual(
            shell.store.conversation.prefix(2).map(\.text),
            ["Line 0", "Line 1"],
            "the thread opens on its earlier messages"
        )
    }

    func testThePreviewIsTheDaemonScrubbedField() {
        let rows = [
            ChatMessage(id: "1", threadKey: "mail", author: .agent("mail"), ts: 1,
                        blocks: [.text("\n\n  Inbox   triaged \n 31 filed")],
                        preview: "Inbox triaged"),
            ChatMessage(id: "2", threadKey: "mail", author: .tool, ts: 2, blocks: [.text("exit 0")]),
            ChatMessage(id: "3", threadKey: "mail", author: .system, ts: 3, blocks: [.text("# mail  You are mail")]),
        ]
        XCTAssertEqual(ConversationPreview.latest(in: rows)?.text, "Inbox triaged")
        XCTAssertEqual(ConversationPreview.latest(in: rows)?.line(.en), "Inbox triaged")
        XCTAssertNil(ConversationPreview.latest(in: [rows[1], rows[2]]))
    }

    func testTheApiPreviewFieldReachesTheSidebarScrubbed() throws {
        let json = """
        {"id": 1, "thread_id": 1, "role": "assistant",
         "content": "Hello\\nlena.ortiz@example.org", "preview": "Hello [e-mail]",
         "at": "2026-10-27 09:00:00"}
        """
        let decoded = try JSONDecoder().decode(MessageJson.self, from: Data(json.utf8))
        let row = Mapper.message(from: decoded, threadKey: "mail", agentName: "mail")
        XCTAssertEqual(row.preview, "Hello [e-mail]")
        XCTAssertEqual(ConversationPreview.latest(in: [row])?.text, "Hello [e-mail]")
        XCTAssertFalse(ConversationPreview.latest(in: [row])?.text.contains("@") ?? true)
    }
}
