// CHAT-DOUBLE-1: one turn shows one agent bubble. The frames below are the
// daemon's real shapes (crates/auxd/src/api/wire.rs, turn_events.rs): a
// streamed round carries a `draft-<thread>-<run>-<round>` id, the stored reply
// that ends it names that draft in `draft_id`, and every row names its run.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ChatDoubleTests: XCTestCase {
    private func frame(_ json: String) -> WireEvent {
        (try? WireEventDecoder.decode(Data(json.utf8))) ?? .other("bad")
    }

    private func delta(_ draft: String, _ text: String) -> WireEvent {
        frame(#"{"type":"message.delta","at":"t","agent":"scout","thread_id":"7","message_id":"\#(draft)","seq":1,"text":"\#(text)"}"#)
    }

    private func stored(_ id: Int, _ kind: String, _ text: String, draft: String? = nil, run: String? = nil) -> WireEvent {
        let author = kind == "tool" ? #"{"kind":"tool"}"# : kind == "you" ? #"{"kind":"you"}"# : #"{"kind":"agent","id":"scout"}"#
        let link = (draft.map { #","draft_id":"\#($0)""# } ?? "") + (run.map { #","run_id":"\#($0)""# } ?? "")
        return frame(#"{"type":"message.new","at":"t","agent":"scout","message":{"id":"\#(id)","thread_id":"7","author":\#(author),"ts":\#(1_800_000_000_000 + id),"blocks":[{"kind":"text","text":"\#(text)"}],"streaming":false,"pending":false\#(link)}}"#)
    }

    private func liveStore(_ transport: FakeTransport) -> Store {
        transport.approvalsResult = .success([])
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        let store = Store(transport: transport, language: .fr)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.selectedAgentName == "scout" })
        return store
    }

    private func bubbles(_ store: Store) -> [ChatMessage] {
        ThreadTimeline.build(agent: "scout", messages: store.messages, delegations: [], approvals: []).flatMap { item -> [ChatMessage] in
            guard case .group(let group) = item else { return [] }
            return group.entries.compactMap { if case .message(let m) = $0 { return m } else { return nil } }
        }
    }

    func testAStreamedTurnWithAToolCallShowsOneBubble() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        transport.emit(delta("draft-7-1", "I'll check your calendar for today."))
        XCTAssertTrue(waitUntil { store.messages.count == 1 })
        transport.emit(stored(21, "agent", "I'll check your calendar for today.", draft: "draft-7-1"))
        transport.emit(stored(22, "tool", "[{\\\"title\\\":\\\"Standup\\\"}]"))
        transport.emit(delta("draft-7-2", "You have one meeting at 10:00."))
        transport.emit(stored(23, "agent", "You have one meeting at 10:00.", draft: "draft-7-2"))
        transport.emit(frame(#"{"type":"message.done","at":"t","agent":"scout","thread_id":"7","message_id":"23"}"#))
        XCTAssertTrue(waitUntil { store.messages.last?.id == "23" && store.messages.last?.streaming == false })

        XCTAssertEqual(store.messages.map(\.id), ["21", "22", "23"], "the store keeps both replies, no drafts")
        let shown = bubbles(store)
        XCTAssertEqual(shown.map(\.id), ["23"])
        XCTAssertEqual(shown.first?.statusLines(), ["I'll check your calendar for today."])
        XCTAssertEqual(shown.first?.text, "You have one meeting at 10:00.")
        store.stop()
    }

    func testAStreamedTurnWithoutAToolShowsOneBubble() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        transport.emit(delta("draft-7-1", "Hi!"))
        transport.emit(stored(21, "agent", "Hi!", draft: "draft-7-1"))
        XCTAssertTrue(waitUntil { store.messages.first?.id == "21" })
        XCTAssertEqual(bubbles(store).map(\.id), ["21"])
        XCTAssertEqual(bubbles(store).first?.statusLines(), [])
        store.stop()
    }

    func testTheSendResponseClearsADraftWhoseStoredFrameWasMissed() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        transport.sendResult = .success(SendResponse(
            thread: SessionJson(id: 7, agent: "scout"),
            messages: [
                MessageJson(id: 20, threadId: 7, role: "user", content: "Hello", at: "2026-10-05 10:00:00"),
                MessageJson(id: 21, threadId: 7, role: "assistant", content: "Hi!", at: "2026-10-05 10:00:01"),
            ],
            runId: "turn-a"
        ))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("Hello")
        XCTAssertTrue(waitUntil { transport.calls.contains("send:scout") })
        transport.emit(delta("draft-7-turn-a-1", "Hi!"))
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == "draft-7-turn-a-1" } })
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        XCTAssertEqual(store.messages.map(\.id), ["20", "21"])
        XCTAssertEqual(bubbles(store).map(\.text), ["Hello", "Hi!"], "the owner turn and provider reply both remain visible")
        XCTAssertEqual(bubbles(store).map(\.author), [.you, .agent("scout")])
        store.stop()
    }

    func testRESTUserAndAssistantRowsRenderAsOwnerAndAuxBubbles() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        transport.messagesResult = .success(MessagesPage(thread: SessionJson(id: 7, agent: "scout"), messages: [
            MessageJson(id: 20, threadId: 7, role: "user", content: "Check the inbox.", at: "2026-10-05 10:00:00"),
            MessageJson(id: 21, threadId: 7, role: "assistant", content: "There are five unread messages.", at: "2026-10-05 10:00:01"),
        ]))
        let store = Store(transport: transport, language: .en)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.messages.count == 2 })
        let timeline = ThreadTimeline.build(agent: "scout", messages: store.messages, delegations: [], approvals: [])
        let messages = timeline.flatMap { item -> [ChatMessage] in
            guard case .group(let group) = item else { return [] }
            return group.entries.compactMap { if case .message(let message) = $0 { return message } else { return nil } }
        }
        XCTAssertEqual(messages.map(\.author), [.you, .agent("scout")])
        XCTAssertEqual(messages.map(\.text), ["Check the inbox.", "There are five unread messages."])
        store.stop()
    }

    private func row(_ id: String, _ author: Author, _ text: String, run: String? = nil) -> ChatMessage {
        var message = ChatMessage(id: id, threadKey: "7", author: author, ts: 1_800_000_000_000 + Int64(id)!, blocks: [.text(text)])
        message.runId = run
        return message
    }

    func testHistoryFoldsAToolPreambleButNotTwoSeparateReplies() {
        let history = [
            row("281", .you, "What's on today?"),
            row("282", .agent("scout"), "I'll check your calendar for today."),
            row("287", .tool, "[]"),
            row("288", .agent("scout"), "Nothing today."),
            row("290", .agent("scout"), "Reminder: invoice due."),
        ]
        let folded = ThreadTimeline.foldPreambles(history).filter { $0.author != .tool }
        XCTAssertEqual(folded.map(\.id), ["281", "288", "290"])
        XCTAssertEqual(folded[1].statusLines(), ["I'll check your calendar for today."])
        XCTAssertEqual(folded[2].statusLines(), [])
    }

    // MARK: Revision 2

    private func auxBubbles(_ store: Store) -> [ChatMessage] {
        bubbles(store).filter { $0.author == .agent("scout") }
    }

    private func replay(_ store: Store, _ transport: FakeTransport, send: String, frames: String, response: String, last: String) {
        transport.sendResult = .success(try! JSONDecoder().decode(SendResponse.self, from: Data(response.utf8)))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let before = transport.calls.filter { $0 == "send:scout" }.count
        store.sendMessage(send)
        XCTAssertTrue(waitUntil { transport.calls.filter { $0 == "send:scout" }.count > before })
        for line in frames.split(separator: "\n") { transport.emit(frame(String(line))) }
        // The socket wins the race here; the sweep test has the other order.
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == last } })
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
    }

    /// The owner's case, end to end: frames and responses of a real sandbox
    /// auxd, one turn without a tool and one with; one Aux bubble per turn.
    func testARealSandboxTurnPairShowsOneAuxBubblePerTurn() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        replay(store, transport, send: "Hi Aux, say hello in one short sentence.", frames: ChatDoubleReplay.plainFrames, response: ChatDoubleReplay.plainSend, last: "2")
        XCTAssertEqual(auxBubbles(store).map(\.id), ["2"])
        replay(store, transport, send: "What is on my calendar today? Check it with your tools.", frames: ChatDoubleReplay.toolFrames, response: ChatDoubleReplay.toolSend, last: "10")
        XCTAssertEqual(auxBubbles(store).map(\.id), ["2", "10"])
        XCTAssertEqual(auxBubbles(store).last?.statusLines(), ["I'll check your calendar for today."])
        XCTAssertEqual(store.messages.filter { $0.author == .you }.map(\.id), ["1", "3"])
        XCTAssertFalse(store.messages.contains { $0.id.hasPrefix("draft-") })
        store.stop()
    }

    /// Item 1: the end of this send leaves another live turn's draft alone.
    func testTheSendSweepKeepsAnotherTurnsDraft() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        let response = #"{"thread":{"id":7,"agent":"scout"},"messages":[{"id":20,"thread_id":7,"role":"user","content":"Hello","at":"2026-10-05 10:00:00"},{"id":21,"thread_id":7,"role":"assistant","content":"Hi!","at":"2026-10-05 10:00:01"}],"rounds":1,"capped":false,"run_id":"turn-a"}"#
        let frames = [
            #"{"type":"message.delta","at":"t","agent":"scout","thread_id":"7","message_id":"draft-7-turn-a-1","seq":1,"text":"Hi!"}"#,
            #"{"type":"message.delta","at":"t","agent":"scout","thread_id":"7","message_id":"draft-7-turn-job-1","seq":1,"text":"Job half "}"#,
        ].joined(separator: "\n")
        replay(store, transport, send: "Hello", frames: frames, response: response, last: "draft-7-turn-job-1")
        XCTAssertEqual(store.messages.map(\.id), ["20", "draft-7-turn-job-1", "21"])
        transport.emit(delta("draft-7-turn-job-1", "done."))
        transport.emit(stored(30, "agent", "Job half done.", draft: "draft-7-turn-job-1", run: "turn-job"))
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == "30" } })
        XCTAssertEqual(store.messages.map(\.id), ["20", "30", "21"])
        XCTAssertEqual(store.messages[1].text, "Job half done.")
        store.stop()
    }

    /// Item 2: a failed stream's partial draft goes, and the next turn's
    /// round 1 never appends into it.
    func testAFailedStreamLeavesNoDraftForTheNextTurn() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        transport.sendResult = .failure(URLError(.timedOut))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        store.sendMessage("Hello")
        XCTAssertTrue(waitUntil { transport.calls.contains("send:scout") })
        transport.emit(stored(20, "you", "Hello", run: "turn-a"))
        transport.emit(delta("draft-7-turn-a-1", "Half an ans"))
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == "draft-7-turn-a-1" } })
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        XCTAssertFalse(store.messages.contains { $0.id.hasPrefix("draft-") })
        transport.emit(delta("draft-7-turn-b-1", "Hi!"))
        XCTAssertTrue(waitUntil { store.messages.last?.text == "Hi!" })
        store.stop()
    }

    /// Item 3: the stored reply first, then a late delta of its draft: one bubble.
    func testALateDeltaAfterTheStoredReplyAddsNoBubble() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        transport.emit(stored(21, "agent", "Hi there", draft: "draft-7-turn-a-1", run: "turn-a"))
        transport.emit(delta("draft-7-turn-a-1", " there"))
        transport.emit(stored(22, "you", "Thanks", run: "turn-b"))
        XCTAssertTrue(waitUntil { store.messages.last?.id == "22" })
        XCTAssertEqual(store.messages.map(\.id), ["21", "22"])
        store.stop()
    }

    /// Addendum A: a turn in another session of the agent (an iMessage turn)
    /// keeps its tool row, so it folds into one bubble; the owner's words from
    /// that channel stay out of this chat (they would vanish on reload).
    func testAnotherSessionsTurnKeepsItsToolRowAndShowsOneBubble() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = liveStore(transport)
        let job = #""agent":"scout","message":{"thread_id":"12","run_id":"turn-12-job""#
        for row in [
            #"{"type":"message.new",\#(job),"id":"40","author":{"kind":"you"},"ts":1,"blocks":[{"kind":"text","text":"Morning check"}]}}"#,
            #"{"type":"message.new",\#(job),"id":"41","author":{"kind":"agent","id":"scout"},"ts":2,"blocks":[{"kind":"text","text":"I'll check your mail."}]}}"#,
            #"{"type":"message.new",\#(job),"id":"42","author":{"kind":"tool"},"ts":3,"blocks":[{"kind":"text","text":"[]"}]}}"#,
            #"{"type":"message.new",\#(job),"id":"43","author":{"kind":"agent","id":"scout"},"ts":4,"blocks":[{"kind":"text","text":"No new mail."}]}}"#,
        ] { transport.emit(frame(row)) }
        XCTAssertTrue(waitUntil { store.messages.last?.id == "43" })
        XCTAssertEqual(store.messages.map(\.id), ["41", "42", "43"])
        XCTAssertEqual(auxBubbles(store).map(\.id), ["43"])
        XCTAssertEqual(auxBubbles(store).first?.statusLines(), ["I'll check your mail."])
        store.stop()
    }

    /// Addendum B: on reconnect the snapshot already holds the stored reply;
    /// the buffered delta and its `message.new` leave no draft behind.
    func testAReconnectReplayLeavesNoDraft() {
        let transport = FakeTransport()
        let gate = Gate()
        transport.beforeAgents = { await gate.wait() }
        transport.approvalsResult = .success([])
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: [
            MessageJson(id: 21, threadId: 7, role: "assistant", content: "Hi!", at: "2026-10-05 10:00:01"),
        ]))
        transport.eventScripts = [.hold([
            delta("draft-7-turn-a-1", "Hi!"),
            stored(21, "agent", "Hi!", draft: "draft-7-turn-a-1", run: "turn-a"),
        ])]
        let store = Store(transport: transport, language: .fr)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .syncing })
        gate.open()
        XCTAssertTrue(waitUntil { store.phase == .live && store.messages.first?.runId == "turn-a" })
        XCTAssertEqual(store.messages.map(\.id), ["21"])
        store.stop()
    }

    /// Item 4: the folded status line shows the model's words in the
    /// "what the model saw" view, as the answer does.
    func testTheFoldedPreambleShowsWhatTheModelSaw() {
        let folded = ThreadTimeline.foldPreambles([
            row("282", .agent("scout"), "I'll write to Ana."),
            row("287", .tool, "ok"),
            row("288", .agent("scout"), "Sent."),
        ])
        XCTAssertEqual(folded.last?.statusLines(tokenised: ["282": "I'll write to ⟦PERSON_1⟧."]), ["I'll write to ⟦PERSON_1⟧."])
        XCTAssertEqual(folded.last?.statusLines(), ["I'll write to Ana."])
    }

    /// Item 5: a live answer of one run never folds into another run's reply.
    func testAnAnswerOfAnotherRunIsNotFolded() {
        let folded = ThreadTimeline.foldPreambles([
            row("281", .agent("scout"), "Done.", run: "turn-a"),
            row("287", .tool, "[]", run: "turn-job"),
            row("288", .agent("scout"), "Nothing new.", run: "turn-job"),
        ]).filter { $0.author != .tool }
        XCTAssertEqual(folded.map(\.id), ["281", "288"])
        XCTAssertEqual(folded.last?.statusLines(), [])
    }
}
