// SEND-WHILE-BUSY-1: a message sent while a turn runs is accepted at once,
// shown as "Queued", and sent once when the turn ends; Stop marks it "Not
// sent"; a `thread_busy` refusal keeps it queued. CHAT-DUP-BUBBLE-1: the
// owner's words show once, and Aux's ask in a domain thread is the handoff
// row, never an owner bubble.
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class SendWhileBusyTests: XCTestCase {
    private func frame(_ json: String) -> WireEvent {
        (try? WireEventDecoder.decode(Data(json.utf8))) ?? .other("bad")
    }

    private func liveStore(_ transport: FakeTransport, approvals: [Approval] = []) -> Store {
        transport.eventScripts = [.hold([])]
        transport.approvalsResult = .success(approvals)
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        let store = Store(transport: transport, language: .en)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.selectedAgentName == "scout" })
        return store
    }

    private func reply(_ id: Int64, _ owner: String) -> SendResponse {
        SendResponse(thread: SessionJson(id: 7, agent: "scout"), messages: [
            MessageJson(id: id, threadId: 7, role: "user", content: owner, at: "2026-10-05 10:00:00"),
            MessageJson(id: id + 1, threadId: 7, role: "assistant", content: "ok: \(owner)", at: "2026-10-05 10:00:01"),
        ])
    }

    private func owner(_ store: Store, _ text: String) -> ChatMessage? {
        store.messages.first { $0.author == .you && $0.text == text }
    }

    private var busy: AuxdError {
        .http(status: 409, body: #"{"error":{"code":"thread_busy","message":"x"}}"#)
    }

    func testASendWhileWorkingIsQueuedThenSentExactlyOnceAfterTheTurnEnds() {
        let transport = FakeTransport()
        transport.sendResults = [.success(reply(20, "first")), .success(reply(22, "second"))]
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("first")
        XCTAssertTrue(waitUntil { transport.sentContents == ["first"] })
        store.composerText = "second"
        store.sendMessage()

        XCTAssertEqual(store.composerText, "", "the composer clears at once")
        XCTAssertEqual(owner(store, "second")?.delivery, .queued)
        XCTAssertEqual(transport.sentContents, ["first"], "nothing is sent while the turn runs")
        gate.open()
        XCTAssertTrue(waitUntil { transport.sentContents == ["first", "second"] && !store.isSendingMessage })
        XCTAssertTrue(waitUntil { store.messages.map(\.text) == ["first", "ok: first", "second", "ok: second"] })
        XCTAssertEqual(owner(store, "second")?.delivery, nil)
        _ = waitUntil(timeout: 0.3) { transport.sentContents.count > 2 }
        XCTAssertEqual(transport.sentContents, ["first", "second"], "one message, one send")
        store.stop()
    }

    func testTwoQueuedMessagesKeepTheirOrder() {
        let transport = FakeTransport()
        transport.sendResults = [.success(reply(20, "a")), .success(reply(22, "b")), .success(reply(24, "c"))]
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("a")
        XCTAssertTrue(waitUntil { transport.sentContents == ["a"] })
        store.sendMessage("b")
        store.sendMessage("c")
        XCTAssertEqual(store.messages.compactMap(\.delivery), [.queued, .queued])
        gate.open()
        XCTAssertTrue(waitUntil { transport.sentContents == ["a", "b", "c"] && !store.isSendingMessage })
        XCTAssertEqual(store.messages.filter { $0.author == .you }.map(\.text), ["a", "b", "c"])
        store.stop()
    }

    /// CONV-SIDEBAR-1: a message queued in session 7 keeps that session when
    /// the owner switches to Mail before the running turn ends.
    func testAQueuedMessageKeepsTheConversationItWasTypedIn() {
        let transport = FakeTransport()
        transport.sendResults = [.success(reply(40, "first")), .success(reply(42, "second"))]
        transport.messagesByThread["7"] = MessagesPage(
            thread: SessionJson(id: 7, agent: "aux"), messages: [])
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.selectAgent("aux")
        XCTAssertTrue(waitUntil { store.selectedAgentName == "aux" })
        store.selectConversation(7)
        XCTAssertTrue(waitUntil { store.selectedConversationId == 7 })
        store.sendMessage("first")
        XCTAssertTrue(waitUntil { transport.sentContents == ["first"] })
        store.sendMessage("second")
        XCTAssertEqual(owner(store, "second")?.delivery, .queued)

        store.selectAgent("mail")
        XCTAssertTrue(waitUntil { store.selectedConversationId == nil })
        gate.open()
        XCTAssertTrue(waitUntil { transport.sentContents == ["first", "second"] })
        XCTAssertEqual(transport.calls.filter { $0 == "send:7" }.count, 2,
                       "both turns go to the session the owner typed in")
        XCTAssertFalse(transport.calls.contains("send:mail"))
        store.stop()
    }

    /// "x" sent once and refused `thread_busy`; the retry answers. With `gate`
    /// the refusal waits until the test opens it.
    private func refusedSend(gate: Gate? = nil) -> (FakeTransport, Store) {
        let transport = FakeTransport()
        transport.sendResults = [.failure(busy), .success(reply(30, "x"))]
        if let gate { transport.beforeSend = { await gate.wait() } }
        let store = liveStore(transport)
        store.sendMessage("x")
        XCTAssertTrue(waitUntil { transport.sentContents == ["x"] && (gate != nil || !store.isSendingMessage) })
        return (transport, store)
    }

    private func idle(_ agent: String = "scout") -> WireEvent {
        frame(#"{"type":"agent.state","at":"t","agent":"\#(agent)","state":"idle"}"#)
    }

    func testAThreadBusyRefusalStaysQueuedAndIsRetriedOnlyWhenItsTurnEnds() {
        let (transport, store) = refusedSend()
        XCTAssertEqual(owner(store, "x")?.delivery, .queued, "a busy thread never drops the message")
        XCTAssertEqual(store.composerText, "")
        transport.emit(frame(#"{"type":"agent.state","at":"t","agent":"scout","state":"needs_you"}"#))
        transport.emit(idle("mail"))
        _ = waitUntil(timeout: 0.3) { transport.sentContents.count > 1 }
        XCTAssertEqual(transport.sentContents, ["x"], "a card or another agent's idle is no turn end")
        transport.emit(idle())
        XCTAssertTrue(waitUntil { transport.sentContents == ["x", "x"] && !store.isSendingMessage })
        XCTAssertTrue(waitUntil { store.messages.map(\.text) == ["x", "ok: x"] })
        XCTAssertNil(store.lastMessageError)
        store.stop()
    }

    /// CANCEL-AT-CARD: with a card waiting, the words are POSTed at once; a
    /// `thread_busy` refusal becomes a "Not sent" note now, never a queue
    /// held for the card's timeout.
    func testAPendingCardSendsAtOnceAndA409ShowsTheNote() {
        let transport = FakeTransport()
        transport.sendResults = [.success(reply(20, "first")), .failure(busy)]
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("first")
        XCTAssertTrue(waitUntil { transport.sentContents == ["first"] })
        transport.emit(frame(#"{"type":"approval.new","at":"t","agent":"scout","approval":{"id":"ap-card","audit_id":1,"agent":"scout","thread_id":"7","ts":1,"action":"run mail_send","headline":"SEND","scope_tool":"mail_send","state":{"state":"pending"}}}"#))
        XCTAssertTrue(waitUntil { store.pendingApprovals.count == 1 })
        // The card message must not wait on the first turn's own gate.
        transport.beforeSend = nil
        store.composerText = "cancel"
        store.sendMessage()
        XCTAssertTrue(waitUntil { transport.sentContents == ["first", "cancel"] })
        XCTAssertTrue(waitUntil { owner(store, "cancel")?.delivery == .notSent })
        XCTAssertEqual(store.lastMessageError, L10n.t(.errorThreadBusy, .en))
        XCTAssertTrue(store.isSendingMessage, "the first turn is still parked")
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        _ = waitUntil(timeout: 0.3) { transport.sentContents.count > 2 }
        XCTAssertEqual(transport.sentContents, ["first", "cancel"], "a card refusal is never retried")
        store.stop()
    }

    /// CARD-NEVER-BLOCKS: a card an agent Aux delegated to raised in its own
    /// thread parks the turn in flight. A new message is POSTed at once, never
    /// held in the queue, and its reply shows while the card still waits.
    func testADelegatedCardNeverHoldsTheComposer() {
        let transport = FakeTransport()
        transport.sendResults = [.success(reply(20, "first")), .success(reply(40, "what's on fri"))]
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("first")
        XCTAssertTrue(waitUntil { transport.sentContents == ["first"] })
        transport.emit(frame(#"{"type":"approval.new","at":"t","agent":"calendar","approval":{"id":"ap-cal","audit_id":1,"agent":"calendar","thread_id":"99","ts":1,"action":"run skill__move-event","headline":"MOVE","scope_tool":"skill__move-event","delegation_id":"d-1","state":{"state":"pending"}}}"#))
        XCTAssertTrue(waitUntil { store.pendingApprovals.count == 1 })
        transport.beforeSend = nil
        store.composerText = "what's on fri"
        store.sendMessage()
        XCTAssertTrue(waitUntil { transport.sentContents == ["first", "what's on fri"] })
        XCTAssertTrue(waitUntil { store.messages.contains { $0.text == "ok: what's on fri" } })
        XCTAssertNil(owner(store, "what's on fri")?.delivery, "never queued")
        XCTAssertEqual(store.composerText, "")
        XCTAssertNil(store.lastMessageError)
        XCTAssertEqual(store.pendingApprovals.count, 1, "the card still waits")
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        store.stop()
    }

    /// The 200 of a card message: the stored words and reply replace the echo.
    func testAPendingCardReplyReplacesTheEcho() {
        let transport = FakeTransport()
        transport.sendResult = .success(reply(30, "cancel"))
        let card = Approval(id: "ap-card", auditId: 1, agent: "scout", threadId: "7", ts: 1, action: "run mail_send", headline: "SEND", scopeTool: "mail_send")
        let store = liveStore(transport, approvals: [card])
        store.composerText = "cancel"
        store.sendMessage()
        XCTAssertTrue(waitUntil { store.messages.map(\.text) == ["cancel", "ok: cancel"] })
        XCTAssertNil(owner(store, "cancel")?.delivery)
        store.stop()
    }

    func testTheLiveEchoOfTheOwnersWordsIsNotDuplicated() {
        let transport = FakeTransport()
        transport.sendResult = .success(reply(20, "Hello"))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("Hello")
        XCTAssertTrue(waitUntil { transport.sentContents == ["Hello"] })
        transport.emit(frame(#"{"type":"message.new","at":"t","agent":"scout","message":{"id":"20","thread_id":"7","author":{"kind":"you"},"ts":1800000000020,"blocks":[{"kind":"text","text":"Hello"}],"streaming":false,"pending":false,"run_id":"turn-a"}}"#))
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == "20" } })
        XCTAssertEqual(store.messages.filter { $0.author == .you }.map(\.id), ["20"], "one bubble while the turn runs")
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        XCTAssertEqual(store.messages.filter { $0.author == .you }.map(\.id), ["20"])
        store.stop()
    }

    func testAuxsAskInADomainThreadIsTheHandoffRowNotAnOwnerBubble() {
        let ask = "List the quote requests in the inbox."
        let messages = [
            ChatMessage(id: "40", threadKey: "mail", author: .you, ts: 1_800_000_000_000, blocks: [.text(ask + "\n")]),
            ChatMessage(id: "41", threadKey: "mail", author: .agent("mail"), ts: 1_800_000_001_000, blocks: [.text("Two requests.")]),
        ]
        let delegation = Delegation(id: "d1", agent: "mail", ask: ask, at: "2027-01-15 08:00:00", state: .done)
        // Owner bubbles shown; the owner typing the same words later keeps theirs.
        func owned(_ rows: [ChatMessage]) -> [String] {
            ThreadTimeline.build(agent: "mail", messages: rows, delegations: [delegation], approvals: []).flatMap { item -> [String] in
                guard case .group(let g) = item, g.voice == .owner else { return [] }
                return g.entries.compactMap { if case .message(let m) = $0 { return m.id } else { return nil } }
            }
        }
        XCTAssertEqual(owned(messages), [], "Aux's words are not the owner's")
        let mine = ChatMessage(id: "42", threadKey: "mail", author: .you, ts: 1_800_000_002_000, blocks: [.text(ask)])
        XCTAssertEqual(owned(messages + [mine]), ["42"], "one row per ask")
    }

    func testARefusalThatLandsAfterStopIsNotSentAndNeverRetried() {
        let gate = Gate()
        let (transport, store) = refusedSend(gate: gate)
        store.cancelQueuedSends()
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        XCTAssertEqual(owner(store, "x")?.delivery, .notSent)
        transport.emit(idle())
        _ = waitUntil(timeout: 0.3) { transport.sentContents.count > 1 }
        XCTAssertEqual(transport.sentContents, ["x"])
        store.stop()
    }

    func testStopMarksAnotherThreadsQueuedMessageNotSent() {
        let transport = FakeTransport()
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = liveStore(transport)
        store.sendMessage("a")
        XCTAssertTrue(waitUntil { transport.sentContents == ["a"] })
        store.sendMessage("b")
        store.selectAgent("mail")
        store.cancelQueuedSends()
        store.selectAgent("scout")
        XCTAssertEqual(owner(store, "b")?.delivery, .notSent, "never vanishes silently")
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage && self.owner(store, "b")?.delivery == .notSent && store.messages.last?.text == "b" })
        _ = waitUntil(timeout: 0.3) { transport.sentContents.count > 1 }
        XCTAssertEqual(transport.sentContents, ["a"], "a stopped message is never sent")
        store.stop()
    }

    func testATurnEndDuringTheRefusedSendRetriesAtOnce() {
        let gate = Gate()
        let (transport, store) = refusedSend(gate: gate)
        transport.emit(idle())
        _ = waitUntil(timeout: 0.2) { false }
        gate.open()
        XCTAssertTrue(waitUntil { transport.sentContents == ["x", "x"] }, "no lost wake-up")
        store.stop()
    }

    func testAnIdlePollReleasesAHeldSend() {
        let (transport, store) = refusedSend()
        transport.emit(frame(#"{"type":"agent.state","at":"t","agent":"scout","state":{"name":"scout","enabled":true,"jobs_total":0,"jobs_enabled":0,"running_job":null,"stop":false,"paused":false,"killed":false,"thread_id":"7"}}"#))
        XCTAssertTrue(waitUntil { transport.sentContents == ["x", "x"] }, "the poll is the fallback wake-up")
        store.stop()
    }
}
