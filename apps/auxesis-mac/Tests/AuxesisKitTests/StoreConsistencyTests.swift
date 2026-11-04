// Snapshot-then-events consistency: no lost frames, no duplicates, honest
// reconnect with backoff and a fresh snapshot.
import Testing
@testable import AuxesisKit

final class DelayRecorder {
    nonisolated(unsafe) var delays: [TimeInterval] = []
}

@objcMembers @MainActor final class StoreConsistencyTests: XCTestCase {
    func testMcpAddRequiresNonemptyIDAndTheExactTestedURL() {
        XCTAssertTrue(Store.pluginAddReady(url: "https://example.test/mcp", id: "safe", testedURL: "https://example.test/mcp"))
        XCTAssertFalse(Store.pluginAddReady(url: "https://edited.test/mcp", id: "safe", testedURL: "https://example.test/mcp"))
        XCTAssertFalse(Store.pluginAddReady(url: "https://example.test/mcp", id: "  ", testedURL: "https://example.test/mcp"))
        XCTAssertFalse(Store.pluginAddReady(url: "https://example.test/mcp", id: "safe", testedURL: nil))
    }

    private func makeStore(_ transport: FakeTransport, recorder: DelayRecorder? = nil) -> Store {
        if let recorder {
            return Store(
                transport: transport,
                language: .fr,
                sleeper: { delay in recorder.delays.append(delay) }
            )
        }
        return Store(transport: transport, language: .fr)
    }

    func testEventsDuringSnapshotAreBufferedThenAppliedWithoutDuplicates() {
        let transport = FakeTransport()
        let gate = Gate()
        transport.beforeAgents = { await gate.wait() }
        // Duplicate of snapshot message 11 (updated), delta on message 10, new message 99.
        transport.eventScripts = [.hold([
            .messageNew(ChatMessage(
                id: "11", threadKey: "7", author: .agent("scout"), ts: 200,
                blocks: [.text("On it. (updated)")], streaming: false
            )),
            .messageDelta(threadId: "7", messageId: "10", text: " Indeed.", agent: "scout"),
            .messageNew(ChatMessage(
                id: "99", threadKey: "7", author: .agent("scout"), ts: 300,
                blocks: [.text("Follow-up.")], streaming: false
            )),
        ])]
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .syncing }, "must reach syncing")
        gate.open()
        XCTAssertTrue(waitUntil { store.phase == .live && store.messages.count == 4 }, "snapshot + buffered events")

        XCTAssertEqual(store.syncCount, 1)
        XCTAssertEqual(store.messages.map(\.id), ["10", "11", "12", "99"])
        XCTAssertEqual(store.messages.first { $0.id == "11" }?.text, "On it. (updated)")
        XCTAssertEqual(
            store.messages.first { $0.id == "10" }?.text,
            "Find out whether Lightpanda works with chromiumoxide. Indeed."
        )
        XCTAssertEqual(store.acceptedDeltas, 1)
        XCTAssertEqual(store.selectedAgentName, "scout")
        store.stop()
    }

    func testLatestSnapshotPageMergesIntoFullConversationInChronologicalOrder() {
        let earlier = ChatMessage(id: "1", threadKey: "7", author: .you, ts: 100,
                                  blocks: [.text("first question")])
        let priorReply = ChatMessage(id: "2", threadKey: "7", author: .agent("scout"), ts: 200,
                                     blocks: [.text("checking")])
        let refreshedReply = ChatMessage(id: "2", threadKey: "7", author: .agent("scout"), ts: 200,
                                         blocks: [.text("the complete answer")])
        let newest = ChatMessage(id: "3", threadKey: "7", author: .you, ts: 300,
                                 blocks: [.text("next question")])

        let merged = Store.mergeMessages([earlier, priorReply], with: [refreshedReply, newest])
        XCTAssertEqual(merged.map(\.text), ["first question", "the complete answer", "next question"])
    }

    func testFinishedRunReceiptClearsLiveWorkingStateForEveryOutcome() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.agents.contains { $0.name == "scout" } })
        // Failed is the receipt outcome for both provider errors and a
        // cancelled run; the UI must clear live state for either terminal.
        let outcomes: [(String, ReceiptStatus)] = [
            ("success", .done), ("error", .failed), ("cancel", .failed),
        ]
        for (index, outcome) in outcomes.enumerated() {
            let runId = "run-\(index)-\(outcome.0)"
            transport.emit(.agentStateLive(agent: "scout", state: .working))
            XCTAssertTrue(waitUntil { store.agents.first { $0.name == "scout" }?.state == .working })
            var message = ChatMessage(id: "user-\(runId)", threadKey: "7", author: .you, ts: Int64(index), blocks: [.text("turn")])
            message.runId = runId
            message.frameAgent = "scout"
            transport.emit(.messageNew(message))
            transport.emit(.runFinished(Receipt(runId: runId, agent: "scout", status: outcome.1)))
            XCTAssertTrue(waitUntil { store.agents.first { $0.name == "scout" }?.state == .idle }, "\(outcome.0) must clear working state")
        }
        store.stop()
    }

    func testLateReceiptForAnOlderRunDoesNotClearCurrentWorkingRun() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.agents.contains { $0.name == "scout" } })

        transport.emit(.agentStateLive(agent: "scout", state: .working))
        var current = ChatMessage(id: "user-run-b", threadKey: "7", author: .you, ts: 2, blocks: [.text("second turn")])
        current.runId = "run-b"
        current.frameAgent = "scout"
        transport.emit(.messageNew(current))
        XCTAssertTrue(waitUntil { store.agents.first { $0.name == "scout" }?.state == .working })

        transport.emit(.runFinished(Receipt(runId: "run-a", agent: "scout", status: .done)))
        XCTAssertTrue(waitUntil { store.receiptLog.receipts.contains { $0.runId == "run-a" } })
        XCTAssertEqual(store.agents.first { $0.name == "scout" }?.state, .working)

        transport.emit(.runFinished(Receipt(runId: "run-b", agent: "scout", status: .done)))
        XCTAssertTrue(waitUntil { store.agents.first { $0.name == "scout" }?.state == .idle })
        store.stop()
    }

    func testReceiptForAnUnknownRunStillClearsWorkingState() {
        let transport = FakeTransport()
        transport.eventScripts = [.hold([])]
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.agents.contains { $0.name == "scout" } })

        // No run id was ever tracked (older daemon, dropped frame): the
        // receipt must not leave the agent working forever.
        transport.emit(.agentStateLive(agent: "scout", state: .working))
        XCTAssertTrue(waitUntil { store.agents.first { $0.name == "scout" }?.state == .working })
        transport.emit(.runFinished(Receipt(runId: "", agent: "scout", status: .done)))
        XCTAssertTrue(waitUntil { store.agents.first { $0.name == "scout" }?.state == .idle })
        store.stop()
    }

    func testReconnectBacksOffAndResyncsFromSnapshot() {
        let transport = FakeTransport()
        transport.eventScripts = [
            .fail(.transport("boom")),
            .fail(.transport("boom")),
            .hold([]),
        ]
        let recorder = DelayRecorder()
        let store = makeStore(transport, recorder: recorder)
        store.start()
        XCTAssertTrue(waitUntil(timeout: 3) { store.syncCount >= 3 && store.phase == .live })
        XCTAssertEqual(recorder.delays, [0.5, 1.0])
        XCTAssertEqual(store.messages.count, 3)
        XCTAssertEqual(store.connection, .online(version: "0.1.0"))
        store.stop()
    }

    func testApprovalFramesDuringSnapshotAreNotLost() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        let gate = Gate()
        transport.beforeAgents = { await gate.wait() }
        guard let approval = try? Fixtures.approvals().first else { return XCTFail("fixture") }
        transport.eventScripts = [.hold([.approvalNew(approval)])]

        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .syncing })
        gate.open()
        XCTAssertTrue(waitUntil { store.phase == .live && store.pendingApprovals.count == 1 })
        XCTAssertEqual(store.focusedApprovalId, approval.id)
        XCTAssertEqual(store.agents.first { $0.name == "scout" }?.waiting, 1)

        transport.emit(.approvalResolved(id: approval.id, state: .allowed(by: "you", always: false)))
        XCTAssertTrue(waitUntil { store.approvals.first?.state == .allowed(by: "you", always: false) })
        XCTAssertEqual(store.pendingApprovals.count, 0)
        XCTAssertEqual(store.agents.first { $0.name == "scout" }?.waiting, 0)
        store.stop()
    }

    func testAStaleSnapshotCannotResurrectALocallyResolvedApproval() {
        let transport = FakeTransport()
        guard let approval = try? Fixtures.approvals().first else { return XCTFail("fixture") }
        transport.approvalsResult = .success([approval])
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.approvals.count == 1 })

        store.resolve(store.approvals[0], decision: .allowOnce)
        XCTAssertTrue(waitUntil { store.approvals.first?.state == .allowed(by: "you", always: false) })

        // Reconnect: the daemon still reports the ask as pending (stale), the
        // local answer must win.
        store.restart()
        XCTAssertTrue(waitUntil(timeout: 3) { store.syncCount >= 2 && store.approvals.count == 1 })
        XCTAssertTrue(waitUntil { store.phase == .live })
        XCTAssertEqual(store.approvals.first?.state, .allowed(by: "you", always: false))
        XCTAssertEqual(store.pendingApprovals.count, 0)
        store.stop()
    }

    func testDeltasStreamIntoOneBubbleThenMessageNewReplacesIt() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        transport.eventScripts = [.hold([
            .messageDelta(threadId: "7", messageId: "13", text: "Working", agent: "scout"),
            .messageDelta(threadId: "7", messageId: "13", text: " on it.", agent: "scout"),
        ])]
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.messages.count == 1 })
        XCTAssertEqual(store.messages[0].text, "Working on it.")
        XCTAssertTrue(store.messages[0].streaming)
        XCTAssertEqual(store.acceptedDeltas, 2)

        // The completed message replaces the streamed one: same id, no duplicate.
        transport.emit(.messageNew(ChatMessage(
            id: "13", threadKey: "7", author: .agent("scout"), ts: 400,
            blocks: [.text("Working on it.")], streaming: false
        )))
        XCTAssertTrue(waitUntil { store.messages.count == 1 && !store.messages[0].streaming })
        XCTAssertEqual(store.messages[0].text, "Working on it.")

        // A frame from another agent's thread is ignored.
        transport.emit(.messageNew(ChatMessage(
            id: "77", threadKey: "999", author: .agent("mail"), ts: 500,
            blocks: [.text("other thread")], streaming: false
        )))
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        XCTAssertEqual(store.messages.count, 1)

        transport.emit(.messageDone(threadId: "7", messageId: "13"))
        store.stop()
    }

    func testSendRemovesThePendingEchoAndAddsTheTurn() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.sendResult = .success(SendResponse(
            thread: SessionJson(id: 7, agent: "scout"),
            messages: [
                MessageJson(id: 20, threadId: 7, role: "user", content: "Hello", at: "2026-10-05 10:00:00"),
                MessageJson(id: 21, threadId: 7, role: "assistant", content: "Hi!", at: "2026-10-05 10:00:01"),
            ]
        ))
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.selectedAgentName == "scout" })

        store.composerText = "Hello"
        store.sendMessage()
        XCTAssertTrue(waitUntil { store.syncCount >= 1 && !store.isSendingMessage && store.messages.count == 5 })
        XCTAssertFalse(store.messages.contains { $0.id.hasPrefix("local-") })
        XCTAssertEqual(store.messages.last?.text, "Hi!")
        XCTAssertEqual(store.composerText, "")
        store.stop()
    }

    func testFailedSendKeepsTheTypedTextAndSaysSo() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.sendResult = .failure(AuxdError.transport("connection refused"))
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live })

        store.composerText = "Hello"
        store.sendMessage()
        XCTAssertTrue(waitUntil { !store.isSendingMessage && store.lastMessageError != nil })
        XCTAssertEqual(store.composerText, "Hello", "typed text must not be lost")
        XCTAssertEqual(store.messages.last?.pending, false)
        store.stop()
    }

    func testRetryAfterAFailedSendResendsTheSameText() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.sendResult = .failure(AuxdError.transport("connection refused"))
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live })

        store.composerText = "Hello"
        store.sendMessage()
        XCTAssertTrue(waitUntil { !store.isSendingMessage && store.lastMessageError != nil })
        XCTAssertEqual(store.composerText, "Hello", "the error card can resend the same text")

        // The Réessayer button calls the normal send path: the text goes out
        // again and the error clears once the service answers.
        transport.sendResult = .success(SendResponse())
        let sendsBefore = transport.calls.filter { $0.hasPrefix("send:") }.count
        store.sendMessage()
        XCTAssertTrue(waitUntil { !store.isSendingMessage && store.lastMessageError == nil })
        XCTAssertEqual(transport.calls.filter { $0.hasPrefix("send:") }.count, sendsBefore + 1)
        XCTAssertEqual(store.composerText, "")
        store.stop()
    }

    private func turn(_ text: String) -> SendResponse {
        SendResponse(
            thread: SessionJson(id: 7, agent: "scout"),
            messages: [
                MessageJson(id: 20, threadId: 7, role: "user", content: text, at: "2026-10-05 10:00:00"),
                MessageJson(id: 21, threadId: 7, role: "assistant", content: "Hi!", at: "2026-10-05 10:00:01"),
            ]
        )
    }

    func testAReplyNeverLandsInTheAgentSwitchedTo() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.sendResult = .success(turn("Hello"))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.selectedAgentName == "scout" && store.messages.count == 3 })

        store.composerText = "Hello"
        store.sendMessage()
        XCTAssertTrue(waitUntil { transport.calls.contains("send:scout") })
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        store.selectAgent("mail")
        XCTAssertTrue(waitUntil { transport.calls.contains("messages:mail") })
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))

        XCTAssertEqual(store.selectedAgentName, "mail")
        XCTAssertTrue(store.messages.isEmpty, "scout's turn must not show in Mail: \(store.messages.map(\.text))")
        XCTAssertNil(store.lastMessageError)
        store.stop()
    }

    func testAFailedSendAfterAnAgentSwitchLeavesTheNewThreadAlone() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.sendResult = .failure(AuxdError.transport("connection refused"))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.selectedAgentName == "scout" })

        store.composerText = "Hello"
        store.sendMessage()
        XCTAssertTrue(waitUntil { transport.calls.contains("send:scout") })
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        store.selectAgent("mail")
        XCTAssertTrue(waitUntil { transport.calls.contains("messages:mail") })
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))

        XCTAssertNil(store.lastMessageError, "scout's error must not show in Mail")
        XCTAssertEqual(store.composerText, "", "scout's text must not refill Mail's composer")
        XCTAssertTrue(store.messages.isEmpty)
        store.stop()
    }

    func testASocketReplyBeforeTheSendResponseIsNotDuplicated() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.sendResult = .success(turn("Hello"))
        let gate = Gate()
        transport.beforeSend = { await gate.wait() }
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.messages.count == 3 })

        store.composerText = "Hello"
        store.sendMessage()
        XCTAssertTrue(waitUntil { transport.calls.contains("send:scout") })
        transport.emit(.messageNew(ChatMessage(
            id: "21", threadKey: "7", author: .agent("scout"), ts: 500,
            blocks: [.text("Hi!")], streaming: false
        )))
        XCTAssertTrue(waitUntil { store.messages.contains { $0.id == "21" } })
        gate.open()
        XCTAssertTrue(waitUntil { !store.isSendingMessage })
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))

        XCTAssertEqual(store.messages.map(\.id), ["10", "11", "12", "20", "21"], "the owner's words read before the reply")
        XCTAssertEqual(store.messages.filter { $0.text == "Hi!" }.count, 1)
        XCTAssertEqual(store.messages.filter { $0.text == "Hello" }.count, 1)
        store.stop()
    }

    func testSelectAgentLoadsItsThread() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && !store.messages.isEmpty })
        XCTAssertEqual(transport.calls.filter { $0 == "messages:scout" }.count, 1)

        store.selectAgent("scout") // same agent: no-op
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        XCTAssertEqual(transport.calls.filter { $0 == "messages:scout" }.count, 1)
        store.stop()
    }

    // MARK: Survivor kills

    func testMessageDoneEndsTheStreamingState() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        transport.eventScripts = [.hold([
            .messageDelta(threadId: "7", messageId: "13", text: "Working", agent: "scout"),
        ])]
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.messages.count == 1 })
        XCTAssertTrue(store.messages[0].streaming, "a delta streams")

        transport.emit(.messageDone(threadId: "7", messageId: "13"))
        XCTAssertTrue(
            waitUntil { !store.messages[0].streaming },
            "message.done must clear the streaming flag (M5)"
        )
        store.stop()
    }

    func testNewestApprovalArrivesAtTheTopOfTheInbox() {
        let transport = FakeTransport()
        transport.approvalsResult = .success([])
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live })

        func ask(_ id: String) -> Approval {
            Approval(
                id: id, auditId: 1, agent: "scout", threadId: "7", ts: 1,
                action: "act", headline: "H", scopeTool: "tool"
            )
        }
        transport.emit(.approvalNew(ask("a1")))
        XCTAssertTrue(waitUntil { store.approvals.count == 1 })
        transport.emit(.approvalNew(ask("a2")))
        XCTAssertTrue(waitUntil { store.approvals.count == 2 })

        XCTAssertEqual(store.approvals.map(\.id), ["a2", "a1"], "newest ask first (M6)")
        XCTAssertEqual(store.focusedApprovalId, "a1", "focus stays on the first ask")
        store.stop()
    }

    func testArmingDelayIsPreservedAcrossAReconnect() throws {
        let transport = FakeTransport()
        let destructive = try Fixtures.approvals()[0]
        XCTAssertTrue(destructive.destructive, "fixture must be destructive")
        transport.approvalsResult = .success([destructive])
        let store = makeStore(transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.approvals.count == 1 })
        let received = try XCTUnwrapOptional(store.approvals.first?.receivedAt)

        store.restart()
        XCTAssertTrue(waitUntil(timeout: 3) {
            store.syncCount >= 2 && store.phase == .live && store.approvals.count == 1
        })
        XCTAssertEqual(
            store.approvals.first?.receivedAt, received,
            "a reconnect must not reset receivedAt / re-arm the ask (M9)"
        )
        store.stop()
    }

    // MARK: - A 401 on an app↔daemon route is the app's own local access

    /// A refused bearer token (rotated/stale `api.token` after a reinstall or a
    /// daemon restart) must go offline with the local-service copy — never the
    /// provider-key card ("clé... refusée"), and never `.unauthorized`.
    func testUnauthorizedGoesOfflineWithLocalAccessCopyNotAProviderKey() {
        let errors: [AuxdError] = [.unauthorized, .http(status: 401, body: "")]
        for error in errors {
            let transport = FakeTransport()
            transport.healthResult = .failure(error)
            let store = makeStore(transport)
            store.start()
            XCTAssertTrue(waitUntil { store.connection != .connecting }, "\(error)")

            guard case .offline(let label) = store.connection else {
                store.stop()
                return XCTFail("401 must not surface as .unauthorized: \(store.connection)")
            }
            guard case .unreachable(let reason)? = store.offlineCause else {
                store.stop()
                return XCTFail(
                    "401 must reuse the local-service cause, got \(String(describing: store.offlineCause))"
                )
            }
            XCTAssertEqual(reason, label)
            for text in [label, reason] {
                XCTAssertTrue(text.contains("Auxesis"), "\(error): \(text)")
                XCTAssertTrue(
                    text.lowercased().contains("relance"),
                    "\(error): must tell the owner to relaunch: \(text)"
                )
                XCTAssertFalse(text.lowercased().contains("clé"), "\(error): no provider key: \(text)")
                XCTAssertFalse(text.lowercased().contains("key"), "\(error): no provider key: \(text)")
            }
            store.stop()
        }
    }

    /// `AuxdError.message` for a 401 carries the same plain local-access fix,
    /// not "the local key was refused".
    func testUnauthorizedErrorMessageIsLocalAccessNotAServiceKey() {
        let text = AuxdError.unauthorized.message(.fr)
        XCTAssertTrue(text.contains("Auxesis"), text)
        XCTAssertTrue(text.lowercased().contains("relance"), text)
        XCTAssertTrue(text.localizedCaseInsensitiveContains("accès sur ce Mac"), text)
        XCTAssertFalse(text.lowercased().contains("clé"), text)
        XCTAssertFalse(text.lowercased().contains("key"), text)
    }
}
