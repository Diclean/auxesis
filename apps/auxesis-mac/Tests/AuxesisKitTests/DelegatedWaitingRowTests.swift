// WAITING-ROW-DELEGATE: a delegated agent's card is on the Waiting page at
// once, from its frame or from the pending-list refresh, named by its agent.
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class DelegatedWaitingRowTests: XCTestCase {
    private let asked = #"{"type":"approval.new","at":"t","agent":"calendar","approval":{"id":"ap-cal","audit_id":1,"agent":"calendar","thread_id":"2","ts":1,"action":"run calendar_update_event","headline":"Move the 09:30 call","scope_tool":"calendar_update_event","delegation_id":"d-1","state":{"state":"pending"}}}"#

    private func event(_ json: String) -> WireEvent {
        (try? WireEventDecoder.decode(Data(json.utf8))) ?? .other("bad")
    }
    private func liveStore(_ transport: FakeTransport, interval: TimeInterval = 2) -> Store {
        transport.eventScripts = [.hold([])]
        transport.approvalsResult = .success([])
        transport.messagesResult = .success(MessagesPage(thread: nil, messages: []))
        let store = Store(transport: transport, language: .en, approvalPollInterval: interval)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live })
        return store
    }

    func testADelegatedCardsFrameAddsTheWaitingRowWithItsAgent() {
        let transport = FakeTransport()
        let store = liveStore(transport)
        let shell = ShellModel(store: store, client: nil)
        transport.emit(event(asked))
        XCTAssertTrue(waitUntil { store.pendingApprovals.map(\.id) == ["ap-cal"] })
        XCTAssertEqual(store.pendingApprovals.first?.agent, "calendar")
        XCTAssertEqual(shell.waitingListApprovals.map(\.id), ["ap-cal"])
        XCTAssertEqual(shell.rowHeadline(for: store.pendingApprovals[0]), "Move the 09:30 call")
        XCTAssertEqual(TeamMember.displayName(store.pendingApprovals[0].agent), "Calendar")
        store.stop()
    }

    func testAnAnsweredOrExpiredFrameRemovesTheRow() {
        let transport = FakeTransport()
        let store = liveStore(transport)
        let shell = ShellModel(store: store, client: nil)
        transport.emit(event(asked))
        XCTAssertTrue(waitUntil { shell.waitingListApprovals.count == 1 })
        transport.emit(event(#"{"type":"approval.resolved","at":"t","id":"ap-cal","state":{"state":"denied","by":"you"}}"#))
        XCTAssertTrue(waitUntil { shell.waitingListApprovals.isEmpty })
        XCTAssertEqual(store.approvals.first?.state, .denied(by: "you"))
        let second = asked.replacingOccurrences(of: #""ap-cal""#, with: #""ap-cal-2""#)
        transport.emit(event(second))
        XCTAssertTrue(waitUntil { shell.waitingListApprovals.count == 1 })
        transport.emit(event(#"{"type":"approval.updated","at":"t","id":"ap-cal-2","state":{"state":"expired"}}"#))
        XCTAssertTrue(waitUntil { shell.waitingListApprovals.isEmpty })
        store.stop()
    }

    /// A frame the socket never saw is still on the Waiting page within a poll.
    func testThePendingRefreshAddsACardTheFrameMissed() {
        let transport = FakeTransport()
        let store = liveStore(transport, interval: 0.05)
        let card = Approval(id: "ap-cal", auditId: 1, agent: "calendar", threadId: "2", ts: 2,
                            action: "run calendar_update_event", headline: "Move the 09:30 call",
                            scopeTool: "calendar_update_event", delegationId: "d-1")
        transport.approvalsResult = .success([card])
        XCTAssertTrue(waitUntil { store.pendingApprovals.map(\.id) == ["ap-cal"] })
        store.stop()
    }
}
