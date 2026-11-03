// Session-lifetime regressions for `Store.stop()` / `Store.restart()`.
//
// `LifetimeTransport` records the event stream's lifecycle through
// `onTermination` — the same hook `AuxdClient.events()` uses to cancel the real
// websocket — so tests can assert that `stop()` actually closes the socket, that
// a restart never leaves two sockets open at once, and that the fast
// start/stop/restart churn the app performs leaves nothing behind.
import Foundation
import Testing
@testable import AuxesisKit

/// An `AuxdTransport` whose only open-ended resource is the event stream, with
/// counters for "sockets" opened, closed, and simultaneously live.
final class LifetimeTransport: AuxdTransport {
    typealias Termination = AsyncThrowingStream<WireEvent, Error>.Continuation.Termination

    private let lock = NSLock()
    private var _calls: [String] = []
    private var _liveSockets = 0
    private var _opened = 0
    private var _closed = 0
    private var _maxLive = 0
    private var _terminations: [Termination] = []
    private var continuation: AsyncThrowingStream<WireEvent, Error>.Continuation?

    nonisolated(unsafe) var healthResult: Result<HealthResponse, Error>
    nonisolated(unsafe) var agentsResult: Result<[AgentSummary], Error>
    nonisolated(unsafe) var messagesResult: Result<MessagesPage, Error>
    nonisolated(unsafe) var approvalsResult: Result<[Approval], Error>
    /// Runs before `agents()` answers (lets a test hold the snapshot in flight).
    nonisolated(unsafe) var beforeAgents: (() async -> Void)?

    var liveSockets: Int { lock.withLock { _liveSockets } }
    var openedSockets: Int { lock.withLock { _opened } }
    var closedSockets: Int { lock.withLock { _closed } }
    var maxLiveSockets: Int { lock.withLock { _maxLive } }
    var terminations: [Termination] { lock.withLock { _terminations } }
    var calls: [String] { lock.withLock { _calls } }

    init() {
        healthResult = .success(try! Fixtures.health())
        agentsResult = .success((try? Fixtures.agents()) ?? [])
        messagesResult = .success((try? Fixtures.messagesPage()) ?? MessagesPage(thread: nil, messages: []))
        approvalsResult = .success([])
    }

    private func record(_ call: String) {
        lock.withLock { _calls.append(call) }
    }

    func health() async throws -> HealthResponse {
        record("health")
        return try healthResult.get()
    }

    func agents() async throws -> [AgentSummary] {
        if let beforeAgents { await beforeAgents() }
        record("agents")
        return try agentsResult.get()
    }

    func messages(thread: String, limit: Int) async throws -> MessagesPage {
        record("messages")
        return try messagesResult.get()
    }

    func pendingApprovals() async throws -> [Approval] {
        record("approvals")
        return try approvalsResult.get()
    }

    func receipts(agent: String?, limit: Int) async throws -> [Receipt] {
        record("receipts")
        return []
    }

    func send(thread: String, content: String) async throws -> SendResponse {
        record("send")
        return SendResponse()
    }

    func resolve(id: String, decision: String, scope: ApprovalScope?, text: String?) async throws -> ApprovalState {
        record("resolve")
        return .allowed(by: "you", always: false)
    }

    func events() throws -> AsyncThrowingStream<WireEvent, Error> {
        lock.withLock {
            _calls.append("events")
            _opened += 1
            _liveSockets += 1
            _maxLive = max(_maxLive, _liveSockets)
        }
        return AsyncThrowingStream { continuation in
            self.continuation = continuation
            continuation.onTermination = { [weak self] termination in
                guard let self else { return }
                self.lock.withLock {
                    self._liveSockets -= 1
                    self._closed += 1
                    self._terminations.append(termination)
                }
            }
        }
    }

    /// Push one frame into the currently open socket (if any).
    func emit(_ event: WireEvent) {
        continuation?.yield(event)
    }
}

@objcMembers @MainActor final class StoreLifetimeTests: XCTestCase {
    func testStopCancelsConsumerAndClosesSocket() {
        let transport = LifetimeTransport()
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && transport.liveSockets == 1 }, "session live")
        XCTAssertEqual(transport.openedSockets, 1)

        store.stop()

        XCTAssertTrue(waitUntil { transport.liveSockets == 0 }, "stop() must close the socket")
        XCTAssertEqual(transport.closedSockets, 1)
        guard let termination = transport.terminations.last else {
            return XCTFail("the stopped session's stream never terminated")
        }
        if case .cancelled = termination {} else {
            XCTFail("stop() must cancel the consumer, got \(termination)")
        }
        XCTAssertEqual(store.phase, .idle)
    }

    func testRestartNeverLeavesTwoLiveSessions() {
        let transport = LifetimeTransport()
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && transport.liveSockets == 1 }, "first session live")

        store.restart()

        XCTAssertTrue(waitUntil(timeout: 3) { store.syncCount >= 2 && store.phase == .live }, "second session live")
        XCTAssertLessThanOrEqual(transport.maxLiveSockets, 1, "restart() must tear the old session down first")
        XCTAssertEqual(transport.liveSockets, 1, "exactly one live session after restart")

        store.stop()
        XCTAssertTrue(waitUntil { transport.liveSockets == 0 })
        XCTAssertEqual(transport.openedSockets, transport.closedSockets, "no leaked sockets")
    }

    func testEventsFromAStoppedSessionAreIgnored() {
        let transport = LifetimeTransport()
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live })

        transport.emit(.messageDelta(threadId: "7", messageId: "42", text: "live", agent: "scout"))
        XCTAssertTrue(waitUntil { store.acceptedDeltas == 1 }, "live events still apply")

        store.stop()
        XCTAssertTrue(waitUntil { transport.liveSockets == 0 })

        let deltas = store.acceptedDeltas
        let messages = store.messages.count
        transport.emit(.messageDelta(threadId: "7", messageId: "42", text: "stale", agent: "scout"))
        // Give any stray consumer a chance to run before asserting.
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        XCTAssertEqual(store.acceptedDeltas, deltas, "a stopped session must not mutate the Store")
        XCTAssertEqual(store.messages.count, messages)
    }

    func testSnapshotInFlightAcrossStopIsNotApplied() {
        let transport = LifetimeTransport()
        let gate = Gate()
        transport.beforeAgents = { await gate.wait() }
        let store = Store(transport: transport)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .syncing }, "snapshot held in flight")

        store.stop()
        gate.open()
        RunLoop.main.run(until: Date().addingTimeInterval(0.1))

        XCTAssertEqual(store.phase, .idle, "a snapshot landing after stop() must not resurrect the session")
        XCTAssertEqual(store.syncCount, 0, "the stale snapshot must not be applied")
        XCTAssertEqual(store.connection, .connecting)
    }

    func testRapidStartStopRestartLeavesNoLeakedSessions() {
        let transport = LifetimeTransport()
        let store = Store(transport: transport)
        for iteration in 0..<50 {
            store.start()
            XCTAssertTrue(waitUntil(timeout: 3) { store.phase == .live }, "start \(iteration) live")
            store.restart()
            XCTAssertTrue(waitUntil(timeout: 3) { store.phase == .live && transport.liveSockets == 1 }, "restart \(iteration) live")
            XCTAssertLessThanOrEqual(transport.maxLiveSockets, 1, "two live sessions at iteration \(iteration)")
            store.stop()
            XCTAssertTrue(waitUntil(timeout: 3) { transport.liveSockets == 0 }, "stop \(iteration) closed")
        }
        XCTAssertEqual(transport.liveSockets, 0, "zero live sessions at rest")
        XCTAssertEqual(transport.openedSockets, transport.closedSockets, "every opened socket was closed")
        XCTAssertGreaterThanOrEqual(transport.openedSockets, 100, "the churn actually opened sockets")
        XCTAssertEqual(store.phase, .idle)
    }
}
