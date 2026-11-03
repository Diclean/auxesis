// Shared test doubles: no network, no sleeping.
import AuxesisKit
import Foundation

// MARK: - Fixtures

enum Fixtures {
    static var directory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures", isDirectory: true)
    }

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: directory.appendingPathComponent(name))
    }

    static func decode<T: Decodable>(_ type: T.Type, _ name: String) throws -> T {
        try JSONDecoder().decode(T.self, from: data(name))
    }

    /// Recorded WS frames, one JSON object per line.
    static func events() throws -> [WireEvent] {
        let text = try String(contentsOf: directory.appendingPathComponent("events.jsonl"), encoding: .utf8)
        return try text.split(separator: "\n").compactMap { line in
            let data = Data(line.utf8)
            guard !line.isEmpty else { return nil }
            return try WireEventDecoder.decode(data)
        }
    }

    static func health() throws -> HealthResponse { try decode(HealthResponse.self, "health.json") }
    static func agents() throws -> [AgentSummary] { try decode([AgentSummary].self, "agents.json") }
    static func messagesPage() throws -> MessagesPage { try decode(MessagesPage.self, "messages-page.json") }
    static func approvals() throws -> [Approval] { try decode([Approval].self, "approvals.json") }
    static func receipts() throws -> [Receipt] { try decode([Receipt].self, "receipts.json") }

    /// Recorded `run.finished` frames, one JSON object per line (the daemon's
    /// `events.rs::journal_message` envelope with the typed `receipt`).
    static func receiptFrames() throws -> [WireEvent] {
        let text = try String(contentsOf: directory.appendingPathComponent("receipt-frames.jsonl"), encoding: .utf8)
        return try text.split(separator: "\n").compactMap { line in
            guard !line.isEmpty else { return nil }
            return try WireEventDecoder.decode(Data(line.utf8))
        }
    }
}

// MARK: - Run-loop waiting

/// Spin the main run loop until `condition` holds (no blocking sleeps).
@discardableResult
@MainActor
func waitUntil(timeout: TimeInterval = 5, _ condition: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition(), Date() < deadline {
        // `run(until: past)` returns immediately but still drains main-queue
        // work (MainActor jobs); a longer run-loop slice delays them in this
        // CLT-only test process.
        RunLoop.main.run(until: Date())
        usleep(1_000)
    }
    return condition()
}

/// Wait for an async `condition` by re-reading it on every pass, spinning the
/// main run loop exactly as `waitUntil` does. Use this instead of reading an
/// async result once into a captured variable: a single read races the write it
/// is meant to observe, so under load it samples the old value and the
/// condition never re-checks it.
@discardableResult
@MainActor
func waitUntilObserved(timeout: TimeInterval = 5, _ condition: @escaping () async -> Bool) -> Bool {
    var observed = false
    let deadline = Date().addingTimeInterval(timeout)
    Task {
        while !observed, Date() < deadline {
            if await condition() { observed = true; return }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
    }
    return waitUntil(timeout: timeout) { observed }
}

// MARK: - Gate

/// A gate a test can open to release a suspended transport call. Lock-based
/// (not an actor) so a synchronous main-actor test can open it directly.
final class Gate {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        let alreadyOpen: Bool = lock.withLock { isOpen }
        if alreadyOpen { return }
        await withCheckedContinuation { continuation in
            lock.lock()
            if isOpen {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func open() {
        lock.lock()
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        lock.unlock()
        for waiter in pending { waiter.resume() }
    }
}

// MARK: - Fake transport

/// Scripts the daemon: snapshot answers, WS attempts, and a resolve gate.
///
/// `Store.loadSnapshot` fetches health/agents/approvals concurrently (`async let`),
/// and `FakeTransport`'s methods are nonisolated, so the call logs are guarded
/// by a lock — the unguarded `Array.append` used to segfault `swift test` about
/// one run in five (pre-existing flake, kept out of the store logic).
final class FakeTransport: AuxdTransport, PersonalityClient {
    enum EventScript {
        /// Yield these frames, then keep the socket open until `finishEvents`.
        case hold([WireEvent])
        /// Fail the socket immediately.
        case fail(AuxdError)
    }

    // Snapshot answers (mutable from the test).
    nonisolated(unsafe) var healthResult: Result<HealthResponse, Error>
    nonisolated(unsafe) var agentsResult: Result<[AgentSummary], Error>
    nonisolated(unsafe) var messagesResult: Result<MessagesPage, Error>
    /// A page for one thread id or agent name; other threads answer `messagesResult`.
    nonisolated(unsafe) var messagesByThread: [String: MessagesPage] = [:]
    nonisolated(unsafe) var approvalsResult: Result<[Approval], Error>
    nonisolated(unsafe) var receiptsResult: Result<[Receipt], Error> = .success([])
    nonisolated(unsafe) var sendResult: Result<SendResponse, Error>
    nonisolated(unsafe) var conversationsResult: Result<[ConversationSummary], Error> = .success([])
    nonisolated(unsafe) var resolveResult: Result<ApprovalState, Error> = .success(.allowed(by: "you", always: false))
    /// `GET /v1/agents/{id}/soul` answer.
    nonisolated(unsafe) var soulResult: Result<AgentSoul, Error> = .success(AgentSoul(soulMd: ""))
    /// `PUT /v1/agents/{id}` (`soul_md`) answer.
    nonisolated(unsafe) var updateSoulResult: Result<Void, Error> = .success(())
    nonisolated(unsafe) var debugMark: String = ""

    /// Runs before `agents()` answers (lets a test keep the snapshot in flight).
    nonisolated(unsafe) var beforeAgents: (() async -> Void)?
    /// Runs inside `resolve` (lets a test hold the answer open).
    nonisolated(unsafe) var beforeResolve: (() async -> Void)?
    /// Runs before `pendingApprovals()` answers — from the second call on
    /// (lets a test gate the resolve-failure re-fetch, not the first snapshot).
    nonisolated(unsafe) var beforeApprovals: (() async -> Void)?
    /// Runs before `receipts(agent:limit:)` answers.
    nonisolated(unsafe) var beforeReceipts: (() async -> Void)?
    /// Runs before `send(thread:content:)` answers (lets a test hold a send in flight).
    nonisolated(unsafe) var beforeSend: (() async -> Void)?

    /// Per-call `send` answers, first in first out; `sendResult` once empty.
    nonisolated(unsafe) var sendResults: [Result<SendResponse, Error>] = []

    private var callLog: [String] = []
    private var sentLog: [String] = []
    private var resolveLog: [(id: String, decision: String, scope: ApprovalScope?)] = []
    private var resolveTextLog: [String?] = []
    private var approvalsCallCount = 0
    private var receiptsLog: [(agent: String?, limit: Int)] = []
    private var soulSaveLog: [(agent: String, soul: String)] = []

    /// Locked reads: the snapshot fetch calls the transport concurrently.
    var calls: [String] { logLock.withLock { callLog } }
    var sentContents: [String] { logLock.withLock { sentLog } }
    var resolveCalls: [(id: String, decision: String)] {
        logLock.withLock { resolveLog.map { (id: $0.id, decision: $0.decision) } }
    }
    /// Same log as `resolveCalls`, with the `scope` each answer carried.
    var resolveScopes: [(id: String, decision: String, scope: ApprovalScope?)] {
        logLock.withLock { resolveLog }
    }
    /// The edited text each answer carried, nil for a plain yes or no.
    var resolveTexts: [String?] { logLock.withLock { resolveTextLog } }
    var approvalsCalls: Int { logLock.withLock { approvalsCallCount } }
    var receiptsCalls: [(agent: String?, limit: Int)] { logLock.withLock { receiptsLog } }
    var soulSaves: [(agent: String, soul: String)] { logLock.withLock { soulSaveLog } }

    nonisolated(unsafe) var eventScripts: [EventScript] = []
    nonisolated(unsafe) private var continuation: AsyncThrowingStream<WireEvent, Error>.Continuation?
    private let logLock = NSLock()

    private func record(_ call: String) {
        logLock.withLock { callLog.append(call) }
    }

    init() {
        healthResult = .success(try! Fixtures.health())
        agentsResult = .success((try? Fixtures.agents()) ?? [])
        messagesResult = .success((try? Fixtures.messagesPage()) ?? MessagesPage(thread: nil, messages: []))
        approvalsResult = .success([])
        sendResult = .success(SendResponse())
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
        record("messages:\(thread)")
        if let page = messagesByThread[thread] { return page }
        return try messagesResult.get()
    }

    func conversations() async throws -> [ConversationSummary] {
        record("conversations")
        return try conversationsResult.get()
    }

    func pendingApprovals() async throws -> [Approval] {
        let count = logLock.withLock { () -> Int in
            approvalsCallCount += 1
            return approvalsCallCount
        }
        if count > 1, let beforeApprovals { await beforeApprovals() }
        record("approvals")
        return try approvalsResult.get()
    }

    func receipts(agent: String?, limit: Int) async throws -> [Receipt] {
        if let beforeReceipts { await beforeReceipts() }
        logLock.withLock { receiptsLog.append((agent, limit)) }
        record("receipts:\(agent ?? "all")")
        return try receiptsResult.get()
    }

    func send(thread: String, content: String) async throws -> SendResponse {
        record("send:\(thread)")
        let scripted = logLock.withLock { () -> Result<SendResponse, Error>? in
            sentLog.append(content)
            return sendResults.isEmpty ? nil : sendResults.removeFirst()
        }
        if let beforeSend { await beforeSend() }
        return try (scripted ?? sendResult).get()
    }

    func resolve(id: String, decision: String, scope: ApprovalScope?, text: String?) async throws -> ApprovalState {
        logLock.withLock {
            resolveLog.append((id, decision, scope))
            resolveTextLog.append(text)
        }
        if let beforeResolve { await beforeResolve() }
        return try resolveResult.get()
    }

    func agentSoul(name: String) async throws -> AgentSoul {
        record("agentSoul:\(name)")
        return try soulResult.get()
    }

    func updateAgentSoul(name: String, soul: String) async throws {
        logLock.withLock { soulSaveLog.append((name, soul)) }
        record("updateAgentSoul:\(name)")
        return try updateSoulResult.get()
    }

    func events() throws -> AsyncThrowingStream<WireEvent, Error> {
        record("events")
        let script = eventScripts.isEmpty ? EventScript.hold([]) : eventScripts.removeFirst()
        return AsyncThrowingStream { continuation in
            self.continuation = continuation
            switch script {
            case .hold(let frames):
                for frame in frames { continuation.yield(frame) }
            case .fail(let error):
                continuation.finish(throwing: error)
            }
        }
    }

    /// Push one more frame into the currently open socket.
    func emit(_ event: WireEvent) {
        continuation?.yield(event)
    }

    /// Close the current socket cleanly (the Store will reconnect).
    func finishEvents() {
        continuation?.finish()
    }
}
