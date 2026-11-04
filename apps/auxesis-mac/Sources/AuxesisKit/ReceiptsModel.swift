import Foundation

/// The run receipts the app keeps in memory, newest first. Live `run.finished`
/// frames and the `GET /v1/receipts` snapshot both merge here, deduplicated by
/// `runId`.
///
/// `Store` owns one and forwards its changes, so a view that observes the
/// store redraws when this changes. The model only talks to the service
/// through the read it is given.
@MainActor
public final class ReceiptsModel: ObservableObject {
    /// How many receipts the app keeps in memory (the daemon prunes the rest).
    public static let limit = 100

    @Published public private(set) var receipts: [Receipt] = []

    /// How many receipt reads failed and were handled. The count moves
    /// *after* the catch has run, so a test can wait for it instead of
    /// sleeping: a failure that has not landed yet looks exactly like a
    /// failure that left the state untouched.
    private(set) var failedReads = 0

    private let fetch: (String?, Int) async throws -> [Receipt]

    init(fetch: @escaping (String?, Int) async throws -> [Receipt]) {
        self.fetch = fetch
    }

    /// One agent's recent receipts, newest first (the thread's receipt rows).
    public func receipts(for agentName: String) -> [Receipt] {
        receipts.filter { $0.agent == agentName }
    }

    /// Read from the service, newest first. `nil` when the read failed; the
    /// caller records the failure with `noteFailedRead()` once it has written
    /// whatever state depends on it.
    func read(agent: String?) async -> [Receipt]? {
        try? await fetch(agent, Self.limit)
    }

    func noteFailedRead() {
        failedReads += 1
    }

    /// One receipt: a known `runId` is replaced **in place** (a replayed frame
    /// must not jump an old run to the top); a new one goes to the front.
    func upsert(_ receipt: Receipt) {
        if !receipt.runId.isEmpty,
           let index = receipts.firstIndex(where: { $0.runId == receipt.runId }) {
            receipts[index] = receipt
            return
        }
        receipts.insert(receipt, at: 0)
        if receipts.count > Self.limit {
            receipts.removeLast(receipts.count - Self.limit)
        }
    }

    /// Merge a newest-first page without disturbing an already-known run's
    /// position (the snapshot is authoritative on content, not on order).
    func merge(_ incoming: [Receipt]) {
        for receipt in incoming.reversed() {
            upsert(receipt)
        }
    }
}
