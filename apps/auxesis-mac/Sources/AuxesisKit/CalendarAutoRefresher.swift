import Foundation

/// Keeps the daemon's calendar snapshot fresh for the 08:00 brief without the
/// owner pressing Settings → Calendar access.
///
/// It only ever reads when access is ALREADY granted: it checks `access` and
/// never calls `requestAccessAndRead` otherwise, so it cannot raise the macOS
/// permission prompt (that stays behind the Settings button). A failed read or
/// publish keeps the last snapshot the daemon holds and logs nothing; the
/// cycle's outcome says why, for "Refresh now" on the Calendar page.
@MainActor public final class CalendarAutoRefresher {
    /// What one cycle did. Never content.
    public enum Outcome: Equatable {
        case published
        /// Calendar access is not granted on this Mac.
        case noAccess
        /// The app is not connected to auxd.
        case offline
        /// The read or the publish failed.
        case failed
    }

    /// One refresh when the app is online, then one every 30 minutes.
    public static let interval: TimeInterval = 30 * 60
    /// How often to look again while the app is not yet connected to auxd.
    public static let readyPoll: TimeInterval = 2

    private let kit: AppleEventKitProviding
    private let publish: (AppleEventKitSnapshot) async throws -> Void
    private let isReady: () -> Bool
    private let sleeper: (TimeInterval) async -> Void

    /// Diagnostics (a count, never content).
    public private(set) var published = 0
    /// The last local read, shown on the Calendar page; nil without access.
    public private(set) var lastRead: AppleEventKitSnapshot?
    /// Called after every cycle, published or not.
    public var didRefresh: ((Outcome) -> Void)?
    /// The cycle running now; a second request joins it instead of reading twice.
    private var inFlight: Task<Outcome, Never>?

    public init(
        kit: AppleEventKitProviding,
        isReady: @escaping () -> Bool,
        publish: @escaping (AppleEventKitSnapshot) async throws -> Void,
        sleeper: @escaping (TimeInterval) async -> Void = { delay in
            try? await Task.sleep(nanoseconds: UInt64(max(0, delay) * 1_000_000_000))
        }
    ) {
        self.kit = kit
        self.isReady = isReady
        self.publish = publish
        self.sleeper = sleeper
    }

    /// Runs until the surrounding task is cancelled.
    public func run() async {
        while !Task.isCancelled {
            if isReady() {
                await refreshOnce()
                await pause(Self.interval)
            } else {
                await pause(Self.readyPoll)
            }
        }
    }

    /// One refresh, or the one already running: the loop and "Refresh now"
    /// never read or publish twice at once.
    @discardableResult
    public func refreshOnce() async -> Outcome {
        if let inFlight { return await inFlight.value }
        let cycle = Task { await self.cycle() }
        inFlight = cycle
        let outcome = await cycle.value
        inFlight = nil
        didRefresh?(outcome)
        return outcome
    }

    private func cycle() async -> Outcome {
        guard kit.access == .authorized else {
            lastRead = nil
            return .noAccess
        }
        do {
            // Never the request path: a refresh must not be able to show a prompt.
            let snapshot = try await kit.readIfAuthorized()
            guard snapshot.authorized else { return .noAccess }
            let bounded = snapshot.boundedAndCleaned()
            lastRead = bounded
            // The page still shows the local read when auxd is not there.
            guard isReady() else { return .offline }
            try await publish(bounded)
            published += 1
            return .published
        } catch {
            return .failed
        }
    }

    @inline(never)
    private func pause(_ delay: TimeInterval) async {
        await sleeper(delay)
    }
}
