// Private answers (PRIV-ANSWERS-UI): the answers to the owner's iMessage texts
// that the daemon holds in memory in Private mode (`GET /v1/private/answers`,
// newest first). The app keeps them in this model only: never on disk, never in
// UserDefaults, never in the Store or its cache, never in a log. A restart, or
// a dismiss, drops them.
import Foundation

public struct PrivateAnswer: Decodable, Identifiable, Equatable {
    public let id: String
    public let receivedAt: Date
    public let answer: String

    enum CodingKeys: String, CodingKey {
        case id, answer
        case receivedAt = "received_at"
    }

    public init(id: String, receivedAt: Date, answer: String) {
        self.id = id
        self.receivedAt = receivedAt
        self.answer = answer
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        answer = try container.decode(String.self, forKey: .answer)
        let raw = try container.decode(String.self, forKey: .receivedAt)
        // RFC 3339 with microseconds, e.g. 2026-10-15T09:41:07.123456+00:00.
        // The fraction is not needed for a time of day, so it is dropped.
        let head = raw.prefix(19)
        let zone = raw.dropFirst(19).drop { $0 == "." || $0.isNumber }
        guard let date = ISO8601DateFormatter().date(from: String(head) + String(zone)) else {
            throw DecodingError.dataCorruptedError(forKey: .receivedAt, in: container,
                                                   debugDescription: "received_at is not RFC 3339")
        }
        receivedAt = date
    }

    /// The time of day, 24-hour, for the row: "09:41".
    public func clock(in timeZone: TimeZone = .current) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: receivedAt)
    }
}

/// The Private answers the app is showing. Polls while the Today section is on
/// screen; a dismiss removes the answer at once and keeps it gone on later polls.
@MainActor
public final class PrivateAnswersModel: ObservableObject {
    /// Contract: poll every 10 seconds while the window shows the section.
    public static let interval: UInt64 = 10_000_000_000

    /// Newest first. Empty hides the section.
    @Published public private(set) var answers: [PrivateAnswer] = []
    /// The one answer whose dismiss failed (one inline line, never a modal).
    @Published public private(set) var dismissFailedID: String?

    private let fetch: () async throws -> [PrivateAnswer]
    private let remove: (String) async throws -> Void
    private var dismissed: Set<String> = []
    private var pollTask: Task<Void, Never>?

    public init(fetch: @escaping () async throws -> [PrivateAnswer],
                remove: @escaping (String) async throws -> Void) {
        self.fetch = fetch
        self.remove = remove
    }

    public var isEmpty: Bool { answers.isEmpty }

    /// Starts polling, with a refresh at once. Calling it twice keeps one loop.
    public func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: Self.interval)
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
    }

    /// One read. A failed read keeps what is shown: a blip never blanks the list.
    public func refresh() async {
        guard let fresh = try? await fetch() else { return }
        answers = fresh
            .filter { !dismissed.contains($0.id) }
            .sorted { $0.receivedAt > $1.receivedAt }
    }

    /// Dismisses one answer. A 204 and a 404 (already gone) both remove it;
    /// any other failure keeps it and names it in `dismissFailedID`.
    public func dismiss(_ answer: PrivateAnswer) async {
        do {
            try await remove(answer.id)
        } catch AuxdError.http(status: 404, _) {
            // Already gone on the daemon: the same end state as a 204.
        } catch {
            dismissFailedID = answer.id
            return
        }
        dismissed.insert(answer.id)
        answers.removeAll { $0.id == answer.id }
        dismissFailedID = nil
    }
}
