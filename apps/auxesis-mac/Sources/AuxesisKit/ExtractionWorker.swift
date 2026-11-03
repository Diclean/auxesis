// The extraction worker (C2c): while the app runs, claim one document at a
// time from auxd's local queue, fetch its bytes into memory, extract on device
// and post the text back. The bytes are never written to disk, and the only
// host this file can reach is the loopback auxd the resolver chose.
//
// Privacy: this file has no `print`, no `NSLog` and no `os_log`. The only
// outward reporting is `ExtractionEvent`, which carries a hash prefix and a
// count — never a file name and never a byte of extracted text.
import Foundation

/// One document handed to the bridge: `{hash, mime, size}`, never a name.
public struct PendingDocument: Decodable, Equatable, Sendable {
    public let hash: String
    public let mime: String
    public let size: Int

    public init(hash: String, mime: String, size: Int) {
        self.hash = hash
        self.mime = mime
        self.size = size
    }
}

/// The three docs routes the worker needs. `AuxdClient` is the real one; tests
/// script an in-process fake.
public protocol DocsExtractionClient: AnyObject {
    /// `GET /v1/docs/extract/pending?limit=N`: claim up to N documents.
    func pendingDocuments(limit: Int) async throws -> [PendingDocument]
    /// `GET /v1/docs/{hash}/blob`: the original bytes, only while claimed.
    func documentBlob(sha256: String) async throws -> Data
    /// `POST /v1/docs/{hash}/extraction`: the extracted text.
    func postExtraction(sha256: String, extractor: ExtractionKind, text: String, pages: Int) async throws
}

/// Deterministic backoff for the idle loop (no jitter: tests pin the sequence).
public enum ExtractionBackoff {
    public static let initial: TimeInterval = 5
    public static let maximum: TimeInterval = 300

    /// `5, 10, 20, 40, 80, 160, 300, …` for attempts `1, 2, …`.
    public static func delay(attempt: Int) -> TimeInterval {
        guard attempt > 0 else { return 0 }
        let exponent = min(attempt - 1, 6)
        return min(initial * pow(2, Double(exponent)), maximum)
    }
}

/// What the worker reports, and all it reports: a hash prefix and counts.
public enum ExtractionEvent: Equatable, Sendable {
    case claimed(prefix: String)
    case posted(prefix: String, extractor: ExtractionKind)
    case failed(kind: String)
}

/// Claims, extracts and posts, one document at a time.
public final class ExtractionWorker {
    /// Politeness pause when the queue is empty or a claim was skipped.
    public static let idleInterval: TimeInterval = 30
    /// Claim one document per cycle: one at a time, never a batch.
    public static let claimLimit = 1
    /// A document that keeps failing must not block the head of the queue:
    /// after this many attempts the bridge answers `none` and moves on.
    public static let maxAttemptsPerDocument = 3

    private let client: DocsExtractionClient
    private let extractor: DocumentExtractor
    private let baseURL: URL?
    private let sleeper: (TimeInterval) async -> Void
    private let onEvent: (ExtractionEvent) -> Void
    private var task: Task<Void, Never>?
    private var consecutiveFailures = 0
    /// Retryable failures per hash, cleared once the document settles (posted
    /// or skipped). This is what stops a poison document blocking the queue.
    private var failuresByHash: [String: Int] = [:]

    /// Diagnostics (real counts, never content).
    public private(set) var cycles = 0
    public private(set) var posted = 0
    public private(set) var lastFailure: String?

    public init(
        client: DocsExtractionClient,
        extractor: DocumentExtractor = DocumentExtractor(),
        baseURL: URL?,
        sleeper: @escaping (TimeInterval) async -> Void = { delay in
            try? await Task.sleep(nanoseconds: UInt64(max(0, delay) * 1_000_000_000))
        },
        onEvent: @escaping (ExtractionEvent) -> Void = { _ in }
    ) {
        self.client = client
        self.extractor = extractor
        self.baseURL = baseURL
        self.sleeper = sleeper
        self.onEvent = onEvent
    }

    public var isRunning: Bool { task != nil }

    /// Start only when the resolved endpoint is loopback. Returns `false` and
    /// starts nothing otherwise — a token must never be pointed off-box.
    @discardableResult
    public func start() -> Bool {
        guard task == nil else { return false }
        guard Self.isLoopback(baseURL) else { return false }
        task = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let delay = await self.runOneCycle()
                if Task.isCancelled { return }
                await self.pause(delay)
            }
        }
        return true
    }

    public func stop() {
        task?.cancel()
        task = nil
    }

    /// True when `url` is an `http`/`ws` URL on a loopback host (Loopback.swift
    /// owns the exact rules).
    public static func isLoopback(_ url: URL?) -> Bool {
        guard let url else { return false }
        return LoopbackURL.isSafeRequestURL(url)
    }

    /// One claim → fetch → extract → post. Returns the delay before the next
    /// cycle (`0` while the queue is busy). Exposed so tests drive it without a
    /// clock.
    @discardableResult
    public func runOneCycle() async -> TimeInterval {
        cycles += 1
        let pending: [PendingDocument]
        do {
            pending = try await client.pendingDocuments(limit: Self.claimLimit)
        } catch {
            return recordFailure(error)
        }
        // The hash is the only shape auxd accepts; anything else never gets a
        // URL built and never gets a post.
        guard let document = pending.first, BridgeSHA256.isValid(document.hash) else {
            return settle(Self.idleInterval)
        }
        switch await process(document) {
        case .posted(let hash):
            failuresByHash[hash] = nil
            return settle(0)
        case .skipped(let hash):
            failuresByHash[hash] = nil
            return settle(Self.idleInterval)
        case .retry(let error, let hash):
            failuresByHash[hash, default: 0] += 1
            return recordFailure(error)
        }
    }

    /// A cycle with no retryable failure clears the backoff.
    private func settle(_ delay: TimeInterval) -> TimeInterval {
        consecutiveFailures = 0
        lastFailure = nil
        return delay
    }

    private enum ProcessOutcome {
        case posted(hash: String)
        case skipped(hash: String)
        case retry(Error, hash: String)
    }

    private func process(_ document: PendingDocument) async -> ProcessOutcome {
        let hash = document.hash
        let prefix = String(hash.prefix(8))
        onEvent(.claimed(prefix: prefix))

        // A poison document must not block the head of the queue: after
        // `maxAttemptsPerDocument` retryable failures, answer `none` so the row
        // leaves its claim and the next document is served.
        if (failuresByHash[hash] ?? 0) >= Self.maxAttemptsPerDocument {
            return await post(hash, prefix: prefix, output: .none)
        }

        // Refuse an oversize input before the blob is fetched or parsed, and
        // still answer `none` so the row leaves its claim.
        if document.size > DocumentExtractor.maxInputBytes {
            return await post(hash, prefix: prefix, output: .none)
        }

        let data: Data
        do {
            data = try await client.documentBlob(sha256: hash)
        } catch let error as AuxdError {
            // 404: the claim lapsed; there is no text to post for it.
            if case .http(404, _) = error { return .skipped(hash: hash) }
            return .retry(error, hash: hash)
        } catch {
            return .retry(error, hash: hash)
        }

        let output = extractor.extract(data: data, mime: document.mime)
        return await post(hash, prefix: prefix, output: output)
    }

    private func post(_ hash: String, prefix: String, output: ExtractionOutput) async -> ProcessOutcome {
        do {
            try await client.postExtraction(
                sha256: hash, extractor: output.extractor, text: output.text, pages: output.pages)
            posted += 1
            onEvent(.posted(prefix: prefix, extractor: output.extractor))
            return .posted(hash: hash)
        } catch let error as AuxdError {
            // 404 (claim gone) and 409 (not claimed) mean the text has nowhere
            // to go: drop it, never retry it against an unclaimed hash.
            if case .http(404, _) = error { return .skipped(hash: hash) }
            if case .http(409, _) = error { return .skipped(hash: hash) }
            return .retry(error, hash: hash)
        } catch {
            return .retry(error, hash: hash)
        }
    }

    private func recordFailure(_ error: Error) -> TimeInterval {
        consecutiveFailures += 1
        let label = Self.failureLabel(error)
        lastFailure = label
        onEvent(.failed(kind: label))
        return ExtractionBackoff.delay(attempt: consecutiveFailures)
    }

    /// A value-free label for diagnostics (never a body, path or status text).
    static func failureLabel(_ error: Error) -> String {
        guard let auxd = error as? AuxdError else { return "failed" }
        switch auxd {
        case .unauthorized: return "unauthorized"
        case .http(let status, _): return "http:\(status)"
        case .transport: return "transport"
        case .decode: return "decode"
        case .badURL: return "bad_url"
        case .token: return "token"
        case .offLoopback: return "off_loopback"
        }
    }

    /// Its own frame, so the task allocator does not sink the dealloc across
    /// the loop's suspension point (see `Store.pause`).
    @inline(never)
    private func pause(_ delay: TimeInterval) async {
        await sleeper(delay)
    }
}
