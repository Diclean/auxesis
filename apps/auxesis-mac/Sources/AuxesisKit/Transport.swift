// The transport the Store talks to: one protocol so tests can script the
// daemon (snapshots, failures, WS frames) without any network.
import Foundation

public enum AuxdError: Error, LocalizedError, Equatable {
    case badURL
    case unauthorized
    case http(status: Int, body: String)
    case transport(String)
    case decode(String)
    case token(TokenFileProblem)
    /// The final request URL was not a loopback http/ws URL: the client
    /// refuses before attaching the bearer token.
    case offLoopback

    /// Plain words for the owner, in the requested language: never a raw status
    /// code, path or technical message. Richer surfaces map an error to their
    /// own sentence; this is the honest fallback.
    public func message(_ language: Language) -> String {
        switch self {
        case .badURL:
            return L10n.t(.errorBadURL, language)
        case .unauthorized:
            // A 401 on an app↔daemon route is the app's own bearer token
            // (a stale local access key), never a service key. Relaunching
            // makes the app re-read that local access.
            return L10n.t(.errorLocalAccessRelaunch, language)
        case .http:
            if let refusal = budgetRefusal { return refusal.message(language) }
            if apiErrorCode == "thread_busy" { return L10n.t(.errorThreadBusy, language) }
            return L10n.t(.errorServiceRefused, language)
        case .transport(let message):
            if message == AuxdError.timedOutMessage {
                return L10n.t(.errorTimeout, language)
            }
            return L10n.t(.errorUnreachable, language)
        case .decode:
            return L10n.t(.errorUnreadable, language)
        case .token:
            return L10n.t(.errorTokenUnusable, language)
        case .offLoopback:
            return L10n.t(.errorBadURL, language)
        }
    }

    /// `LocalizedError` fallback: the current system language.
    public var errorDescription: String? {
        message(.default)
    }

    /// True for the daemon's honest "not implemented yet" answers.
    public var isNotImplemented: Bool {
        if case .http(let status, _) = self { return status == 501 }
        return false
    }

    /// The daemon's machine-readable `error.code`, when the failure is an HTTP
    /// error carrying the uniform `{"error":{"code":…}}` body. A surface
    /// switches on this, never on prose.
    public var apiErrorCode: String? {
        apiErrorObject?["code"] as? String
    }

    /// The daemon's `error.message`: the human words of the same envelope.
    public var apiErrorMessage: String? {
        apiErrorObject?["message"] as? String
    }

    /// The daemon's `error.detail`: sanitized, actionable reason when it has one.
    public var apiErrorDetail: String? {
        (apiErrorObject?["detail"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// A `429 budget_denied` refusal, with the cap the daemon named.
    ///
    /// The detail is the kernel's reason, e.g. "agent `mail` reached its daily
    /// tokens_out budget (400000/400000 on 2026-11-04)"; the chat names both.
    public var budgetRefusal: BudgetRefusal? {
        guard case .http(let status, _) = self,
              status == 429,
              apiErrorCode == "budget_denied",
              let detail = apiErrorDetail
        else { return nil }
        return BudgetRefusal(detail: detail)
    }

    /// The daemon's reason for refusing an edited card, when it refused one.
    ///
    /// The daemon answers `409` with the code `edited_card_unshowable` and a
    /// reason the owner can act on ("bcc is not supported for mail_send"). The
    /// ask was never taken, so the card can still be fixed and sent: the app
    /// shows the reason instead of a generic service error.
    public var editedCardRefusalReason: String? {
        guard case .http(let status, _) = self,
              status == 409,
              apiErrorCode == Self.editedCardRefusalCode,
              let message = apiErrorMessage
        else { return nil }
        // The daemon puts its own explanation in front of the reason; the
        // reason is what the owner needs.
        let reason = message.hasPrefix(Self.editedCardRefusalPrefix)
            ? String(message.dropFirst(Self.editedCardRefusalPrefix.count))
            : message
        let trimmed = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// The daemon's code for a refused edited card.
    static let editedCardRefusalCode = "edited_card_unshowable"
    /// The daemon's own explanation, before the reason it gives.
    static let editedCardRefusalPrefix = "the edited arguments cannot be shown for approval: "

    /// The error object of the uniform envelope, when the body carries one.
    private var apiErrorObject: [String: Any]? {
        guard case .http(_, let body) = self,
              let data = body.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let error = object["error"] as? [String: Any]
        else { return nil }
        return error
    }
}

/// The parsed substance of a `budget_denied` turn refusal.
public struct BudgetRefusal: Equatable {
    public enum Cap: String, Equatable {
        case tokensIn = "tokens_in"
        case tokensOut = "tokens_out"
        case usdCents = "usd_cents"

        var labelKey: StringKey {
            switch self {
            case .tokensIn: return .capTokensIn
            case .tokensOut: return .capTokensOut
            case .usdCents: return .capUSD
            }
        }
    }

    public let agent: String
    public let cap: Cap?
    public let spent: UInt64?
    public let limit: UInt64?

    public init?(detail: String) {
        guard let start = detail.firstIndex(of: "`") else { return nil }
        let rest = detail[detail.index(after: start)...]
        guard let end = rest.firstIndex(of: "`") else { return nil }
        agent = String(rest[..<end])
        guard !agent.isEmpty else { return nil }
        if let start = detail.range(of: "reached its daily ")?.upperBound,
           let end = detail.range(of: " budget", range: start..<detail.endIndex)?.lowerBound {
            cap = Cap(rawValue: String(detail[start..<end]))
        } else {
            cap = nil
        }
        let amounts = Self.amounts(in: detail)
        spent = amounts.first
        limit = amounts.last
    }

    /// Which agent, which daily cap, how full it is, and the config key that
    /// raises it (Settings has no cap editor yet).
    public func message(_ language: Language) -> String {
        let name = TeamMember.displayName(agent)
        guard let cap, let spent, let limit else {
            return L10n.f(.budgetDeniedOther, language, name, agent)
        }
        return L10n.f(
            .budgetDeniedCap, language, name, L10n.t(cap.labelKey, language),
            spent.formatted(.number.locale(Locale(identifier: language.localeIdentifier))),
            limit.formatted(.number.locale(Locale(identifier: language.localeIdentifier))),
            cap.rawValue, agent
        )
    }

    /// "400000 spent + 20 reserved / 400000 on 2026-11-04" → [400000, 20, 400000].
    private static func amounts(in detail: String) -> [UInt64] {
        guard let open = detail.lastIndex(of: "("),
              let close = detail[open...].firstIndex(of: ")") else { return [] }
        let body = String(detail[detail.index(after: open)..<close])
        let beforeDay = body.components(separatedBy: " on ").first ?? body
        return beforeDay.split(whereSeparator: { !$0.isNumber }).compactMap { UInt64($0) }
    }
}

public protocol AuxdTransport: AnyObject {
    func health() async throws -> HealthResponse
    func agents() async throws -> [AgentSummary]
    func messages(thread: String, limit: Int) async throws -> MessagesPage
    func pendingApprovals() async throws -> [Approval]
    /// Recent run receipts, newest first (`GET /v1/receipts`). Additive: an
    /// older service without the route answers 404 and the read degrades.
    func receipts(agent: String?, limit: Int) async throws -> [Receipt]
    func send(thread: String, content: String) async throws -> SendResponse
    /// Start a fresh chat session for the thread's agent (`POST /v1/threads/{id}/new`).
    func newThread(thread: String) async throws -> SessionJson
    /// CONV-SIDEBAR-1: the owner's past Aux chats (additive; 404 on an older service).
    func conversations() async throws -> [ConversationSummary]
    func resolve(id: String, decision: String, scope: ApprovalScope?, text: String?) async throws -> ApprovalState
    /// Live WS frames; the stream finishes when the socket closes and throws
    /// when it fails. The Store owns reconnection.
    func events() throws -> AsyncThrowingStream<WireEvent, Error>
}

public extension AuxdTransport {
    func messages(thread: String) async throws -> MessagesPage {
        try await messages(thread: thread, limit: 200)
    }

    /// Transports without the route (test fakes) refuse it.
    func newThread(thread: String) async throws -> SessionJson {
        throw AuxdError.http(status: 404, body: "")
    }
    func conversations() async throws -> [ConversationSummary] {
        throw AuxdError.http(status: 404, body: "")
    }
}

/// Deterministic reconnect backoff (no jitter: tests pin the sequence).
public enum ReconnectPolicy {
    public static let initial: TimeInterval = 0.5
    public static let maximum: TimeInterval = 8

    /// `0.5, 1, 2, 4, 8, 8, …` for attempts `1, 2, 3, …`.
    public static func delay(attempt: Int) -> TimeInterval {
        guard attempt > 0 else { return 0 }
        let exponent = min(attempt - 1, 5)
        return min(initial * pow(2, Double(exponent)), maximum)
    }
}
