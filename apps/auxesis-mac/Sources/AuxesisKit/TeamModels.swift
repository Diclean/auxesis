// Wire shapes the new UI reads beyond the Phase 0 client (E1 screen
// contract). Endpoints marked NEW in E1 are decoded tolerantly: a field the
// daemon does not send yet reads as absent, never as a crash. Shapes follow
// the E0 agents runtime.
import Foundation

// MARK: - Delegations

public enum DelegationState: String, Equatable, CaseIterable {
    case queued, working, waiting, done, stopped, failed

    public var isOpen: Bool { self == .queued || self == .working || self == .waiting }
}

/// Where one step's data went. Absent when the daemon did not record it.
public enum StepPlace: Equatable { case stayed, left }

public struct DelegationStep: Equatable, Decodable {
    public enum State: String, Equatable { case done, working, todo }

    public let text: String
    public let at: String?
    public let state: State
    public let place: StepPlace?

    public init(text: String, at: String? = nil, state: State, place: StepPlace? = nil) {
        self.text = text
        self.at = at
        self.state = state
        self.place = place
    }

    enum CodingKeys: String, CodingKey { case text, at, state, place = "where" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        text = (try? c.decode(String.self, forKey: .text)) ?? ""
        at = try? c.decode(String.self, forKey: .at)
        let raw = (try? c.decode(String.self, forKey: .state)) ?? "done"
        switch raw {
        case "working", "current": state = .working
        case "todo", "queued", "pending": state = .todo
        default: state = .done
        }
        switch try? c.decode(String.self, forKey: .place) {
        case "local": place = .stayed
        case "out": place = .left
        default: place = nil
        }
    }
}

public struct Delegation: Identifiable, Equatable, Decodable {
    public let id: String
    public let agent: String
    public let ask: String
    public let at: String
    public var state: DelegationState
    public var steps: [DelegationStep]
    public var progress: (n: Int, of: Int)?
    public var result: String?
    public var tookMs: Int?
    public let brain: String?
    public let approvalId: String?

    public init(
        id: String, agent: String, ask: String, at: String, state: DelegationState,
        steps: [DelegationStep] = [], progress: (n: Int, of: Int)? = nil, result: String? = nil,
        tookMs: Int? = nil, brain: String? = nil, approvalId: String? = nil
    ) {
        self.id = id
        self.agent = agent
        self.ask = ask
        self.at = at
        self.state = state
        self.steps = steps
        self.progress = progress
        self.result = result
        self.tookMs = tookMs
        self.brain = brain
        self.approvalId = approvalId
    }

    public static func == (lhs: Delegation, rhs: Delegation) -> Bool {
        lhs.id == rhs.id && lhs.agent == rhs.agent && lhs.ask == rhs.ask && lhs.at == rhs.at
            && lhs.state == rhs.state && lhs.steps == rhs.steps && lhs.progress?.n == rhs.progress?.n
            && lhs.progress?.of == rhs.progress?.of && lhs.result == rhs.result && lhs.tookMs == rhs.tookMs
            && lhs.brain == rhs.brain && lhs.approvalId == rhs.approvalId
    }

    /// VAGUE-ASK-1: a task that produced no result and recorded no step
    /// attempted nothing: it never ran. It reads as stopped, never as
    /// "couldn't finish" and never as partial work kept.
    public var attemptedNothing: Bool {
        result == nil && steps.isEmpty
    }

    enum CodingKeys: String, CodingKey {
        case id, agent, ask, task, at, state, steps, progress, result, brain
        case createdAt = "created_at"
        case tookMs = "took_ms"
        case took
        case approvalId = "approval_id"
        case progressN = "progress_n"
        case progressOf = "progress_of"
    }

    struct Progress: Decodable { let n: Int; let of: Int }
    /// E0 sends `brain` as `{provider, model}`; older shapes send a string.
    struct Brain: Decodable { let provider: String?; let model: String? }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? ""
        agent = (try? c.decode(String.self, forKey: .agent)) ?? ""
        ask = (try? c.decode(String.self, forKey: .ask)) ?? (try? c.decode(String.self, forKey: .task)) ?? ""
        at = (try? c.decode(String.self, forKey: .at)) ?? (try? c.decode(String.self, forKey: .createdAt)) ?? ""
        let raw = (try? c.decode(String.self, forKey: .state)) ?? "queued"
        state = DelegationState(rawValue: raw) ?? .queued
        steps = (try? c.decode([DelegationStep].self, forKey: .steps)) ?? []
        if let progress = try? c.decode(Progress.self, forKey: .progress) {
            self.progress = (progress.n, progress.of)
        } else if let n = try? c.decode(Int.self, forKey: .progressN), let of = try? c.decode(Int.self, forKey: .progressOf) {
            self.progress = (n, of)
        } else {
            self.progress = nil
        }
        result = try? c.decode(String.self, forKey: .result)
        tookMs = (try? c.decode(Int.self, forKey: .tookMs)) ?? (try? c.decode(Int.self, forKey: .took))
        if let text = try? c.decode(String.self, forKey: .brain) {
            brain = text
        } else if let object = try? c.decode(Brain.self, forKey: .brain) {
            brain = object.model ?? object.provider
        } else {
            brain = nil
        }
        approvalId = try? c.decode(String.self, forKey: .approvalId)
    }
}

// MARK: - Coverage (`GET /v1/privacy/coverage`)

public struct CoverageRow: Identifiable, Equatable, Decodable {
    public enum State: String, Equatable { case covered, partial, missed }

    public let id: String
    public let label: String
    public let state: State
    /// What Private mode does: `allow`, `ask` or `off`.
    public let privateMode: String
    public let choke: String

    public init(id: String, label: String, state: State, privateMode: String, choke: String) {
        self.id = id
        self.label = label
        self.state = state
        self.privateMode = privateMode
        self.choke = choke
    }

    enum CodingKeys: String, CodingKey {
        case id, label, state, choke
        case privateMode = "private"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? ""
        label = (try? c.decode(String.self, forKey: .label)) ?? ""
        state = State(rawValue: (try? c.decode(String.self, forKey: .state)) ?? "") ?? .missed
        privateMode = (try? c.decode(String.self, forKey: .privateMode)) ?? "off"
        choke = (try? c.decode(String.self, forKey: .choke)) ?? "none"
    }
}

public struct CoverageResponse: Equatable, Decodable {
    public let paths: [CoverageRow]

    public init(paths: [CoverageRow]) { self.paths = paths }
}

// MARK: - Ledger

/// One `GET /v1/activity` row, with the skill and its pinned hash when the
/// event belongs to a skill run (E2 accept line).
public struct LedgerEntry: Equatable, Decodable, Identifiable {
    public let at: String
    public let kind: String
    public let agent: String?
    public let summary: String
    public let skill: String?
    public let skillHash: String?

    public var id: String { "\(at)|\(kind)|\(agent ?? "")|\(summary)" }

    public init(at: String, kind: String, agent: String?, summary: String, skill: String? = nil, skillHash: String? = nil) {
        self.at = at
        self.kind = kind
        self.agent = agent
        self.summary = summary
        self.skill = skill
        self.skillHash = skillHash
    }

    enum CodingKeys: String, CodingKey {
        case at, kind, agent, summary, skill
        case skillHash = "skill_hash"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        at = (try? c.decode(String.self, forKey: .at)) ?? ""
        kind = (try? c.decode(String.self, forKey: .kind)) ?? ""
        agent = try? c.decode(String.self, forKey: .agent)
        summary = (try? c.decode(String.self, forKey: .summary)) ?? ""
        skill = try? c.decode(String.self, forKey: .skill)
        skillHash = try? c.decode(String.self, forKey: .skillHash)
    }
}

/// A scheduled job's health from `GET /v1/jobs`. Anything else, or a
/// missing field (older daemons), reads as `unknown`.
public enum JobHealth: String, Equatable {
    case ok, late, failing, unknown

    public init(raw: String?) {
        self = raw.flatMap { JobHealth(rawValue: $0.trimmingCharacters(in: .whitespaces).lowercased()) } ?? .unknown
    }
}

/// One `GET /v1/jobs` row: the Ledger's Planned tab.
public struct PlannedJob: Equatable, Decodable, Identifiable {
    public let id: Int
    public let agent: String
    public let name: String
    public let schedule: String
    public let enabled: Bool
    public let nextRunAt: String?
    public let health: JobHealth
    /// The daemon's own words, e.g. "Morning brief failed at 07:02".
    public let reason: String?

    public init(id: Int, agent: String, name: String, schedule: String, enabled: Bool = true, nextRunAt: String? = nil,
                health: JobHealth = .unknown, reason: String? = nil) {
        self.id = id
        self.agent = agent
        self.name = name
        self.schedule = schedule
        self.enabled = enabled
        self.nextRunAt = nextRunAt
        self.health = health
        self.reason = reason
    }

    enum CodingKeys: String, CodingKey {
        case id, agent, name, schedule, enabled, health, reason
        case nextRunAt = "next_run_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(Int.self, forKey: .id)) ?? 0
        agent = (try? c.decode(String.self, forKey: .agent)) ?? ""
        name = (try? c.decode(String.self, forKey: .name)) ?? ""
        schedule = (try? c.decode(String.self, forKey: .schedule)) ?? ""
        enabled = (try? c.decode(Bool.self, forKey: .enabled)) ?? true
        nextRunAt = try? c.decode(String.self, forKey: .nextRunAt)
        health = JobHealth(raw: try? c.decode(String.self, forKey: .health))
        let said = (try? c.decode(String.self, forKey: .reason))?.trimmingCharacters(in: .whitespacesAndNewlines)
        reason = said?.isEmpty == false ? said : nil
    }
}

/// `GET /v1/usage`: today's spend for Budgets & Stop.
public struct UsageDay: Equatable, Decodable {
    public let day: String
    public let total: UsageTotals

    public init(day: String, total: UsageTotals) {
        self.day = day
        self.total = total
    }

    enum CodingKeys: String, CodingKey { case day, total }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        day = (try? c.decode(String.self, forKey: .day)) ?? ""
        total = (try? c.decode(UsageTotals.self, forKey: .total)) ?? UsageTotals()
    }
}

// MARK: - Agent profile

public struct AgentGrants: Equatable, Decodable {
    public struct See: Equatable, Decodable {
        public let scope: String
        public let via: String
        /// `read`, `ask` or `off`.
        public let level: String

        public init(scope: String, via: String, level: String) {
            self.scope = scope
            self.via = via
            self.level = level
        }
    }

    public struct Do: Equatable, Decodable {
        public let skill: String
        /// `auto`, `ask` or `off`.
        public let level: String

        public init(skill: String, level: String) {
            self.skill = skill
            self.level = level
        }
    }

    public let see: [See]
    public let canDo: [Do]
    public let never: [String]
    public let egressNote: String

    public init(see: [See], canDo: [Do], never: [String], egressNote: String) {
        self.see = see
        self.canDo = canDo
        self.never = never
        self.egressNote = egressNote
    }

    enum CodingKeys: String, CodingKey {
        case see, never
        case canDo = "do"
        case canDoLong = "can_do"
        case egressNote = "egress_note"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        see = (try? c.decode([See].self, forKey: .see)) ?? []
        canDo = (try? c.decode([Do].self, forKey: .canDo)) ?? (try? c.decode([Do].self, forKey: .canDoLong)) ?? []
        never = (try? c.decode([String].self, forKey: .never)) ?? []
        egressNote = (try? c.decode(String.self, forKey: .egressNote)) ?? ""
    }
}

public struct MemoryItem: Equatable, Decodable, Identifiable {
    public let id: String
    public let text: String
    public let at: String?

    public init(id: String, text: String, at: String? = nil) {
        self.id = id
        self.text = text
        self.at = at
    }

    enum CodingKeys: String, CodingKey { case id, text, at }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let number = try? c.decode(Int.self, forKey: .id) {
            id = String(number)
        } else {
            id = (try? c.decode(String.self, forKey: .id)) ?? ""
        }
        text = (try? c.decode(String.self, forKey: .text)) ?? ""
        at = try? c.decode(String.self, forKey: .at)
    }
}

// MARK: - What the model saw

/// The record behind "What Mail sent to its brain". `tokenised`
/// maps a message id to the text the provider received, tokens included
/// (NEW in E1); without it the panel still says who sent what, when, and how
/// much left this Mac, from the receipt.
public struct ModelSawRecord: Equatable {
    public let agent: String
    public let at: Date?
    public let kept: [String]
    public let sentSummary: String
    public let tokenised: [String: String]

    public init(agent: String, at: Date?, kept: [String], sentSummary: String, tokenised: [String: String] = [:]) {
        self.agent = agent
        self.at = at
        self.kept = kept
        self.sentSummary = sentSummary
        self.tokenised = tokenised
    }

    /// The receipt of the run that produced a reply at `at` (newest first in
    /// `receipts`): the first one that started before it.
    public static func from(receipts: [Receipt], agent: String, at: Date) -> ModelSawRecord? {
        let match = receipts.first { receipt in
            guard receipt.agent == agent else { return false }
            let started = TimeText.parse(receipt.started) ?? TimeText.parse(receipt.finished)
            return started.map { $0 <= at.addingTimeInterval(60) } ?? false
        }
        guard let match else { return nil }
        let hosts = match.hostsContacted.isEmpty ? "" : " · " + match.hostsContacted.joined(separator: ", ")
        return ModelSawRecord(
            agent: agent,
            at: TimeText.parse(match.finished) ?? TimeText.parse(match.started),
            kept: [],
            sentSummary: "\(match.tokensIn) tokens in, \(match.tokensOut) out\(hosts)"
        )
    }
}
