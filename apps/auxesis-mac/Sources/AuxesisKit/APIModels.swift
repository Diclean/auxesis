// Codable models for the real auxd API (B-API v1/v2/v3).
//
// Two layers, on purpose:
//   * `…Wire`-style structs below decode the daemon's *exact* JSON —
//     crates/auxd/src/api/snapshot.rs (REST), wire.rs (WS frames),
//     and routes.rs (health, resolve) — the Swift client is now the
//     reference consumer contract;
//   * `Agent` / `ChatMessage` / `Approval` are what the UI renders, mapped by
//     the small functions at the bottom.
//
// Unknown JSON fields are ignored; unknown `kind`s/`type`s become `.other`
// so a newer daemon never breaks decoding (WF-1's `message.delta` included).
import Foundation

// MARK: - Health / agents (GET /v1/health, GET /v1/agents)

public struct HealthResponse: Decodable, Equatable {
    public let ok: Bool
    public let version: String
    public let pid: UInt32
    /// True until at least one provider is configured and one agent exists.
    public let firstRun: Bool
    /// True when this Mac holds a Google authorization (G4). An older service
    /// that does not answer the field reads as not connected.
    public let googleConnected: Bool
    /// True when Google needs to approve a permission added by Auxesis.
    public let googleReconnectNeeded: Bool

    enum CodingKeys: String, CodingKey {
        case ok, version, pid
        case firstRun = "first_run"
        case googleConnected = "google_connected"
        case googleReconnectNeeded = "google_reconnect_needed"
    }

    public init(
        ok: Bool,
        version: String,
        pid: UInt32,
        firstRun: Bool,
        googleConnected: Bool = false,
        googleReconnectNeeded: Bool = false
    ) {
        self.ok = ok
        self.version = version
        self.pid = pid
        self.firstRun = firstRun
        self.googleConnected = googleConnected
        self.googleReconnectNeeded = googleReconnectNeeded
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ok = try container.decode(Bool.self, forKey: .ok)
        version = try container.decode(String.self, forKey: .version)
        pid = try container.decode(UInt32.self, forKey: .pid)
        firstRun = try container.decode(Bool.self, forKey: .firstRun)
        // Additive: a service older than G4 simply has no such field.
        googleConnected = try container.decodeIfPresent(Bool.self, forKey: .googleConnected) ?? false
        googleReconnectNeeded = try container.decodeIfPresent(Bool.self, forKey: .googleReconnectNeeded) ?? false
    }
}

/// `POST /v1/google/connect` and `POST /v1/google/disconnect` answer with
/// booleans only: never a token, never an email address, never a client id.
public struct GoogleConnection: Decodable, Equatable {
    /// Whether this Mac holds a Google authorization right now.
    public let connected: Bool
    /// True when the call just started a sign-in that is still in flight; the
    /// browser page is open and the owner has not answered yet.
    public let started: Bool
    /// True when the flow was started to add permissions to an old grant.
    public let reconnectNeeded: Bool

    enum CodingKeys: String, CodingKey {
        case connected, started
        case reconnectNeeded = "reconnect_needed"
    }

    public init(connected: Bool, started: Bool, reconnectNeeded: Bool = false) {
        self.connected = connected
        self.started = started
        self.reconnectNeeded = reconnectNeeded
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        connected = try container.decode(Bool.self, forKey: .connected)
        started = try container.decode(Bool.self, forKey: .started)
        reconnectNeeded = try container.decodeIfPresent(Bool.self, forKey: .reconnectNeeded) ?? false
    }
}

public struct TelegramSettings: Decodable, Equatable {
    public let enabled: Bool
    public let secretPresent: Bool
    public let paired: Bool

    enum CodingKeys: String, CodingKey {
        case enabled
        case secretPresent = "secret_present"
        case paired
    }
}

public struct McpCatalogEntry: Decodable, Equatable, Identifiable {
    public let id: String; public let name: String; public let region: String; public let category: String
    public let status: String; public let tier: String; public let auth: String; public let access: String
    public let transport: String; public let endpoint: String?; public let repoUrl: String?; public let notes: String?; public let dataClass: String
    enum CodingKeys: String, CodingKey { case id, name, region, category, status, tier, auth, access, transport, endpoint, notes; case repoUrl = "repo_url"; case dataClass = "data_class" }
}
public struct McpToolView: Decodable, Equatable, Identifiable { public let name: String; public let risk: String; public var id: String { name } }
public struct McpServerView: Decodable, Equatable, Identifiable {
    public let id: String; public let enabled: Bool; public let state: String; public let transport: String
    public let auth: String; public let tools: [McpToolView]; public let agents: [String: [String]]; public let dataClass: String
    public let reason: String?; public let highRisk: String?
    enum CodingKeys: String, CodingKey { case id, enabled, state, transport, auth, tools, agents, dots, reason; case dataClass = "data_class"; case highRisk = "high_risk" }

    /// `agents` is the current key; the pre-WO-07 `dots` spelling is still read
    /// for one release, so an older daemon keeps decoding.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        state = try container.decode(String.self, forKey: .state)
        transport = try container.decode(String.self, forKey: .transport)
        auth = try container.decode(String.self, forKey: .auth)
        tools = try container.decode([McpToolView].self, forKey: .tools)
        if let current = try container.decodeIfPresent([String: [String]].self, forKey: .agents) {
            agents = current
        } else {
            agents = try container.decode([String: [String]].self, forKey: .dots)
        }
        dataClass = try container.decode(String.self, forKey: .dataClass)
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
        highRisk = try container.decodeIfPresent(String.self, forKey: .highRisk)
    }
}
public struct McpCatalogResponse: Decodable { public let servers: [McpCatalogEntry] }
public struct McpPack: Decodable, Equatable, Identifiable {
    public let id: String; public let titleEn: String; public let titleFr: String
    public let descriptionEn: String; public let descriptionFr: String
    public let serverCount: Int; public let keyRequired: [String]
    enum CodingKeys: String, CodingKey { case id; case titleEn = "title_en"; case titleFr = "title_fr"; case descriptionEn = "description_en"; case descriptionFr = "description_fr"; case serverCount = "server_count"; case keyRequired = "key_required" }
}
public struct McpPacksResponse: Decodable { public let packs: [McpPack] }
public struct McpPackEnableBody: Encodable { public let agent: String }
public struct McpServersResponse: Decodable { public let servers: [McpServerView] }
public struct McpAck: Decodable { public let ok: Bool }
public struct McpConnectionTest: Decodable, Equatable { public struct Tool: Decodable, Equatable, Identifiable { public let name: String; public let risk: String; public var id: String { name } }; public let name: String; public let tools: [Tool]; public let digest: String }
public struct McpUrlBody: Encodable { let id: String; let url: String; let dataClass: String; let testDigest: String; enum CodingKeys: String, CodingKey { case id, url; case dataClass = "data_class"; case testDigest = "test_digest" } }
public struct McpTestBody: Encodable { let url: String }
public struct McpAddBody: Encodable { let id: String; let catalogID: String; let agent: String; enum CodingKeys: String, CodingKey { case id, agent; case catalogID = "catalog_id" } }
public struct McpEnabledBody: Encodable { let enabled: Bool }
public struct McpToolsBody: Encodable { let tools: [String] }
// M6-2 (#527): the install preview from `POST /servers` (flat, beside `ok`) or `GET /servers/{id}/approval`.
public struct McpApprovalPreview: Decodable, Equatable, Identifiable {
    public struct Tool: Decodable, Equatable, Identifiable { public let name: String; public let risk: String; public let access: String; public var id: String { name } }
    public let id: String; public let transport: String; public let enabled: Bool; public let network: Bool
    public let env: [String]; public let dataClass: String; public let endpoint: String?; public let command: String?
    public let args: [String]; public let tools: [Tool]; public let catalogPin: String?; public let hash: String
    enum CodingKeys: String, CodingKey { case id, transport, enabled, network, env, endpoint, command, args, tools, hash; case dataClass = "data_class"; case catalogPin = "catalog_pin" }
}
public struct McpApproveBody: Encodable { let hash: String; let agent: String }
// Item 12: the confirmation preview and the confirm request. NOTE: these
// Swift sources are NOT compiled by the Rust gates; kept deliberately simple.
public struct McpConfirmationDetails: Decodable, Equatable {
    public let id: String; public let command: String; public let args: [String]; public let env: [String]
    public let network: Bool; public let dataClass: String; public let binaryHash: String
    public let highRisk: String?; public let hash: String; public let warning: String
    /// Item 2: `stdio_unverified_program` for every non-catalog stdio server,
    /// whatever `high_risk` says, so a missing heuristic label is never
    /// reassuring. `nil` only for a catalog server.
    public let unverifiedProgram: String?
    enum CodingKeys: String, CodingKey {
        case id, command, args, env, network, hash, warning
        case dataClass = "data_class"; case binaryHash = "binary_hash"; case highRisk = "high_risk"
        case unverifiedProgram = "unverified_program"
    }

    /// Item 6: the daemon sends a warning **code**, never English copy. Translate
    /// it here, following the app language; an unknown code falls back to the
    /// generic confirmation warning rather than showing a raw key.
    public func warningText(_ language: Language) -> String {
        switch warning {
        case "mcp_stdio_confirmation": return L10n.t(.pluginsConfirmWarning, language)
        default: return L10n.t(.pluginsConfirmWarning, language)
        }
    }

    /// Item 2: the generic "unverified program" copy, shown in addition to the
    /// heuristic warnings. `nil` when the daemon did not send the code.
    public func unverifiedProgramText(_ language: Language) -> String? {
        guard unverifiedProgram == "stdio_unverified_program" else { return nil }
        return L10n.t(.pluginsUnverifiedProgram, language)
    }
}
public struct McpConfirmBody: Encodable { public let hash: String }

public struct TelegramPairingCode: Decodable, Equatable {
    public let code: String
}

public struct UsageTotals: Decodable, Equatable {
    public let tokensIn: UInt64
    public let tokensOut: UInt64
    public let usdCents: UInt64

    enum CodingKeys: String, CodingKey {
        case tokensIn = "tokens_in"
        case tokensOut = "tokens_out"
        case usdCents = "usd_cents"
    }

    public init(tokensIn: UInt64 = 0, tokensOut: UInt64 = 0, usdCents: UInt64 = 0) {
        self.tokensIn = tokensIn
        self.tokensOut = tokensOut
        self.usdCents = usdCents
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        tokensIn = (try? c.decode(UInt64.self, forKey: .tokensIn)) ?? 0
        tokensOut = (try? c.decode(UInt64.self, forKey: .tokensOut)) ?? 0
        usdCents = (try? c.decode(UInt64.self, forKey: .usdCents)) ?? 0
    }
}

public struct ActivityEntry: Decodable, Equatable {
    public let at: String
    public let kind: String
    public let agent: String?
    public let summary: String

    public init(at: String = "", kind: String = "", agent: String? = nil, summary: String = "") {
        self.at = at
        self.kind = kind
        self.agent = agent
        self.summary = summary
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        at = (try? c.decode(String.self, forKey: .at)) ?? ""
        kind = (try? c.decode(String.self, forKey: .kind)) ?? ""
        agent = try? c.decode(String.self, forKey: .agent)
        summary = (try? c.decode(String.self, forKey: .summary)) ?? ""
    }

    enum CodingKeys: String, CodingKey { case at, kind, agent, summary }
}

/// The daemon's live privacy mode for one agent (MODE-CHIP-TRUTH).
///
/// It comes from `privacy_mode` on `GET /v1/agents`. A missing or
/// unrecognised value is `.unknown`, so the app never claims "Private" on an
/// old daemon or a read it could not understand.
public enum PrivacyMode: Equatable {
    case privateMode
    case open
    case unknown

    public init(raw: String?) {
        switch raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "private": self = .privateMode
        case "open": self = .open
        default: self = .unknown
        }
    }

    /// The header chip's words. Unknown says so, never "Private".
    public var chipKey: UIKey {
        switch self {
        case .privateMode: return .privateChip
        case .open: return .open
        case .unknown: return .modeUnknownChip
        }
    }

    /// The phrase the composer footer inserts for this mode.
    public var composerKey: UIKey {
        switch self {
        case .privateMode: return .modePhrasePrivate
        case .open: return .modePhraseOpen
        case .unknown: return .modePhraseUnknown
        }
    }

    /// The hover detail behind the footer, when the mode has its own text.
    /// Private keeps the per-agent, per-brain detail the composer builds.
    public var detailKey: UIKey? {
        switch self {
        case .privateMode: return nil
        case .open: return .hintOpen
        case .unknown: return .hintUnknown
        }
    }
}

/// One agent as `GET /v1/agents` (and polled `agent.state` frames) expose it.
public struct AgentSummary: Decodable, Equatable, Identifiable {
    public let name: String
    public let enabled: Bool
    public let jobsTotal: Int
    public let jobsEnabled: Int
    public let runningJob: String?
    public let stop: Bool
    public let paused: Bool
    public let killed: Bool
    public let usageToday: UsageTotals
    public let lastActivity: ActivityEntry?
    /// The agent's current session id as a string, or nil when it has no
    /// session yet (auxd resolves the agent name to this session).
    public let threadId: String?
    /// D33 (NEW, E0): the brain this agent runs with, as `model` (or the
    /// provider id when no model is named). Absent before the agents runtime.
    public let brain: String?
    /// MODE-CHIP-TRUTH: the mode the daemon last reported for this agent.
    /// Absent on an old daemon, which reads as `.unknown`, never `.private`.
    public let privacyMode: PrivacyMode

    public var id: String { name }

    struct BrainJson: Decodable {
        let provider: String?
        let model: String?
    }

    enum CodingKeys: String, CodingKey {
        case name, enabled, stop, paused, killed, brain
        case jobsTotal = "jobs_total"
        case jobsEnabled = "jobs_enabled"
        case runningJob = "running_job"
        case usageToday = "usage_today"
        case lastActivity = "last_activity"
        case threadId = "thread_id"
        case privacyMode = "privacy_mode"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = (try? c.decode(String.self, forKey: .name)) ?? ""
        enabled = (try? c.decode(Bool.self, forKey: .enabled)) ?? true
        jobsTotal = (try? c.decode(Int.self, forKey: .jobsTotal)) ?? 0
        jobsEnabled = (try? c.decode(Int.self, forKey: .jobsEnabled)) ?? 0
        runningJob = try? c.decode(String.self, forKey: .runningJob)
        stop = (try? c.decode(Bool.self, forKey: .stop)) ?? false
        paused = (try? c.decode(Bool.self, forKey: .paused)) ?? false
        killed = (try? c.decode(Bool.self, forKey: .killed)) ?? false
        usageToday = (try? c.decode(UsageTotals.self, forKey: .usageToday)) ?? UsageTotals()
        lastActivity = try? c.decode(ActivityEntry.self, forKey: .lastActivity)
        threadId = try? c.decode(String.self, forKey: .threadId)
        let brainJson = try? c.decode(BrainJson.self, forKey: .brain)
        brain = brainJson?.model ?? brainJson?.provider
        privacyMode = PrivacyMode(raw: try? c.decode(String.self, forKey: .privacyMode))
    }

    public init(
        name: String,
        enabled: Bool = true,
        jobsTotal: Int = 0,
        jobsEnabled: Int = 0,
        runningJob: String? = nil,
        stop: Bool = false,
        paused: Bool = false,
        killed: Bool = false,
        usageToday: UsageTotals = UsageTotals(),
        lastActivity: ActivityEntry? = nil,
        threadId: String? = nil,
        brain: String? = nil,
        privacyMode: PrivacyMode = .unknown
    ) {
        self.brain = brain
        self.privacyMode = privacyMode
        self.name = name
        self.enabled = enabled
        self.jobsTotal = jobsTotal
        self.jobsEnabled = jobsEnabled
        self.runningJob = runningJob
        self.stop = stop
        self.paused = paused
        self.killed = killed
        self.usageToday = usageToday
        self.lastActivity = lastActivity
        self.threadId = threadId
    }
}

/// The current allowlist and registry returned by `GET /v1/agents/{id}`.
public struct AgentToolsDetail: Decodable, Equatable {
    public let tools: [String]?
    public let skills: [String]?
    public let availableTools: [String]

    enum CodingKeys: String, CodingKey {
        case tools
        case skills
        case availableTools = "available_tools"
    }

    public init(tools: [String]?, availableTools: [String], skills: [String]? = nil) {
        self.tools = tools
        self.availableTools = availableTools
        self.skills = skills
    }
}

public struct LocalSkill: Decodable, Equatable, Identifiable {
    public let name: String
    public let description: String?
    public let size: Int
    public let status: SkillStatus
    public var id: String { name }
    public var warning: String? {
        if case .valid(let warning) = status { return warning }
        return nil
    }

    public enum SkillStatus: Decodable, Equatable {
        case valid(String?)
        case ignored(String)

        enum CodingKeys: String, CodingKey { case state, reason, warning }
        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            switch try c.decode(String.self, forKey: .state) {
            case "valid": self = .valid(try c.decodeIfPresent(String.self, forKey: .warning))
            case "ignored": self = .ignored(try c.decode(String.self, forKey: .reason))
            default: self = .ignored("Unavailable")
            }
        }
    }
}

public struct AgentSkillsUpdate: Encodable, Equatable {
    public let skills: [String]
    public init(skills: [String]) { self.skills = skills }
}

public struct AgentSkillsUpdateResponse: Decodable, Equatable {
    public let changed: Bool
}

public struct AgentDetailResponse: Decodable, Equatable {
    public let agent: AgentToolsDetail
}

public struct AgentToolsUpdate: Encodable, Equatable {
    public let tools: [String]?

    public init(tools: [String]?) { self.tools = tools }

    enum CodingKeys: String, CodingKey { case tools }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if let tools {
            try container.encode(tools, forKey: .tools)
        } else {
            try container.encodeNil(forKey: .tools)
        }
    }
}

public struct AgentToolsUpdateResponse: Decodable, Equatable {
    public let changed: Bool
}

// MARK: - Personality (GET /v1/agents/{id}/soul, PUT /v1/agents/{id})

/// One agent's personality, whole, as `GET /v1/agents/{id}/soul` answers it.
///
/// The `instructions` field of the detail view is a scrubbed, capped preview;
/// this read is the owner's own text, so the editor can round-trip it.
public struct AgentSoul: Decodable, Equatable {
    /// The personality text exactly as stored.
    public let soulMd: String
    /// Largest accepted personality, in bytes, as the daemon reports it.
    public let maxBytes: Int
    /// True when no personality file exists yet: the daemon shows the built-in
    /// default and the first save writes the real file.
    public let isDefault: Bool

    /// The daemon's own ceiling when it does not report one (an older build).
    public static let builtInMaxBytes = 1024 * 1024

    enum CodingKeys: String, CodingKey {
        case soulMd = "soul_md"
        case maxBytes = "max_bytes"
        case isDefault = "is_default"
    }

    public init(soulMd: String, maxBytes: Int = AgentSoul.builtInMaxBytes, isDefault: Bool = false) {
        self.soulMd = soulMd
        self.maxBytes = maxBytes
        self.isDefault = isDefault
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        soulMd = (try? c.decode(String.self, forKey: .soulMd)) ?? ""
        maxBytes = (try? c.decode(Int.self, forKey: .maxBytes)) ?? AgentSoul.builtInMaxBytes
        isDefault = (try? c.decode(Bool.self, forKey: .isDefault)) ?? false
    }
}

/// `PUT /v1/agents/{id}` body for a personality save. `soul_md` is the alias the
/// daemon accepts for `role`/`instructions`.
public struct AgentSoulUpdate: Encodable, Equatable {
    public let soulMd: String

    enum CodingKeys: String, CodingKey { case soulMd = "soul_md" }

    public init(soulMd: String) { self.soulMd = soulMd }
}

// MARK: - Threads (GET/POST /v1/threads/{id}/messages)

public struct SessionJson: Decodable, Equatable {
    public let id: Int64
    public let agent: String
    public let title: String?
    public let createdAt: String
    public let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case id, agent, title
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }

    public init(id: Int64, agent: String, title: String? = nil, createdAt: String = "", updatedAt: String = "") {
        self.id = id
        self.agent = agent
        self.title = title
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(Int64.self, forKey: .id)) ?? 0
        agent = (try? c.decode(String.self, forKey: .agent)) ?? ""
        title = try? c.decode(String.self, forKey: .title)
        createdAt = (try? c.decode(String.self, forKey: .createdAt)) ?? ""
        updatedAt = (try? c.decode(String.self, forKey: .updatedAt)) ?? ""
    }
}

public struct MessageJson: Decodable, Equatable {
    public let id: Int64
    public let threadId: Int64
    public let role: String
    public let content: String
    public let at: String
    /// On a tool row: the tool that wrote it.
    public var tool: String?
    /// The daemon-built one-line sidebar preview, already scrubbed by the
    /// full detector. Swift shows this field only; it never builds one from
    /// raw content.
    public var preview: String?
    /// DELEGATION-SOURCE-1: who wrote this row (`delegation` for a task Aux
    /// handed to an agent). `nil` is the owner's own words.
    public var source: String?

    enum CodingKeys: String, CodingKey {
        case id, role, content, preview, at, tool, source
        case threadId = "thread_id"
    }

    public init(id: Int64, threadId: Int64, role: String, content: String, preview: String? = nil, at: String, tool: String? = nil, source: String? = nil) {
        self.id = id
        self.threadId = threadId
        self.role = role
        self.content = content
        self.preview = preview
        self.at = at
        self.tool = tool
        self.source = source
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(Int64.self, forKey: .id)) ?? 0
        threadId = (try? c.decode(Int64.self, forKey: .threadId)) ?? 0
        role = (try? c.decode(String.self, forKey: .role)) ?? "system"
        content = (try? c.decode(String.self, forKey: .content)) ?? ""
        preview = try? c.decode(String.self, forKey: .preview)
        at = (try? c.decode(String.self, forKey: .at)) ?? ""
        tool = try? c.decode(String.self, forKey: .tool)
        source = try? c.decode(String.self, forKey: .source)
    }
}

public struct MessagesPage: Decodable, Equatable {
    public let thread: SessionJson?
    public let messages: [MessageJson]
    public let hasMore: Bool
    public let oldestId: Int64?

    enum CodingKeys: String, CodingKey {
        case thread, messages
        case hasMore = "has_more"
        case oldestId = "oldest_id"
    }

    public init(thread: SessionJson?, messages: [MessageJson], hasMore: Bool = false, oldestId: Int64? = nil) {
        self.thread = thread
        self.messages = messages
        self.hasMore = hasMore
        self.oldestId = oldestId
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        thread = try? c.decode(SessionJson.self, forKey: .thread)
        messages = (try? c.decode([MessageJson].self, forKey: .messages)) ?? []
        hasMore = (try? c.decode(Bool.self, forKey: .hasMore)) ?? false
        oldestId = try? c.decode(Int64.self, forKey: .oldestId)
    }
}

public struct SendResponse: Decodable, Equatable {
    public let thread: SessionJson?
    public let messages: [MessageJson]
    public let rounds: Int
    public let capped: Bool
    /// The turn's run: it names the turn's streamed drafts.
    public let runId: String?

    public init(thread: SessionJson? = nil, messages: [MessageJson] = [], rounds: Int = 0, capped: Bool = false, runId: String? = nil) {
        self.thread = thread
        self.messages = messages
        self.rounds = rounds
        self.capped = capped
        self.runId = runId
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        thread = try? c.decode(SessionJson.self, forKey: .thread)
        messages = (try? c.decode([MessageJson].self, forKey: .messages)) ?? []
        rounds = (try? c.decode(Int.self, forKey: .rounds)) ?? 0
        capped = (try? c.decode(Bool.self, forKey: .capped)) ?? false
        runId = try? c.decode(String.self, forKey: .runId)
    }

    enum CodingKeys: String, CodingKey { case thread, messages, rounds, capped, runId = "run_id" }
}

// MARK: - Approvals (GET /v1/approvals, POST /v1/approvals/{id})

public enum ApprovalState: Equatable, Decodable {
    case pending
    case allowed(by: String, always: Bool)
    case denied(by: String)
    case expired
    /// A state this build does not know (forward compatibility: `superseded`,
    /// `deferred`, …). Never `pending`: the card is not answerable, focus never
    /// lands on it, and it does not count as "waiting" for the agent.
    case unknown(String)

    enum CodingKeys: String, CodingKey { case state, by, always }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let state = (try? c.decode(String.self, forKey: .state)) ?? "pending"
        switch state {
        case "pending":
            self = .pending
        case "allowed":
            self = .allowed(
                by: (try? c.decode(String.self, forKey: .by)) ?? "you",
                always: (try? c.decode(Bool.self, forKey: .always)) ?? false
            )
        case "denied":
            self = .denied(by: (try? c.decode(String.self, forKey: .by)) ?? "you")
        case "expired":
            self = .expired
        default:
            self = .unknown(state)
        }
    }

    public var isPending: Bool {
        if case .pending = self { return true }
        return false
    }
}

public struct VerifierVerdict: Decodable, Equatable {
    public let agrees: Bool
    public let model: String
    public let family: String
    public let rationale: String
    public let mainModel: String?
    public let mainRationale: String?

    enum CodingKeys: String, CodingKey {
        case agrees, model, family, rationale
        case mainModel = "main_model"
        case mainRationale = "main_rationale"
    }

    public init(agrees: Bool, model: String, family: String, rationale: String, mainModel: String? = nil, mainRationale: String? = nil) {
        self.agrees = agrees
        self.model = model
        self.family = family
        self.rationale = rationale
        self.mainModel = mainModel
        self.mainRationale = mainRationale
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        agrees = (try? c.decode(Bool.self, forKey: .agrees)) ?? false
        model = (try? c.decode(String.self, forKey: .model)) ?? ""
        family = (try? c.decode(String.self, forKey: .family)) ?? ""
        rationale = (try? c.decode(String.self, forKey: .rationale)) ?? ""
        mainModel = try? c.decode(String.self, forKey: .mainModel)
        mainRationale = try? c.decode(String.self, forKey: .mainRationale)
    }
}

/// The broker's ask, field for field the daemon's `wire::ApprovalFrame`.
public struct Approval: Decodable, Identifiable, Equatable {
    public let id: String
    public let auditId: UInt64
    public let agent: String
    public let threadId: String
    public let ts: Int64
    public let action: String
    public let headline: String
    public let preview: String?
    public let fullPreview: String?
    public let editPreview: String?
    public let detail: [String]
    public let why: String
    public let verifier: VerifierVerdict?
    /// Present → the content was in contact with an untrusted source;
    /// "Always" must stay disabled.
    public let taint: String?
    /// The call would run without the sandbox; also refuses "Always".
    public let unsandboxed: Bool
    public let cleanNote: String?
    public let scopeTool: String
    public let scopeResource: String?
    public let scopeRule: String
    public let destructive: Bool
    public var state: ApprovalState
    /// Local receipt time (not on the wire): drives the destructive arming delay.
    public var receivedAt: Date?
    /// The skill that drafted it and the delegation that
    /// asked for it. Absent on a daemon without the agents runtime.
    public let skill: String?
    public let delegationId: String?

    enum CodingKeys: String, CodingKey {
        case id, agent, ts, action, headline, preview, detail, why, verifier, taint, destructive, state
        case auditId = "audit_id"
        case threadId = "thread_id"
        case fullPreview = "full_preview"
        case editPreview = "edit_preview"
        case unsandboxed
        case cleanNote = "clean_note"
        case scopeTool = "scope_tool"
        case scopeResource = "scope_resource"
        case scopeRule = "scope_rule"
        case skill
        case delegationId = "delegation_id"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        skill = try? c.decode(String.self, forKey: .skill)
        delegationId = try? c.decode(String.self, forKey: .delegationId)
        id = (try? c.decode(String.self, forKey: .id)) ?? ""
        auditId = (try? c.decode(UInt64.self, forKey: .auditId)) ?? 0
        agent = (try? c.decode(String.self, forKey: .agent)) ?? ""
        threadId = (try? c.decode(String.self, forKey: .threadId)) ?? ""
        ts = (try? c.decode(Int64.self, forKey: .ts)) ?? 0
        action = (try? c.decode(String.self, forKey: .action)) ?? ""
        headline = (try? c.decode(String.self, forKey: .headline)) ?? ""
        preview = try? c.decode(String.self, forKey: .preview)
        fullPreview = try? c.decode(String.self, forKey: .fullPreview)
        editPreview = try? c.decode(String.self, forKey: .editPreview)
        detail = (try? c.decode([String].self, forKey: .detail)) ?? []
        why = (try? c.decode(String.self, forKey: .why)) ?? ""
        verifier = try? c.decode(VerifierVerdict.self, forKey: .verifier)
        taint = try? c.decode(String.self, forKey: .taint)
        unsandboxed = (try? c.decode(Bool.self, forKey: .unsandboxed)) ?? false
        cleanNote = try? c.decode(String.self, forKey: .cleanNote)
        scopeTool = (try? c.decode(String.self, forKey: .scopeTool)) ?? ""
        scopeResource = try? c.decode(String.self, forKey: .scopeResource)
        scopeRule = (try? c.decode(String.self, forKey: .scopeRule)) ?? ""
        destructive = (try? c.decode(Bool.self, forKey: .destructive)) ?? false
        state = (try? c.decode(ApprovalState.self, forKey: .state)) ?? .pending
        receivedAt = nil
    }

    public init(
        id: String,
        auditId: UInt64,
        agent: String,
        threadId: String,
        ts: Int64,
        action: String,
        headline: String,
        preview: String? = nil,
        fullPreview: String? = nil,
        editPreview: String? = nil,
        detail: [String] = [],
        why: String = "",
        verifier: VerifierVerdict? = nil,
        taint: String? = nil,
        unsandboxed: Bool = false,
        cleanNote: String? = nil,
        scopeTool: String,
        scopeResource: String? = nil,
        scopeRule: String = "",
        destructive: Bool = false,
        state: ApprovalState = .pending,
        receivedAt: Date? = nil,
        skill: String? = nil,
        delegationId: String? = nil
    ) {
        self.skill = skill
        self.delegationId = delegationId
        self.id = id
        self.auditId = auditId
        self.agent = agent
        self.threadId = threadId
        self.ts = ts
        self.action = action
        self.headline = headline
        self.preview = preview
        self.fullPreview = fullPreview
        self.editPreview = editPreview
        self.detail = detail
        self.why = why
        self.verifier = verifier
        self.taint = taint
        self.unsandboxed = unsandboxed
        self.cleanNote = cleanNote
        self.scopeTool = scopeTool
        self.scopeResource = scopeResource
        self.scopeRule = scopeRule
        self.destructive = destructive
        self.state = state
        self.receivedAt = receivedAt
    }
}

/// The `scope` of an allow-always answer (a subset of a broker rule).
public struct ApprovalScope: Encodable, Equatable {
    public let tool: String
    public let agent: String
    public let resource: String?

    public init(tool: String, agent: String, resource: String? = nil) {
        self.tool = tool
        self.agent = agent
        self.resource = resource
    }
}

extension Approval {
    /// The always-allow scope for *this* card: same card's tool, agent and
    /// resource — never a neighboring approval's. The view used to build this
    /// inline; a pure helper keeps the scope-to-id pairing testable.
    public var alwaysScope: ApprovalScope {
        ApprovalScope(tool: scopeTool, agent: agent, resource: scopeResource)
    }
}

public struct ResolveRequest: Encodable {
    public let decision: String
    public let scope: ApprovalScope?
    public let text: String?

    public init(decision: String, scope: ApprovalScope? = nil, text: String? = nil) {
        self.decision = decision
        self.scope = scope
        self.text = text
    }
}

public struct ResolveResponse: Decodable, Equatable {
    public let state: ApprovalState
}

// MARK: - Messages the UI renders

public enum Author: Equatable, Decodable {
    case you
    case agent(String)
    case tool
    case system

    enum CodingKeys: String, CodingKey { case kind, id }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = (try? c.decode(String.self, forKey: .kind)) ?? "system"
        switch kind {
        case "you":
            self = .you
        case "agent":
            self = .agent((try? c.decode(String.self, forKey: .id)) ?? "agent")
        case "tool":
            self = .tool
        default:
            self = .system
        }
    }

    public var agentName: String? {
        if case .agent(let name) = self { return name }
        return nil
    }
}

/// One block of a message; S0 renders text, everything else is carried
/// without pretending to render it.
public enum ChatBlock: Equatable, Decodable {
    case text(String)
    case other(kind: String)

    enum CodingKeys: String, CodingKey { case kind, text }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = (try? c.decode(String.self, forKey: .kind)) ?? "other"
        if kind == "text" {
            self = .text((try? c.decode(String.self, forKey: .text)) ?? "")
        } else {
            self = .other(kind: kind)
        }
    }

    public var text: String? {
        if case .text(let value) = self { return value }
        return nil
    }
}

public struct ToolCall: Decodable, Equatable {
    public let tool: String
    public let args: String
    public let ok: Bool?
    public let resultPreview: String?

    enum CodingKeys: String, CodingKey {
        case tool, args, ok
        case resultPreview = "result_preview"
    }

    public init(tool: String, args: String, ok: Bool? = nil, resultPreview: String? = nil) {
        self.tool = tool
        self.args = args
        self.ok = ok
        self.resultPreview = resultPreview
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        tool = (try? c.decode(String.self, forKey: .tool)) ?? ""
        args = (try? c.decode(String.self, forKey: .args)) ?? ""
        ok = try? c.decode(Bool.self, forKey: .ok)
        resultPreview = try? c.decode(String.self, forKey: .resultPreview)
    }
}

/// A message as the thread renders it.
public struct ChatMessage: Identifiable, Equatable, Decodable {
    public let id: String
    public let threadKey: String
    public let author: Author
    public let ts: Int64
    public var blocks: [ChatBlock]
    /// True while `message.delta` chunks are still arriving.
    public var streaming: Bool
    /// Composer echo not yet confirmed by auxd.
    public var pending: Bool
    /// A reference in this reply stayed masked because its session values were
    /// unavailable; the screen shows the banner and the token text.
    public var rehydrationUnavailable: Bool
    /// The streamed draft (`draft-<thread>-<run>-<round>`) this stored reply
    /// replaces; only on a live `message.new` that ends a streamed round.
    public var draftId: String?
    /// The turn that wrote this row; only on live `message.new` frames.
    public var runId: String?
    /// The agent of the live frame; places a tool or owner row of another
    /// session (a job, an iMessage turn) in that agent's chat.
    public var frameAgent: String?
    /// Earlier replies of the same turn that called a tool ("I'll check your
    /// calendar…"), shown as a quiet status line above this one. Display only:
    /// set by `ThreadTimeline`, never by the daemon.
    public var preamble: [ChatMessage] = []
    /// The calendar card under this reply (`CalendarCard.attach`). Display
    /// only: never set by the daemon, never stored, never sent to a model.
    public var calendarCard: CalendarCardModel?
    /// On a tool row: the tool that wrote it (auxd's `tool` field).
    public var toolName: String?
    /// DELEGATION-SOURCE-1: who wrote this row (auxd's `source` field).
    /// `delegation` marks a task Aux handed to an agent; `nil` is the
    /// owner's own words. Display only: never sent to a model.
    public var source: String?
    /// The daemon's already-scrubbed one-line sidebar preview. Display only:
    /// `ConversationPreview` never builds one from raw blocks.
    public var preview: String?
    /// An owner message the app holds back (a turn runs) or gave up on (Stop).
    /// App only: never decoded, never sent.
    public var delivery: Delivery?

    public enum Delivery: Equatable { case queued, notSent }

    /// Queued or not sent; `nil` is a send in flight (the pending echo).
    mutating func mark(_ delivery: Delivery?) {
        self.delivery = delivery
        pending = delivery == nil
    }

    public init(id: String, threadKey: String, author: Author, ts: Int64, blocks: [ChatBlock], streaming: Bool = false, pending: Bool = false, rehydrationUnavailable: Bool = false, preview: String? = nil) {
        self.id = id
        self.threadKey = threadKey
        self.author = author
        self.ts = ts
        self.blocks = blocks
        self.streaming = streaming
        self.pending = pending
        self.rehydrationUnavailable = rehydrationUnavailable
        self.preview = preview
    }

    public var text: String {
        blocks.compactMap(\.text).joined()
    }

    /// The preamble as status lines; with `tokenised` (the "what the model
    /// saw" view) each line shows the model's words, as the answer does.
    public func statusLines(tokenised: [String: String]? = nil) -> [String] {
        preamble.map { (tokenised?[$0.id] ?? $0.text).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    public mutating func appendDelta(_ delta: String) {
        if let index = blocks.firstIndex(where: { $0.text != nil }) {
            if case .text(let existing) = blocks[index] {
                blocks[index] = .text(existing + delta)
            }
        } else {
            blocks.append(.text(delta))
        }
    }

    /// `message.new` frames carry the full message; this shape decodes them.
    enum CodingKeys: String, CodingKey {
        case id, author, ts, blocks, streaming, pending
        case threadId = "thread_id"
        case rehydrationUnavailable = "rehydration_unavailable"
        case draftId = "draft_id"
        case runId = "run_id"
        case toolName = "tool"
        case source
        case preview
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? ""
        threadKey = (try? c.decode(String.self, forKey: .threadId)) ?? ""
        author = (try? c.decode(Author.self, forKey: .author)) ?? .system
        ts = (try? c.decode(Int64.self, forKey: .ts)) ?? 0
        blocks = (try? c.decode([ChatBlock].self, forKey: .blocks)) ?? []
        streaming = (try? c.decode(Bool.self, forKey: .streaming)) ?? false
        pending = (try? c.decode(Bool.self, forKey: .pending)) ?? false
        rehydrationUnavailable = (try? c.decode(Bool.self, forKey: .rehydrationUnavailable)) ?? false
        draftId = try? c.decode(String.self, forKey: .draftId)
        runId = try? c.decode(String.self, forKey: .runId)
        toolName = try? c.decode(String.self, forKey: .toolName)
        source = try? c.decode(String.self, forKey: .source)
        preview = try? c.decode(String.self, forKey: .preview)
    }
}

// MARK: - Run receipts (GET /v1/receipts, `run.finished` frames)

/// The daemon's run status (`crates/auxd/src/api/receipt.rs`, snake_case).
/// A status this build does not know decodes to `.unknown`, never a crash.
public enum ReceiptStatus: Equatable, Decodable {
    case done
    case doneUnverified
    case pausedNeedsYou
    case stoppedBudget
    case failed
    case unknown(String)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = (try? container.decode(String.self)) ?? ""
        switch raw {
        case "done": self = .done
        case "done_unverified": self = .doneUnverified
        case "paused_needs_you": self = .pausedNeedsYou
        case "stopped_budget": self = .stoppedBudget
        case "failed": self = .failed
        default: self = .unknown(raw)
        }
    }

    /// The wire value, or `nil` for an unknown status (never re-emitted).
    public var wire: String? {
        switch self {
        case .done: return "done"
        case .doneUnverified: return "done_unverified"
        case .pausedNeedsYou: return "paused_needs_you"
        case .stoppedBudget: return "stopped_budget"
        case .failed: return "failed"
        case .unknown: return nil
        }
    }
}

// MARK: - Roadmap status (the words the task timeline shows)

/// The eight roadmap words a task timeline can show, plus `unknown` so a
/// status this build does not know stays visible instead of being masked as
/// one of the eight. The mapping from a receipt (`ReceiptStatus`) is explicit
/// and total: every known receipt status lands on exactly one roadmap word,
/// and an unknown wire token is carried through in `.unknown`.
public enum RoadmapStatus: Equatable {
    /// en attente
    case waiting
    /// en préparation
    case preparing
    /// en cours
    case running
    /// en attente de toi
    case needsYou
    /// terminé
    case done
    /// terminé, à vérifier
    case doneUnverified
    /// échoué
    case failed
    /// en pause
    case paused
    /// A status outside the roadmap; the raw token stays visible, never hidden.
    case unknown(String)

    /// Explicit receipt -> displayed status correspondence.
    public init(receipt: ReceiptStatus) {
        switch receipt {
        case .done: self = .done
        case .doneUnverified: self = .doneUnverified
        case .pausedNeedsYou: self = .needsYou
        case .stoppedBudget: self = .paused
        case .failed: self = .failed
        case .unknown(let raw): self = .unknown(raw)
        }
    }

    /// The plain word shown for this status, in the requested language.
    /// An unknown status says so and keeps its raw token, so nothing is masked.
    public func label(_ language: Language) -> String {
        switch self {
        case .waiting: return L10n.t(.roadmapWaiting, language)
        case .preparing: return L10n.t(.roadmapPreparing, language)
        case .running: return L10n.t(.roadmapRunning, language)
        case .needsYou: return L10n.t(.roadmapNeedsYou, language)
        case .done: return L10n.t(.roadmapDone, language)
        case .doneUnverified: return L10n.t(.roadmapDoneUnverified, language)
        case .failed: return L10n.t(.roadmapFailed, language)
        case .paused: return L10n.t(.roadmapPaused, language)
        case .unknown(let raw):
            let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty { return L10n.t(.roadmapUnknown, language) }
            return L10n.f(.roadmapUnknownToken, language, token)
        }
    }

    /// True for the statuses that need the owner's attention.
    public var isProblem: Bool {
        switch self {
        case .failed, .needsYou, .paused: return true
        case .waiting, .preparing, .running, .done, .doneUnverified, .unknown: return false
        }
    }
}

/// One bounded run receipt, field for field the daemon's `receipt::Receipt`
/// (`run.finished`). Unknown JSON fields are ignored and every field has a
/// tolerant default, so a newer daemon never breaks decoding.
public struct Receipt: Decodable, Identifiable, Equatable {
    public let runId: String
    public let agent: String
    public let trigger: String?
    public let skills: [String]
    public let replacedValues: [String: UInt32]
    public let started: String?
    public let finished: String?
    public let status: ReceiptStatus
    public let tokensIn: UInt64
    public let tokensOut: UInt64
    public let costCents: UInt64
    public let tools: [String: UInt32]
    public let filesTouched: [String]
    public let hostsContacted: [String]
    public let messagesSent: [String]
    public let approvalsAsked: [String]
    public let approvalsAnswered: [String]
    public let couldNotVerify: [String]
    public let tainted: Bool
    public let receiptError: Bool

    public var id: String { runId }

    enum CodingKeys: String, CodingKey {
        case agent, trigger, skills, started, finished, status, tools, tainted
        case runId = "run_id"
        case tokensIn = "tokens_in"
        case tokensOut = "tokens_out"
        case costCents = "cost_cents"
        case filesTouched = "files_touched"
        case hostsContacted = "hosts_contacted"
        case messagesSent = "messages_sent"
        case approvalsAsked = "approvals_asked"
        case approvalsAnswered = "approvals_answered"
        case couldNotVerify = "could_not_verify"
        case receiptError = "receipt_error"
        case replacedValues = "replaced_values"
    }

    public init(
        runId: String,
        agent: String,
        trigger: String? = nil,
        skills: [String] = [],
        replacedValues: [String: UInt32] = [:],
        started: String? = nil,
        finished: String? = nil,
        status: ReceiptStatus = .done,
        tokensIn: UInt64 = 0,
        tokensOut: UInt64 = 0,
        costCents: UInt64 = 0,
        tools: [String: UInt32] = [:],
        filesTouched: [String] = [],
        hostsContacted: [String] = [],
        messagesSent: [String] = [],
        approvalsAsked: [String] = [],
        approvalsAnswered: [String] = [],
        couldNotVerify: [String] = [],
        tainted: Bool = false,
        receiptError: Bool = false
    ) {
        self.runId = runId
        self.agent = agent
        self.trigger = trigger
        self.skills = skills
        self.replacedValues = replacedValues
        self.started = started
        self.finished = finished
        self.status = status
        self.tokensIn = tokensIn
        self.tokensOut = tokensOut
        self.costCents = costCents
        self.tools = tools
        self.filesTouched = filesTouched
        self.hostsContacted = hostsContacted
        self.messagesSent = messagesSent
        self.approvalsAsked = approvalsAsked
        self.approvalsAnswered = approvalsAnswered
        self.couldNotVerify = couldNotVerify
        self.tainted = tainted
        self.receiptError = receiptError
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        runId = (try? c.decode(String.self, forKey: .runId)) ?? ""
        agent = (try? c.decode(String.self, forKey: .agent)) ?? ""
        trigger = try? c.decode(String.self, forKey: .trigger)
        skills = (try? c.decode([String].self, forKey: .skills)) ?? []
        replacedValues = (try? c.decode([String: UInt32].self, forKey: .replacedValues)) ?? [:]
        started = try? c.decode(String.self, forKey: .started)
        finished = try? c.decode(String.self, forKey: .finished)
        status = (try? c.decode(ReceiptStatus.self, forKey: .status)) ?? .done
        tokensIn = (try? c.decode(UInt64.self, forKey: .tokensIn)) ?? 0
        tokensOut = (try? c.decode(UInt64.self, forKey: .tokensOut)) ?? 0
        costCents = (try? c.decode(UInt64.self, forKey: .costCents)) ?? 0
        tools = (try? c.decode([String: UInt32].self, forKey: .tools)) ?? [:]
        filesTouched = (try? c.decode([String].self, forKey: .filesTouched)) ?? []
        hostsContacted = (try? c.decode([String].self, forKey: .hostsContacted)) ?? []
        messagesSent = (try? c.decode([String].self, forKey: .messagesSent)) ?? []
        approvalsAsked = (try? c.decode([String].self, forKey: .approvalsAsked)) ?? []
        approvalsAnswered = (try? c.decode([String].self, forKey: .approvalsAnswered)) ?? []
        couldNotVerify = (try? c.decode([String].self, forKey: .couldNotVerify)) ?? []
        tainted = (try? c.decode(Bool.self, forKey: .tainted)) ?? false
        receiptError = (try? c.decode(Bool.self, forKey: .receiptError)) ?? false
    }
}

// MARK: - WS /v1/events frames

public enum WireEvent: Equatable {
    case messageNew(ChatMessage)
    /// `rehydrationUnavailable` is set when a reference in `text` stayed masked
    /// because the session's values could not be read (`rehydration_unavailable`).
    case messageDelta(threadId: String, messageId: String, text: String, agent: String?, rehydrationUnavailable: Bool = false)
    case messageDone(threadId: String, messageId: String)
    case toolStart(threadId: String, messageId: String, call: ToolCall)
    case toolEnd(threadId: String, messageId: String, index: Int, call: ToolCall)
    case approvalNew(Approval)
    case approvalResolved(id: String, state: ApprovalState)
    case agentStateLive(agent: String, state: AgentState)
    case agentSnapshot(AgentSummary)
    /// One finished run, with its receipt attached by the daemon
    /// (`events.rs::journal_message`).
    case runFinished(Receipt)
    case other(String)
}

/// Frame decoder. Malformed *shapes* degrade to `.other(type)`; only
/// unparseable JSON throws, and the client skips those frames.
public enum WireEventDecoder {
    public static func decode(_ data: Data) throws -> WireEvent {
        let decoder = JSONDecoder()
        let envelope = try decoder.decode(Envelope.self, from: data)
        switch envelope.type {
        case "message.new":
            struct Frame: Decodable { let message: ChatMessage; let agent: String? }
            let frame = try decoder.decode(Frame.self, from: data)
            var message = frame.message
            message.frameAgent = frame.agent
            return .messageNew(message)
        case "message.delta":
            struct Frame: Decodable {
                let threadId: String
                let messageId: String
                let text: String
                let agent: String?
                let rehydrationUnavailable: Bool
                enum CodingKeys: String, CodingKey {
                    case text, agent
                    case threadId = "thread_id"
                    case messageId = "message_id"
                    case rehydrationUnavailable = "rehydration_unavailable"
                }
                init(from decoder: Decoder) throws {
                    let c = try decoder.container(keyedBy: CodingKeys.self)
                    threadId = (try? c.decode(String.self, forKey: .threadId)) ?? ""
                    messageId = (try? c.decode(String.self, forKey: .messageId)) ?? ""
                    text = (try? c.decode(String.self, forKey: .text)) ?? ""
                    agent = try? c.decode(String.self, forKey: .agent)
                    rehydrationUnavailable = (try? c.decode(Bool.self, forKey: .rehydrationUnavailable)) ?? false
                }
            }
            let frame = try decoder.decode(Frame.self, from: data)
            return .messageDelta(
                threadId: frame.threadId,
                messageId: frame.messageId,
                text: frame.text,
                agent: frame.agent,
                rehydrationUnavailable: frame.rehydrationUnavailable
            )
        case "message.done":
            struct Frame: Decodable {
                let threadId: String
                let messageId: String
                enum CodingKeys: String, CodingKey {
                    case threadId = "thread_id"
                    case messageId = "message_id"
                }
                init(from decoder: Decoder) throws {
                    let c = try decoder.container(keyedBy: CodingKeys.self)
                    threadId = (try? c.decode(String.self, forKey: .threadId)) ?? ""
                    messageId = (try? c.decode(String.self, forKey: .messageId)) ?? ""
                }
            }
            let frame = try decoder.decode(Frame.self, from: data)
            return .messageDone(threadId: frame.threadId, messageId: frame.messageId)
        case "tool.start":
            struct Frame: Decodable {
                let threadId: String
                let messageId: String
                let call: ToolCall
                enum CodingKeys: String, CodingKey {
                    case call
                    case threadId = "thread_id"
                    case messageId = "message_id"
                }
                init(from decoder: Decoder) throws {
                    let c = try decoder.container(keyedBy: CodingKeys.self)
                    threadId = (try? c.decode(String.self, forKey: .threadId)) ?? ""
                    messageId = (try? c.decode(String.self, forKey: .messageId)) ?? ""
                    call = (try? c.decode(ToolCall.self, forKey: .call)) ?? ToolCall(tool: "", args: "")
                }
            }
            let frame = try decoder.decode(Frame.self, from: data)
            return .toolStart(threadId: frame.threadId, messageId: frame.messageId, call: frame.call)
        case "tool.end":
            struct Frame: Decodable {
                let threadId: String
                let messageId: String
                let index: Int
                let call: ToolCall
                enum CodingKeys: String, CodingKey {
                    case index, call
                    case threadId = "thread_id"
                    case messageId = "message_id"
                }
                init(from decoder: Decoder) throws {
                    let c = try decoder.container(keyedBy: CodingKeys.self)
                    threadId = (try? c.decode(String.self, forKey: .threadId)) ?? ""
                    messageId = (try? c.decode(String.self, forKey: .messageId)) ?? ""
                    index = (try? c.decode(Int.self, forKey: .index)) ?? 0
                    call = (try? c.decode(ToolCall.self, forKey: .call)) ?? ToolCall(tool: "", args: "")
                }
            }
            let frame = try decoder.decode(Frame.self, from: data)
            return .toolEnd(threadId: frame.threadId, messageId: frame.messageId, index: frame.index, call: frame.call)
        case "approval.new":
            struct Frame: Decodable { let approval: Approval }
            return .approvalNew(try decoder.decode(Frame.self, from: data).approval)
        case "approval.resolved", "approval.updated":
            // `approval.updated` carries the same id and state; a client that
            // only sees that frame must still retire the card.
            struct Frame: Decodable { let id: String; let state: ApprovalState }
            let frame = try decoder.decode(Frame.self, from: data)
            return .approvalResolved(id: frame.id, state: frame.state)
        case "run.finished":
            // The receipt rides both as a typed field and inside `payload`.
            // Prefer the typed field; a frame without it stays honest `.other`.
            struct Frame: Decodable { let receipt: Receipt }
            if let frame = try? decoder.decode(Frame.self, from: data) {
                return .runFinished(frame.receipt)
            }
            return .other("run.finished")
        case "agent.state":
            // Live turn transition: `"state": "thinking"` (wire.rs).
            if let live = try? decoder.decode(LiveAgentState.self, from: data) {
                return .agentStateLive(agent: live.agent, state: AgentState(rawValue: live.state) ?? .idle)
            }
            // Polled snapshot: `"state": { …AgentJson… }`.
            if let snapshot = try? decoder.decode(SnapshotAgentState.self, from: data) {
                return .agentSnapshot(snapshot.state)
            }
            return .other("agent.state")
        default:
            return .other(envelope.type)
        }
    }

    private struct Envelope: Decodable { let type: String }

    private struct LiveAgentState: Decodable {
        let agent: String
        let state: String
    }

    private struct SnapshotAgentState: Decodable {
        let state: AgentSummary
    }
}

// MARK: - App-side agent

public enum AgentState: String, Equatable, CaseIterable {
    case idle
    case thinking
    case working
    case needsYou = "needs_you"
    case paused
    case killed

    /// Rail order: needs-you → working → idle → paused.
    public var urgency: Int {
        switch self {
        case .needsYou: return 0
        case .thinking, .working: return 1
        case .idle: return 2
        case .paused: return 3
        case .killed: return 4
        }
    }

    public var animates: Bool {
        switch self {
        case .thinking, .working, .needsYou: return true
        case .idle, .paused, .killed: return false
        }
    }
}

public struct Agent: Identifiable, Equatable {
    public let id: String
    public let name: String
    public let hue: Int
    public let glyph: String
    public var state: AgentState
    public var status: String
    public var statusShort: String?
    public var waiting: Int
    public var budgetUsed: Double
    public var budgetHit: Bool
    /// The key used for reads/turns; equal to the name (auxd resolves a name
    /// to the agent's current session).
    public var threadKey: String
    public var lastActive: Int64?
    public var runningJob: String?
    /// The brain this agent runs with, when the daemon names one.
    public var brain: String?
    /// The daemon's live mode for this agent; unknown until it says.
    public var privacyMode: PrivacyMode

    public init(
        id: String,
        name: String,
        hue: Int,
        glyph: String,
        state: AgentState,
        status: String,
        statusShort: String? = nil,
        waiting: Int = 0,
        budgetUsed: Double = 0,
        budgetHit: Bool = false,
        threadKey: String,
        lastActive: Int64? = nil,
        runningJob: String? = nil,
        brain: String? = nil,
        privacyMode: PrivacyMode = .unknown
    ) {
        self.brain = brain
        self.privacyMode = privacyMode
        self.id = id
        self.name = name
        self.hue = hue
        self.glyph = glyph
        self.state = state
        self.status = status
        self.statusShort = statusShort
        self.waiting = waiting
        self.budgetUsed = budgetUsed
        self.budgetHit = budgetHit
        self.threadKey = threadKey
        self.lastActive = lastActive
        self.runningJob = runningJob
    }

    /// Stable rail order (urgency, then name), used everywhere the rail and
    /// the store agree on "which agent comes first".
    public static func sorted(_ agents: [Agent]) -> [Agent] {
        agents.sorted { lhs, rhs in
            if lhs.state.urgency != rhs.state.urgency { return lhs.state.urgency < rhs.state.urgency }
            return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }
    }
}

// MARK: - Mapping (daemon shapes → what the UI renders)

public enum Mapper {
    /// `AgentJson` + the latest live state → `Agent` (same rules as live.rs).
    public static func agent(from agent: AgentSummary, live: AgentState?, language: Language = .default) -> Agent {
        let state: AgentState
        if agent.killed {
            state = .killed
        } else if agent.stop || agent.paused {
            state = .paused
        } else if agent.runningJob != nil {
            state = .working
        } else {
            state = live ?? .idle
        }
        let status: String
        switch (agent.runningJob, agent.lastActivity) {
        case (let job?, _): status = job
        case (nil, let activity?): status = LedgerText.what(activity, language: language)
        case (nil, nil): status = agent.enabled ? "" : ""
        }
        return Agent(
            id: agent.name,
            name: agent.name,
            hue: AgentHues.index(for: agent.name),
            glyph: String(agent.name.prefix(1)).uppercased(),
            state: state,
            status: status,
            statusShort: agent.runningJob != nil ? "running" : nil,
            waiting: 0,
            budgetUsed: budgetRatio(agent.usageToday),
            budgetHit: budgetHit(agent.usageToday),
            threadKey: agent.name,
            lastActive: Timestamps.unixMillis(from: agent.lastActivity?.at).flatMap { $0 > 0 ? $0 : nil },
            runningJob: agent.runningJob,
            brain: agent.brain,
            privacyMode: agent.privacyMode
        )
    }

    /// A REST message → thread message. `threadKey` is the agent name.
    public static func message(from json: MessageJson, threadKey: String, agentName: String) -> ChatMessage {
        let author: Author
        switch json.role {
        case "user": author = .you
        case "assistant": author = .agent(agentName)
        case "tool": author = .tool
        default: author = .system
        }
        var message = ChatMessage(
            id: String(json.id),
            threadKey: threadKey,
            author: author,
            ts: Timestamps.unixMillis(from: json.at) ?? 0,
            blocks: [.text(json.content)],
            streaming: false,
            pending: false
        )
        message.toolName = json.tool
        // DELEGATION-SOURCE-1: the row says who wrote it.
        message.source = json.source
        // The sidebar line is the daemon's scrubbed field, never raw content.
        message.preview = json.preview
        return message
    }

    static func budgetRatio(_ usage: UsageTotals) -> Double {
        // S0 has no caps endpoint in the snapshot; usage exists but no cap.
        // The ring stays at 0 until /v1/usage is wired (S3+).
        _ = usage
        return 0
    }

    static func budgetHit(_ usage: UsageTotals) -> Bool {
        _ = usage
        return false
    }
}

public enum Timestamps {
    /// "YYYY-MM-DD HH:MM:SS" (UTC, auxd's store shape) → unix milliseconds.
    public static func unixMillis(from stamp: String?) -> Int64? {
        guard let stamp, !stamp.isEmpty else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        guard let date = formatter.date(from: stamp) else { return nil }
        return Int64(date.timeIntervalSince1970 * 1000)
    }
}

/// Thread correlation (UM-01): live frames carry the
/// numeric session id, the UI keys threads by agent name.
public struct ThreadAliases: Equatable {
    private var bySession: [String: String] = [:]
    private var byAgent: [String: String] = [:]

    public init() {}

    public mutating func learn(agent: String, sessionId: String?) {
        byAgent[agent] = agent
        if let sessionId, !sessionId.isEmpty {
            bySession[sessionId] = agent
        }
    }

    public mutating func learn(page: MessagesPage, agent: String) {
        byAgent[agent] = agent
        if let id = page.thread?.id {
            bySession[String(id)] = agent
        }
    }

    /// The visible thread key for a frame (session id first, then its agent).
    public func visible(threadId: String, agent: String?) -> String? {
        if let agent = bySession[threadId] { return agent }
        if let agent, let agent = byAgent[agent] { return agent }
        if let agent, !agent.isEmpty { return agent }
        return threadId.isEmpty ? nil : threadId
    }
}

// MARK: - Provider setup + first run (B-API v4)
//
// The in-app setup path (`docs/providers.md` §8): save a service
// and its key, run the spend-free test, then create the first agent. The key
// travels only in the POST bodies below and is never echoed back; every
// response carries booleans (`key_present`), never key material.

/// One service as `GET /v1/providers` reports it. Key material is never in
/// this shape: `key_present` is a boolean and `key_location` says where the
/// key lives (the app does not read it).
public struct ProviderSummary: Decodable, Equatable, Identifiable {
    public let id: String
    public let name: String
    public let baseURL: String
    public let model: String
    public let kind: String
    public let keyLocation: String
    public let keyPresent: Bool?
    public let keyRequired: Bool
    public let keyError: String?
    public let lastTest: String

    enum CodingKeys: String, CodingKey {
        case id, name, model, kind
        case baseURL = "base_url"
        case keyLocation = "key_location"
        case keyPresent = "key_present"
        case keyRequired = "key_required"
        case keyError = "key_error"
        case lastTest = "last_test"
    }
}

/// `POST /v1/providers` body. `apiKey` is optional and is only ever sent to
/// this route; it is dropped from memory as soon as the call returns.
public struct CreateProviderRequest: Encodable, Equatable {
    public let name: String
    public let kind: String
    public let baseURL: String
    public let model: String
    public let apiKey: String?

    enum CodingKeys: String, CodingKey {
        case name, kind, model
        case baseURL = "base_url"
        case apiKey = "api_key"
    }

    public init(name: String, kind: String = "openai_compat", baseURL: String, model: String, apiKey: String?) {
        self.name = name
        self.kind = kind
        self.baseURL = baseURL
        self.model = model
        self.apiKey = apiKey
    }
}

/// `POST /v1/providers` response: `key_present` only, never the key.
public struct ProviderSaved: Decodable, Equatable {
    public let name: String
    public let keyPresent: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case keyPresent = "key_present"
    }
}

/// `PUT /v1/providers/{name}/key` body: the secret for an existing service
/// whose key was never stored. The name travels in the path; the key is used
/// and forgotten and is never echoed by any response.
public struct UpdateProviderKeyRequest: Encodable, Equatable {
    public let apiKey: String

    enum CodingKeys: String, CodingKey {
        case apiKey = "api_key"
    }

    public init(apiKey: String) {
        self.apiKey = apiKey
    }
}

/// `POST /v1/providers/test` body. For an already-configured service the
/// daemon resolves the stored key by `name`, so `apiKey` stays `nil`.
public struct ProviderTestRequest: Encodable, Equatable {
    public let name: String
    public let kind: String
    public let baseURL: String
    public let model: String
    public let apiKey: String?

    enum CodingKeys: String, CodingKey {
        case name, kind, model
        case baseURL = "base_url"
        case apiKey = "api_key"
    }

    public init(name: String, kind: String = "openai_compat", baseURL: String, model: String, apiKey: String?) {
        self.name = name
        self.kind = kind
        self.baseURL = baseURL
        self.model = model
        self.apiKey = apiKey
    }
}

/// The spend-free test result. `reason` is the machine-readable bucket the
/// guided flow turns into one plain sentence: `ok`, `bad_key`, `unreachable`,
/// `model_not_found`, `invalid_config` or `unknown`.
public struct ProviderTest: Decodable, Equatable {
    public let ok: Bool
    public let reason: String
    public let latencyMs: UInt32?
    public let models: [String]
    public let error: String?
    public let keyPresent: Bool?
    public let keyRequired: Bool
    public let reachable: Bool?
    public let note: String?

    enum CodingKeys: String, CodingKey {
        case ok, reason, models, error, reachable, note
        case latencyMs = "latency_ms"
        case keyPresent = "key_present"
        case keyRequired = "key_required"
    }
}

/// `GET /v1/first-run`: the guided flow's step states, derived per request.
public struct FirstRunStatus: Decodable, Equatable {
    public let firstRun: Bool
    public let providerSaved: Bool
    public let providerTested: Bool
    public let agentCreated: Bool
    public let nextStep: String
    public let provider: String?
    public let agent: String?

    enum CodingKeys: String, CodingKey {
        case provider, agent
        case firstRun = "first_run"
        case providerSaved = "provider_saved"
        case providerTested = "provider_tested"
        case agentCreated = "agent_created"
        case nextStep = "next_step"
    }
}

/// The agent `POST /v1/agents` / first-run answers with.
public struct CreatedAgent: Decodable, Equatable {
    public let name: String
    public let provider: String?
    public let model: String?
}

/// `POST /v1/agents` body.
public struct CreateAgentRequest: Encodable, Equatable {
    public let name: String
    public let provider: String?
    public let model: String?
    public let role: String?

    enum CodingKeys: String, CodingKey { case name, provider, model, role }

    public init(name: String, provider: String?, model: String?, role: String?) {
        self.name = name
        self.provider = provider
        self.model = model
        self.role = role
    }
}

/// `POST /v1/agents` response (`created` is false for an idempotent repeat).
public struct AgentCreateResponse: Decodable, Equatable {
    public let agent: CreatedAgent
    public let created: Bool
}

/// `POST /v1/first-run/complete` body (every field optional).
public struct FirstRunCompleteRequest: Encodable, Equatable {
    public let provider: String?
    public let model: String?
    public let role: String?

    enum CodingKeys: String, CodingKey { case provider, model, role }

    public init(provider: String?, model: String?, role: String?) {
        self.provider = provider
        self.model = model
        self.role = role
    }
}

/// `POST /v1/first-run/complete` response.
public struct FirstRunComplete: Decodable, Equatable {
    public let firstRun: Bool
    public let created: Bool
    public let provider: String
    public let agent: CreatedAgent

    enum CodingKeys: String, CodingKey {
        case created, provider, agent
        case firstRun = "first_run"
    }
}

// MARK: - Contacts import (POST /v1/contacts/import, WO-CRMIO-2)

/// The party kind every row of an import becomes. `none` sends no tag.
public enum ContactsImportTag: String, CaseIterable, Equatable {
    case client, partner, none

    /// The wire value: `client`, `partner`, or nil (omitted).
    public var wire: String? { self == .none ? nil : rawValue }
}

/// The request body. `dry_run` is always sent, so an import is never one
/// missing field away from a preview.
public struct ContactsImportRequest: Encodable, Equatable {
    public let path: String
    public let dryRun: Bool
    public let tag: String?
    public let country: String?

    public init(path: String, dryRun: Bool, tag: String?, country: String?) {
        self.path = path
        self.dryRun = dryRun
        self.tag = tag
        self.country = country
    }

    enum CodingKeys: String, CodingKey {
        case path, tag, country
        case dryRun = "dry_run"
    }
}

/// One CSV column the import read: its header text and what it became
/// (`name`, `given`, `family`, `nickname`, `email` or `phone`).
public struct ContactsImportMappedColumn: Decodable, Equatable {
    public let column: String
    public let role: String

    enum CodingKeys: String, CodingKey {
        case column
        case role = "as"
    }
}

/// Rows that did not import, by reason. Counts only.
public struct ContactsImportSkipped: Decodable, Equatable {
    public let noNameOrContact: Int
    public let repeatedInFile: Int
    public let phoneNeedsCountry: Int
    public let phoneInvalid: Int
    public let refusedCharset: Int
    public let undecodableFields: Int
    public let overSizeCap: Int

    public init(noNameOrContact: Int = 0, repeatedInFile: Int = 0, phoneNeedsCountry: Int = 0, phoneInvalid: Int = 0,
                refusedCharset: Int = 0, undecodableFields: Int = 0, overSizeCap: Int = 0) {
        self.noNameOrContact = noNameOrContact
        self.repeatedInFile = repeatedInFile
        self.phoneNeedsCountry = phoneNeedsCountry
        self.phoneInvalid = phoneInvalid
        self.refusedCharset = refusedCharset
        self.undecodableFields = undecodableFields
        self.overSizeCap = overSizeCap
    }

    enum CodingKeys: String, CodingKey {
        case noNameOrContact = "no_name_or_contact"
        case repeatedInFile = "repeated_in_file"
        case phoneNeedsCountry = "phone_needs_country"
        case phoneInvalid = "phone_invalid"
        case refusedCharset = "refused_charset"
        case undecodableFields = "undecodable_fields"
        case overSizeCap = "over_size_cap"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        noNameOrContact = (try? c.decode(Int.self, forKey: .noNameOrContact)) ?? 0
        repeatedInFile = (try? c.decode(Int.self, forKey: .repeatedInFile)) ?? 0
        phoneNeedsCountry = (try? c.decode(Int.self, forKey: .phoneNeedsCountry)) ?? 0
        phoneInvalid = (try? c.decode(Int.self, forKey: .phoneInvalid)) ?? 0
        refusedCharset = (try? c.decode(Int.self, forKey: .refusedCharset)) ?? 0
        undecodableFields = (try? c.decode(Int.self, forKey: .undecodableFields)) ?? 0
        overSizeCap = (try? c.decode(Int.self, forKey: .overSizeCap)) ?? 0
    }
}

/// `POST /v1/contacts/import` answer, for a preview (`dry_run`) and for an
/// import. Only the preview carries the format and the columns. No contact
/// value is ever in it.
public struct ContactsImportAnswer: Decodable, Equatable {
    public let dryRun: Bool
    /// `vcard` or `csv`; nil on an import.
    public let format: String?
    public let mappedColumns: [ContactsImportMappedColumn]
    public let unmappedColumns: [String]
    /// Contacts the file yields, after merging its repeats.
    public let contacts: Int
    public let emails: Int
    public let phones: Int
    public let partiesCreated: Int
    public let partiesUpdated: Int
    public let partiesRefused: Int
    public let skipped: ContactsImportSkipped

    public init(dryRun: Bool, format: String? = nil, mappedColumns: [ContactsImportMappedColumn] = [],
                unmappedColumns: [String] = [], contacts: Int = 0, emails: Int = 0, phones: Int = 0,
                partiesCreated: Int = 0, partiesUpdated: Int = 0, partiesRefused: Int = 0,
                skipped: ContactsImportSkipped = ContactsImportSkipped()) {
        self.dryRun = dryRun
        self.format = format
        self.mappedColumns = mappedColumns
        self.unmappedColumns = unmappedColumns
        self.contacts = contacts
        self.emails = emails
        self.phones = phones
        self.partiesCreated = partiesCreated
        self.partiesUpdated = partiesUpdated
        self.partiesRefused = partiesRefused
        self.skipped = skipped
    }

    enum CodingKeys: String, CodingKey {
        case format, contacts, emails, phones, skipped
        case dryRun = "dry_run"
        case mappedColumns = "mapped_columns"
        case unmappedColumns = "unmapped_columns"
        case partiesCreated = "parties_created"
        case partiesUpdated = "parties_updated"
        case partiesRefused = "parties_refused"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        dryRun = (try? c.decode(Bool.self, forKey: .dryRun)) ?? false
        format = try? c.decode(String.self, forKey: .format)
        mappedColumns = (try? c.decode([ContactsImportMappedColumn].self, forKey: .mappedColumns)) ?? []
        unmappedColumns = (try? c.decode([String].self, forKey: .unmappedColumns)) ?? []
        contacts = (try? c.decode(Int.self, forKey: .contacts)) ?? 0
        emails = (try? c.decode(Int.self, forKey: .emails)) ?? 0
        phones = (try? c.decode(Int.self, forKey: .phones)) ?? 0
        partiesCreated = (try? c.decode(Int.self, forKey: .partiesCreated)) ?? 0
        partiesUpdated = (try? c.decode(Int.self, forKey: .partiesUpdated)) ?? 0
        partiesRefused = (try? c.decode(Int.self, forKey: .partiesRefused)) ?? 0
        skipped = (try? c.decode(ContactsImportSkipped.self, forKey: .skipped)) ?? ContactsImportSkipped()
    }
}
