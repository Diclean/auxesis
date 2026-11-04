// The one observable state: a snapshot of auxd, then live events merged into
// it. Consistency rule (the reason this class exists):
//
//   1. open the WS *first* and buffer events while the snapshot loads;
//   2. fetch `/v1/health`, `/v1/agents`, the selected agent's messages and the
//      pending approvals;
//   3. apply the snapshot, then drain the buffered events in order.
//
// So nothing that happened during the fetch is lost, and nothing is
// duplicated (messages/approvals are upserted by id). When the socket drops,
// the loop reconnects with backoff and re-syncs from a fresh snapshot.
//
// Approvals never use optimistic UI: a card leaves "pending" only when auxd
// answers or a frame says so, and exactly one answer can be in flight per id.
import Combine
import Foundation

public enum ApprovalDecision: String, Equatable {
    case allowOnce
    case deny
    case allowAlways
    case edit

    public var wire: String {
        switch self {
        case .allowOnce: return "allow_once"
        case .deny: return "deny"
        case .allowAlways: return "allow_always"
        case .edit: return "edit"
        }
    }
}

/// Structured reason for the last failed connect: the offline screen picks the
/// right fix from this (token vs service vs key) instead of parsing an error
/// string. `nil` means "no failure recorded yet / still connecting".
public enum OfflineCause: Equatable {
    case tokenMissing
    case tokenUnsafe
    case keyRefused
    case unreachable(String)
}

// MARK: - First-run setup (B-API v4)

extension AuxdError {
    /// The HTTP status carried by an `.http` failure, when there is one. Used
    /// to treat `409 provider_exists` as "already saved" rather than a failure.
    var httpStatus: Int? {
        if case .http(let status, _) = self { return status }
        return nil
    }

    /// The machine-readable `code` of the daemon's uniform error body
    /// (`{"error":{"code":…}}`), when the failure carries one. The app switches
    /// on this — never on prose — so a benign `provider_exists` conflict is
    /// told apart from a real `provider_key_conflict` (or any other 409).
    var daemonErrorCode: String? {
        guard case .http(_, let body) = self,
              let data = body.data(using: .utf8) else { return nil }
        struct Envelope: Decodable {
            struct Detail: Decodable { let code: String }
            let error: Detail
        }
        return (try? JSONDecoder().decode(Envelope.self, from: data))?.error.code
    }
}

/// One entry in the service picker: a configured `[[providers]]` entry, or a
/// built-in suggestion shown while the daemon has none yet.
public struct ProviderChoice: Equatable, Identifiable {
    public let id: String
    public let title: String
    /// Set only for a built-in suggestion whose title must follow the owner's
    /// language; a title from the service is shown verbatim.
    public let titleKey: StringKey?
    public let baseURL: String
    public let model: String
    public let kind: String
    public let keyRequired: Bool
    /// True when the service already has what it needs: the daemon reports
    /// `key_present` (or needs no key at all). A service that exists with no
    /// key is **not** configured, so the key field is shown.
    public let configured: Bool
    /// True when the daemon already lists this service. Such an entry is never
    /// re-saved: a pasted key goes through the update-key route instead.
    public let knownToDaemon: Bool

    public init(
        id: String,
        title: String,
        titleKey: StringKey? = nil,
        baseURL: String,
        model: String,
        kind: String,
        keyRequired: Bool,
        configured: Bool,
        knownToDaemon: Bool = false
    ) {
        self.id = id
        self.title = title
        self.titleKey = titleKey
        self.baseURL = baseURL
        self.model = model
        self.kind = kind
        self.keyRequired = keyRequired
        self.configured = configured
        self.knownToDaemon = knownToDaemon
    }
}

/// Built-in fallback services: the daemon's `GET /v1/providers` is empty on a
/// fresh install, so the picker needs something honest to offer. Configured
/// entries always come first and win by id.
public enum FirstRunCatalog {
    /// The daemon's own default agent id (`auxd::DEFAULT_AGENT`) and the same
    /// id `POST /v1/first-run/complete` targets, so the two calls stay
    /// idempotent instead of creating a second agent. Agent ids are ASCII
    /// letters/digits/`-`/`_`/`.` (no spaces), hence `main` rather than a
    /// French display name.
    public static let defaultAgentID = "main"
    /// What the first-run screen calls that agent, in both languages.
    public static let defaultAgentLabel: StringKey = .firstRunDefaultAgentLabel

    public static let suggestions: [ProviderChoice] = [
        ProviderChoice(
            id: "deepseek",
            title: "DeepSeek",
            baseURL: "https://api.deepseek.com/v1",
            model: "deepseek-chat",
            kind: "openai_compat",
            keyRequired: true,
            configured: false
        ),
        ProviderChoice(
            id: "openai",
            title: "OpenAI (ChatGPT)",
            baseURL: "https://api.openai.com/v1",
            model: "gpt-4o-mini",
            kind: "openai_compat",
            keyRequired: true,
            configured: false
        ),
        ProviderChoice(
            id: "mistral",
            title: "Mistral",
            baseURL: "https://api.mistral.ai/v1",
            model: "mistral-large-latest",
            kind: "openai_compat",
            keyRequired: true,
            configured: false
        ),
        ProviderChoice(
            id: "openrouter",
            title: "OpenRouter",
            baseURL: "https://openrouter.ai/api/v1",
            model: "openai/gpt-4o-mini",
            kind: "openai_compat",
            keyRequired: true,
            configured: false
        ),
        ProviderChoice(
            id: "ollama",
            title: "Ollama",
            titleKey: .providerOllamaTitle,
            baseURL: "http://127.0.0.1:11434/v1",
            model: "llama3.1",
            kind: "openai_compat",
            keyRequired: false,
            configured: false
        ),
    ]
}

/// Plain-words explanation of one setup failure: the cause, one next step, and
/// whether Retry makes sense (connection trouble always does). The copy lives
/// in `L10n`; the screens resolve it with the owner's language at render time.
public struct FirstRunFailure: Equatable {
    /// A fixed sentence from the table, or daemon-provided text shown verbatim.
    public enum Detail: Equatable {
        case key(StringKey)
        case text(String)
    }

    public let titleKey: StringKey
    public let detail: Detail?
    public let nextStepKey: StringKey
    public let isConnection: Bool

    public init(
        title: StringKey,
        detail: Detail? = nil,
        nextStep: StringKey,
        isConnection: Bool = false
    ) {
        self.titleKey = title
        self.detail = detail
        self.nextStepKey = nextStep
        self.isConnection = isConnection
    }

    public func title(_ language: Language) -> String { L10n.t(titleKey, language) }

    public func detail(_ language: Language) -> String? {
        switch detail {
        case .key(let key): return L10n.t(key, language)
        case .text(let value): return value
        case nil: return nil
        }
    }

    public func nextStep(_ language: Language) -> String { L10n.t(nextStepKey, language) }
}

extension FirstRunFailure {
    /// 401 / a refused service key.
    public static let keyRefused = FirstRunFailure(
        title: .firstRunKeyRefusedTitle,
        detail: .key(.firstRunKeyRefusedDetail),
        nextStep: .firstRunKeyRefusedNext
    )
    /// 403.
    public static let accessDenied = FirstRunFailure(
        title: .firstRunAccessDeniedTitle,
        detail: .key(.firstRunAccessDeniedDetail),
        nextStep: .firstRunAccessDeniedNext
    )
    /// 429.
    public static let tooManyRequests = FirstRunFailure(
        title: .firstRunTooManyTitle,
        detail: .key(.firstRunTooManyDetail),
        nextStep: .firstRunTooManyNext,
        isConnection: true
    )
    /// The AI service itself did not answer.
    public static let serviceUnreachable = FirstRunFailure(
        title: .firstRunUnreachableTitle,
        detail: .key(.firstRunUnreachableDetail),
        nextStep: .firstRunUnreachableNext,
        isConnection: true
    )
    /// The local Auxesis service (auxd) is not answering.
    public static let localService = FirstRunFailure(
        title: .firstRunLocalServiceTitle,
        detail: .key(.firstRunLocalServiceDetail),
        nextStep: .firstRunLocalServiceNext,
        isConnection: true
    )
    /// The local service answered late or in a shape the app could not read.
    /// Retrying is enough — the service is alive, so never tell the owner to
    /// quit and relaunch.
    public static let localServiceUnreadable = FirstRunFailure(
        title: .firstRunUnreadableTitle,
        detail: .key(.firstRunUnreadableDetail),
        nextStep: .firstRunUnreadableNext,
        isConnection: true
    )
    /// The service name collides with another one's key slot.
    public static let providerKeyConflict = FirstRunFailure(
        title: .firstRunKeyConflictTitle,
        detail: .key(.firstRunKeyConflictDetail),
        nextStep: .firstRunKeyConflictNext
    )
    /// The key field is empty while the service needs one.
    public static let missingKey = FirstRunFailure(
        title: .firstRunMissingKeyTitle,
        detail: .key(.firstRunMissingKeyDetail),
        nextStep: .firstRunMissingKeyNext
    )
    /// The service address or model is wrong.
    public static let invalidConfig = FirstRunFailure(
        title: .firstRunInvalidConfigTitle,
        detail: .key(.firstRunInvalidConfigDetail),
        nextStep: .firstRunInvalidConfigNext
    )
    /// The model id does not exist.
    public static let modelNotFound = FirstRunFailure(
        title: .firstRunModelNotFoundTitle,
        detail: .key(.firstRunModelNotFoundDetail),
        nextStep: .firstRunModelNotFoundNext
    )
    /// Anything else.
    public static let unknown = FirstRunFailure(
        title: .firstRunUnknownTitle,
        detail: .key(.firstRunUnknownDetail),
        nextStep: .firstRunUnknownNext,
        isConnection: true
    )

    /// Map an HTTP / transport error to a plain card.
    ///
    /// A `401` / `.unauthorized` from the local service means the **app's own**
    /// bearer token failed, not the service key: it maps to the local-service
    /// card, never to "the AI service refused this key". The only real
    /// service-key refusal is the Test endpoint's `bad_key` reason.
    public init(error: Error) {
        guard let auxd = error as? AuxdError else {
            self = .unknown
            return
        }
        switch auxd {
        case .unauthorized:
            self = .localService
        case .http(let status, _):
            switch status {
            case 401: self = .localService
            case 403: self = .accessDenied
            case 409 where auxd.daemonErrorCode == "provider_key_conflict":
                self = .providerKeyConflict
            case 429: self = .tooManyRequests
            default:
                self = FirstRunFailure(
                    title: .firstRunRefusedTitle,
                    detail: .key(.firstRunRefusedDetail),
                    nextStep: .firstRunRefusedNext
                )
            }
        case .decode:
            self = .localServiceUnreadable
        case .transport(let message) where message == AuxdError.timedOutMessage:
            self = .localServiceUnreadable
        case .transport:
            self = .localService
        case .token:
            self = .localService
        case .badURL, .offLoopback:
            self = .localService
        }
    }

    /// Map the daemon's spend-free test verdict (`reason`).
    public init(test: ProviderTest) {
        switch test.reason {
        case "ok":
            self = FirstRunFailure(
                title: .firstRunReadyTitle,
                nextStep: .firstRunReadyNext
            )
        case "bad_key":
            self = .keyRefused
        case "unreachable":
            self = .serviceUnreachable
        case "invalid_config":
            self = .invalidConfig
        case "model_not_found":
            self = .modelNotFound
        default:
            if let error = test.error, !error.isEmpty {
                self = FirstRunFailure(
                    title: .firstRunUnknownTitle,
                    detail: .text(error),
                    nextStep: .firstRunUnknownNext,
                    isConnection: true
                )
            } else {
                self = .unknown
            }
        }
    }
}

/// The Test button's state machine: idle → testing → ok / failed. The `ok`
/// case carries a table key so its sentence follows the owner's language.
public enum FirstRunTestState: Equatable {
    case idle
    case testing
    /// Honest success sentence (the check is spend-free: no completion was
    /// sent, so it must not claim the key is valid with the service).
    case ok(StringKey)
    case failed(FirstRunFailure)
}

/// The setup screen's state machine.
public enum FirstRunSetupState: Equatable {
    case loading
    case ready
    case working
    case done(agent: String)
    case failed(FirstRunFailure)
}

/// Table keys for the setup screen. Kept here (not in the view) so tests can
/// assert the exact wording without a window.
public enum FirstRunCopy {
    /// Honest wording: the service's test never sends a completion, so a
    /// success means "the key is stored and the address answers", never "the
    /// key is valid for a conversation".
    public static func successKey(for test: ProviderTest) -> StringKey {
        test.reachable == true ? .firstRunSuccessReachable : .firstRunSuccess
    }

    public static let testHonestyNote: StringKey = .firstRunHonestyNote
    public static let pickProviderTitle: StringKey = .firstRunPickTitle
    public static let pickProviderBody: StringKey = .firstRunPickBody
    public static let keyFieldTitle: StringKey = .firstRunKeyFieldTitle
    public static let keyOnDiskNote: StringKey = .firstRunKeyOnDiskNote
    public static let testButton: StringKey = .firstRunTestButton
    public static let retryButton: StringKey = .retry
    public static let loadingLabel: StringKey = .firstRunLoading
    public static let testingLabel: StringKey = .firstRunTesting
    public static let creatingLabel: StringKey = .firstRunCreating
    public static let doneTitle: StringKey = .firstRunDoneTitle
    public static func doneBody(agent: String, _ language: Language) -> String {
        L10n.f(.firstRunDoneBody, language, agent)
    }
    public static let doneButton: StringKey = .firstRunDoneButton

    /// The plain label for an agent, or its raw id when it is a custom one.
    /// The daemon's first agent is `main` (the id the rest of the system
    /// expects); the owner reads « Mon agent » / “My agent”.
    public static func displayName(for agent: String, _ language: Language) -> String {
        agent == FirstRunCatalog.defaultAgentID
            ? L10n.t(FirstRunCatalog.defaultAgentLabel, language)
            : agent
    }
}

/// The sign-in a click on « Connecter Google » started, from this screen only.
public enum GoogleFlow: Equatable {
    case idle
    /// The service started the sign-in; the browser page is open.
    case waiting
    /// The sign-in ended without an authorization.
    case failed
}

/// What the Réglages row « Google : … » shows (G4).
///
/// The mapping is pure so the copy rule (one French phrase per state) is
/// testable without a window or a service.
public enum GoogleConnectionState: Equatable {
    /// The service has not answered yet; the row stays honest and says so.
    case unknown
    case disconnected
    /// The sign-in page is open and the owner has not answered yet.
    case waitingForConsent
    case needsUpdate
    case connected
    /// The sign-in did not complete.
    case failed

    /// From the three facts the screen holds: whether the service's status
    /// answer is known, whether it reports a Google authorization, and whether
    /// a sign-in started from this screen is still in flight.
    public static func resolve(
        known: Bool,
        connected: Bool,
        reconnectNeeded: Bool = false,
        waiting: Bool,
        failed: Bool
    ) -> Self {
        if waiting { return .waitingForConsent }
        if reconnectNeeded { return .needsUpdate }
        if connected {
            return .connected
        }
        if failed {
            return .failed
        }
        return known ? .disconnected : .unknown
    }

    /// The value the row prints after « Google : ».
    public var valueKey: StringKey {
        switch self {
        case .unknown: return .googleUnknownValue
        case .disconnected: return .googleDisconnectedValue
        case .waitingForConsent: return .googleWaitingValue
        case .connected: return .googleConnectedValue
        case .needsUpdate: return .googleUpdateNeededValue
        case .failed: return .googleFailedValue
        }
    }

    /// The « Connecter Google » button is enabled only when there is something
    /// to do; pressing it always asks the service, never opens anything here.
    public var canConnect: Bool {
        switch self {
        case .disconnected, .unknown, .failed: return true
        case .connected, .needsUpdate, .waitingForConsent: return false
        }
    }

    /// « Déconnecter » shows while a connection exists (or is being accepted).
    public var canDisconnect: Bool {
        self == .connected || self == .needsUpdate || self == .waitingForConsent
    }
}

@MainActor
public final class Store: ObservableObject {
    public enum Connection: Equatable {
        case connecting
        case online(version: String)
        case offline(String)
        case unauthorized
    }

    public enum Phase: Equatable {
        case idle
        case syncing
        case live
        case offline
    }

    // MARK: Published state

    @Published public private(set) var connection: Connection = .connecting
    /// Why the last connect failed; nil while connecting / online.
    @Published public private(set) var offlineCause: OfflineCause?
    @Published public private(set) var phase: Phase = .idle
    @Published public private(set) var firstRun: Bool = false
    @Published public private(set) var firstRunKnown = false
    /// First-run setup screen state (service picker + key + test).
    @Published public private(set) var firstRunSetupState: FirstRunSetupState = .loading
    @Published public private(set) var firstRunTestState: FirstRunTestState = .idle
    /// Google connection (G4): the service's last honest answer and any
    /// sign-in in flight. Its changes redraw this store's observers too.
    public let google: GoogleConnectionModel
    /// Snapshot of whether the service the app itself started is up; published
    /// so a start/stop redraws the menu bar and Réglages. `serviceLabel` reads
    /// the supervisor's live state, never a live network probe, so it can never
    /// claim a service the app did not start.
    @Published public private(set) var serviceState: ServiceSupervisor.State = .stopped
    @Published public private(set) var providerChoices: [ProviderChoice] = []
    @Published public private(set) var mcpCatalog: [McpCatalogEntry] = []
    @Published public private(set) var mcpPacks: [McpPack] = []
    @Published public private(set) var mcpServers: [McpServerView] = []
    @Published public private(set) var mcpFailed = false
    @Published public private(set) var mcpFailureCode: String?
    @Published public private(set) var mcpTestResult: McpConnectionTest?
    @Published public private(set) var mcpTestedURL: String?
    @Published public var mcpCustomDataClass = "sensitive"
    /// M6-4: the install preview waiting for the owner's one yes.
    @Published public private(set) var pluginPreview: McpApprovalPreview?
    /// The agent picked in the preview sheet (a team id; Aux by default).
    @Published public private(set) var pluginAgent = TeamMember.aux.id
    /// The agent the preview on screen was staged for; `nil` while a new one loads (Approve is off).
    @Published public private(set) var pluginPreviewAgent: String?
    /// The catalog entry the preview can be staged again from; `nil` keeps the agent fixed.
    @Published public private(set) var pluginPreviewCatalogID: String?
    /// The last approve met a 409 `stale_confirmation`: the sheet now shows the fresh
    /// preview and says so; Approve waits for a new yes, never an automatic one.
    @Published public private(set) var pluginPreviewChanged = false
    private var pluginStage = 0
    @Published public private(set) var createdAgentName: String?
    @Published public var selectedProviderID: String?
    /// The key field. Bound to a `SecureField`, cleared after every submit and
    /// never logged, echoed, or persisted by the app.
    @Published public var providerKeyInput = ""
    @Published public private(set) var agents: [Agent] = []
    @Published public private(set) var messages: [ChatMessage] = []
    /// The agent's previous session, shown above a current thread that has no
    /// message yet (a "New chat" was started): history is never hidden. Cleared
    /// when another agent is selected.
    @Published public private(set) var earlierMessages: [ChatMessage] = []
    /// The newest owner or agent message of each agent's thread, for the
    /// sidebar rows. Read once per snapshot, kept current by live frames.
    @Published public private(set) var previews: [String: ConversationPreview] = [:]
    @Published public private(set) var approvals: [Approval] = []
    /// Recent run receipts, newest first. Live `run.finished` frames and the
    /// `GET /v1/receipts` snapshot both merge here, deduplicated by `runId`.
    @Published public private(set) var receipts: [Receipt] = []
    /// What the app knows about the privacy record it read: still reading,
    /// read, or unreadable. The sidebar footer counts from it.
    @Published public private(set) var privacyRecordRead: PrivacyRecordRead = .loading
    @Published public private(set) var focusedApprovalId: String?
    @Published public private(set) var sendingApprovalIds: Set<String> = []
    @Published public private(set) var approvalErrors: [String: String] = [:]
    /// The approvals whose edited card the daemon refused to show: the ask was
    /// never taken, so the card stays open and editable and the reason is
    /// shown on it. Nothing was sent.
    @Published public private(set) var refusedEdits: Set<String> = []
    @Published public private(set) var isSendingMessage = false
    /// Owner messages typed while a turn runs (FIFO), each sent once when it ends.
    private var sendQueue: [(echo: ChatMessage, agent: Agent, session: Int64?)] = []
    /// `thread_busy` (a turn waits on a card): wait for this agent's turn end.
    private var sendQueueHeldBy: String?
    /// Turn ends per agent: a turn end during a refused send retries at once.
    private var turnEnds: [String: Int] = [:]
    /// Bumped by Stop: a refusal that lands after it never re-queues.
    private var stopGeneration = 0
    /// Messages Stop cancelled, per agent: every thread shows "Not sent".
    private var unsentEchoes: [(echo: ChatMessage, agent: Agent)] = []
    @Published public private(set) var lastMessageError: String?
    @Published public private(set) var acceptedDeltas = 0
    @Published public private(set) var liveStates: [String: AgentState] = [:]
    @Published public var selectedAgentName: String?
    @Published public private(set) var conversations: Loadable<[ConversationSummary]> = .loading
    @Published public private(set) var selectedConversationId: Int64?
    /// Bumped per thread read, so a slow page never lands on a newer choice.
    private var threadLoad = 0
    /// The tool the selected agent is running right now (`tool.start` until
    /// `tool.end` or `message.done`): the thread's one live tool line.
    @Published public private(set) var liveTool: ToolCall?
    /// Stop all is engaged: the daemon reports its kill switch on every agent.
    @Published public private(set) var stopEngaged = false
    @Published public var composerText = ""
    @Published public var language: Language {
        didSet {
            guard language != oldValue else { return }
            defaults?.set(language.rawValue, forKey: Store.languageKey)
            (transport as? LanguageReporting)?.language = language
        }
    }

    // MARK: Diagnostics (real values, used by tests and the status line)

    public private(set) var syncCount = 0
    public private(set) var reconnectDelays: [TimeInterval] = []
    public let endpoint: AuxdEndpoint?
    /// Starts/stops the `auxd` shipped inside this app. `nil` in tests that do
    /// not exercise service ownership; the app always provides one.
    public let service: ServiceSupervisor?

    // MARK: Test seam (the Mac app tests only)
    //
    /// How many receipt reads failed and were handled. The count moves
    /// *after* the catch has run, so a test can wait for it instead of
    /// sleeping: a failure that has not landed yet looks exactly like a
    /// failure that left the state untouched.
    private(set) var failedReceiptReads = 0

    // MARK: Internals

    public static let languageKey = "auxesis.language"
    /// How many receipts the app keeps in memory (the daemon prunes the rest).
    public static let receiptLimit = 100

    private let transport: AuxdTransport
    /// Non-nil when the transport also speaks the first-run routes (the real
    /// `AuxdClient` does); tests inject a scripted one.
    private let firstRunClient: FirstRunClient?
    private var googleChanges: AnyCancellable?
    private let sleeper: (TimeInterval) async -> Void
    /// How often a live session re-reads pending approvals (WAITING-ROW-DELEGATE).
    private let approvalPollInterval: TimeInterval
    private let defaults: UserDefaults?
    private var connectionTask: Task<Void, Never>?
    /// The session's event consumer (an unstructured child task). Retained so
    /// `stop()` can cancel it; its `for await` owns the socket's liveness.
    private var sessionConsumer: Task<Void, Never>?
    /// Bumped on every start/stop. A session only mutates the Store while its
    /// captured generation still matches, so a stopped session is inert even
    /// if one of its tasks is still unwinding.
    private var sessionGeneration = 0
    private var buffered: [WireEvent] = []
    /// Drafts whose stored reply arrived (or whose turn ended): a late delta
    /// for one of them must not bring the streamed bubble back.
    private var finishedDrafts: Set<String> = []
    /// The run of the owner's send in flight, from its first live `message.new`.
    private var sendRunId: String?
    /// The echo of the words in flight, replaced by their stored copy.
    private var sendingEchoId: String?
    private var streamFailure: Error?
    private var localApprovalStates: [String: ApprovalState] = [:]
    private var activeRunIds: [String: String] = [:]
    private var currentThreadStarts: [String: Date] = [:]
    private var firstSeen: [String: Date] = [:]
    /// Ids whose last answer failed: blocked until a fresh snapshot (or the
    /// resolve-failure re-fetch) reports their real state — never auto-resent.
    private var approvalsAwaitingResync: Set<String> = []
    private var aliases = ThreadAliases()
    private var version = ""
    /// True once this episode has tried to start the bundled service, so a
    /// child that exits immediately (port held) is never respawned in a loop.
    private var didAttemptServiceStart = false

    public init(
        transport: AuxdTransport,
        firstRunClient: FirstRunClient? = nil,
        googleClient: GoogleConnectionClient? = nil,
        language: Language? = nil,
        localeProvider: LocaleLanguageProviding = SystemLocaleLanguageProvider(),
        defaults: UserDefaults? = nil,
        endpoint: AuxdEndpoint? = nil,
        sleeper: @escaping (TimeInterval) async -> Void = { delay in
            try? await Task.sleep(nanoseconds: UInt64(max(0, delay) * 1_000_000_000))
        },
        service: ServiceSupervisor? = nil,
        approvalPollInterval: TimeInterval = 2
    ) {
        self.transport = transport
        self.approvalPollInterval = approvalPollInterval
        self.firstRunClient = firstRunClient ?? (transport as? FirstRunClient)
        self.sleeper = sleeper
        // Non-nil client when the transport also speaks the Google routes (the
        // real `AuxdClient` does); tests inject a scripted one.
        self.google = GoogleConnectionModel(
            client: googleClient ?? (transport as? GoogleConnectionClient),
            health: { try await transport.health() },
            pause: sleeper
        )
        self.defaults = defaults
        self.endpoint = endpoint
        self.service = service
        // A language the owner chose by hand (`auxesis.language`) always wins;
        // otherwise a fresh install follows the system's preferred language.
        let chosen = defaults?.string(forKey: Store.languageKey).flatMap(Language.init(rawValue:))
        self.language = chosen ?? language ?? Language.preferred(using: localeProvider)
        // The client tags every request with the current language so the
        // service can answer in it once it learns to.
        (transport as? LanguageReporting)?.language = self.language
        // F4: the child we own can exit on its own (crash, held port). The
        // supervisor marshals that to the main queue; republish the snapshot the
        // menu bar and Réglages read, so the line flips to « Service arrêté »
        // without waiting for an explicit start/stop.
        service?.onChildExit = { [weak self] in
            MainActor.assumeIsolated {
                self?.publishServiceState()
            }
        }
        googleChanges = google.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
    }

    // MARK: Lifecycle

    public func start() {
        beginSession(after: nil)
    }

    public func stop() {
        // Invalidate the running session first: its consumer, its in-flight
        // snapshot and any buffered events must never touch the Store again.
        sessionGeneration &+= 1
        sessionConsumer?.cancel()
        sessionConsumer = nil
        connectionTask?.cancel()
        connectionTask = nil
        buffered.removeAll()
        phase = .idle
    }

    /// Tear the previous session down, then start a fresh one. The new session
    /// does not open its socket until the previous session's task has fully
    /// unwound, so `restart()` can never leave two live sessions.
    ///
    /// Synchronous because the SwiftUI call sites are; the sequencing happens
    /// inside the new connection task (which awaits the old one first).
    public func restart() {
        let previous = connectionTask
        stop()
        // A fresh attempt may start the bundled service again: the owner
        // pressing "Relancer Auxesis" is exactly the retry that would follow a
        // first child that exited.
        didAttemptServiceStart = false
        beginSession(after: previous)
    }

    /// Starts a session loop, first awaiting `previous` (if any) so only one
    /// session is ever live. `generation` pins the new session so a later
    /// `stop()` can invalidate it.
    private func beginSession(after previous: Task<Void, Never>?) {
        guard connectionTask == nil else { return }
        sessionGeneration &+= 1
        let generation = sessionGeneration
        connectionTask = Task { [weak self] in
            if let previous {
                _ = await previous.value
            }
            guard let self, !Task.isCancelled else { return }
            await self.connectionLoop(generation: generation)
        }
    }

    private func connectionLoop(generation: Int) async {
        var attempt = 0
        while !Task.isCancelled, generation == sessionGeneration {
            connection = .connecting
            offlineCause = nil
            // The service the app starts writes `api.token` at startup, so the
            // client re-reads it before each attempt: a fresh install connects
            // on its own instead of asking the owner to relaunch Auxesis.
            (transport as? TokenRefreshing)?.refreshToken()
            do {
                try await runSession(generation: generation)
                attempt = 0
            } catch is CancellationError {
                return
            } catch {
                if Task.isCancelled || generation != sessionGeneration { return }
                connection = connectionState(for: error)
                // The service is not answering: the record cannot be read, so
                // the footer says the count is unavailable rather than
                // keeping a number the app can no longer stand behind.
                privacyRecordRead = .unavailable
                maybeStartBundledService()
            }
            if Task.isCancelled || generation != sessionGeneration { return }
            attempt += 1
            let delay = ReconnectPolicy.delay(attempt: attempt)
            reconnectDelays.append(delay)
            await pause(delay)
        }
    }

    /// One reconnect pause, kept in its own frame.
    ///
    /// `sleeper` is an escaping async closure; calling it straight from the
    /// retry loop lets the optimiser sink its task-stack `swift_task_dealloc`
    /// across the loop's suspension point, which trips the concurrency task
    /// allocator ("freed pointer was not the last allocation"). A separate,
    /// non-inlined frame keeps the alloc/dealloc pair off the loop's back-edge.
    /// See swiftlang/swift#75501 / #81771 / #87481.
    @inline(never)
    private func pause(_ delay: TimeInterval) async {
        await sleeper(delay)
    }

    private func runSession(generation: Int) async throws {
        phase = .syncing
        buffered.removeAll()
        streamFailure = nil
        let stream = try transport.events()
        let consumer = Task { @MainActor [weak self] in
            do {
                for try await event in stream {
                    guard let self, self.sessionGeneration == generation else { return }
                    self.receive(event)
                }
            } catch {
                guard let self, self.sessionGeneration == generation else { return }
                self.streamFailure = error
            }
        }
        // Retained so `stop()` can cancel it directly. Cancelling the consumer
        // ends the `for await`, which terminates the stream and fires the
        // transport's `onTermination` (AuxdClient cancels the WS task: the
        // socket is closed, not merely abandoned).
        sessionConsumer = consumer
        // A delegated card may never reach this socket: re-read the list too.
        let approvalPoll = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(max(0.05, self?.approvalPollInterval ?? 2) * 1_000_000_000))
                guard let self, self.sessionGeneration == generation, self.phase == .live else { return }
                await self.refreshPendingApprovals()
            }
        }
        defer {
            consumer.cancel()
            approvalPoll.cancel()
            if sessionConsumer == consumer { sessionConsumer = nil }
        }

        let snapshot = try await loadSnapshot()
        // A stop/restart while the snapshot was in flight must not apply it.
        guard generation == sessionGeneration, !Task.isCancelled else {
            throw CancellationError()
        }
        syncCount += 1
        apply(snapshot)
        connection = .online(version: snapshot.health.version)
        offlineCause = nil
        phase = .live
        // The service answered: a later drop may start it again.
        didAttemptServiceStart = false
        drainBuffered()
        try await consumer.value
        guard generation == sessionGeneration else { return }
        if let failure = streamFailure {
            streamFailure = nil
            throw failure
        }
    }

    private struct Snapshot {
        let health: HealthResponse
        let agents: [AgentSummary]
        let approvals: [Approval]
        let selected: String?
        let page: MessagesPage?
        let receipts: [Receipt]
    }

    private func loadSnapshot() async throws -> Snapshot {
        async let health = transport.health()
        async let agents = transport.agents()
        async let approvals = transport.pendingApprovals()
        let (healthValue, agentValues, approvalValues) = try await (health, agents, approvals)
        // Receipts are additive: an older service without `/v1/receipts` must
        // not fail the whole snapshot, so a failed read degrades to an empty
        // list and the live frames still stream in.
        let receiptValues = await loadReceipts(agent: nil, decidesReadState: true)
        // A selected team agent stays selected even before the daemon lists
        // it: auxd resolves the name and creates the thread on first send.
        let selected = selectedAgentName ?? agentValues.first?.name
        var page: MessagesPage?
        if let selected {
            page = try await transport.messages(thread: selected)
        }
        return Snapshot(
            health: healthValue,
            agents: agentValues,
            approvals: approvalValues,
            selected: selected,
            page: page,
            receipts: receiptValues
        )
    }

    /// Best-effort receipt read: a failed read (older service, timeout) is an
    /// empty list, never a snapshot failure. Newest-first from the daemon.
    ///
    /// Only the snapshot read decides what the footer says (`decidesReadState`):
    /// a per-agent read on thread selection must not turn a known count into
    /// "unavailable" because that one agent's receipts could not be read.
    private func loadReceipts(agent: String?, decidesReadState: Bool = false) async -> [Receipt] {
        do {
            let values = try await transport.receipts(agent: agent, limit: Store.receiptLimit)
            if decidesReadState { privacyRecordRead = .loaded }
            return values
        } catch {
            // The record could not be read: the footer says the count is
            // unavailable instead of showing a number it cannot back.
            if decidesReadState { privacyRecordRead = .unavailable }
            // The count moves after the state write above, so a test that
            // waits for it knows the failure has already landed.
            failedReceiptReads += 1
            return []
        }
    }

    private func apply(_ snapshot: Snapshot) {
        version = snapshot.health.version
        firstRun = snapshot.health.firstRun
        firstRunKnown = true
        google.apply(
            connected: snapshot.health.googleConnected,
            reconnectNeeded: snapshot.health.googleReconnectNeeded
        )
        for agent in snapshot.agents {
            aliases.learn(agent: agent.name, sessionId: agent.threadId)
        }
        agents = snapshot.agents.map { Mapper.agent(from: $0, live: liveStates[$0.name], language: language) }
        stopEngaged = snapshot.agents.contains(where: \.stop)
        if let selected = snapshot.selected {
            if let previous = selectedAgentName, previous != selected { messages = [] }
            selectedAgentName = selected
        }
        if selectedAgentName == nil {
            selectedAgentName = agents.first?.name
        }
        if let page = snapshot.page, let selected = snapshot.selected {
            aliases.learn(page: page, agent: selected)
            if let createdAt = page.thread?.createdAt, let date = TimeText.parse(createdAt) {
                if let previous = currentThreadStarts[selected], previous != date { messages = [] }
                currentThreadStarts[selected] = date
            }
            let refreshed = page.messages.map { Mapper.message(from: $0, threadKey: selected, agentName: selected) }
            messages = Self.mergeMessages(messages, with: refreshed)
            loadEarlierIfEmpty(agent: selected, current: page.thread, generation: threadLoad)
            setPreview(agent: selected, from: refreshed)
        }
        // The selected agent's thread is read above; the others' newest rows now.
        refreshPreviews(names: Set(TeamMember.all.map(\.id)).union(snapshot.agents.map(\.name)).subtracting([snapshot.selected ?? ""]))
        applyApprovalsSnapshot(snapshot.approvals)
        mergeReceipts(snapshot.receipts)
        loadConversations()
        resortAgents()
    }

    /// Re-read the pending list and merge it: a missed frame cannot hide a
    /// card, and a pending card the daemon no longer lists leaves.
    private func refreshPendingApprovals() async {
        guard let fetched = try? await transport.pendingApprovals() else { return }
        let ids = Set(fetched.map(\.id))
        approvals.removeAll { $0.state.isPending && !ids.contains($0.id) }
        for approval in fetched { upsert(approval: approval) }
        if let focused = focusedApprovalId, !approvals.contains(where: { $0.id == focused }) {
            focusedApprovalId = approvals.first(where: { $0.state.isPending })?.id
        }
        resortAgents()
    }

    private func applyApprovalsSnapshot(_ fetched: [Approval]) {
        let ids = Set(fetched.map(\.id))
        localApprovalStates = localApprovalStates.filter { ids.contains($0.key) }
        firstSeen = firstSeen.filter { ids.contains($0.key) }
        // A successfully fetched list is the daemon's real state for every id
        // (present → still pending/known, absent → gone): answers may leave
        // again once the failure has been reconciled.
        approvalsAwaitingResync.removeAll()
        let mapped = fetched.map { incoming in
            var copy = incoming
            if let seen = firstSeen[copy.id] {
                copy.receivedAt = seen
            } else {
                firstSeen[copy.id] = Date()
                copy.receivedAt = firstSeen[copy.id]
            }
            if let known = localApprovalStates[copy.id] {
                copy.state = known
            }
            return copy
        }
        // Newest ask first, matching the live path (`approval.new` inserts at
        // index 0, see StoreConsistencyTests "newest ask first"): sorting by the
        // wire `ts` keeps snapshots and live arrivals in one order, so a
        // reconnect cannot flip oldest/newest and change what J/K focuses.
        approvals = mapped.sorted { $0.ts > $1.ts }
        if let focused = focusedApprovalId, !approvals.contains(where: { $0.id == focused }) {
            focusedApprovalId = approvals.first(where: { $0.state.isPending })?.id
        }
    }

    private func drainBuffered() {
        let pending = buffered
        buffered.removeAll()
        for event in pending {
            apply(event: event)
        }
    }

    private func receive(_ event: WireEvent) {
        if phase == .live {
            apply(event: event)
        } else {
            buffered.append(event)
        }
    }

    // MARK: Event application

    private func apply(event: WireEvent) {
        switch event {
        case .messageNew(let message):
            let runAgent = message.author.agentName ?? message.frameAgent ??
                (message.author == .you ? selectedAgentName : nil)
            if let runAgent, let runId = message.runId, !runId.isEmpty {
                activeRunIds[runAgent] = runId
            }
            // The frame's agent places another session's tool and reply rows; the
            // owner's own words from another channel (iMessage) never enter this chat.
            let agent = message.author == .you ? message.author.agentName : (message.author.agentName ?? message.frameAgent)
            guard let key = aliases.visible(threadId: message.threadKey, agent: agent) else { return }
            setPreview(agent: key, from: [message])
            guard key == selectedAgentName else { return }
            let ofSend = message.author == .you && isSendingMessage && sendRunId == nil
            if ofSend { sendRunId = message.runId }
            var merged = message
            merged = ChatMessage(
                id: message.id,
                threadKey: key,
                author: message.author,
                ts: message.ts,
                blocks: message.blocks,
                streaming: message.streaming,
                pending: false,
                rehydrationUnavailable: message.rehydrationUnavailable
            )
            merged.runId = message.runId
            // DELEGATION-SOURCE-1: the row is rebuilt here, so the source the
            // frame carries must be carried over: a delegated ask is the grey
            // delegation line, never the owner's bubble (its stored text is
            // not the ask when the ask was truncated).
            merged.source = message.source
            // The stored reply takes its streamed draft's place: one bubble,
            // even when the stored row is already shown.
            if let draft = message.draftId {
                finishedDrafts.insert(draft)
                if let index = messages.firstIndex(where: { $0.id == draft }) {
                    guard messages.contains(where: { $0.id == message.id }) else {
                        messages[index] = merged
                        return
                    }
                    messages.remove(at: index)
                }
            }
            // The stored words in flight take their echo's place (text may differ).
            if ofSend, let index = messages.firstIndex(where: { $0.id == sendingEchoId }),
               !messages.contains(where: { $0.id == message.id }) {
                messages[index] = merged
                return
            }
            upsert(message: merged)
        case .messageDelta(let threadId, let messageId, let text, let agent, let rehydrationUnavailable):
            guard aliases.visible(threadId: threadId, agent: agent) == selectedAgentName else { return }
            guard !finishedDrafts.contains(messageId) else { return }
            if let index = messages.firstIndex(where: { $0.id == messageId }) {
                messages[index].appendDelta(text)
                messages[index].streaming = true
                if rehydrationUnavailable { messages[index].rehydrationUnavailable = true }
            } else {
                let message = ChatMessage(
                    id: messageId,
                    threadKey: selectedAgentName ?? "",
                    author: .agent(agent ?? selectedAgentName ?? "agent"),
                    ts: 0,
                    blocks: [.text(text)],
                    streaming: true,
                    rehydrationUnavailable: rehydrationUnavailable
                )
                appendRow(message)
            }
            acceptedDeltas += 1
        case .messageDone(_, let messageId):
            liveTool = nil
            if let index = messages.firstIndex(where: { $0.id == messageId }) {
                messages[index].streaming = false
            }
        case .toolStart(let threadId, _, let call):
            if aliases.visible(threadId: threadId, agent: nil) == selectedAgentName { liveTool = call }
        case .toolEnd(let threadId, _, _, _):
            if aliases.visible(threadId: threadId, agent: nil) == selectedAgentName { liveTool = nil }
        case .other:
            break
        case .approvalNew(let approval):
            upsert(approval: approval)
        case .approvalResolved(let id, let state):
            localApprovalStates[id] = state
            if let index = approvals.firstIndex(where: { $0.id == id }) {
                approvals[index].state = state
            }
            resortAgents()
        case .agentStateLive(let agent, let state):
            liveStates[agent] = state
            if state == .idle { turnEnded(agent) }
            if state == .thinking || state == .working { activeRunIds[agent] = nil }
            if let index = agents.firstIndex(where: { $0.name == agent }) {
                let current = agents[index]
                if current.state != .paused, current.state != .killed, current.runningJob == nil {
                    agents[index].state = state
                }
                resortAgents()
            }
        case .agentSnapshot(let agent):
            aliases.learn(agent: agent.name, sessionId: agent.threadId)
            // Fallback for a missed idle frame: a polled state with no turn.
            if agent.runningJob == nil, liveStates[agent.name].map({ $0 == .idle }) ?? true { turnEnded(agent.name) }
            upsert(agent: agent)
        case .runFinished(let receipt):
            // Clear on the matching run, and also when the run is unknown
            // (no tracked id, or an older daemon's empty run id): a dropped
            // idle frame must never leave an agent "working" forever. A
            // genuinely live run reports its state again on the next frame.
            let tracked = activeRunIds[receipt.agent]
            if tracked == nil || receipt.runId.isEmpty || tracked == receipt.runId {
                activeRunIds[receipt.agent] = nil
                liveStates[receipt.agent] = nil
                if let index = agents.firstIndex(where: { $0.name == receipt.agent }),
                   agents[index].runningJob == nil,
                   agents[index].state == .working || agents[index].state == .thinking {
                    agents[index].state = .idle
                    resortAgents()
                }
            }
            upsert(receipt: receipt)
            turnEnded(receipt.agent)
        }
    }

    private func upsert(agent agent: AgentSummary) {
        let mapped = Mapper.agent(from: agent, live: liveStates[agent.name], language: language)
        stopEngaged = agent.stop
        if let index = agents.firstIndex(where: { $0.name == agent.name }) {
            var updated = mapped
            updated.waiting = agents[index].waiting
            agents[index] = updated
        } else {
            agents.append(mapped)
        }
        resortAgents()
    }

    private func upsert(message: ChatMessage) {
        if let index = messages.firstIndex(where: { $0.id == message.id }) {
            var message = message
            message.runId = message.runId ?? messages[index].runId
            messages[index] = message
            return
        }
        // The send response carries provisional ids (≤ 0); the socket carries
        // the stored message. One turn, one bubble: the stored copy wins.
        if let index = messages.firstIndex(where: { Store.sameMessage($0, message) }) {
            if Store.isProvisional(messages[index].id) { messages[index] = message }
            return
        }
        appendRow(message)
    }

    /// A new row reads above the queued words: they have not been sent yet.
    private func appendRow(_ message: ChatMessage) {
        let index = messages.firstIndex { $0.delivery == .queued } ?? messages.endIndex
        messages.insert(message, at: index)
    }

    nonisolated static func isProvisional(_ id: String) -> Bool {
        guard let value = Int64(id) else { return false }
        return value <= 0
    }

    /// The same message seen once with a provisional id and once stored.
    nonisolated static func sameMessage(_ a: ChatMessage, _ b: ChatMessage) -> Bool {
        isProvisional(a.id) != isProvisional(b.id) && a.author == b.author && a.text == b.text
    }

    nonisolated static func mergeMessages(_ existing: [ChatMessage], with incoming: [ChatMessage]) -> [ChatMessage] {
        var merged = existing
        for message in incoming {
            if let index = merged.firstIndex(where: { $0.id == message.id || sameMessage($0, message) }) {
                merged[index] = message
            } else {
                merged.append(message)
            }
        }
        return merged.enumerated()
            .sorted { left, right in
                let a = left.element.ts
                let b = right.element.ts
                return a > 0 && b > 0 && a != b ? a < b : left.offset < right.offset
            }
            .map(\.element)
    }

    /// One receipt: a known `runId` is replaced **in place** (a replayed frame
    /// must not jump an old run to the top); a new one goes to the front.
    private func upsert(receipt: Receipt) {
        if !receipt.runId.isEmpty,
           let index = receipts.firstIndex(where: { $0.runId == receipt.runId }) {
            receipts[index] = receipt
            return
        }
        receipts.insert(receipt, at: 0)
        if receipts.count > Store.receiptLimit {
            receipts.removeLast(receipts.count - Store.receiptLimit)
        }
    }

    /// Merge a newest-first page without disturbing an already-known run's
    /// position (the snapshot is authoritative on content, not on order).
    private func mergeReceipts(_ incoming: [Receipt]) {
        for receipt in incoming.reversed() {
            upsert(receipt: receipt)
        }
    }

    private func upsert(approval: Approval) {
        var copy = approval
        if let seen = firstSeen[copy.id] {
            copy.receivedAt = seen
        } else {
            firstSeen[copy.id] = Date()
            copy.receivedAt = firstSeen[copy.id]
        }
        if let known = localApprovalStates[copy.id] {
            copy.state = known
        }
        if let index = approvals.firstIndex(where: { $0.id == copy.id }) {
            approvals[index] = copy
        } else {
            approvals.insert(copy, at: 0)
        }
        // A new card takes the focus from an answered one: the detail pane
        // never keeps showing a declined card while a new one waits.
        let focusedAnswered = approvals.first { $0.id == focusedApprovalId }.map { !$0.state.isPending } ?? true
        if focusedAnswered, copy.state.isPending {
            focusedApprovalId = copy.id
        }
        resortAgents()
    }

    private func resortAgents() {
        var waitingByAgent: [String: Int] = [:]
        for approval in approvals where approval.state.isPending {
            waitingByAgent[approval.agent, default: 0] += 1
        }
        for index in agents.indices {
            agents[index].waiting = waitingByAgent[agents[index].name] ?? 0
        }
        agents = Agent.sorted(agents)
    }

    // MARK: Conversation

    public var selectedAgent: Agent? {
        guard let selectedAgentName else { return nil }
        // A team agent the daemon does not list yet (E0 seeds them) is still
        // addressable: auxd resolves the name and creates its thread lazily.
        return agents.first(where: { $0.name == selectedAgentName })
            ?? Agent(
                id: selectedAgentName, name: selectedAgentName, hue: AgentHues.index(for: selectedAgentName),
                glyph: "", state: liveStates[selectedAgentName] ?? .idle, status: "", threadKey: selectedAgentName
            )
    }

    public func agentTools(name: String) async throws -> AgentToolsDetail {
        guard let client = transport as? PackClient else {
            throw AuxdError.transport(L10n.t(.packsUnavailable, language))
        }
        return try await client.agentTools(name: name)
    }

    public func updateAgentTools(name: String, tools: [String]?) async throws {
        guard let client = transport as? PackClient else {
            throw AuxdError.transport(L10n.t(.packsUnavailable, language))
        }
        try await client.updateAgentTools(name: name, tools: tools)
    }

    public func refreshPlugins() { Task { await loadPlugins() } }
    /// Browse: three GETs, nothing else. No add, no approve, no server starts.
    public func loadPlugins() async {
        guard let client = transport as? PluginsClient else { mcpFailed = true; return }
        do { async let catalog = client.mcpCatalog(); async let servers = client.mcpServers(); async let packs = client.mcpPacks(); let (c, s, p) = try await (catalog, servers, packs); mcpCatalog = c; mcpServers = s; mcpPacks = p; mcpFailed = false } catch { mcpFailed = true }
    }
    public func enablePluginPack(_ pack: McpPack, agent: String) { guard let client = transport as? PluginsClient else { return }; Task { do { try await client.enableMcpPack(id: pack.id, agent: agent); self.refreshPlugins() } catch { self.mcpFailed = true } } }
    /// M6-4: Install stages the entry off for Aux and opens its preview; nothing runs before `approvePluginPreview`.
    public func installPlugin(_ entry: McpCatalogEntry) async {
        pluginAgent = TeamMember.aux.id
        await stagePlugin(id: String(entry.id.prefix(32)), catalogID: entry.id, agent: pluginAgent, replace: false)
        await loadPlugins()
    }
    /// An installed server that is off or waits for a yes: show its preview again. Its staged
    /// allowlist names the agent; with several agents staged there is no single target to show.
    public func reviewPlugin(_ server: McpServerView) async {
        let staged = server.agents.keys.sorted()
        pluginAgent = staged.first ?? TeamMember.aux.id
        pluginPreviewCatalogID = mcpCatalog.first { $0.id == server.id }?.id
        await showPluginPreview(agent: staged.count > 1 ? nil : pluginAgent) { try await $0.mcpApproval(id: server.id) }
    }
    /// r1 (#532 P2): the hash binds the agent's allowlist, so another agent means a new staging
    /// and a new preview. Until it arrives, Approve does nothing: the old hash never goes out.
    public func choosePluginAgent(_ agent: String) async {
        guard agent != pluginAgent, pluginPreviewAgent != nil, let preview = pluginPreview, let catalogID = pluginPreviewCatalogID else { return }
        pluginAgent = agent
        await stagePlugin(id: preview.id, catalogID: catalogID, agent: agent, replace: true)
    }
    private func stagePlugin(id: String, catalogID: String, agent: String, replace: Bool) async {
        pluginPreviewCatalogID = catalogID
        await showPluginPreview(agent: agent) { client in
            if replace { try await client.deleteMcpServer(id: id) } // still off: nothing was running
            return try await client.addMcpServer(id: id, catalogID: catalogID, agent: agent)
        }
    }
    private func showPluginPreview(agent: String?, changed: Bool = false, _ fetch: (PluginsClient) async throws -> McpApprovalPreview) async {
        guard let client = transport as? PluginsClient else { return }
        pluginStage += 1
        let stage = pluginStage
        pluginPreviewAgent = nil
        pluginPreviewChanged = false
        do {
            let preview = try await fetch(client)
            guard stage == pluginStage else { return }
            pluginPreview = preview; pluginPreviewAgent = agent; pluginPreviewChanged = changed; mcpFailureCode = nil
        } catch {
            guard stage == pluginStage else { return }
            mcpFailed = true; mcpFailureCode = mcpCode(error)
        }
    }
    /// The owner's one yes: approves exactly the shown preview (its hash) for exactly the shown agent.
    public func approvePluginPreview() async {
        guard let client = transport as? PluginsClient, let preview = pluginPreview, let agent = pluginPreviewAgent, agent == pluginAgent else { return }
        do { try await client.approveMcpServer(id: preview.id, hash: preview.hash, agent: agent); cancelPluginPreview(); mcpFailureCode = nil } catch {
            let code = mcpCode(error)
            if Self.wantsApprove(code) {
                // The shown preview went stale: fetch the current one; the owner says yes again.
                await showPluginPreview(agent: agent, changed: code == "stale_confirmation") { try await $0.mcpApproval(id: preview.id) }
            } else {
                mcpFailed = true; mcpFailureCode = code
            }
        }
        await loadPlugins()
    }
    public func cancelPluginPreview() { pluginStage += 1; pluginPreview = nil; pluginPreviewAgent = nil; pluginPreviewCatalogID = nil; pluginPreviewChanged = false }
    public func clearPluginTest() { mcpTestResult = nil; mcpTestedURL = nil }
    public static func pluginAddReady(url: String, id: String, testedURL: String?) -> Bool {
        !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && testedURL == url
    }
    private func mcpCode(_ error: Error) -> String? {
        guard case AuxdError.http(_, let body) = error, let data = body.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let detail = root["error"] as? [String: Any] else { return nil }
        return detail["code"] as? String
    }
    public func testPluginURL(_ url: String) { guard let client = transport as? PluginsClient else { mcpFailed = true; return }; clearPluginTest(); Task { do { self.mcpTestResult = try await client.testMcpServer(url: url); self.mcpTestedURL = url; self.mcpFailed = false; self.mcpFailureCode = nil } catch { self.mcpTestResult = nil; self.mcpTestedURL = nil; self.mcpFailed = true; self.mcpFailureCode = self.mcpCode(error) } } }
    public func addPluginURL(_ url: String, id: String) { guard let client = transport as? PluginsClient, let test = mcpTestResult, Self.pluginAddReady(url: url, id: id, testedURL: mcpTestedURL) else { return }; Task { do { try await client.addMcpUrlServer(id: id, url: url, dataClass: mcpCustomDataClass, testDigest: test.digest); clearPluginTest(); self.refreshPlugins(); self.mcpFailureCode = nil } catch { self.mcpFailed = true; self.mcpFailureCode = self.mcpCode(error) } } }
    /// M6-APP-APPROVE-ONLY: turning a server on is never a bare PUT; it goes through the
    /// preview and the one approve (`reviewPlugin`). Only "off" is a direct call.
    public func setPlugin(_ server: McpServerView, enabled: Bool) async {
        guard enabled else { await mcpCall(server) { try await $0.setMcpServer(id: server.id, enabled: false) }; return }
        await reviewPlugin(server)
    }
    public func setPluginTools(_ server: McpServerView, agent: String, tools: [String]) async { await mcpCall(server) { try await $0.setMcpTools(id: server.id, agent: agent, tools: tools) } }
    /// One plugin write, then a refresh. A daemon asking for the approve flow is not an error:
    /// it opens the server's preview sheet.
    private func mcpCall(_ server: McpServerView, _ call: (PluginsClient) async throws -> Void) async {
        guard let client = transport as? PluginsClient else { return }
        do { try await call(client) } catch let error where Self.wantsApprove(mcpCode(error)) { await reviewPlugin(server) } catch { mcpFailed = true }
        await loadPlugins()
    }
    /// 409 `use_approve` (legacy confirm gone), `approval_required` or `stale_confirmation`:
    /// show the current preview instead of an error.
    static func wantsApprove(_ code: String?) -> Bool { ["use_approve", "approval_required", "stale_confirmation"].contains(code) }
    public func deletePlugin(_ server: McpServerView) { guard let client = transport as? PluginsClient else { return }; Task { do { try await client.deleteMcpServer(id: server.id); self.refreshPlugins() } catch { self.mcpFailed = true } } }

    public func skills() async throws -> [LocalSkill] {
        guard let client = transport as? SkillsClient else {
            throw AuxdError.transport(L10n.t(.skillsUnavailable, language))
        }
        return try await client.skills()
    }

    public func updateAgentSkills(name: String, skills: [String]) async throws {
        guard let client = transport as? SkillsClient else {
            throw AuxdError.transport(L10n.t(.skillsUnavailable, language))
        }
        try await client.updateAgentSkills(name: name, skills: skills)
    }

    /// The agent's personality, whole (`GET /v1/agents/{id}/soul`).
    public func agentSoul(name: String) async throws -> AgentSoul {
        guard let client = transport as? PersonalityClient else {
            throw AuxdError.transport(
                "Cette version d'Auxesis ne propose pas encore la personnalité.")
        }
        return try await client.agentSoul(name: name)
    }

    /// Save the agent's personality (`PUT /v1/agents/{id}`, `soul_md`).
    public func updateAgentSoul(name: String, soul: String) async throws {
        guard let client = transport as? PersonalityClient else {
            throw AuxdError.transport(
                "Cette version d'Auxesis ne propose pas encore la personnalité.")
        }
        try await client.updateAgentSoul(name: name, soul: soul)
    }

    public func selectAgent(_ name: String) {
        guard name != selectedAgentName || selectedConversationId != nil else { return }
        loadThread(agent: name, session: nil)
    }

    /// CONV-SIDEBAR-1: open a listed conversation as the agent's current one.
    public func selectConversation(_ id: Int64) {
        guard !isSendingMessage else { return }
        loadThread(agent: TeamMember.aux.id, session: id)
    }

    private func loadThread(agent name: String, session: Int64?) {
        threadLoad &+= 1
        let generation = threadLoad
        selectedAgentName = name
        selectedConversationId = session
        messages = localEchoes(of: name)
        earlierMessages = []
        finishedDrafts.removeAll()
        liveTool = nil
        lastMessageError = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                if let session {
                    self.aliases.learn(agent: name, sessionId: String(session))
                }
                let page = try await self.transport.messages(thread: session.map(String.init) ?? name, limit: 200)
                guard self.threadLoad == generation, self.selectedAgentName == name else { return }
                self.aliases.learn(page: page, agent: name)
                if let createdAt = page.thread?.createdAt, let date = TimeText.parse(createdAt) {
                    self.currentThreadStarts[name] = date
                }
                let loaded = page.messages.map {
                    Mapper.message(from: $0, threadKey: name, agentName: name)
                }
                // Words not sent yet (queued, or cancelled by Stop) stay last.
                self.messages = Store.mergeMessages(self.messages.filter { $0.delivery == nil }, with: loaded)
                    + self.messages.filter { $0.delivery != nil }
                self.loadEarlierIfEmpty(agent: name, current: page.thread, generation: generation)
                let fetched = await self.loadReceipts(agent: name)
                guard self.threadLoad == generation, self.selectedAgentName == name else { return }
                self.mergeReceipts(fetched)
            } catch {
                guard self.threadLoad == generation, self.selectedAgentName == name else { return }
                if session != nil { self.selectedConversationId = nil }
                self.lastMessageError = self.humanMessage(for: error)
            }
        }
    }

    /// CONV-SIDEBAR-1: refresh at the start and when Aux's turn ends.
    public func loadConversations() {
        Task { [weak self] in
            guard let self else { return }
            do {
                let rows = try await self.transport.conversations()
                self.conversations = .loaded(rows)
            } catch {
                if self.conversations.value == nil { self.conversations = .failed }
            }
        }
    }

    /// The thread the owner reads: the agent's previous session (if any), then
    /// the current one. A session a "New chat" started has no message yet; the
    /// owner still opens on the last conversation, never on the welcome.
    public var conversation: [ChatMessage] {
        guard !earlierMessages.isEmpty else { return messages }
        let name = selectedAgentName ?? ""
        let divider = ChatMessage(
            id: Store.newChatDividerId, threadKey: name, author: .system,
            ts: (earlierMessages.last?.ts ?? 0) + 1, blocks: [.text(L10n.ui(.newChatDivider, language))]
        )
        return earlierMessages + [divider] + messages
    }

    nonisolated static let newChatDividerId = "new-chat-divider"
    /// Session ids are shared by all agents: look this far back for the agent's own.
    nonisolated static let earlierLookback: Int64 = 40

    /// A current session with no message: read the agent's last session that has some.
    private func loadEarlierIfEmpty(agent: String, current: SessionJson?, generation: Int) {
        guard messages.isEmpty, earlierMessages.isEmpty, let current, current.id > 1 else { return }
        Task { [weak self] in
            guard let self else { return }
            var id = current.id - 1
            while id >= max(1, current.id - Store.earlierLookback) {
                if let page = try? await self.transport.messages(thread: String(id), limit: 200),
                   page.thread?.agent == agent, !page.messages.isEmpty {
                    guard self.threadLoad == generation, self.selectedAgentName == agent else { return }
                    self.earlierMessages = page.messages.map { Mapper.message(from: $0, threadKey: agent, agentName: agent) }
                    self.setPreview(agent: agent, from: self.earlierMessages)
                    return
                }
                id -= 1
            }
        }
    }

    /// One read per agent with the newest rows (existing endpoint, limit 12):
    /// the newest owner or agent message is the sidebar's last line.
    private func refreshPreviews(names: Set<String>) {
        Task { [weak self] in
            guard let self else { return }
            for name in names.sorted() {
                guard let page = try? await self.transport.messages(thread: name, limit: 12) else { continue }
                let rows = page.messages.map { Mapper.message(from: $0, threadKey: name, agentName: name) }
                self.setPreview(agent: name, from: rows)
            }
        }
    }

    private func setPreview(agent: String, from rows: [ChatMessage]) {
        guard let preview = ConversationPreview.latest(in: rows) else { return }
        if let known = previews[agent], known.ts > preview.ts { return }
        previews[agent] = preview
    }

    public func sendMessage() {
        sendMessage(composerText)
    }

    /// Start a fresh conversation with the selected agent; the old one stays on this Mac.
    public func startNewChat() {
        guard let agent = selectedAgent, !isSendingMessage else { return }
        threadLoad &+= 1
        let generation = threadLoad
        selectedConversationId = nil
        lastMessageError = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                let session = try await self.transport.newThread(thread: agent.threadKey)
                self.aliases.learn(agent: agent.name, sessionId: String(session.id))
                if let date = TimeText.parse(session.createdAt) { self.currentThreadStarts[agent.name] = date }
                guard self.threadLoad == generation, self.selectedAgentName == agent.name else { return }
                self.selectedConversationId = nil
                self.messages = []
                self.finishedDrafts.removeAll()
                self.liveTool = nil
            } catch {
                guard self.threadLoad == generation, self.selectedAgentName == agent.name else { return }
                self.lastMessageError = self.humanMessage(for: error)
            }
        }
    }

    public func sendMessage(_ raw: String) {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let agent = selectedAgent, !text.isEmpty else { return }
        lastMessageError = nil
        composerText = ""
        var echo = ChatMessage(
            id: "local-\(UUID().uuidString)",
            threadKey: agent.threadKey,
            author: .you,
            ts: 0,
            blocks: [.text(text)],
            streaming: false,
            pending: true
        )
        // CANCEL-AT-CARD, CARD-NEVER-BLOCKS: a card may hold the turn in
        // flight. Send at once: a refusal withdraws it, anything else runs
        // beside it; the queue would hold the words for the card's timeout.
        if hasPendingApproval {
            messages.append(echo)
            deliver(echo, to: agent, session: selectedConversationId, holdingCard: true)
            return
        }
        // A turn runs (or a queued message waits its turn): accept the words
        // now, send them when it ends. Never a second request in flight.
        guard !isSendingMessage, sendQueue.isEmpty else {
            echo.mark(.queued)
            messages.append(echo)
            sendQueue.append((echo, agent, selectedConversationId))
            return
        }
        messages.append(echo)
        deliver(echo, to: agent, session: selectedConversationId)
    }

    /// True when any card waits: the turn in flight may be parked on it,
    /// even one an agent Aux delegated to raised in its own thread. The
    /// daemon runs the words beside the card, or queues them behind a turn
    /// that still works (CARD-NEVER-BLOCKS).
    private var hasPendingApproval: Bool {
        approvals.contains { $0.state.isPending }
    }

    /// Stop all: the queued messages are never sent, and say so.
    public func cancelQueuedSends() {
        stopGeneration += 1
        sendQueue.forEach(markNotSent)
        sendQueue.removeAll()
        sendQueueHeldBy = nil
    }

    private func markNotSent(_ entry: (echo: ChatMessage, agent: Agent, session: Int64?)) {
        var echo = entry.echo
        echo.mark(.notSent)
        unsentEchoes.append((echo, entry.agent))
        setDelivery(.notSent, of: echo.id)
    }

    private func localEchoes(of agent: String) -> [ChatMessage] {
        unsentEchoes.filter { $0.agent.name == agent }.map(\.echo)
            + sendQueue.filter { $0.agent.name == agent }.map(\.echo)
    }

    /// One agent's turn ended (idle frame, run finished, idle poll): a queue
    /// held by that agent's `thread_busy` may try again.
    private func turnEnded(_ agent: String) {
        turnEnds[agent, default: 0] += 1
        // CONV-SIDEBAR-1: a finished Aux turn may add a conversation or move
        // its last activity; the list refreshes now, not on the next launch.
        if agent == TeamMember.aux.id { loadConversations() }
        guard sendQueueHeldBy == agent else { return }
        sendQueueHeldBy = nil
        drainSendQueue()
    }

    private func drainSendQueue() {
        // Stop engaged (here or elsewhere) cancels the queue in the shell.
        guard !isSendingMessage, sendQueueHeldBy == nil, !sendQueue.isEmpty else { return }
        let next = sendQueue.removeFirst()
        setDelivery(nil, of: next.echo.id)
        deliver(next.echo, to: next.agent, session: next.session)
    }

    private func setDelivery(_ delivery: ChatMessage.Delivery?, of id: String) {
        guard let index = messages.firstIndex(where: { $0.id == id }) else { return }
        messages[index].mark(delivery)
    }

    private func deliver(_ echo: ChatMessage, to agent: Agent, session: Int64?, holdingCard: Bool = false) {
        let text = echo.text
        let threadKey = session.map(String.init) ?? agent.threadKey
        let conversation = session
        // A card message rides beside the turn it is about to withdraw: that
        // turn's request is still open and owns the sending state.
        let alreadySending = isSendingMessage
        if !alreadySending {
            isSendingMessage = true
            sendRunId = nil
            sendingEchoId = echo.id
        }
        let (generation, endsBefore) = (stopGeneration, turnEnds[agent.name, default: 0])
        Task { [weak self] in
            guard let self else { return }
            defer {
                if !alreadySending {
                    self.isSendingMessage = false
                    self.sendingEchoId = nil
                    self.drainSendQueue()
                }
            }
            do {
                let response = try await self.transport.send(thread: threadKey, content: text)
                if let page = response.thread {
                    self.aliases.learn(agent: agent.name, sessionId: String(page.id))
                    if let date = TimeText.parse(page.createdAt) { self.currentThreadStarts[agent.name] = date }
                }
                // The owner moved to another agent while this send was in
                // flight: the reply belongs to the old thread, which reloads
                // from the daemon when it is opened again.
                guard self.selectedAgentName == agent.name, self.selectedConversationId == conversation else { return }
                let mapped = response.messages.map { Mapper.message(from: $0, threadKey: agent.name, agentName: agent.name) }
                // The owner's words take the echo's place: a reply that came
                // over the socket first must still read after them.
                if let index = self.messages.firstIndex(where: { $0.id == echo.id }) {
                    if let mine = mapped.first(where: { $0.author == .you }),
                       !self.messages.contains(where: { $0.id != echo.id && ($0.id == mine.id || Store.sameMessage($0, mine)) }) {
                        self.messages[index] = mine
                    } else {
                        self.messages.remove(at: index)
                    }
                }
                for message in mapped {
                    self.upsert(message: message)
                }
                // The turn is over and its rows are stored: a streamed draft
                // of this run whose `message.new` never arrived would read as
                // a double. Another live turn's drafts stay.
                self.endDrafts(run: response.runId ?? self.run(ofSent: text))
            } catch let error as AuxdError where error.apiErrorCode == "thread_busy" {
                if holdingCard {
                    // The card still holds the turn: never park the words in a
                    // queue that only wakes when the turn ends. Show them as
                    // not sent, and say why now.
                    self.markNotSent((echo, agent, session))
                    if self.selectedAgentName == agent.name, self.selectedConversationId == conversation {
                        self.lastMessageError = self.humanMessage(for: error)
                    }
                    return
                }
                // No turn started: keep the words queued, first in line, and
                // try again when a turn ends. Never dropped, never sent twice.
                guard self.stopGeneration == generation else { return self.markNotSent((echo, agent, session)) }
                var held = echo
                held.mark(.queued)
                self.sendQueue.insert((held, agent, session), at: 0)
                self.setDelivery(.queued, of: echo.id)
                if self.turnEnds[agent.name, default: 0] == endsBefore { self.sendQueueHeldBy = agent.name }
            } catch {
                guard self.selectedAgentName == agent.name, self.selectedConversationId == conversation else { return }
                if let index = self.messages.firstIndex(where: { $0.id == echo.id }) {
                    self.messages[index].pending = false
                }
                // A failed stream leaves no stored reply: drop its partial text.
                if !holdingCard { self.endDrafts(run: self.run(ofSent: text)) }
                self.lastMessageError = self.humanMessage(for: error)
                if self.composerText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    self.composerText = text
                }
            }
        }
    }

    /// The run of the owner's words just sent, from their live `message.new`.
    private func run(ofSent text: String) -> String? {
        // The stored copy can differ from the composer text (a masked e-mail), so
        // the run seen during the send wins over a text match.
        if let sendRunId { return sendRunId }
        return messages.last { $0.author == .you && $0.runId != nil && $0.text == text }?.runId
    }

    /// Retire the streamed drafts of one run; an unknown run retires none.
    private func endDrafts(run: String?) {
        guard let run else { return }
        // `draft-<thread>-<run>-<round>`
        let ended = messages.map(\.id).filter { $0.hasPrefix("draft-") && $0.contains("-\(run)-") }
        finishedDrafts.formUnion(ended)
        messages.removeAll { ended.contains($0.id) }
    }

    // MARK: Approvals

    public var pendingApprovals: [Approval] {
        approvals.filter { $0.state.isPending }
    }

    public func approvals(for agentName: String) -> [Approval] {
        approvals.filter { $0.agent == agentName }
    }

    // MARK: Receipts

    /// One agent's recent receipts, newest first (the thread's receipt rows).
    public func receipts(for agentName: String) -> [Receipt] {
        receipts.filter { $0.agent == agentName }
    }

    public func threadStartedAt(for agentName: String) -> Date? {
        currentThreadStarts[agentName]
    }

    /// Exactly one answer can be in flight per approval id; the UI disables
    /// the buttons too, but this guard is the guarantee (double-click, two
    /// shortcuts, a frame racing the click). After a failed answer the card is
    /// blocked until the daemon's state has been re-fetched (F4).
    public func resolve(_ approval: Approval, decision: ApprovalDecision, scope: ApprovalScope? = nil, text: String? = nil) {
        guard approval.state.isPending,
              !sendingApprovalIds.contains(approval.id),
              !approvalsAwaitingResync.contains(approval.id)
        else { return }
        // The card's gates are the contract, not just the view: a shortcut, a
        // direct call or a future caller gets the same refusal. Nothing is sent
        // and the ask is not resolved; the explicit message reuses the card's own
        // copy and shows where a send error would.
        if decision == .allowOnce, unknownToolTooLong(approval) {
            approvalErrors[approval.id] = L10n.t(.approvalAllowUnknownToolTooLong, language)
            return
        }
        // "Always" must clear exactly the gate its button does: the whole
        // `alwaysAllowed` rule (unknown tool included), never only that one
        // clause. A tainted, unsandboxed, shell or unknown ask is refused even
        // by a direct call. `canAct` is spelled here for symmetry with the card,
        // though the `guard` above already enforces it.
        if decision == .allowAlways, !alwaysAllowed(approval) || !canAct(approval) {
            approvalErrors[approval.id] = alwaysRefusalMessage(approval)
            return
        }
        // The card saves a rule for the ask's own tool. A direct call must not
        // widen to another tool through `scope`: for "Always", a supplied scope
        // must name exactly the approval's tool. This runs after the
        // `alwaysAllowed`/`canAct` gate above, so that gate still applies to the
        // approval itself; a mismatched scope sends nothing and the card's own
        // unknown-tool copy explains why (reused text, no new visible string).
        if decision == .allowAlways, let scope, scope.tool != approval.scopeTool {
            approvalErrors[approval.id] = L10n.t(.approvalAlwaysUnknownTool, language)
            return
        }
        // "Always" never transmits the caller's scope: a nil scope would let the
        // server choose the rule's perimeter, and a matching scope could still
        // name another agent. The perimeter is always the one the card builds,
        // derived from the approval itself — never the caller's, never nil.
        let sentScope: ApprovalScope?
        if decision == .allowAlways {
            var derived = ApprovalScope(tool: approval.scopeTool, agent: approval.agent)
            if let resource = approval.scopeResource {
                derived = ApprovalScope(tool: approval.scopeTool, agent: approval.agent, resource: resource)
            }
            sentScope = derived
        } else {
            sentScope = scope
        }
        sendingApprovalIds.insert(approval.id)
        approvalErrors[approval.id] = nil
        refusedEdits.remove(approval.id)
        Task { [weak self] in
            guard let self else { return }
            do {
                let state = try await self.transport.resolve(
                    id: approval.id,
                    decision: decision.wire,
                    scope: sentScope,
                    text: text
                )
                self.localApprovalStates[approval.id] = state
                if let index = self.approvals.firstIndex(where: { $0.id == approval.id }) {
                    self.approvals[index].state = state
                }
                self.resortAgents()
            } catch {
                // A refused edited card is not a failure of the service: the
                // daemon never took the ask, so the card stays open and
                // editable and the reason is shown on it.
                let refused = (error as? AuxdError)?.editedCardRefusalReason != nil
                if refused { self.refusedEdits.insert(approval.id) }
                self.approvalErrors[approval.id] = self.humanMessage(for: error, decision: decision)
                // Zero-desync: the answer may have landed even though the HTTP
                // call failed (timeout after commit). Re-fetch the daemon's
                // truth before allowing another answer; never re-send by
                // ourselves.
                self.approvalsAwaitingResync.insert(approval.id)
                await self.resyncApprovals(afterFailureOf: approval.id)
            }
            self.sendingApprovalIds.remove(approval.id)
        }
    }

    /// Re-reads the pending list after a failed answer. On success the card
    /// either disappears (daemon resolved it) or becomes answerable again; on
    /// failure it stays blocked until the next successful snapshot.
    private func resyncApprovals(afterFailureOf id: String) async {
        do {
            let fetched = try await transport.pendingApprovals()
            applyApprovalsSnapshot(fetched)
        } catch {
            // Keep the block: a reconnect/fresh snapshot will clear it.
        }
    }

    /// True while `approval` cannot be answered because its last answer
    /// failed and the daemon's state has not been re-read yet.
    public func isAwaitingResync(_ approval: Approval) -> Bool {
        approvalsAwaitingResync.contains(approval.id)
    }

    /// Destructive scopes arm for one second before Allow becomes active.
    public func armingProgress(_ approval: Approval, now: Date = Date()) -> Double {
        guard approval.destructive, approval.state.isPending else { return 1 }
        let start = approval.receivedAt ?? now
        return min(1, max(0, now.timeIntervalSince(start)))
    }

    public func canAllow(_ approval: Approval, now: Date = Date()) -> Bool {
        approval.state.isPending
            && !sendingApprovalIds.contains(approval.id)
            && !approvalsAwaitingResync.contains(approval.id)
            && armingProgress(approval, now: now) >= 1
    }

    /// The shell refused an answer by itself (a stale edit): the card says why.
    func noteApprovalError(_ id: String, _ message: String) {
        approvalErrors[id] = message
    }

    public func canAct(_ approval: Approval) -> Bool {
        approval.state.isPending
            && !sendingApprovalIds.contains(approval.id)
            && !approvalsAwaitingResync.contains(approval.id)
    }

    /// Tainted, unsandboxed, command and unknown asks can never be widened to
    /// "always".
    public func alwaysAllowed(_ approval: Approval) -> Bool {
        // Compare on sanitised text: zero-width/bidi characters must not hide
        // a "shell" prefix from the refusal.
        let tool = ServerText.clean(approval.scopeTool, maxLength: ServerText.Limits.scopeTool)
        // Case-insensitive: the daemon may spell the id `Shell`, `SHELL` or
        // `SHELL.exec`, and the known-tool table matches on `lowercased()` too.
        // The `shell` prefix is kept, and the whole command class is refused on
        // its label, so `run_command`, `run`, `bash` and `exec` cannot widen.
        return approval.taint == nil
            && !approval.unsandboxed
            && !tool.lowercased().hasPrefix("shell")
            && !ReceiptDetailCopy.isCommandTool(approval.scopeTool)
            // Same raw id the card labels: a tool this build does not know by
            // name has no rule to save, so "Always" is unavailable.
            && ReceiptDetailCopy.isKnownTool(approval.scopeTool)
    }

    /// The plain-French reason "Always" is refused for `approval`, named in the
    /// same order as the card's disabled button. Only meaningful when
    /// `alwaysAllowed` is false; kept beside it so a direct `resolve` explains
    /// itself with the same copy the view shows.
    private func alwaysRefusalMessage(_ approval: Approval) -> String {
        if approval.taint != nil { return L10n.t(.approvalAlwaysTainted, language) }
        if approval.unsandboxed { return L10n.t(.approvalAlwaysUnsandboxed, language) }
        let tool = ServerText.clean(approval.scopeTool, maxLength: ServerText.Limits.scopeTool)
        if tool.lowercased().hasPrefix("shell")
            || ReceiptDetailCopy.isCommandTool(approval.scopeTool) {
            return L10n.t(.approvalAlwaysShell, language)
        }
        return L10n.t(.approvalAlwaysUnknownTool, language)
    }

    /// True when the ask cannot be shown faithfully: an unknown tool id past
    /// `ServerText.Limits.unknownTool` is truncated on the card, so two distinct
    /// ids render identically and a click could not be an informed one. Same
    /// rule as `alwaysAllowed`'s unknown check, one step stronger: an over-long
    /// unknown id refuses "Allow once" too, leaving only "Refuse" (and
    /// "Modifier", which never sends this id to the daemon).
    public func unknownToolTooLong(_ approval: Approval) -> Bool {
        ReceiptDetailCopy.isUnknownToolOverLong(approval.scopeTool)
    }

    /// `canAllow` plus the ambiguity refusal above — the gate the Allow button
    /// and the `A` shortcut use. `canAllow` keeps its arming/sending meaning.
    public func canAllowOnce(_ approval: Approval, now: Date = Date()) -> Bool {
        canAllow(approval, now: now) && !unknownToolTooLong(approval)
    }

    public func focusNext() {
        cycleFocus(by: 1)
    }

    public func focusPrev() {
        cycleFocus(by: -1)
    }

    public func focus(_ id: String?) {
        focusedApprovalId = id
    }

    private func cycleFocus(by offset: Int) {
        let pending = pendingApprovals
        guard !pending.isEmpty else { return }
        guard let current = focusedApprovalId,
              let index = pending.firstIndex(where: { $0.id == current }) else {
            focusedApprovalId = pending.first?.id
            return
        }
        let next = (index + offset + pending.count) % pending.count
        focusedApprovalId = pending[next].id
    }

    // MARK: Health

    public func refreshFirstRun() {
        Task { [weak self] in
            guard let self else { return }
            do {
                let health = try await self.transport.health()
                self.firstRun = health.firstRun
                self.firstRunKnown = true
                self.version = health.version
                self.google.apply(
                    connected: health.googleConnected,
                    reconnectNeeded: health.googleReconnectNeeded
                )
            } catch {
                self.connection = self.connectionState(for: error)
            }
        }
    }

    public func publishAppleEventKit(_ snapshot: AppleEventKitSnapshot) async throws {
        guard let client = transport as? AppleEventKitSnapshotClient else {
            throw AuxdError.transport(L10n.t(.appleEventKitUnavailable, language))
        }
        try await client.publishAppleEventKit(snapshot)
    }

    // MARK: First-run setup (service + key + test + first agent)

    /// The picker entry the owner selected, if any.
    public var selectedProviderChoice: ProviderChoice? {
        guard let id = selectedProviderID else { return nil }
        return providerChoices.first { $0.id == id }
    }

    /// A configured service already has its key on disk; a service the daemon
    /// lists but that has no key (`key_present:false`, or a failed lookup)
    /// still asks the owner to paste one.
    public func providerNeedsKey(_ choice: ProviderChoice) -> Bool {
        choice.keyRequired && !choice.configured
    }

    /// The Test button is enabled only when the form is idle (no test in
    /// flight or already shown) and the key the service needs is present.
    public var canTestProvider: Bool {
        guard firstRunSetupState == .ready, firstRunTestState == .idle else { return false }
        guard let choice = selectedProviderChoice else { return false }
        if providerNeedsKey(choice) {
            return !providerKeyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        return true
    }

    /// Load `GET /v1/providers` + `GET /v1/first-run` and build the picker.
    /// Any failure is shown as a plain offline card with a Retry.
    public func beginFirstRunSetup() {
        firstRunSetupState = .loading
        firstRunTestState = .idle
        Task { [weak self] in
            guard let self else { return }
            guard let client = self.firstRunClient else {
                self.firstRunSetupState = .failed(.localService)
                return
            }
            do {
                let providers = try await client.providers()
                let runStatus = try await client.firstRunStatus()
                self.applyFirstRunSetup(providers: providers, status: runStatus)
            } catch {
                self.firstRunSetupState = .failed(FirstRunFailure(error: error))
            }
        }
    }

    /// Retry re-reads the daemon state; the key field stays cleared.
    public func retryFirstRunSetup() {
        beginFirstRunSetup()
    }

    /// Dismiss an inline Test error so the owner can paste the key again.
    public func clearProviderTestError() {
        if case .failed = firstRunTestState {
            firstRunTestState = .idle
        }
    }

    private func applyFirstRunSetup(providers: [ProviderSummary], status: FirstRunStatus) {
        var choices: [ProviderChoice] = []
        var seen = Set<String>()
        for provider in providers {
            choices.append(ProviderChoice(
                id: provider.id,
                title: provider.name,
                baseURL: provider.baseURL,
                model: provider.model,
                kind: provider.kind,
                keyRequired: provider.keyRequired,
                // Derive readiness from the daemon's key presence: a service
                // that exists without a key is not ready and must show the key
                // field. A service that needs no key is ready either way.
                configured: provider.keyPresent == true || !provider.keyRequired,
                knownToDaemon: true
            ))
            seen.insert(provider.id)
        }
        // The daemon is the truth; when it has nothing yet, offer the built-in
        // suggestions so a fresh install can still finish here.
        for suggestion in FirstRunCatalog.suggestions where !seen.contains(suggestion.id) {
            choices.append(suggestion)
            seen.insert(suggestion.id)
        }
        providerChoices = choices

        if !status.firstRun, status.agentCreated {
            let agent = status.agent ?? FirstRunCatalog.defaultAgentID
            createdAgentName = agent
            firstRunSetupState = .done(agent: agent)
            return
        }

        if selectedProviderID == nil || !choices.contains(where: { $0.id == selectedProviderID }) {
            let preferred = status.provider.flatMap { id in choices.first { $0.id == id }?.id }
            selectedProviderID = preferred ?? choices.first?.id
        }
        firstRunSetupState = .ready
    }

    /// Press Test: one spend-free check, then save + create the first agent on
    /// success. The key field is cleared as soon as the check returns.
    public func testProviderKey() {
        guard firstRunTestState == .idle else { return }
        guard let client = firstRunClient, let choice = selectedProviderChoice else {
            firstRunSetupState = .failed(.localService)
            return
        }
        let key = providerKeyInput.trimmingCharacters(in: .whitespacesAndNewlines)
        let needsKey = providerNeedsKey(choice)
        if needsKey, key.isEmpty {
            firstRunTestState = .failed(.missingKey)
            return
        }
        firstRunTestState = .testing
        Task { [weak self] in
            guard let self else { return }
            // A service the daemon already lists but that has no key gets the
            // pasted key through the update route first, so the daemon's test
            // reads the key that was really stored (not an inline copy).
            if needsKey, choice.knownToDaemon {
                do {
                    _ = try await client.updateProviderKey(name: choice.id, apiKey: key)
                } catch {
                    self.providerKeyInput = ""
                    self.firstRunTestState = .failed(FirstRunFailure(error: error))
                    return
                }
            }
            let payload = ProviderTestRequest(
                name: choice.id,
                kind: choice.kind,
                baseURL: choice.baseURL,
                model: choice.model,
                apiKey: (needsKey && !choice.knownToDaemon) ? key : nil
            )
            do {
                let result = try await client.testProvider(payload)
                self.providerKeyInput = ""
                if result.ok {
                    self.firstRunTestState = .ok(FirstRunCopy.successKey(for: result))
                    await self.finishFirstRunSetup(choice: choice, key: (needsKey && !choice.knownToDaemon) ? key : nil)
                } else {
                    self.firstRunTestState = .failed(FirstRunFailure(test: result))
                }
            } catch {
                self.providerKeyInput = ""
                self.firstRunTestState = .failed(FirstRunFailure(error: error))
            }
        }
    }

    /// Save the service (new one only), create the first agent through
    /// `POST /v1/agents`, then clear the gate through `POST /v1/first-run/complete`.
    private func finishFirstRunSetup(choice: ProviderChoice, key: String?) async {
        guard let client = firstRunClient else {
            firstRunSetupState = .failed(.localService)
            return
        }
        firstRunSetupState = .working
        do {
            // Only a built-in suggestion is saved. A service the daemon already
            // lists is never re-created: its missing key (if any) was already
            // written through the update route before the test ran.
            if !choice.knownToDaemon {
                do {
                    _ = try await client.saveProvider(CreateProviderRequest(
                        name: choice.id,
                        kind: choice.kind,
                        baseURL: choice.baseURL,
                        model: choice.model,
                        apiKey: key
                    ))
                } catch let auxd as AuxdError where auxd.daemonErrorCode == "provider_exists" {
                    // Already saved by an earlier attempt: carry on. Any other
                    // 409 (a key-slot conflict, a future code) is a real
                    // failure and falls through to the card below.
                }
            }
            do {
                _ = try await client.createAgent(CreateAgentRequest(
                    name: FirstRunCatalog.defaultAgentID,
                    provider: choice.id,
                    model: choice.model,
                    role: nil
                ))
            } catch let auxd as AuxdError where auxd.httpStatus == 409 {
                // The agent already exists (a previous attempt): the complete
                // call below is idempotent, so keep going.
            }
            let complete = try await client.completeFirstRun(FirstRunCompleteRequest(
                provider: choice.id,
                model: choice.model,
                role: nil
            ))
            createdAgentName = complete.agent.name
            firstRunSetupState = .done(agent: complete.agent.name)
            // The gate is derived from health: re-reading it flips the shell
            // from the setup screen to the conversation.
            refreshFirstRun()
        } catch {
            firstRunSetupState = .failed(FirstRunFailure(error: error))
        }
    }

    // MARK: Copy helpers (plain words, no jargon)

    public func stateLabel(_ state: AgentState) -> String {
        AgentStateCopy.label(state, language)
    }

    public var connectionLabel: String {
        switch connection {
        case .connecting:
            return L10n.t(.connConnecting, language)
        case .online:
            return L10n.f(.connOnline, language, version)
        case .offline(let reason):
            return L10n.f(.connOffline, language, reason)
        case .unauthorized:
            return L10n.t(.connUnauthorized, language)
        }
    }

    /// The health line (menu bar + Réglages): whether the service this app
    /// started is up. It reports the child we own, never a live probe, so it can
    /// never claim a service the app did not start.
    public var serviceLabel: String {
        switch service?.state ?? serviceState {
        case .running:
            return L10n.t(.serviceRunning, language)
        case .stopped, .unavailable:
            return L10n.t(.serviceStopped, language)
        }
    }

    /// Start the `auxd` shipped inside this app when it looks absent. Called on
    /// every failed connect; the policy plus the supervisor's liveness check
    /// make it a no-op once our child runs. A missing bundled binary leaves
    /// `.unavailable` and the existing offline screen in place — never a
    /// service from elsewhere.
    private func maybeStartBundledService() {
        guard BundledServicePolicy.shouldStart(
            cause: offlineCause,
            alreadyAttempted: didAttemptServiceStart
        ) else { return }
        didAttemptServiceStart = true
        // F3: a refused home — or no resolved endpoint at all — is not "the
        // service looks absent". Starting the child would neither fix the
        // refusal nor give the app anywhere to connect, and it would run a
        // service the app must not own; the offline screen stays. (A `nil`
        // endpoint is the test seam; only an endpoint that resolved to a
        // refusal or to no address blocks the start.)
        if let endpoint, endpoint.homeRefused || endpoint.baseURL == nil {
            publishServiceState()
            return
        }
        guard let service else { return }
        serviceState = service.start()
        // The service writes `api.token` a moment after launch; pick it up now
        // and again before each reconnect attempt.
        (transport as? TokenRefreshing)?.refreshToken()
    }

    /// Quit path: stop the child this app started. Safe when none was started,
    /// and it never touches a service owned by another process.
    public func stopBundledService() {
        service?.stop()
        publishServiceState()
    }

    /// Copy the supervisor's live state into the published snapshot the menu
    /// bar and Réglages read. Called after an explicit start/stop, and whenever
    /// the child exits on its own (F4).
    private func publishServiceState() {
        serviceState = service?.state ?? .stopped
    }

    public func humanMessage(for error: Error, decision: ApprovalDecision? = nil) -> String {
        if let auxd = error as? AuxdError {
            switch auxd {
            case .token(.missing):
                return L10n.t(.offlineTokenMissing, language)
            case .token:
                return L10n.t(.offlineTokenUnsafe, language)
            case .unauthorized:
                return Self.localAccessRefused(language)
            case .http(let status, _):
                // A 401 on an app↔daemon route is the app's own bearer token
                // (a stale api.token), not a service key — same copy as
                // `.unauthorized` so the two shapes stay consistent.
                if status == 401 { return Self.localAccessRefused(language) }
                if auxd.apiErrorCode == "thread_busy" { return L10n.t(.errorThreadBusy, language) }
                if status == 501, decision == .edit {
                    return L10n.t(.approvalEditSoon, language)
                }
                // A refused edited card carries the reason the daemon gives
                // ("bcc is not supported for mail_send"): the owner can fix the
                // draft, so the app says why instead of a generic error.
                if let reason = auxd.editedCardRefusalReason {
                    return L10n.f(.draftEditRefused, language, reason)
                }
                return L10n.t(.serviceError, language)
            case .transport(let message):
                if message == AuxdError.timedOutMessage {
                    return L10n.t(.errorTimeout, language)
                }
                return L10n.t(.errorUnreachable, language)
            case .decode:
                return L10n.t(.errorUnreadable, language)
            case .badURL:
                return L10n.t(.offlineTitle, language)
            case .offLoopback:
                return L10n.t(.addrOffLoopback, language)
            }
        }
        return L10n.t(.errorUnexpected, language)
    }

    /// The reason a refused edited card shows on the card, when it carries one.
    ///
    /// Only a refused edit has a reason: any other failure keeps the generic
    /// error and leaves the draft card.
    public func refusalReason(for approval: Approval) -> String? {
        guard refusedEdits.contains(approval.id) else { return nil }
        return approvalErrors[approval.id]
    }

    /// Plain line for a refused local bearer token (an app↔daemon `401`).
    /// The app's own `api.token` is stale (a reinstall or a service restart
    /// wrote a new one), so relaunching Auxesis — which makes it re-read that
    /// local access — is the fix. Never blames a service key.
    static func localAccessRefused(_ language: Language) -> String {
        L10n.t(.errorLocalAccessRefused, language)
    }

    /// Go offline on a refused local bearer token: the local-service wording
    /// (the existing `.unreachable` cause), never the service-key card.
    private func localAccessRefusedOffline() -> Connection {
        let message = Self.localAccessRefused(language)
        offlineCause = .unreachable(message)
        return .offline(message)
    }

    private func connectionState(for error: Error) -> Connection {
        if let auxd = error as? AuxdError {
            switch auxd {
            case .unauthorized:
                return localAccessRefusedOffline()
            case .http(let status, _) where status == 401:
                // `.unauthorized` is what `AuxdClient` throws for a 401; a
                // different transport may surface the raw `.http(401, _)`.
                return localAccessRefusedOffline()
            case .token(.missing):
                offlineCause = .tokenMissing
                return .offline(humanMessage(for: error))
            case .token:
                offlineCause = .tokenUnsafe
                return .offline(humanMessage(for: error))
            case .badURL, .offLoopback, .http, .transport, .decode:
                offlineCause = .unreachable(humanMessage(for: error))
                return .offline(humanMessage(for: error))
            }
        }
        let message = L10n.t(.errorUnexpected, language)
        offlineCause = .unreachable(message)
        return .offline(message)
    }
}
