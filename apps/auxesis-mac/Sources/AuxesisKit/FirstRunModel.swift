import Foundation

/// The first-run setup screen's state and steps: pick a service, test the key,
/// save it, create the first agent. Also holds the "is this a first run" gate
/// read from health.
///
/// `Store` owns one and forwards its changes, so a view that observes the
/// store redraws when this changes. The model only talks to the service
/// through the client it is given.
@MainActor
public final class FirstRunModel: ObservableObject {
    /// Whether the service says setup is not finished, and whether it has said so yet.
    @Published public private(set) var firstRun: Bool = false
    @Published public private(set) var firstRunKnown = false
    /// First-run setup screen state (service picker + key + test).
    @Published public private(set) var setupState: FirstRunSetupState = .loading
    @Published public private(set) var testState: FirstRunTestState = .idle
    @Published public private(set) var providerChoices: [ProviderChoice] = []
    @Published public private(set) var createdAgentName: String?
    @Published public var selectedProviderID: String?
    /// The key field. Bound to a `SecureField`, cleared after every submit and
    /// never logged, echoed, or persisted by the app.
    @Published public var providerKeyInput = ""

    /// Non-nil when the transport also speaks the first-run routes (the real
    /// `AuxdClient` does); tests inject a scripted one.
    private let client: FirstRunClient?
    /// Called once setup is complete, so the store re-reads health and the
    /// shell flips from the setup screen to the conversation.
    var onFinished: (() -> Void)?

    init(client: FirstRunClient?) {
        self.client = client
    }

    /// Record the gate as the service reported it.
    func record(firstRun: Bool) {
        self.firstRun = firstRun
        firstRunKnown = true
    }

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
        guard setupState == .ready, testState == .idle else { return false }
        guard let choice = selectedProviderChoice else { return false }
        if providerNeedsKey(choice) {
            return !providerKeyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        return true
    }

    /// Load `GET /v1/providers` + `GET /v1/first-run` and build the picker.
    /// Any failure is shown as a plain offline card with a Retry.
    public func beginFirstRunSetup() {
        setupState = .loading
        testState = .idle
        Task { [weak self] in
            guard let self else { return }
            guard let client = self.client else {
                self.setupState = .failed(.localService)
                return
            }
            do {
                let providers = try await client.providers()
                let runStatus = try await client.firstRunStatus()
                self.applyFirstRunSetup(providers: providers, status: runStatus)
            } catch {
                self.setupState = .failed(FirstRunFailure(error: error))
            }
        }
    }

    /// Retry re-reads the daemon state; the key field stays cleared.
    public func retryFirstRunSetup() {
        beginFirstRunSetup()
    }

    /// Dismiss an inline Test error so the owner can paste the key again.
    public func clearProviderTestError() {
        if case .failed = testState {
            testState = .idle
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
            setupState = .done(agent: agent)
            return
        }

        if selectedProviderID == nil || !choices.contains(where: { $0.id == selectedProviderID }) {
            let preferred = status.provider.flatMap { id in choices.first { $0.id == id }?.id }
            selectedProviderID = preferred ?? choices.first?.id
        }
        setupState = .ready
    }

    /// Press Test: one spend-free check, then save + create the first agent on
    /// success. The key field is cleared as soon as the check returns.
    public func testProviderKey() {
        guard testState == .idle else { return }
        guard let client = client, let choice = selectedProviderChoice else {
            setupState = .failed(.localService)
            return
        }
        let key = providerKeyInput.trimmingCharacters(in: .whitespacesAndNewlines)
        let needsKey = providerNeedsKey(choice)
        if needsKey, key.isEmpty {
            testState = .failed(.missingKey)
            return
        }
        testState = .testing
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
                    self.testState = .failed(FirstRunFailure(error: error))
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
                    self.testState = .ok(FirstRunCopy.successKey(for: result))
                    await self.finishFirstRunSetup(choice: choice, key: (needsKey && !choice.knownToDaemon) ? key : nil)
                } else {
                    self.testState = .failed(FirstRunFailure(test: result))
                }
            } catch {
                self.providerKeyInput = ""
                self.testState = .failed(FirstRunFailure(error: error))
            }
        }
    }

    /// Save the service (new one only), create the first agent through
    /// `POST /v1/agents`, then clear the gate through `POST /v1/first-run/complete`.
    private func finishFirstRunSetup(choice: ProviderChoice, key: String?) async {
        guard let client else {
            setupState = .failed(.localService)
            return
        }
        setupState = .working
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
            setupState = .done(agent: complete.agent.name)
            // The gate is derived from health: re-reading it flips the shell
            // from the setup screen to the conversation.
            onFinished?()
        } catch {
            setupState = .failed(FirstRunFailure(error: error))
        }
    }
}

// MARK: - Value types of the setup screen

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
