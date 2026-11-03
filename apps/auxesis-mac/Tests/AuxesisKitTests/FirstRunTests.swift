// First-run setup, entirely offline: a scripted fake client drives the Store's
// state machine and French copy. No network, no daemon, no keychain, no key in
// any assertion that could print it.
import Testing
@testable import AuxesisKit

/// Scripts the four setup routes. Nothing here touches the network; every
/// answer is a fixture built in-process.
final class FakeFirstRunClient: FirstRunClient {
    nonisolated(unsafe) var providersResult: Result<[ProviderSummary], Error> = .success([])
    nonisolated(unsafe) var statusResult: Result<FirstRunStatus, Error> = .success(.freshInstall)
    nonisolated(unsafe) var saveResult: Result<ProviderSaved, Error> = .success(ProviderSaved(name: "deepseek", keyPresent: true))
    nonisolated(unsafe) var updateKeyResult: Result<ProviderSaved, Error> = .success(ProviderSaved(name: "mine", keyPresent: true))
    nonisolated(unsafe) var testResult: Result<ProviderTest, Error> = .success(.passing)
    nonisolated(unsafe) var createResult: Result<AgentCreateResponse, Error> = .success(
        AgentCreateResponse(agent: CreatedAgent(name: "main", provider: "deepseek", model: "deepseek-chat"), created: true)
    )
    nonisolated(unsafe) var completeResult: Result<FirstRunComplete, Error> = .success(
        FirstRunComplete(
            firstRun: false,
            created: true,
            provider: "deepseek",
            agent: CreatedAgent(name: "main", provider: "deepseek", model: "deepseek-chat")
        )
    )

    private let lock = NSLock()
    private var tested: [ProviderTestRequest] = []
    private var saved: [CreateProviderRequest] = []
    private var updated: [(name: String, apiKey: String)] = []
    private var created: [CreateAgentRequest] = []
    private var completed: [FirstRunCompleteRequest] = []
    private var loaded = 0

    var testedRequests: [ProviderTestRequest] { lock.withLock { tested } }
    var savedRequests: [CreateProviderRequest] { lock.withLock { saved } }
    var updatedKeys: [(name: String, apiKey: String)] { lock.withLock { updated } }
    var createdRequests: [CreateAgentRequest] { lock.withLock { created } }
    var completedRequests: [FirstRunCompleteRequest] { lock.withLock { completed } }
    var loadCount: Int { lock.withLock { loaded } }

    func providers() async throws -> [ProviderSummary] {
        lock.withLock { loaded += 1 }
        return try providersResult.get()
    }

    func firstRunStatus() async throws -> FirstRunStatus {
        try statusResult.get()
    }

    func testProvider(_ request: ProviderTestRequest) async throws -> ProviderTest {
        lock.withLock { tested.append(request) }
        return try testResult.get()
    }

    func saveProvider(_ request: CreateProviderRequest) async throws -> ProviderSaved {
        lock.withLock { saved.append(request) }
        return try saveResult.get()
    }

    func updateProviderKey(name: String, apiKey: String) async throws -> ProviderSaved {
        lock.withLock { updated.append((name, apiKey)) }
        return try updateKeyResult.get()
    }

    func createAgent(_ request: CreateAgentRequest) async throws -> AgentCreateResponse {
        lock.withLock { created.append(request) }
        return try createResult.get()
    }

    func completeFirstRun(_ request: FirstRunCompleteRequest) async throws -> FirstRunComplete {
        lock.withLock { completed.append(request) }
        return try completeResult.get()
    }
}

extension FirstRunStatus {
    static let freshInstall = FirstRunStatus(
        firstRun: true,
        providerSaved: false,
        providerTested: false,
        agentCreated: false,
        nextStep: "provider",
        provider: nil,
        agent: nil
    )
}

extension ProviderTest {
    /// What the daemon answers for a valid, reachable entry.
    static let passing = ProviderTest(
        ok: true,
        reason: "ok",
        latencyMs: 12,
        models: [],
        error: nil,
        keyPresent: true,
        keyRequired: true,
        reachable: true,
        note: "reachable at 1.2.3.4:443"
    )

    static func failing(reason: String, error: String? = nil) -> ProviderTest {
        ProviderTest(
            ok: false,
            reason: reason,
            latencyMs: nil,
            models: [],
            error: error,
            keyPresent: false,
            keyRequired: true,
            reachable: nil,
            note: nil
        )
    }
}

func providerSummary(
    id: String,
    model: String = "deepseek-chat",
    keyRequired: Bool = true,
    keyPresent: Bool? = true,
    keyError: String? = nil
) -> ProviderSummary {
    ProviderSummary(
        id: id,
        name: id,
        baseURL: "https://api.example.com/v1",
        model: model,
        kind: "openai-compat",
        keyLocation: keyPresent == true ? "env" : "none",
        keyPresent: keyPresent,
        keyRequired: keyRequired,
        keyError: keyError,
        lastTest: ""
    )
}

/// The daemon's uniform error body, carrying only the machine-readable code.
func daemonErrorBody(_ code: String) -> String {
    "{\"error\":{\"code\":\"\(code)\",\"message\":\"refused\"}}"
}

@objcMembers @MainActor final class FirstRunTests: XCTestCase {
    private func makeStore(_ fake: FakeFirstRunClient) -> Store {
        Store(transport: FakeTransport(), firstRunClient: fake, language: .fr)
    }

    private func readyStore(_ fake: FakeFirstRunClient) -> Store {
        let store = makeStore(fake)
        store.beginFirstRunSetup()
        XCTAssertTrue(waitUntil { store.firstRunSetupState == .ready }, "setup must reach ready")
        return store
    }

    // MARK: Picker

    func testFreshInstallOffersBuiltInServicesInPlainFrench() {
        let fake = FakeFirstRunClient()
        let store = readyStore(fake)

        XCTAssertFalse(store.providerChoices.isEmpty, "a fresh install still offers choices")
        XCTAssertEqual(store.selectedProviderID, "deepseek")
        XCTAssertEqual(store.providerChoices.first?.title, "DeepSeek")
        XCTAssertTrue(store.providerChoices.allSatisfy { !$0.title.isEmpty })
        // The daemon's agent id is ASCII-only; the owner reads a French label.
        XCTAssertEqual(FirstRunCopy.displayName(for: "main", .fr), "Mon agent")
        XCTAssertEqual(FirstRunCopy.displayName(for: "scribe", .fr), "scribe")
    }

    func testDaemonServicesComeFirstAndAreNotResaved() {
        let fake = FakeFirstRunClient()
        fake.providersResult = .success([providerSummary(id: "mine")])
        let store = readyStore(fake)

        XCTAssertEqual(store.providerChoices.first?.id, "mine")
        XCTAssertEqual(store.providerChoices.first?.configured, true)
        XCTAssertEqual(store.selectedProviderID, "mine")

        let choice = store.selectedProviderChoice
        XCTAssertNotNil(choice)
        XCTAssertFalse(store.providerNeedsKey(choice!), "an already-saved service keeps its key on disk")
        XCTAssertTrue(store.canTestProvider, "no key typed is fine for a saved service")

        store.testProviderKey()
        XCTAssertTrue(waitUntil { store.firstRunSetupState == .done(agent: "main") })
        XCTAssertTrue(fake.savedRequests.isEmpty, "a configured service is not saved again")
        XCTAssertEqual(fake.testedRequests.count, 1)
        XCTAssertNil(fake.testedRequests.first?.apiKey, "the typed key is never resent for a saved service")
        XCTAssertEqual(fake.createdRequests.first?.name, "main")
        XCTAssertEqual(fake.completedRequests.first?.provider, "mine")
    }

    // MARK: Happy path

    func testSuccessfulTestSavesServiceCreatesAgentAndClearsTheKey() {
        let fake = FakeFirstRunClient()
        let store = readyStore(fake)
        store.selectedProviderID = "deepseek"
        store.providerKeyInput = "  sk-not-a-real-key  "

        store.testProviderKey()
        XCTAssertTrue(waitUntil { store.firstRunSetupState == .done(agent: "main") })

        // The key went to the daemon and nowhere else, and the field is empty.
        XCTAssertEqual(fake.testedRequests.first?.apiKey, "sk-not-a-real-key")
        XCTAssertEqual(fake.savedRequests.first?.apiKey, "sk-not-a-real-key")
        XCTAssertEqual(fake.savedRequests.first?.name, "deepseek")
        XCTAssertEqual(store.providerKeyInput, "")

        // Agent created through POST /v1/agents, then the gate cleared.
        XCTAssertEqual(fake.createdRequests.first?.name, "main")
        XCTAssertEqual(fake.createdRequests.first?.provider, "deepseek")
        XCTAssertEqual(fake.completedRequests.first?.provider, "deepseek")
        XCTAssertEqual(store.createdAgentName, "main")
        XCTAssertEqual(store.firstRunTestState, .ok(.firstRunSuccessReachable))
    }

    func testSaveConflictIsTreatedAsAlreadySaved() {
        let fake = FakeFirstRunClient()
        fake.saveResult = .failure(AuxdError.http(status: 409, body: daemonErrorBody("provider_exists")))
        let store = readyStore(fake)
        store.providerKeyInput = "sk-key"

        store.testProviderKey()
        XCTAssertTrue(waitUntil { store.firstRunSetupState == .done(agent: "main") }, "409 provider_exists is not fatal")
        XCTAssertEqual(fake.createdRequests.count, 1)
    }

    func testKeylessExistingProviderShowsTheKeyFieldAndCompletesViaTheUpdateRoute() {
        let fake = FakeFirstRunClient()
        fake.providersResult = .success([
            providerSummary(id: "mine", keyPresent: false),
            providerSummary(id: "unknown", keyPresent: nil, keyError: "the key could not be checked"),
        ])
        let store = readyStore(fake)

        guard let choice = store.providerChoices.first(where: { $0.id == "mine" }) else {
            return XCTFail("missing mine")
        }
        XCTAssertTrue(choice.knownToDaemon)
        XCTAssertFalse(choice.configured, "a service without a key is not ready")
        XCTAssertTrue(store.providerNeedsKey(choice), "a keyless saved service asks for the key")

        // A failed key lookup is treated the same way: the field is shown.
        guard let lookupFailed = store.providerChoices.first(where: { $0.id == "unknown" }) else {
            return XCTFail("missing unknown")
        }
        XCTAssertTrue(store.providerNeedsKey(lookupFailed), "a failed lookup still asks for the key")

        store.selectedProviderID = "mine"
        XCTAssertFalse(store.canTestProvider, "no key pasted yet")
        store.providerKeyInput = "  sk-late-key  "
        XCTAssertTrue(store.canTestProvider)

        store.testProviderKey()
        XCTAssertTrue(waitUntil { store.firstRunSetupState == .done(agent: "main") })

        // The key went through the update route, not the save or test bodies.
        XCTAssertEqual(fake.updatedKeys.count, 1)
        XCTAssertEqual(fake.updatedKeys.first?.name, "mine")
        XCTAssertEqual(fake.updatedKeys.first?.apiKey, "sk-late-key")
        XCTAssertTrue(fake.savedRequests.isEmpty, "an existing service is never saved again")
        XCTAssertNil(fake.testedRequests.first?.apiKey, "the daemon resolves the stored key")
        XCTAssertEqual(fake.createdRequests.first?.provider, "mine")
        XCTAssertEqual(store.providerKeyInput, "")
    }

    func testSaveKeyConflictSurfacesAndNeverCreatesTheAgent() {
        let fake = FakeFirstRunClient()
        fake.saveResult = .failure(AuxdError.http(status: 409, body: daemonErrorBody("provider_key_conflict")))
        let store = readyStore(fake)
        store.providerKeyInput = "sk-key"

        store.testProviderKey()
        XCTAssertTrue(waitUntil {
            if case .failed = store.firstRunSetupState { return true }
            return false
        })
        guard case .failed(let failure) = store.firstRunSetupState else {
            return XCTFail("expected a failure card")
        }
        XCTAssertEqual(failure, .providerKeyConflict)
        XCTAssertFalse(failure.title(.fr).isEmpty)
        XCTAssertFalse(failure.nextStep(.fr).isEmpty)
        XCTAssertTrue(fake.createdRequests.isEmpty, "a refused save must not create the agent")
        XCTAssertTrue(fake.completedRequests.isEmpty, "first-run must not complete")
    }

    func testAnyOtherSaveConflictAlsoSurfaces() {
        let fake = FakeFirstRunClient()
        fake.saveResult = .failure(AuxdError.http(status: 409, body: daemonErrorBody("something_else")))
        let store = readyStore(fake)
        store.providerKeyInput = "sk-key"

        store.testProviderKey()
        XCTAssertTrue(waitUntil {
            if case .failed = store.firstRunSetupState { return true }
            return false
        })
        XCTAssertTrue(fake.createdRequests.isEmpty, "an unknown 409 must not create the agent")
        XCTAssertTrue(fake.completedRequests.isEmpty, "an unknown 409 must not complete first-run")
    }

    // MARK: Plain-French failures

    func testBadKeyShowsCauseNextStepAndDoesNotTouchTheAgent() {
        let fake = FakeFirstRunClient()
        fake.testResult = .success(.failing(reason: "bad_key"))
        let store = readyStore(fake)
        store.providerKeyInput = "sk-wrong"

        store.testProviderKey()
        XCTAssertTrue(waitUntil {
            if case .failed = store.firstRunTestState { return true }
            return false
        })

        guard case .failed(let failure) = store.firstRunTestState else {
            return XCTFail("expected a failure")
        }
        XCTAssertEqual(failure, .keyRefused)
        XCTAssertTrue(failure.title(.fr).contains("refusée"))
        XCTAssertFalse(failure.nextStep(.fr).isEmpty, "every error has one next step")
        XCTAssertEqual(store.firstRunSetupState, .ready, "the form stays so Retry works")
        XCTAssertTrue(fake.savedRequests.isEmpty)
        XCTAssertTrue(fake.createdRequests.isEmpty)
        XCTAssertEqual(store.providerKeyInput, "", "the key is dropped after submit")

        store.clearProviderTestError()
        XCTAssertEqual(store.firstRunTestState, .idle)
    }

    func testHttpStatusesMapToPlainFrenchCausesAndNextSteps() {
        let cases: [(AuxdError, FirstRunFailure)] = [
            // A 401 from the local service is the app's own token failing, not
            // the provider key: it must not read "the AI service refused this key".
            (.unauthorized, .localService),
            (.http(status: 401, body: ""), .localService),
            (.http(status: 403, body: ""), .accessDenied),
            (.http(status: 429, body: ""), .tooManyRequests),
            (.transport("connection refused"), .localService),
            // A late or unreadable answer is not a dead daemon.
            (.transport(AuxdError.timedOutMessage), .localServiceUnreadable),
            (.decode("bad json"), .localServiceUnreadable),
            (.token(.missing), .localService),
        ]
        for (error, expected) in cases {
            XCTAssertEqual(FirstRunFailure(error: error), expected)
            XCTAssertFalse(expected.title(.fr).isEmpty)
            XCTAssertFalse(expected.nextStep(.fr).isEmpty)
        }
        XCTAssertTrue(FirstRunFailure(error: AuxdError.http(status: 403, body: "")).nextStep(.fr).contains("droits"))
        XCTAssertTrue(FirstRunFailure.tooManyRequests.nextStep(.fr).contains("Attends"))
        XCTAssertTrue(FirstRunFailure.localService.isConnection)
        XCTAssertFalse(
            FirstRunFailure.localServiceUnreadable.nextStep(.fr).contains("relance"),
            "a slow answer must not tell the owner to relaunch Auxesis"
        )
    }

    func testTestReasonsMapToPlainFrench() {
        XCTAssertEqual(FirstRunFailure(test: .failing(reason: "bad_key")), .keyRefused)
        XCTAssertEqual(FirstRunFailure(test: .failing(reason: "unreachable")), .serviceUnreachable)
        XCTAssertEqual(FirstRunFailure(test: .failing(reason: "invalid_config")), .invalidConfig)
        XCTAssertEqual(FirstRunFailure(test: .failing(reason: "model_not_found")), .modelNotFound)
        XCTAssertEqual(FirstRunFailure(test: .failing(reason: "nonsense")), .unknown)
    }

    func testMissingKeyIsRefusedWithoutCallingTheDaemon() {
        let fake = FakeFirstRunClient()
        let store = readyStore(fake)
        store.selectedProviderID = "deepseek"
        store.providerKeyInput = "   "

        XCTAssertFalse(store.canTestProvider, "the button stays off with an empty key")
        store.testProviderKey()

        XCTAssertEqual(store.firstRunTestState, .failed(.missingKey))
        XCTAssertTrue(fake.testedRequests.isEmpty, "an empty key never leaves the app")
    }

    func testDaemonUnreachableShowsOfflineStateAndRetryRecovers() {
        let fake = FakeFirstRunClient()
        fake.providersResult = .failure(AuxdError.transport("connection refused"))
        let store = makeStore(fake)
        store.beginFirstRunSetup()
        XCTAssertTrue(waitUntil {
            if case .failed = store.firstRunSetupState { return true }
            return false
        })

        guard case .failed(let failure) = store.firstRunSetupState else {
            return XCTFail("expected the offline card")
        }
        XCTAssertEqual(failure, .localService)
        XCTAssertTrue(failure.isConnection)

        fake.providersResult = .success([])
        store.retryFirstRunSetup()
        XCTAssertTrue(waitUntil { store.firstRunSetupState == .ready })
        XCTAssertEqual(fake.loadCount, 2)
    }

    // MARK: Wire shapes

    func testDecodesTheDaemonWireShapes() throws {
        let decoder = JSONDecoder()
        let test = try decoder.decode(ProviderTest.self, from: Data(#"""
        {"ok":false,"reason":"bad_key","latency_ms":null,"models":[],
         "error":"no API key found for this service","key_present":false,
         "key_required":true,"reachable":null,"note":"not checked"}
        """#.utf8))
        XCTAssertFalse(test.ok)
        XCTAssertEqual(test.reason, "bad_key")

        let status = try decoder.decode(FirstRunStatus.self, from: Data(#"""
        {"first_run":true,"provider_saved":true,"provider_tested":false,
         "agent_created":false,"next_step":"test","provider":"deepseek"}
        """#.utf8))
        XCTAssertEqual(status.nextStep, "test")
        XCTAssertTrue(status.providerSaved)

        let saved = try decoder.decode(ProviderSaved.self, from: Data(#"{"name":"deepseek","key_present":true}"#.utf8))
        XCTAssertTrue(saved.keyPresent)

        let complete = try decoder.decode(FirstRunComplete.self, from: Data(#"""
        {"first_run":false,"created":true,"provider":"deepseek",
         "agent":{"name":"main","provider":"deepseek","model":"deepseek-chat",
                  "tools":null,"paused":false,"killed":false}}
        """#.utf8))
        XCTAssertTrue(complete.created)
        XCTAssertEqual(complete.agent.name, "main")

        let encoded = try JSONEncoder().encode(
            CreateProviderRequest(name: "deepseek", baseURL: "https://api.deepseek.com/v1", model: "deepseek-chat", apiKey: "sk")
        )
        let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        XCTAssertEqual(object?["name"] as? String, "deepseek")
        XCTAssertEqual(object?["base_url"] as? String, "https://api.deepseek.com/v1")
        XCTAssertEqual(object?["api_key"] as? String, "sk")
        XCTAssertEqual(object?["kind"] as? String, "openai_compat")
    }
}
