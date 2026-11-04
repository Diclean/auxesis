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
