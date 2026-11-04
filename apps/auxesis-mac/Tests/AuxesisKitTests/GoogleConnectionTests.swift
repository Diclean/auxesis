// The owner's Google connection screen (G4), entirely offline: a scripted
// client drives the Store's state machine and the French/English copy. No
// network, no browser, no real `~/.auxesis`, and no secret in any assertion.
import Testing
@testable import AuxesisKit

/// Scripts `POST /v1/google/connect` and `POST /v1/google/disconnect`. Nothing
/// here touches the network; every answer is a fixture built in-process.
final class FakeGoogleClient: GoogleConnectionClient {
    nonisolated(unsafe) var startResult: Result<GoogleConnection, Error> = .success(
        GoogleConnection(connected: false, started: true)
    )
    nonisolated(unsafe) var disconnectResult: Result<GoogleConnection, Error> = .success(
        GoogleConnection(connected: false, started: false)
    )
    nonisolated(unsafe) var updateResult: Result<GoogleConnection, Error> = .success(
        GoogleConnection(connected: false, started: true)
    )

    private let lock = NSLock()
    private var starts = 0
    private var disconnects = 0
    private var updates = 0
    private var startContinuation: CheckedContinuation<Void, Never>?

    /// When true, `startGoogleConnection` waits until `releaseStart()` — the
    /// browser page is "open" and the owner has not answered yet.
    nonisolated(unsafe) var holdStart = false

    var startCount: Int { lock.withLock { starts } }
    var disconnectCount: Int { lock.withLock { disconnects } }
    var updateCount: Int { lock.withLock { updates } }

    func startGoogleConnection() async throws -> GoogleConnection {
        lock.withLock { starts += 1 }
        if holdStart {
            await withCheckedContinuation { continuation in
                lock.withLock { startContinuation = continuation }
            }
        }
        return try startResult.get()
    }

    func releaseStart() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            let pending = startContinuation
            startContinuation = nil
            return pending
        }
        continuation?.resume()
    }

    func disconnectGoogle() async throws -> GoogleConnection {
        lock.withLock { disconnects += 1 }
        return try disconnectResult.get()
    }

    func updateGooglePermissions() async throws -> GoogleConnection {
        lock.withLock { updates += 1 }
        return try updateResult.get()
    }
}

@objcMembers @MainActor final class GoogleConnectionTests: XCTestCase {
    private func makeStore(_ google: FakeGoogleClient, transport: FakeTransport = FakeTransport()) -> Store {
        // The scripted sleeper never waits: the consent poll is bounded and the
        // test drives the health answer instead of the clock.
        Store(
            transport: transport,
            firstRunClient: nil,
            googleClient: google,
            language: .fr,
            sleeper: { _ in }
        )
    }

    // MARK: State mapping (pure)

    func testEveryConnectionStateMapsToItsOwnPlainFrenchLabel() {
        XCTAssertEqual(
            GoogleConnectionState.resolve(known: false, connected: false, waiting: false, failed: false),
            .unknown
        )
        XCTAssertEqual(
            GoogleConnectionState.resolve(known: true, connected: false, waiting: false, failed: false),
            .disconnected
        )
        XCTAssertEqual(
            GoogleConnectionState.resolve(known: true, connected: false, waiting: true, failed: false),
            .waitingForConsent
        )
        XCTAssertEqual(
            GoogleConnectionState.resolve(known: true, connected: true, waiting: false, failed: false),
            .connected
        )
        XCTAssertEqual(
            GoogleConnectionState.resolve(
                known: true,
                connected: true,
                reconnectNeeded: true,
                waiting: false,
                failed: false
            ),
            .needsUpdate
        )
        XCTAssertEqual(
            GoogleConnectionState.resolve(known: true, connected: false, waiting: false, failed: true),
            .failed
        )
    }

    func testConnectionAndHealthResponsesExposeOnlyPermissionUpdateBooleans() throws {
        let connection = try JSONDecoder().decode(
            GoogleConnection.self,
            from: Data(#"{"connected":false,"started":true,"reconnect_needed":true}"#.utf8)
        )
        XCTAssertTrue(connection.reconnectNeeded)

        let health = try JSONDecoder().decode(
            HealthResponse.self,
            from: Data(#"{"ok":true,"version":"0.1.0","pid":1,"first_run":false,"google_connected":true,"google_reconnect_needed":true}"#.utf8)
        )
        XCTAssertTrue(health.googleConnected)
        XCTAssertTrue(health.googleReconnectNeeded)
    }

    func testTheRowSaysConnectedOrNotConnectedInBothLanguages() {
        XCTAssertEqual(L10n.t(.googleConnectedValue, .fr), "connecté")
        XCTAssertEqual(L10n.t(.googleDisconnectedValue, .fr), "non connecté")
        XCTAssertEqual(L10n.t(.googleConnectedValue, .en), "connected")
        XCTAssertEqual(L10n.t(.googleDisconnectedValue, .en), "not connected")
        XCTAssertEqual(L10n.t(.googleAppName, .fr), "Google")
        XCTAssertEqual(L10n.t(.googleAppName, .en), "Google")
        XCTAssertEqual(L10n.t(.connectedAppsTitle, .fr), "Applications connectées")
        XCTAssertEqual(L10n.t(.connectedAppsTitle, .en), "Connected apps")
        XCTAssertEqual(L10n.t(.googleUpdatePermissions, .fr), "Mettre à jour les autorisations Google")
    }

    func testTheButtonsAreTranslatedAndOnlyOfferedWhenTheyDoSomething() {
        XCTAssertEqual(L10n.t(.googleConnect, .fr), "Connecter Google")
        XCTAssertEqual(L10n.t(.googleConnect, .en), "Connect Google")
        XCTAssertEqual(L10n.t(.googleDisconnect, .fr), "Déconnecter")
        XCTAssertEqual(L10n.t(.googleDisconnect, .en), "Disconnect")

        XCTAssertFalse(GoogleConnectionState.connected.canConnect)
        XCTAssertTrue(GoogleConnectionState.connected.canDisconnect)
        XCTAssertTrue(GoogleConnectionState.disconnected.canConnect)
        XCTAssertFalse(GoogleConnectionState.disconnected.canDisconnect)
        XCTAssertFalse(GoogleConnectionState.waitingForConsent.canConnect)
        XCTAssertTrue(GoogleConnectionState.waitingForConsent.canDisconnect)
    }

    func testTheHintTalksToTheOwnerInFrenchAndNamesNoInternalWord() {
        let hint = L10n.t(.googleHint, .fr)
        XCTAssertTrue(hint.contains("tes e-mails"), "unexpected hint: \(hint)")
        XCTAssertTrue(hint.contains("retirer cet accès"), "unexpected hint: \(hint)")
        for banned in ["jeton", "fournisseur", "audit", "scope", "sandbox", "daemon", "MCP", "connecteur"] {
            XCTAssertFalse(
                hint.localizedCaseInsensitiveContains(banned),
                "the hint must not say \(banned): \(hint)"
            )
        }
        XCTAssertFalse(L10n.t(.googleHint, .en).isEmpty)
        XCTAssertFalse(L10n.t(.googleWaitingHint, .fr).isEmpty)
        XCTAssertFalse(L10n.t(.googleWaitingHint, .en).isEmpty)
    }

    // MARK: Store flow

    func testTheConnectButtonAsksTheServiceExactlyOnceAndThenWaits() {
        let google = FakeGoogleClient()
        let transport = FakeTransport()
        transport.healthResult = .success(health(googleConnected: false))
        let store = makeStore(google, transport: transport)

        XCTAssertEqual(store.google.state, .unknown)
        store.google.connect()
        XCTAssertTrue(waitUntil { google.startCount == 1 })
        // The scripted transport never flips to connected, so the bounded wait
        // ends as an honest failure rather than a claim.
        XCTAssertTrue(waitUntil { store.google.state == .failed })
    }

    func testASecondClickNeverOpensASecondPage() {
        let google = FakeGoogleClient()
        google.holdStart = true
        let store = makeStore(google)

        store.google.connect()
        XCTAssertTrue(waitUntil { google.startCount == 1 })
        XCTAssertEqual(store.google.state, .waitingForConsent)

        // The page is open; pressing the button again must not start a second
        // sign-in.
        store.google.connect()
        XCTAssertEqual(google.startCount, 1)

        google.releaseStart()
        XCTAssertTrue(waitUntil { store.google.state == .failed })
    }

    func testTheRowTurnsConnectedWhenTheServiceReportsTheAuthorization() {
        let google = FakeGoogleClient()
        let transport = FakeTransport()
        transport.healthResult = .success(health(googleConnected: false))
        let store = makeStore(google, transport: transport)

        store.google.connect()
        XCTAssertTrue(waitUntil { store.google.state == .waitingForConsent })

        // The owner accepts in the browser; the service's status flips.
        transport.healthResult = .success(health(googleConnected: true))
        XCTAssertTrue(waitUntil { store.google.state == .connected })
        XCTAssertTrue(store.google.connected)
        XCTAssertFalse(store.google.state.canConnect)
    }

    func testUpdatingPermissionsOnlyStartsFromTheUpdateStateAndReturnsToConnected() {
        let google = FakeGoogleClient()
        google.updateResult = .success(GoogleConnection(connected: true, started: false))
        let transport = FakeTransport()
        transport.healthResult = .success(health(googleConnected: true, reconnectNeeded: true))
        let store = makeStore(google, transport: transport)

        store.refreshFirstRun()
        XCTAssertTrue(waitUntil { store.google.state == .needsUpdate })
        store.google.updatePermissions()
        XCTAssertTrue(waitUntil { google.updateCount == 1 })
        XCTAssertTrue(waitUntil { store.google.state == .connected })
        XCTAssertFalse(store.google.reconnectNeeded)
    }

    func testAnAlreadyConnectedServiceIsNeverAskedToStartAgain() {
        let google = FakeGoogleClient()
        let transport = FakeTransport()
        transport.healthResult = .success(health(googleConnected: true))
        let store = makeStore(google, transport: transport)

        store.refreshFirstRun()
        XCTAssertTrue(waitUntil { store.google.state == .connected })
        store.google.connect()
        XCTAssertEqual(google.startCount, 0)
    }

    func testDisconnectAsksTheServiceAndReturnsToNotConnected() {
        let google = FakeGoogleClient()
        let transport = FakeTransport()
        transport.healthResult = .success(health(googleConnected: true))
        let store = makeStore(google, transport: transport)
        store.refreshFirstRun()
        XCTAssertTrue(waitUntil { store.google.state == .connected })

        google.disconnectResult = .success(GoogleConnection(connected: false, started: false))
        store.google.disconnect()
        XCTAssertTrue(waitUntil { google.disconnectCount == 1 })
        XCTAssertTrue(waitUntil { store.google.state == .disconnected })
        XCTAssertFalse(store.google.connected)
    }

    func testDisconnectIsNotOfferedWhenNothingIsConnected() {
        let google = FakeGoogleClient()
        let store = makeStore(google)
        store.google.disconnect()
        XCTAssertEqual(google.disconnectCount, 0)
    }

    func testAFailedStartIsReportedHonestlyInsteadOfASpinner() {
        let google = FakeGoogleClient()
        google.startResult = .failure(AuxdError.transport("down"))
        let store = makeStore(google)

        store.google.connect()
        XCTAssertTrue(waitUntil { store.google.state == .failed })
        XCTAssertEqual(L10n.t(store.google.state.valueKey, .fr), "la connexion n'a pas abouti")
    }

    private func health(googleConnected: Bool, reconnectNeeded: Bool = false) -> HealthResponse {
        HealthResponse(
            ok: true,
            version: "0.1.0",
            pid: 1,
            firstRun: false,
            googleConnected: googleConnected,
            googleReconnectNeeded: reconnectNeeded
        )
    }
}
