import Foundation

/// The Google connection shown in Réglages (G4): the service's last honest
/// answer, plus the sign-in this screen started and is still waiting on.
///
/// `Store` owns one and forwards its changes, so a view that observes the
/// store redraws when this changes. The model only talks to the service
/// through the three things it is given.
@MainActor
public final class GoogleConnectionModel: ObservableObject {
    @Published public private(set) var connected = false
    @Published public private(set) var reconnectNeeded = false
    @Published public private(set) var connectedKnown = false
    @Published public private(set) var flow: GoogleFlow = .idle

    /// Nil when the transport does not speak the Google routes.
    private let client: GoogleConnectionClient?
    private let readHealth: () async throws -> HealthResponse
    private let pause: (TimeInterval) async -> Void

    init(
        client: GoogleConnectionClient?,
        health: @escaping () async throws -> HealthResponse,
        pause: @escaping (TimeInterval) async -> Void
    ) {
        self.client = client
        self.readHealth = health
        self.pause = pause
    }

    /// What the Réglages row shows, from the last honest answer plus this
    /// screen's own in-flight sign-in.
    public var state: GoogleConnectionState {
        GoogleConnectionState.resolve(
            known: connectedKnown,
            connected: connected,
            reconnectNeeded: reconnectNeeded,
            waiting: flow == .waiting,
            failed: flow == .failed
        )
    }

    /// Record the service's answer. A sign-in this screen started is never
    /// silently dropped: only a real "connected" (or the explicit end of the
    /// flow) moves it out of `.waiting`.
    func apply(connected: Bool, reconnectNeeded: Bool = false) {
        self.connected = connected
        self.reconnectNeeded = reconnectNeeded
        connectedKnown = true
        if connected && !reconnectNeeded {
            flow = .idle
        }
    }

    /// Ask the service to open the Google sign-in. Only the owner's click calls
    /// this; the app itself never opens a page and never sends an email.
    public func connect() {
        guard state.canConnect, let client else { return }
        flow = .waiting
        Task { [weak self] in
            guard let self else { return }
            do {
                let answer = try await client.startGoogleConnection()
                if answer.connected {
                    self.connected = true
                    self.connectedKnown = true
                    self.flow = .idle
                    return
                }
                await self.awaitConsent(requiringUpdatedPermissions: answer.reconnectNeeded)
            } catch {
                self.flow = .failed
            }
        }
    }

    public func updatePermissions() {
        guard state == .needsUpdate, let client else { return }
        flow = .waiting
        Task { [weak self] in
            guard let self else { return }
            do {
                let answer = try await client.updateGooglePermissions()
                if answer.connected && !answer.started {
                    self.apply(connected: true, reconnectNeeded: false)
                    self.flow = .idle
                    return
                }
                await self.awaitConsent(requiringUpdatedPermissions: true)
            } catch {
                self.flow = .failed
            }
        }
    }

    /// Wait, bounded, for the sign-in page to be answered. The service's own
    /// flow deadline is five minutes; two seconds per check is enough to feel
    /// immediate and costs nothing.
    private func awaitConsent(requiringUpdatedPermissions: Bool) async {
        let interval: TimeInterval = 2
        let attempts = 150
        for _ in 0..<attempts {
            await pause(interval)
            if Task.isCancelled { return }
            guard let health = try? await readHealth() else { continue }
            if health.googleConnected && (!requiringUpdatedPermissions || !health.googleReconnectNeeded) {
                apply(connected: true, reconnectNeeded: false)
                return
            }
        }
        // The browser tab may still be open; say the sign-in did not complete
        // rather than claim a connection that is not there.
        if !connected {
            flow = .failed
        }
    }

    /// Revoke and delete this Mac's Google authorization.
    public func disconnect() {
        guard state.canDisconnect, let client else { return }
        Task { [weak self] in
            guard let self else { return }
            do {
                let answer = try await client.disconnectGoogle()
                self.apply(connected: answer.connected)
                self.flow = .idle
            } catch {
                self.flow = .failed
            }
        }
    }
}
