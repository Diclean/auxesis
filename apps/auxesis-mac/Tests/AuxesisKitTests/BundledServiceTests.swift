// The app starts the service it ships: the `auxd` inside its own bundle, at a
// fixed path, with no shell, a minimal environment, and a private log file. It
// stops that child on quit, and a missing binary keeps the existing offline
// screen. Every test uses the launcher seam — no real process is ever started.
import Dispatch
import Foundation
import Testing
@testable import AuxesisKit

// MARK: - Small helpers

private enum UnwrapFailure: Error { case missing }

/// `XCTUnwrap` is not in the CLT-only shim; this is the same idea.
private func required<T>(_ value: T?, _ message: String = "expected a value") throws -> T {
    guard let value else {
        XCTFail(message)
        throw UnwrapFailure.missing
    }
    return value
}

// MARK: - Doubles

final class FakeServiceProcess: ServiceProcess {
    var processIdentifier: Int32 = 4242
    var isRunning = true
    private(set) var terminateCount = 0
    private var terminationHandler: (() -> Void)?

    func setTerminationHandler(_ handler: @escaping () -> Void) {
        terminationHandler = handler
    }

    /// Test seam: the child dies on its own. No real process is involved — the
    /// supervisor's handler fires exactly as Foundation's would.
    func simulateExit() {
        isRunning = false
        terminationHandler?()
    }

    func terminate() {
        terminateCount += 1
        isRunning = false
    }
}

final class FakeServiceLauncher: ServiceLauncher {
    private(set) var plans: [ServiceLaunchPlan] = []
    let process = FakeServiceProcess()

    func launch(_ plan: ServiceLaunchPlan) throws -> ServiceProcess {
        plans.append(plan)
        return process
    }
}

// MARK: - Fake bundle on disk

struct FakeBundle {
    let base: URL
    let bundle: URL
    let home: URL
    let userHome: URL

    var executable: URL {
        bundle.appendingPathComponent(BundledService.relativeExecutablePath)
    }
}

/// A throwaway bundle with (optionally) the bundled binary, plus throwaway home
/// directories. `base` is resolved once so `/var` vs `/private/var` never makes
/// an equality assertion flaky.
func makeFakeBundle(binary: Bool) throws -> FakeBundle {
    let raw = FileManager.default.temporaryDirectory
        .appendingPathComponent("bundled-service-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
    let base = raw.resolvingSymlinksInPath()
    let bundle = base.appendingPathComponent("Auxesis.app", isDirectory: true)
    let home = base.appendingPathComponent(".auxesis", isDirectory: true)
    let userHome = base.appendingPathComponent("home", isDirectory: true)
    try FileManager.default.createDirectory(
        at: bundle.appendingPathComponent("Contents/Resources/bin", isDirectory: true),
        withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: userHome, withIntermediateDirectories: true)
    if binary {
        let executable = bundle.appendingPathComponent(BundledService.relativeExecutablePath)
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: executable.path)
    }
    return FakeBundle(base: base, bundle: bundle, home: home, userHome: userHome)
}

// MARK: - Plan

@objcMembers @MainActor final class BundledServiceTests: XCTestCase {
    func testPathIsResolvedFromTheBundleNotFromAnythingElse() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }

        let plan = BundledService.plan(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome)
        let resolved = try required(plan)
        XCTAssertEqual(resolved.executableURL, fake.executable)
        XCTAssertTrue(resolved.executableURL.path.hasPrefix(fake.bundle.path))
        XCTAssertEqual(resolved.logURL, fake.home.appendingPathComponent("logs/auxd.log"))
        XCTAssertEqual(resolved.arguments, BundledService.fixedArguments)
        XCTAssertTrue(resolved.arguments.isEmpty)
    }

    /// The launcher receives the bundled path itself: no shell, no `env`, no
    /// `PATH` lookup, and no argument from the environment or user input.
    func testNoShellAndFixedArguments() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }

        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }
        XCTAssertEqual(supervisor.start(), .running)
        let plan = try required(launcher.plans.first)
        XCTAssertEqual(plan.executableURL, fake.executable)
        XCTAssertEqual(plan.executableURL.lastPathComponent, "auxd")
        for shell in ["/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/env"] {
            XCTAssertNotEqual(plan.executableURL.path, shell)
        }
        XCTAssertEqual(plan.arguments, [])
        XCTAssertFalse(plan.arguments.contains("-c"))
    }

    func testEnvironmentIsMinimalAndCarriesNoSecret() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }

        let plan = try required(BundledService.plan(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome))
        XCTAssertEqual(Set(plan.environment.keys), BundledService.environmentKeys)
        XCTAssertEqual(plan.environment["AUXESIS_HOME"], fake.home.path)
        XCTAssertEqual(plan.environment["HOME"], fake.userHome.path)
        XCTAssertEqual(plan.environment["PATH"], BundledService.minimalPath)
        // Nothing from the app's own environment is forwarded: no key, token or
        // secret can survive into the child.
        for (key, value) in plan.environment {
            let name = key.lowercased()
            for forbidden in ["token", "secret", "key", "password", "authorization"] {
                XCTAssertFalse(name.contains(forbidden), "leaked \(key)")
            }
            XCTAssertFalse(value.isEmpty)
        }
    }

    func testMissingBinaryHasNoPlanAndKeepsTheOfflineState() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }

        XCTAssertNil(BundledService.plan(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome))

        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        XCTAssertEqual(supervisor.start(), .unavailable)
        XCTAssertTrue(launcher.plans.isEmpty, "a missing binary must never launch anything")
        XCTAssertEqual(supervisor.state, .unavailable)

        // The existing offline screen is what the owner sees.
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: false,
                firstRun: false,
                connection: .offline("connection refused"),
                hasLoadedContent: false
            ),
            .offline
        )
    }

    /// A binary symlinked outside the bundle is not "the bundled binary".
    func testSymlinkEscapingTheBundleIsRefused() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        try FileManager.default.createSymbolicLink(
            at: fake.executable, withDestinationURL: URL(fileURLWithPath: "/bin/ls"))
        XCTAssertNil(BundledService.plan(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome))
    }

    /// F1: the plan resolves the bundle link exactly once and pins the resolved
    /// path. Retargeting that link outside the bundle *after* the check therefore
    /// cannot change what the launcher runs — it still holds the in-bundle file.
    func testRetargetedSymlinkAfterVerificationNeverRunsTheOutsideTarget() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }

        // The fixed path is a link to the real, in-bundle binary.
        let insideExecutable = fake.bundle
            .appendingPathComponent("Contents/Resources/bin/auxd-core")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: insideExecutable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: insideExecutable.path)
        try FileManager.default.createSymbolicLink(
            at: fake.executable, withDestinationURL: insideExecutable)

        // The out-of-bundle target an attacker would redirect to.
        let outside = fake.base.appendingPathComponent("outside-auxd")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: outside)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: outside.path)

        // Plan first (the verification), then retarget the link.
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }
        XCTAssertEqual(supervisor.start(), .running)
        let plan = try required(launcher.plans.first)

        try FileManager.default.removeItem(at: fake.executable)
        try FileManager.default.createSymbolicLink(
            at: fake.executable, withDestinationURL: outside)

        // The seamed launcher received the resolved file, not the linkable path.
        XCTAssertEqual(
            plan.executableURL.resolvingSymlinksInPath().standardizedFileURL,
            insideExecutable.standardizedFileURL)
        XCTAssertTrue(plan.executableURL.path.hasPrefix(fake.bundle.path))
        XCTAssertNotEqual(
            plan.executableURL.resolvingSymlinksInPath().standardizedFileURL,
            outside.standardizedFileURL)
        // The retargeted link is irrelevant to the pinned path, and the link
        // itself is no longer launchable.
        XCTAssertTrue(BundledService.isStillLaunchable(plan.executableURL))
        XCTAssertFalse(BundledService.isStillLaunchable(fake.executable))
    }

    /// F1: if the pinned path itself is swapped for a link to an outside binary
    /// between the plan and the launch, the launcher refuses instead of running
    /// the outside target. No real process is started: the guard throws first.
    func testSwappedResolvedExecutableIsRefusedBeforeLaunch() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }

        let plan = try required(BundledService.plan(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome))

        // Swap the verified file for a link to an executable outside the bundle.
        let outside = fake.base.appendingPathComponent("outside-auxd")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: outside)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: outside.path)
        try FileManager.default.removeItem(at: plan.executableURL)
        try FileManager.default.createSymbolicLink(
            at: plan.executableURL, withDestinationURL: outside)

        XCTAssertFalse(BundledService.isStillLaunchable(plan.executableURL))
        XCTAssertThrowsError(try FoundationServiceLauncher().launch(plan)) { error in
            XCTAssertEqual(error as? BundledService.LaunchError, .executableChanged)
        }
    }

    // MARK: Child lifetime

    func testChildIsStoppedOnQuitAndStopIsIdempotent() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }

        XCTAssertEqual(supervisor.start(), .running)
        ServiceSupervisor.stopCurrent()
        XCTAssertEqual(launcher.process.terminateCount, 1)
        XCTAssertEqual(supervisor.state, .stopped)
        supervisor.stop()
        XCTAssertEqual(launcher.process.terminateCount, 1, "a second stop must not signal again")
    }

    func testStartIsIdempotentWhileTheChildRuns() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }

        XCTAssertEqual(supervisor.start(), .running)
        XCTAssertEqual(supervisor.start(), .running)
        XCTAssertEqual(launcher.plans.count, 1)
        XCTAssertEqual(supervisor.state, .running)
    }

    func testLogFileIsCreatedPrivate() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let url = fake.home.appendingPathComponent("logs/auxd.log")
        let handle = try ServiceLog.open(url)
        try handle.close()

        let file = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual((file[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let directory = try FileManager.default.attributesOfItem(
            atPath: url.deletingLastPathComponent().path)
        XCTAssertEqual((directory[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }

    func testPolicyOnlyStartsWhenTheServiceLooksAbsent() {
        XCTAssertTrue(BundledServicePolicy.shouldStart(cause: .unreachable("x"), alreadyAttempted: false))
        XCTAssertTrue(BundledServicePolicy.shouldStart(cause: .tokenMissing, alreadyAttempted: false))
        XCTAssertFalse(BundledServicePolicy.shouldStart(cause: .tokenUnsafe, alreadyAttempted: false))
        XCTAssertFalse(BundledServicePolicy.shouldStart(cause: .keyRefused, alreadyAttempted: false))
        XCTAssertFalse(BundledServicePolicy.shouldStart(cause: nil, alreadyAttempted: false))
        XCTAssertFalse(BundledServicePolicy.shouldStart(cause: .unreachable("x"), alreadyAttempted: true))
    }

    /// The service the app starts writes `api.token` a moment after launch. The
    /// client re-reads the same verified path, so the owner never has to relaunch
    /// Auxesis to be let in.
    func testClientPicksUpTheTokenTheStartedServiceWrites() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893"),
            home: fake.home,
            tokenFile: fake.home.appendingPathComponent("api.token"),
            lockPID: nil,
            source: "test"
        )
        let client = AuxdClient(endpoint: endpoint)
        XCTAssertEqual(client.tokenProblem, .missing)
        XCTAssertTrue(client.token.isEmpty)

        let tokenFile = endpoint.tokenFile
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)

        client.refreshToken()
        XCTAssertNil(client.tokenProblem)
        XCTAssertEqual(client.token, "deadbeef")
    }

    /// The refresh repeats `init`'s refusal rules: a refused home is still never
    /// read, even after a token file appears.
    func testRefreshNeverReadsATokenWhenTheHomeWasRefused() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let tokenFile = fake.home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)

        let client = AuxdClient(endpoint: AuxdEndpoint(
            baseURL: nil,
            home: fake.home,
            tokenFile: tokenFile,
            lockPID: nil,
            source: "refused",
            homeRefused: true
        ))
        client.refreshToken()
        XCTAssertTrue(client.token.isEmpty)
        XCTAssertEqual(client.tokenProblem, .missing)
    }

    /// F2: the public `token` / `tokenProblem` reads go through `tokenLock` too,
    /// so readers running while `refreshToken()` rewrites both never race the
    /// writer. Simple concurrent-read smoke test: many readers plus periodic
    /// refreshes must stay coherent and never crash.
    func testConcurrentTokenReadsWhileRefreshing() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let tokenFile = fake.home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)

        let client = AuxdClient(endpoint: AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893"),
            home: fake.home,
            tokenFile: tokenFile,
            lockPID: nil,
            source: "test"
        ))

        DispatchQueue.concurrentPerform(iterations: 500) { iteration in
            if iteration % 5 == 0 {
                client.refreshToken()
            } else {
                _ = client.token
                _ = client.tokenProblem
            }
        }

        XCTAssertNil(client.tokenProblem)
        XCTAssertEqual(client.token, "deadbeef")
    }

    func testHealthCopyIsPlainFrench() {
        XCTAssertEqual(L10n.t(.serviceRunning, .fr), "Service en marche")
        XCTAssertEqual(L10n.t(.serviceStopped, .fr), "Service arrêté")
        let keys: [StringKey] = [.serviceRunning, .serviceStopped, .settingsService]
        for key in keys {
            for language in Language.allCases {
                XCTAssertFalse(L10n.t(key, language).isEmpty)
            }
        }
    }
}

// MARK: - Store integration (offline → start, quit → stop)

@objcMembers @MainActor final class BundledServiceStoreTests: XCTestCase {
    func testOfflineConnectStartsTheBundledServiceAndQuitStopsIt() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }

        let transport = FakeTransport()
        transport.healthResult = .failure(AuxdError.transport("connection refused"))
        let gate = Gate()
        let store = Store(
            transport: transport,
            endpoint: nil,
            sleeper: { _ in await gate.wait() },
            service: supervisor
        )
        store.start()
        XCTAssertTrue(
            waitUntil { launcher.plans.count == 1 },
            "the app must start the auxd shipped in its bundle when the service is unreachable")
        XCTAssertEqual(store.serviceState, .running)
        XCTAssertEqual(store.serviceLabel, L10n.t(.serviceRunning, store.language))

        store.stopBundledService()
        XCTAssertEqual(launcher.process.terminateCount, 1)
        XCTAssertEqual(store.serviceLabel, L10n.t(.serviceStopped, store.language))

        store.stop()
        gate.open()
    }

    /// A missing bundled binary leaves the app offline and never starts a
    /// substitute service; the health line still reads plainly.
    func testMissingBinaryKeepsTheAppOffline() throws {
        let fake = try makeFakeBundle(binary: false)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)

        let transport = FakeTransport()
        transport.healthResult = .failure(AuxdError.transport("connection refused"))
        let gate = Gate()
        let store = Store(
            transport: transport,
            endpoint: nil,
            sleeper: { _ in await gate.wait() },
            service: supervisor
        )
        store.start()
        XCTAssertTrue(waitUntil { store.offlineCause != nil })
        XCTAssertEqual(store.serviceState, .unavailable)
        XCTAssertEqual(store.serviceLabel, L10n.t(.serviceStopped, store.language))
        XCTAssertTrue(launcher.plans.isEmpty)
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: store.setup.firstRunKnown,
                firstRun: store.setup.firstRun,
                connection: store.connection,
                hasLoadedContent: !store.agents.isEmpty
            ),
            .offline
        )
        store.stop()
        gate.open()
    }

    /// F3: a refused home is not "the service looks absent". Starting the child
    /// would neither fix the refusal nor give the app anywhere to connect, and
    /// it would run a service the app must not own. The launcher is never called
    /// and the health line stays « Service arrêté ».
    func testRefusedHomeNeverStartsTheBundledService() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }

        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893"),
            home: fake.home,
            tokenFile: fake.home.appendingPathComponent("api.token"),
            lockPID: nil,
            source: "refused",
            homeRefused: true
        )
        let transport = FakeTransport()
        transport.healthResult = .failure(AuxdError.transport("connection refused"))
        let gate = Gate()
        let store = Store(
            transport: transport,
            endpoint: endpoint,
            sleeper: { _ in await gate.wait() },
            service: supervisor
        )
        store.start()
        XCTAssertTrue(waitUntil { store.offlineCause != nil })
        XCTAssertTrue(launcher.plans.isEmpty, "a refused home must never launch the bundled service")
        XCTAssertEqual(store.serviceState, .stopped)
        XCTAssertEqual(store.serviceLabel, L10n.t(.serviceStopped, store.language))
        store.stop()
        gate.open()
    }

    /// F3: an endpoint that resolved to no address (`AUXESIS_API_PORT=0`, a
    /// sandbox without an explicit port) is refused the same way: there is
    /// nothing to connect to, so no child is spawned.
    func testEndpointWithoutAddressNeverStartsTheBundledService() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }

        let endpoint = AuxdEndpoint(
            baseURL: nil,
            home: fake.home,
            tokenFile: fake.home.appendingPathComponent("api.token"),
            lockPID: nil,
            source: "no endpoint"
        )
        let transport = FakeTransport()
        transport.healthResult = .failure(AuxdError.transport("connection refused"))
        let gate = Gate()
        let store = Store(
            transport: transport,
            endpoint: endpoint,
            sleeper: { _ in await gate.wait() },
            service: supervisor
        )
        store.start()
        XCTAssertTrue(waitUntil { store.offlineCause != nil })
        XCTAssertTrue(launcher.plans.isEmpty, "no address means no service to start")
        XCTAssertEqual(store.serviceState, .stopped)
        store.stop()
        gate.open()
    }

    /// F4: the child we own can exit on its own (crash, held port). The
    /// supervisor's termination handler republishes the snapshot, so the health
    /// line stops claiming « Service en marche » without an explicit stop. The
    /// launcher simulates the exit; no real process is started.
    func testChildExitRepublishesTheStoppedState() throws {
        let fake = try makeFakeBundle(binary: true)
        defer { try? FileManager.default.removeItem(at: fake.base) }
        let launcher = FakeServiceLauncher()
        let supervisor = ServiceSupervisor(
            bundleURL: fake.bundle, home: fake.home, userHome: fake.userHome, launcher: launcher)
        defer { ServiceSupervisor.resetCurrentForTesting() }

        let transport = FakeTransport()
        transport.healthResult = .failure(AuxdError.transport("connection refused"))
        let gate = Gate()
        let store = Store(
            transport: transport,
            endpoint: nil,
            sleeper: { _ in await gate.wait() },
            service: supervisor
        )
        store.start()
        XCTAssertTrue(waitUntil { launcher.plans.count == 1 })
        XCTAssertEqual(store.serviceState, .running)
        XCTAssertEqual(store.serviceLabel, L10n.t(.serviceRunning, store.language))

        // The child dies: the supervisor's handler fires, no process involved.
        launcher.process.simulateExit()

        XCTAssertTrue(
            waitUntil { store.serviceState == .stopped },
            "the published state must follow the child's death")
        XCTAssertEqual(store.serviceLabel, L10n.t(.serviceStopped, store.language))
        XCTAssertFalse(launcher.process.isRunning)
        store.stop()
        gate.open()
    }
}
