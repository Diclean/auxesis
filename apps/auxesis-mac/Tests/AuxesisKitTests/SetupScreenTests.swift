// First-launch setup screen (SETUP-SCREEN): a fake permission provider only.
// No test raises a macOS prompt, reads a calendar or touches a real permission.
import XCTest
@testable import AuxesisKit

@MainActor final class FakePermissions: PermissionProviding {
    var states: [SetupPermission: PermissionState]
    var answers: [SetupPermission: PermissionState] = [:]
    private(set) var requests: [SetupPermission] = []
    private(set) var opened: [SetupPermission] = []

    init(_ states: [SetupPermission: PermissionState]) { self.states = states }

    func state(of permission: SetupPermission) async -> PermissionState { states[permission] ?? .notYet }

    func request(_ permission: SetupPermission) async -> PermissionState {
        requests.append(permission)
        states[permission] = answers[permission] ?? .granted
        return states[permission]!
    }

    func openSystemSettings(for permission: SetupPermission) { opened.append(permission) }
}

@objcMembers @MainActor final class SetupScreenTests: XCTestCase {
    /// A throwaway defaults domain; callers `defer` its removal.
    private func freshDefaults() -> (UserDefaults, String) {
        let suite = "auxesis.tests.setup.\(UUID().uuidString)"
        return (UserDefaults(suiteName: suite)!, suite)
    }

    func testFirstLaunchShowsTheScreenOnceThenNeverAfterDoneOrSkip() {
        for finish in [true, false] {
            let (defaults, suite) = freshDefaults()
            defer { UserDefaults().removePersistentDomain(forName: suite) }
            XCTAssertTrue(SetupModel.shouldShow(defaults: defaults))
            let model = SetupModel(provider: FakePermissions([:]), defaults: defaults)
            if finish { model.finish() } else { model.skip() }
            XCTAssertFalse(SetupModel.shouldShow(defaults: defaults))
        }
    }

    func testEachRowMapsItsStateToTheRightAction() {
        for permission in [SetupPermission.calendar, .notifications, .messages] {
            XCTAssertEqual(permission.action(for: .granted), SetupAction.none)
            XCTAssertEqual(permission.action(for: .notYet), .ask)
            XCTAssertEqual(permission.action(for: .denied), .openSystemSettings)
        }
        // macOS never lets an app ask for Full Disk Access: always System Settings.
        for state in [PermissionState.notYet, .denied, .unknown] {
            XCTAssertEqual(SetupPermission.fullDiskAccess.action(for: state), .openSystemSettings)
        }
        XCTAssertEqual(SetupPermission.fullDiskAccess.settingsURL.absoluteString,
                       "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
    }

    func testAppearingReadsStatusButNeverRequests() async {
        let fake = FakePermissions([.calendar: .granted, .notifications: .denied, .messages: .notYet])
        let (defaults, suite) = freshDefaults()
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let model = SetupModel(provider: fake, defaults: defaults)
        await model.refresh()
        XCTAssertEqual(fake.requests.count, 0)
        XCTAssertEqual(fake.opened.count, 0)
        XCTAssertEqual(model.state(.calendar), .granted)
        XCTAssertEqual(model.state(.notifications), .denied)
        XCTAssertEqual(model.state(.messages), .notYet)
    }

    func testAClickAsksOnlyThatRowAndAGrantedCalendarIsPublished() async {
        let fake = FakePermissions([.notifications: .denied, .fullDiskAccess: .unknown])
        var granted: [SetupPermission] = []
        let (defaults, suite) = freshDefaults()
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let model = SetupModel(provider: fake, defaults: defaults, onGranted: { granted.append($0) })
        await model.refresh()

        await model.press(.calendar)
        XCTAssertEqual(fake.requests, [.calendar])
        XCTAssertEqual(model.state(.calendar), .granted)
        XCTAssertEqual(granted, [.calendar])

        // A denied row and Full Disk Access go to System Settings, never to a prompt.
        await model.press(.notifications)
        await model.press(.fullDiskAccess)
        XCTAssertEqual(fake.requests, [.calendar])
        XCTAssertEqual(fake.opened, [.notifications, .fullDiskAccess])

        fake.answers[.messages] = .denied
        await model.press(.messages)
        XCTAssertEqual(model.state(.messages), .denied)
        XCTAssertEqual(granted, [.calendar])
    }

    func testFullDiskAccessNamesTheAuxdThatRunsInOrder() throws {
        let fm = FileManager.default
        let home = fm.temporaryDirectory.appendingPathComponent("setup-\(UUID().uuidString)")  // fake HOME
        defer { try? fm.removeItem(at: home) }
        let auxesis = home.appendingPathComponent(".auxesis")
        let app = home.appendingPathComponent("Auxesis.app")
        func resolve() -> String? {
            SetupModel.fullDiskAccessBinary(userHome: home, auxesisHome: auxesis, appBundle: app)?.path
        }
        func makeExecutable(_ url: URL) throws {
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            XCTAssertTrue(fm.createFile(atPath: url.path, contents: Data("#!/bin/sh\n".utf8),
                                        attributes: [.posixPermissions: 0o755]))
        }
        // 4. Nothing installed: no file to add yet.
        XCTAssertNil(resolve())
        // 3. Only the app's bundled service.
        let bundled = app.appendingPathComponent(BundledService.relativeExecutablePath)
        try makeExecutable(bundled)
        XCTAssertEqual(resolve(), bundled.resolvingSymlinksInPath().path)
        // 2. The deployed copy in the Auxesis home wins over the bundle.
        try makeExecutable(auxesis.appendingPathComponent("bin/auxd"))
        XCTAssertEqual(resolve(), auxesis.appendingPathComponent("bin/auxd").path)
        // 1. The LaunchAgent's program wins, but only an executable named auxd.
        let agent = home.appendingPathComponent("Library/LaunchAgents/dev.auxesis.auxd.plist")
        try fm.createDirectory(at: agent.deletingLastPathComponent(), withIntermediateDirectories: true)
        func agentRuns(_ arguments: Any) throws {
            let plist = ["Label": "dev.auxesis.auxd", "ProgramArguments": arguments] as [String: Any]
            try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: agent)
        }
        let deployed = home.appendingPathComponent("deploy/auxd")
        try makeExecutable(deployed)
        try agentRuns([deployed.path])
        XCTAssertEqual(resolve(), deployed.resolvingSymlinksInPath().path)
        // Hostile or malformed: missing file, another binary, empty, not a string, relative.
        let fallback = auxesis.appendingPathComponent("bin/auxd").path
        for bad: Any in [["/opt/missing/auxd"], ["/bin/sh"], ["/etc/passwd"], [String](), [42], ["bin/auxd"], "auxd"] {
            try agentRuns(bad)
            XCTAssertEqual(resolve(), fallback, "\(bad) must fall back")
        }
        try Data("not a plist".utf8).write(to: agent)
        XCTAssertEqual(resolve(), fallback)
        // No LaunchAgent lookup when the caller passes no user home (sandbox).
        XCTAssertEqual(SetupModel.fullDiskAccessBinary(userHome: nil, auxesisHome: auxesis, appBundle: app)?.path,
                       auxesis.appendingPathComponent("bin/auxd").path)
    }
}
