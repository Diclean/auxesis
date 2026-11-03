// The one way the app may start the service it ships.
//
// The app launches the `auxd` binary inside its own bundle, from a FIXED path
// (`Contents/Resources/bin/auxd`), directly — no shell, no `PATH` lookup, no
// argument built from the environment or from user input. The child gets a
// minimal environment built from scratch (so no secret from the app's own
// environment can leak into it) and writes stdout+stderr to
// `~/.auxesis/logs/auxd.log` (0600).
//
// "Never start a service that is not from the bundle": the path is resolved
// from the bundle only, symlinks are resolved and must stay inside the bundle,
// and the file must be a regular executable. A missing or escaping binary means
// no launch at all — the existing offline screen stays.
//
// Everything here is headless and testable: `BundledService.plan` decides, and
// the `Process` itself sits behind `ServiceLauncher`, so tests inject a fake and
// never start a real process.
import Dispatch
import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// A fully decided launch: what to run, how, where its output goes. Built
/// before any process exists, so a test can assert every field.
public struct ServiceLaunchPlan: Equatable {
    /// Absolute path inside the app bundle. Process never resolves this
    /// through `PATH`.
    public let executableURL: URL
    /// Fixed and empty: `auxd` parses no arguments.
    public let arguments: [String]
    /// The complete environment the child receives (never the app's own).
    public let environment: [String: String]
    /// `~/.auxesis/logs/auxd.log`, created 0600.
    public let logURL: URL

    public init(
        executableURL: URL,
        arguments: [String],
        environment: [String: String],
        logURL: URL
    ) {
        self.executableURL = executableURL
        self.arguments = arguments
        self.environment = environment
        self.logURL = logURL
    }
}

public enum BundledService {
    /// Why a decided plan is refused at the last moment.
    public enum LaunchError: Error, Equatable {
        /// The resolved binary is no longer the verified, in-bundle regular
        /// executable: it was replaced by a link or a non-file between the plan
        /// and the launch.
        case executableChanged
    }

    /// Relative to the bundle root. Fixed by contract: `scripts/package-mac.sh`
    /// copies the daemon to exactly this path.
    public static let relativeExecutablePath = "Contents/Resources/bin/auxd"

    /// `auxd` accepts no arguments (`crates/auxd/src/main.rs`: `struct Args {}`).
    /// Fixed and empty, so no flag can ever come from the environment or from
    /// the owner's input.
    public static let fixedArguments: [String] = []

    /// The only variables the child is given. Built from scratch: nothing from
    /// the app's environment is forwarded, so an API key sitting in the app's
    /// environment can never reach the child. No `LANG` either: a fixed one
    /// would make a French Mac read English, so `auxd` reads the macOS
    /// languages itself when no locale is set.
    public static let environmentKeys: Set<String> = ["HOME", "AUXESIS_HOME", "PATH"]

    /// A fixed, minimal `PATH` for the child's own helpers. It is never used to
    /// find `auxd` — that path is absolute, from the bundle.
    public static let minimalPath = "/usr/bin:/bin:/usr/sbin:/sbin"

    public static let logFileName = "auxd.log"

    /// The launch plan for the service shipped in `bundleURL`, or `nil` when
    /// the app has no bundle, no bundled binary, or a binary that escapes the
    /// bundle. `nil` always means "stay on the offline screen".
    ///
    /// The symlink chain is resolved ONCE here, and the plan keeps that resolved
    /// path — never the original, replaceable link — so `Process` cannot be
    /// re-pointed at an out-of-bundle target between the check and the launch.
    public static func plan(
        bundleURL: URL?,
        home: URL,
        userHome: URL,
        fileManager: FileManager = .default
    ) -> ServiceLaunchPlan? {
        guard let bundleURL else { return nil }
        let root = bundleURL.standardizedFileURL.resolvingSymlinksInPath()
        let candidate = root.appendingPathComponent(relativeExecutablePath)
        guard let executable = resolvedBundledExecutable(
            candidate, under: root, fileManager: fileManager
        ) else {
            return nil
        }
        return ServiceLaunchPlan(
            executableURL: executable,
            arguments: fixedArguments,
            environment: minimalEnvironment(home: home, userHome: userHome),
            logURL: home.appendingPathComponent("logs").appendingPathComponent(logFileName)
        )
    }

    /// Resolves `url` once and validates the *resolved* target: a regular,
    /// executable file whose real path stays inside `root`. Returns the resolved
    /// path to launch, or `nil`.
    public static func resolvedBundledExecutable(
        _ url: URL,
        under root: URL,
        fileManager: FileManager = .default
    ) -> URL? {
        let resolved = url.standardizedFileURL.resolvingSymlinksInPath().standardizedFileURL
        let base = root.standardizedFileURL.resolvingSymlinksInPath().path
        guard resolved.path.hasPrefix(base.hasSuffix("/") ? base : base + "/") else { return nil }
        guard isRegularExecutable(at: resolved, fileManager: fileManager) else { return nil }
        return resolved
    }

    /// A regular, executable file whose real path stays inside the bundle: the
    /// symlink is resolved first, so a link pointing at `/tmp/auxd` is refused
    /// rather than run.
    public static func isBundledExecutable(
        _ url: URL,
        under root: URL,
        fileManager: FileManager = .default
    ) -> Bool {
        resolvedBundledExecutable(url, under: root, fileManager: fileManager) != nil
    }

    /// A regular file with at least one execute bit. Callers pass an
    /// already-resolved path; this does not follow a link itself.
    static func isRegularExecutable(at url: URL, fileManager: FileManager = .default) -> Bool {
        guard let attributes = try? fileManager.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular
        else { return false }
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        return permissions & 0o111 != 0
    }

    /// The last check before `Process.run()`, on the plan's *resolved* path: it
    /// must not have become a symlink since `plan` verified it, and must still be
    /// a regular executable. The plan already pinned an in-bundle target, so a
    /// path that no longer resolves to itself (a parent directory or the file
    /// swapped for a link) has been re-pointed and is refused.
    ///
    /// LIMIT: `Process` takes a path, not an open file descriptor, so a tiny
    /// TOCTOU window remains between this check and the kernel's `execve`. This
    /// narrows that window as far as Foundation allows; closing it entirely would
    /// need `posix_spawn` on a pre-opened fd.
    public static func isStillLaunchable(
        _ url: URL,
        fileManager: FileManager = .default
    ) -> Bool {
        let target = url.standardizedFileURL
        let resolved = target.resolvingSymlinksInPath().standardizedFileURL
        guard resolved == target else { return false }
        return isRegularExecutable(at: resolved, fileManager: fileManager)
    }

    /// The child's complete environment: the user's home, the Auxesis home the
    /// app itself read its token from and a fixed `PATH`. No variable is copied
    /// from the caller's environment.
    public static func minimalEnvironment(home: URL, userHome: URL) -> [String: String] {
        [
            "HOME": userHome.standardizedFileURL.path,
            "AUXESIS_HOME": home.standardizedFileURL.path,
            "PATH": minimalPath,
        ]
    }
}

/// Creates the log file the child writes to. The directory is 0700 and the file
/// 0600, on every launch (a pre-existing file is re-tightened, never followed
/// through a symlink).
public enum ServiceLog {
    public enum LogError: Error, Equatable {
        case notRegularFile
        case createFailed
    }

    public static func open(_ url: URL, fileManager: FileManager = .default) throws -> FileHandle {
        let directory = url.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

        if isSymlink(url.path) {
            throw LogError.notRegularFile
        }
        if !fileManager.fileExists(atPath: url.path) {
            guard fileManager.createFile(
                atPath: url.path,
                contents: nil,
                attributes: [.posixPermissions: 0o600]
            ) else {
                throw LogError.createFailed
            }
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular
        else {
            throw LogError.notRegularFile
        }
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)

        // Append: a relaunch keeps the previous service's output instead of
        // erasing it. (`FileHandle(forWritingTo:)` starts at offset 0.)
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        return handle
    }

    private static func isSymlink(_ path: String) -> Bool {
        #if canImport(Darwin)
        var info = stat()
        guard lstat(path, &info) == 0 else { return false }
        return (info.st_mode & S_IFMT) == S_IFLNK
        #else
        return false
        #endif
    }
}

/// A child the app started. Tests inject a fake so nothing real ever runs.
public protocol ServiceProcess: AnyObject {
    var processIdentifier: Int32 { get }
    var isRunning: Bool { get }
    /// Called once the child is gone, on a non-main thread (the supervisor
    /// marshals the republish to the main queue). Setting a handler on an
    /// already-dead child must call it, so an exit that beats the handler is
    /// never missed. Tests simulate the exit instead of spawning a process.
    func setTerminationHandler(_ handler: @escaping () -> Void)
    /// Stop the child (SIGTERM). Called on quit for the child this app owns.
    func terminate()
}

/// Starts one bundled service. The app's only implementation is
/// `FoundationServiceLauncher`; tests provide a fake and never spawn a process.
public protocol ServiceLauncher {
    func launch(_ plan: ServiceLaunchPlan) throws -> ServiceProcess
}

/// The real launcher: `Process` with a fixed executable URL — never a shell,
/// never `/usr/bin/env`, never a `PATH` lookup.
public final class FoundationServiceLauncher: ServiceLauncher {
    public init() {}

    public func launch(_ plan: ServiceLaunchPlan) throws -> ServiceProcess {
        // Last-moment re-check of the plan's *resolved* path, then launch exactly
        // that path — never the original, replaceable candidate.
        guard BundledService.isStillLaunchable(plan.executableURL) else {
            throw BundledService.LaunchError.executableChanged
        }
        let process = Process()
        process.executableURL = plan.executableURL
        process.arguments = plan.arguments
        process.environment = plan.environment
        process.standardInput = FileHandle.nullDevice
        let log = try ServiceLog.open(plan.logURL)
        process.standardOutput = log
        process.standardError = log
        do {
            try process.run()
        } catch {
            try? log.close()
            throw error
        }
        return FoundationServiceProcess(process: process, log: log)
    }
}

final class FoundationServiceProcess: ServiceProcess {
    private let process: Process
    private let log: FileHandle

    init(process: Process, log: FileHandle) {
        self.process = process
        self.log = log
    }

    var processIdentifier: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }

    /// Foundation runs the block on a background thread when the child exits;
    /// an already-terminated process calls it right away, so an exit that beats
    /// the handler is never missed. The block captures only `handler` — never
    /// this object — so the process cannot retain itself through its own handler.
    func setTerminationHandler(_ handler: @escaping () -> Void) {
        process.terminationHandler = { _ in handler() }
    }

    func terminate() {
        if process.isRunning { process.terminate() }
        try? log.close()
    }
}

/// Owns at most one child: the service binary from this app's own bundle.
///
/// `start()` is idempotent while our child is alive, so a reconnect loop can
/// call it on every failed connect without ever spawning a second service.
/// `stop()` terminates only the child this supervisor started — never a service
/// owned by another process.
public final class ServiceSupervisor {
    public enum State: Equatable {
        /// No child of ours is running.
        case stopped
        /// The child we started is alive.
        case running
        /// No bundled binary: the app must stay on the existing offline screen.
        case unavailable
    }

    private let bundleURL: URL?
    private let home: URL
    private let userHome: URL
    private let launcher: ServiceLauncher
    private let fileManager: FileManager
    private var child: ServiceProcess?
    private var binaryMissing = false
    /// Bumped on every launch, so a termination handler left behind by an
    /// earlier child can never clear a later one.
    private var launchGeneration = 0

    /// Called on the main queue when the child this supervisor started exits on
    /// its own (crash, port conflict, quit of the daemon). The Store republishes
    /// its `serviceState` snapshot here, so the health line stops claiming
    /// « Service en marche » without waiting for an explicit start/stop.
    public var onChildExit: (() -> Void)?

    /// The one live supervisor, so AppKit's quit hook can stop the child
    /// without threading it through the SwiftUI scene.
    private static var current: ServiceSupervisor?

    public init(
        bundleURL: URL?,
        home: URL,
        userHome: URL,
        launcher: ServiceLauncher = FoundationServiceLauncher(),
        fileManager: FileManager = .default
    ) {
        self.bundleURL = bundleURL
        self.home = home
        self.userHome = userHome
        self.launcher = launcher
        self.fileManager = fileManager
    }

    /// Live state: derived from the child's own liveness, so the health line
    /// turns to "Service arrêté" the moment the child exits — it never claims a
    /// running service that is gone.
    public var state: State {
        if let child { return child.isRunning ? .running : .stopped }
        return binaryMissing ? .unavailable : .stopped
    }

    /// Launch the bundled service unless our child is already running. Returns
    /// the resulting state. `.unavailable` (no bundled binary) never launches.
    @discardableResult
    public func start() -> State {
        if let child, child.isRunning { return .running }
        guard let plan = BundledService.plan(
            bundleURL: bundleURL,
            home: home,
            userHome: userHome,
            fileManager: fileManager
        ) else {
            child = nil
            binaryMissing = true
            return .unavailable
        }
        binaryMissing = false
        do {
            let launched = try launcher.launch(plan)
            launchGeneration &+= 1
            let generation = launchGeneration
            child = launched
            launched.setTerminationHandler { [weak self] in
                self?.childExited(generation: generation)
            }
            Self.current = self
        } catch {
            child = nil
        }
        return state
    }

    /// The child we started is gone. Everything — the staleness check, the
    /// bookkeeping, the republish — happens on the main queue, so the published
    /// state never races the supervisor's own fields.
    private func childExited(generation: Int) {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.launchGeneration == generation, self.child != nil else { return }
            self.child = nil
            if Self.current === self { Self.current = nil }
            self.onChildExit?()
        }
    }

    /// Stop the child this supervisor started, if any. Safe to call twice.
    public func stop() {
        if let child, child.isRunning {
            child.terminate()
        }
        child = nil
        if Self.current === self { Self.current = nil }
    }

    /// The quit hook (`applicationWillTerminate`): stop the one live child.
    public static func stopCurrent() {
        current?.stop()
    }

    /// Test seam only: drop the app-wide handle without touching a process.
    public static func resetCurrentForTesting() {
        current = nil
    }
}

/// When the app may try to start the service it ships.
public enum BundledServicePolicy {
    /// `true` only when the service looks absent — never when a token exists
    /// but was refused: a live service wrote that token, and replacing it under
    /// the service's feet would break the running instance.
    ///
    /// `alreadyAttempted` is the app's once-per-episode guard, so a service that
    /// exits immediately (port already held) is never respawned in a loop.
    public static func shouldStart(cause: OfflineCause?, alreadyAttempted: Bool) -> Bool {
        guard !alreadyAttempted else { return false }
        switch cause {
        case .unreachable, .tokenMissing:
            return true
        case .tokenUnsafe, .keyRefused, nil:
            return false
        }
    }
}
