import Foundation

/// The four macOS permissions on the first-launch setup screen. Nothing is
/// asked at launch: a prompt without context gets denied, and a denied
/// Calendar or Automation prompt never shows again.
public enum SetupPermission: String, CaseIterable {
    case calendar, notifications, messages, fullDiskAccess

    /// What the row's button does. macOS never lets an app ask for Full Disk Access.
    public func action(for state: PermissionState) -> SetupAction {
        if state == .granted { return .none }
        return state == .notYet && self != .fullDiskAccess ? .ask : .openSystemSettings
    }

    public var settingsURL: URL {
        let pane = [
            .calendar: "com.apple.preference.security?Privacy_Calendars",
            .notifications: "com.apple.Notifications-Settings.extension",
            .messages: "com.apple.preference.security?Privacy_Automation",
            .fullDiskAccess: "com.apple.preference.security?Privacy_AllFiles",
        ][self]!
        return URL(string: "x-apple.systempreferences:" + pane)!
    }
}

/// `unknown`: macOS does not tell this app (Full Disk Access belongs to auxd).
public enum PermissionState: Equatable { case granted, notYet, denied, unknown }

public enum SetupAction: Equatable { case ask, openSystemSettings, none }

/// The system seam. `state` only reads and never shows a prompt; `request` may.
@MainActor public protocol PermissionProviding: AnyObject {
    func state(of permission: SetupPermission) async -> PermissionState
    func request(_ permission: SetupPermission) async -> PermissionState
    func openSystemSettings(for permission: SetupPermission)
}

@MainActor public final class SetupModel: ObservableObject {
    public static let doneKey = "auxesis.setup.done"

    @Published public private(set) var states: [SetupPermission: PermissionState] = [:]
    @Published public private(set) var busy: SetupPermission?

    private let provider: PermissionProviding
    private let defaults: UserDefaults
    private let onGranted: (SetupPermission) async -> Void

    public init(
        provider: PermissionProviding,
        defaults: UserDefaults = .standard,
        onGranted: @escaping (SetupPermission) async -> Void = { _ in }
    ) {
        self.provider = provider
        self.defaults = defaults
        self.onGranted = onGranted
    }

    /// True until the owner presses Done or Skip once.
    public static func shouldShow(defaults: UserDefaults = .standard) -> Bool {
        !defaults.bool(forKey: doneKey)
    }

    public func state(_ permission: SetupPermission) -> PermissionState { states[permission] ?? .notYet }

    /// Reads every status. Never asks.
    public func refresh() async {
        for permission in SetupPermission.allCases {
            states[permission] = await provider.state(of: permission)
        }
    }

    /// The row's button: the only path to a system prompt.
    public func press(_ permission: SetupPermission) async {
        switch permission.action(for: state(permission)) {
        case .none: return
        case .openSystemSettings: provider.openSystemSettings(for: permission)
        case .ask:
            busy = permission
            defer { busy = nil }
            states[permission] = await provider.request(permission)
            if states[permission] == .granted { await onGranted(permission) }
        }
    }

    public func finish() { defaults.set(true, forKey: Self.doneKey) }
    public func skip() { finish() }

    public static let launchAgentLabel = "dev.auxesis.auxd"

    /// The binary that opens `~/Library/Messages/chat.db`: auxd, in-process
    /// (crates/auxd/src/main.rs `build_messages_gateway`; no helper is spawned,
    /// see docs/imessage.md). Full Disk Access must name the auxd that runs:
    /// 1. ProgramArguments[0] of the dev.auxesis.auxd LaunchAgent (read only),
    ///    when it is an executable named auxd;
    /// 2. else `<auxesis home>/bin/auxd`; 3. else the app's bundled auxd;
    /// 4. else `nil` ("no file to add yet"). `userHome` nil skips the LaunchAgent.
    public static func fullDiskAccessBinary(
        userHome: URL?, auxesisHome: URL, appBundle: URL, fileManager: FileManager = .default
    ) -> URL? {
        if let userHome,
           let data = fileManager.contents(atPath: userHome.appendingPathComponent(
               "Library/LaunchAgents/\(launchAgentLabel).plist").path),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let program = (plist["ProgramArguments"] as? [Any])?.first as? String, program.hasPrefix("/") {
            // Only an executable named auxd; anything else falls through to the next step.
            let url = URL(fileURLWithPath: program).resolvingSymlinksInPath()
            if url.lastPathComponent == "auxd", fileManager.isExecutableFile(atPath: url.path) { return url }
        }
        let installed = auxesisHome.appendingPathComponent("bin/auxd")
        if fileManager.isExecutableFile(atPath: installed.path) { return installed }
        return BundledService.resolvedBundledExecutable(
            appBundle.appendingPathComponent(BundledService.relativeExecutablePath), under: appBundle)
    }
}
