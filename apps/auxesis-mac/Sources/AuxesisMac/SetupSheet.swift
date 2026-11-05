// First-launch setup: one row per macOS permission, a plain
// reason, a button and a live status. Nothing is asked until the owner clicks;
// Settings → General opens it again.
import AppKit
import ApplicationServices
import AuxesisKit
import SwiftUI
import UserNotifications

struct SetupSheet: View {
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model: SetupModel
    /// The auxd that actually runs (LaunchAgent, then the Auxesis home, then the bundle).
    /// The sandbox never reads the owner's LaunchAgents.
    private let diskBinary = SetupModel.fullDiskAccessBinary(
        userHome: EndpointResolver.isSandboxed(
            env: ProcessInfo.processInfo.environment,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            realHomeDirectory: EndpointResolver.osHomeDirectory())
            ? nil : EndpointResolver.osHomeDirectory() ?? FileManager.default.homeDirectoryForCurrentUser,
        auxesisHome: EndpointResolver.resolve(
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            realHomeDirectory: EndpointResolver.osHomeDirectory()).home,
        appBundle: Bundle.main.bundleURL)

    init(publish: @escaping (AppleEventKitSnapshot) async throws -> Void) {
        _model = StateObject(wrappedValue: SetupModel(provider: SystemPermissions(), onGranted: { permission in
            guard permission == .calendar,
                  let snapshot = try? await AppEnvironment.eventKit().readIfAuthorized(), snapshot.authorized else { return }
            try? await publish(snapshot.boundedAndCleaned())
        }))
    }

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 0) {
            Text(copy(.setupTitle)).font(.hk(Theme.Text.title, Theme.Weight.bold)).foregroundStyle(palette.ink.color)
            Text(copy(.setupLede)).font(.ui).foregroundStyle(palette.muted.color).lineSpacing(4)
                .fixedSize(horizontal: false, vertical: true).padding(.top, 6).padding(.bottom, 16)
            FormBox {
                ForEach(Array(SetupPermission.allCases.enumerated()), id: \.element) { index, permission in
                    FormRow(first: index == 0, title: copy(permission.copyKeys.title), detail: detail(permission, copy)) {
                        trailing(permission, copy)
                    }
                }
            }
            HStack {
                Spacer()
                Button(copy(.setupSkip)) { model.skip(); dismiss() }.buttonStyle(AuxButtonStyle(kind: .plain))
                    .accessibilityLabel(copy(.setupSkip)).accessibilityIdentifier("setup-skip")
                Button(copy(.setupDone)) { model.finish(); dismiss() }.buttonStyle(AuxButtonStyle(kind: .primary))
                    .viewShortcut(.confirmSheet)
                    .accessibilityLabel(copy(.setupDone)).accessibilityIdentifier("setup-finish")
            }
        }
        .padding(28)
        .frame(width: 620)
        .background(palette.work.color)
        .task { await model.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refresh() }
        }
    }

    private func detail(_ permission: SetupPermission, _ copy: Copy) -> String {
        let why = copy(permission.copyKeys.why)
        guard permission == .fullDiskAccess else { return why }
        guard let diskBinary else { return why + "\n" + copy(.setupDiskMissing) }
        return [why, copy.f(.setupDiskFile, diskBinary.path), copy(.setupDiskCheck)].joined(separator: "\n")
    }

    @ViewBuilder private func trailing(_ permission: SetupPermission, _ copy: Copy) -> some View {
        let state = model.state(permission)
        let permissionID = String(describing: permission)
            .replacingOccurrences(of: "([a-z0-9])([A-Z])", with: "$1-$2", options: .regularExpression)
            .lowercased()
        HStack(spacing: 8) {
            switch permission.action(for: state) {
            case .none:
                Label(copy(.setupAllowed), systemImage: "checkmark").font(.meta).foregroundStyle(palette.ink.color)
            case .ask:
                Button(copy(.setupAllow)) { Task { await model.press(permission) } }
                    .buttonStyle(AuxButtonStyle()).disabled(model.busy != nil)
                    .accessibilityLabel(copy(.setupAllow)).accessibilityIdentifier("setup-allow-\(permissionID)")
            case .openSystemSettings:
                if state == .denied {
                    Text(copy(.setupDenied)).font(.meta).foregroundStyle(palette.muted.color)
                }
                if permission == .fullDiskAccess, let diskBinary {
                    Button(copy(.setupShowFile)) { NSWorkspace.shared.activateFileViewerSelecting([diskBinary]) }
                        .buttonStyle(AuxButtonStyle(kind: .plain))
                        .accessibilityLabel(copy(.setupShowFile)).accessibilityIdentifier("setup-show-file")
                }
                Button(copy(.setupOpenSettings)) { Task { await model.press(permission) } }
                    .buttonStyle(AuxButtonStyle())
                    .accessibilityLabel(copy(.setupOpenSettings)).accessibilityIdentifier("setup-open-settings-\(permissionID)")
            }
        }
    }
}

private extension SetupPermission {
    var copyKeys: (title: UIKey, why: UIKey) {
        switch self {
        case .calendar: return (.setupCalendar, .setupCalendarWhy)
        case .notifications: return (.notifications, .setupNotificationsWhy)
        case .messages: return (.setupMessages, .setupMessagesWhy)
        case .fullDiskAccess: return (.setupDisk, .setupDiskWhy)
        }
    }
}

/// The real macOS calls. Only `request` can show a prompt, and only the setup
/// sheet's buttons reach it.
@MainActor final class SystemPermissions: PermissionProviding {
    private nonisolated static let messages = "com.apple.MobileSMS"
    private let calendar = AppEnvironment.eventKit()

    func state(of permission: SetupPermission) async -> PermissionState {
        switch permission {
        case .calendar:
            switch calendar.access {
            case .authorized: return .granted
            case .notDetermined: return .notYet
            case .denied, .restricted: return .denied
            }
        case .notifications:
            // UserNotifications needs a bundle; the bare debug binary has none.
            guard Bundle.main.bundleIdentifier != nil else { return .unknown }
            switch await UNUserNotificationCenter.current().notificationSettings().authorizationStatus {
            case .authorized, .provisional: return .granted
            case .notDetermined: return .notYet
            default: return .denied
            }
        case .messages:
            return await Self.automation(ask: false)
        case .fullDiskAccess:
            // The grant belongs to auxd, not to this app: macOS cannot tell us.
            return .unknown
        }
    }

    func request(_ permission: SetupPermission) async -> PermissionState {
        switch permission {
        case .calendar:
            _ = try? await calendar.requestAccessAndRead()
        case .notifications:
            guard Bundle.main.bundleIdentifier != nil else { return .unknown }
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        case .messages:
            // The prompt needs Messages running: open it in the background, never in front.
            if NSRunningApplication.runningApplications(withBundleIdentifier: Self.messages).isEmpty,
               await SystemOpener.launchMessagesHidden() {
                // Wait (about 3 s at most) until Messages answers, so one click is enough.
                var waits = 0
                while waits < 12, await Self.automationStatus(ask: false) == OSStatus(procNotFound) {
                    waits += 1
                    try? await Task.sleep(for: .milliseconds(250))
                }
            }
            return await Self.automation(ask: true)
        case .fullDiskAccess:
            break
        }
        return await state(of: permission)
    }

    func openSystemSettings(for permission: SetupPermission) {
        SystemOpener.openSettings(for: permission)
    }

    /// Asks macOS whether Auxesis may send Messages a read-only "get" event.
    /// No Apple Event is sent: this only checks, or with `ask` shows the prompt.
    private nonisolated static func automation(ask: Bool) async -> PermissionState {
        switch await automationStatus(ask: ask) {
        case noErr: return .granted
        case OSStatus(errAEEventNotPermitted): return .denied
        case OSStatus(errAECoercionFail): return .unknown
        default: return .notYet
        }
    }

    private nonisolated static func automationStatus(ask: Bool) async -> OSStatus {
        await Task.detached {
            var target = AEAddressDesc()
            let id = Array(messages.utf8)
            guard AECreateDesc(DescType(typeApplicationBundleID), id, id.count, &target) == noErr else {
                return OSStatus(errAECoercionFail)
            }
            defer { AEDisposeDesc(&target) }
            return AEDeterminePermissionToAutomateTarget(&target, AEEventClass(kCoreEventClass), AEEventID(kAEGetData), ask)
        }.value
    }
}
