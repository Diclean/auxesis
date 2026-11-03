import AppKit
import AuxesisKit

/// The app's only calls to `NSWorkspace.shared.open…`, kept apart so the
/// rich-render gate can allow this one file. Both targets are fixed: a System
/// Settings pane from `SetupPermission.settingsURL` and Messages by bundle id.
/// Nothing here takes a URL or a path from text.
@MainActor enum SystemOpener {
    static func openSettings(for permission: SetupPermission) {
        NSWorkspace.shared.open(permission.settingsURL)
    }

    /// Launch Messages hidden, in the background. False when it is not installed.
    static func launchMessagesHidden() async -> Bool {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.MobileSMS") else {
            return false
        }
        let config = NSWorkspace.OpenConfiguration()
        config.activates = false
        config.hides = true
        _ = try? await NSWorkspace.shared.openApplication(at: url, configuration: config)
        return true
    }
}
