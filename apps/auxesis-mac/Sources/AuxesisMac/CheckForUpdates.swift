// H4 — the "Check for Updates…" menu command and the opt-in daily check.
// System alerts only: this slice ships no visual design.
import AppKit
import AuxesisKit

@MainActor
enum CheckForUpdates {
    /// Manual check by default; `silent` is the opt-in daily check.
    static func run(silent: Bool = false) {
        let preferences = UpdatePreferences()
        let updater = Updater.live(
            installedBuild: AppVersion.build,
            appVersion: AppVersion.short,
            handOff: { url in
                // Reveal only. Never open, mount, install or execute the dmg.
                NSWorkspace.shared.activateFileViewerSelecting([url])
            })
        Task {
            do {
                let result = try await updater.checkForUpdates()
                preferences.lastCheckAt = Date()
                switch result {
                case .upToDate:
                    if !silent { alert("Auxesis is up to date", "You are running the latest version.") }
                case .available(let update):
                    if !silent {
                        alert(
                            "Auxesis \(update.version) is ready",
                            "The disk image was downloaded and revealed in Finder. Open it to install.")
                    }
                }
            } catch {
                if !silent { alert("Update check failed", describe(error)) }
            }
        }
    }

    private static func describe(_ error: Error) -> String {
        switch error as? UpdateError {
        case .badSignature, .malformedManifest:
            return "The update manifest could not be trusted, so nothing was downloaded."
        case .insecureURL:
            return "The update feed is not secure (https is required)."
        case .unsupportedOS(let required, _):
            return "This update needs macOS \(required) or later."
        case .belowMinAllowedBuild:
            return "This update needs a newer version of Auxesis first."
        case .hashMismatch:
            return "The downloaded disk image did not match the signed checksum (it was deleted)."
        case .httpStatus(let code):
            return "The update server answered with status \(code)."
        case .network(let message):
            return message
        case nil:
            return "\(error)"
        }
    }

    private static func alert(_ title: String, _ body: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = body
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
