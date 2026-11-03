// The offline screens' view-model: which pane wins while the service is not
// reachable, and the exact plain-language words + Terminal commands the window
// shows. Pure (no SwiftUI, no IO), so `swift test` covers it without a window.
import Foundation

/// Which top-level pane the window shows.
public enum ShellScreen: Equatable {
    case firstRun
    case offline
    case main
}

/// Everything the offline screen renders: the one plain sentence and the one
/// restart button that stay visible, plus the technical reason and the
/// copyable command(s) that live under the collapsed "details" disclosure.
public struct OfflineGuidance: Equatable {
    /// The single sentence the calm offline screen shows. Everything below it
    /// (title, detail, hint, notice, commands) is hidden until the owner opens
    /// the details.
    public let sentence: String
    /// The disclosure's title, shown in place of the hidden technical block.
    public let detailsTitle: String
    public let title: String
    public let detail: String
    public let hint: String
    public let terminalLabel: String
    public let commands: [String]
    /// The single button: it restarts the service (`Store.restart()`), never a
    /// bare "retry".
    public let retry: String
    /// Set when an AUXESIS_API_BASE/AUXESIS_API override was refused: one
    /// friendly sentence naming the env var, the refused host (never the full
    /// value) and the loopback address actually used.
    public let notice: String?
}

public enum ShellPresentation {
    /// Never a blank shell: while auxd has not answered yet (or answered with
    /// an error) and nothing ever loaded, the offline screen wins. Once content
    /// is on screen a later drop keeps the shell (the status line shows the
    /// trouble); first-run setup keeps its own screen (it has a live status and
    /// a "check again" button).
    public static func screen(
        firstRunKnown: Bool,
        firstRun: Bool,
        connection: Store.Connection,
        hasLoadedContent: Bool
    ) -> ShellScreen {
        switch connection {
        case .online:
            return firstRunKnown && firstRun ? .firstRun : .main
        case .connecting, .offline, .unauthorized:
            if !firstRunKnown { return .offline }
            if firstRun { return .firstRun }
            return hasLoadedContent ? .main : .offline
        }
    }
}

public enum OfflinePresentation {
    /// The service binary as a command the owner can paste into Terminal. A
    /// DMG install puts nothing on the PATH, so this is always the full path
    /// inside the app bundle — never the bare `auxd` a developer's shell has.
    public static var startServiceCommand: String {
        shellQuoted(L10n.embeddedServicePath)
    }

    /// A single value as one shell word: wrapped in single quotes only when the
    /// shell would otherwise split it or expand something in it. The installed
    /// path needs nothing, but a bundle copied somewhere with a space must not
    /// quietly become two arguments.
    static func shellQuoted(_ value: String) -> String {
        let literal = value.allSatisfy { $0.isLetter || $0.isNumber || "/._-+:@%=".contains($0) }
        guard !literal else { return value }
        return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// The one plain sentence on the offline screen: what happened, that
    /// nothing left the Mac, and what to do next. Technical wording lives only
    /// under the details disclosure.
    public static func offlineSentence(_ language: Language) -> String {
        switch language {
        case .fr: return "Le service s'est arrêté. Rien n'a été envoyé. Relance Auxesis, puis réessaie."
        case .en: return "The service stopped. Nothing was sent. Restart Auxesis, then try again."
        }
    }

    /// The disclosure that hides the copyable Terminal commands and the
    /// technical details, so the offline screen keeps one sentence and one
    /// button.
    public static func detailsTitle(_ language: Language) -> String {
        switch language {
        case .fr: return "Voir les détails"
        case .en: return "Show details"
        }
    }

    /// The single offline button. It restarts the service (`Store.restart()`),
    /// so the label names that action instead of a bare "retry".
    public static func restartLabel(_ language: Language) -> String {
        switch language {
        case .fr: return "Relancer Auxesis"
        case .en: return "Restart Auxesis"
        }
    }

    /// `nil` cause means "still connecting"; every failure path in `Store` sets
    /// a cause before going offline, so this never hides a real problem.
    public static func guidance(
        cause: OfflineCause?,
        language: Language,
        overrideRejection: EndpointOverrideRejection? = nil
    ) -> OfflineGuidance {
        let terminal = L10n.t(.offlineTerminalLabel, language)
        let retry = restartLabel(language)
        let details = detailsTitle(language)
        let notice = overrideRejection.map { overrideNotice($0, language: language) }
        switch cause {
        case nil:
            return OfflineGuidance(
                sentence: L10n.t(.connectingTitle, language),
                detailsTitle: details,
                title: L10n.t(.connectingTitle, language),
                detail: L10n.t(.connConnecting, language),
                hint: L10n.t(.offlineHint, language),
                terminalLabel: terminal,
                commands: [startServiceCommand],
                retry: retry,
                notice: notice
            )
        case .tokenMissing:
            return OfflineGuidance(
                sentence: offlineSentence(language),
                detailsTitle: details,
                title: L10n.t(.offlineTitle, language),
                detail: L10n.t(.offlineTokenMissing, language),
                hint: L10n.t(.offlineHintTokenMissing, language),
                terminalLabel: terminal,
                commands: [startServiceCommand],
                retry: retry,
                notice: notice
            )
        case .tokenUnsafe:
            return OfflineGuidance(
                sentence: offlineSentence(language),
                detailsTitle: details,
                title: L10n.t(.offlineTitle, language),
                detail: L10n.t(.offlineTokenUnsafe, language),
                hint: L10n.t(.offlineHintTokenUnsafe, language),
                terminalLabel: terminal,
                commands: ["chmod 600 ~/.auxesis/api.token", startServiceCommand],
                retry: retry,
                notice: notice
            )
        case .keyRefused:
            return OfflineGuidance(
                sentence: offlineSentence(language),
                detailsTitle: details,
                title: L10n.t(.offlineTitle, language),
                detail: L10n.t(.connUnauthorized, language),
                hint: L10n.t(.offlineHintKeyRefused, language),
                terminalLabel: terminal,
                commands: ["rm ~/.auxesis/api.token", startServiceCommand],
                retry: retry,
                notice: notice
            )
        case .unreachable(let reason):
            return OfflineGuidance(
                sentence: offlineSentence(language),
                detailsTitle: details,
                title: L10n.t(.offlineTitle, language),
                detail: L10n.f(.connOffline, language, reason),
                hint: L10n.t(.offlineHint, language),
                terminalLabel: terminal,
                commands: [startServiceCommand],
                retry: retry,
                notice: notice
            )
        }
    }

    /// The one-sentence notice for a refused override, in plain words. Names
    /// the env var, the refused host when there is one, and the loopback
    /// address actually used — never the full rejected value.
    public static func overrideNotice(_ rejection: EndpointOverrideRejection, language: Language) -> String {
        let fallback = "http://127.0.0.1:\(EndpointResolver.defaultPort)"
        if let host = rejection.host {
            return L10n.f(.overrideRejectedWithHost, language, rejection.source, host, fallback)
        }
        return L10n.f(.overrideRejectedPlain, language, rejection.source, fallback)
    }
}
