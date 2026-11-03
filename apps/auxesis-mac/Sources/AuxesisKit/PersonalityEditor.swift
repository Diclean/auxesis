// The personality editor's state machine, kept out of the SwiftUI view so it
// is testable against the fake transport: load the agent's own text, count its
// bytes against the ceiling the daemon reports, save through `soul_md`, and
// never claim "saved" for a write that did not reach the service.
//
// The copy lives in `L10n`; this type only names *what happened* so the view
// can say it in the owner's language.
import Combine
import Foundation

/// What went wrong, in words the view turns into plain copy.
public enum PersonalityFailure: Equatable {
    /// The text is larger than the ceiling the daemon reported.
    case tooLong
    /// The read failed: the service is unreachable, too old, or the stored
    /// file is unreadable (the daemon refuses rather than showing a cut).
    case readFailed
    /// The save was refused or failed. The text stays in the editor.
    case saveFailed
}

/// Edits one agent's personality. One instance per selected agent; the view
/// recreates it when the selection changes.
@MainActor
public final class PersonalityEditor: ObservableObject {
    /// Where the editor is: idle before a load, ready with the text, saving,
    /// saved, or failed with an honest reason.
    public enum State: Equatable {
        case idle
        case loading
        case ready
        case saving
        case saved
        case failed(PersonalityFailure)
    }

    /// The text in the box. Bound to the view's `TextEditor`.
    @Published public var text: String = ""
    /// The last load/save outcome.
    @Published public private(set) var state: State = .idle
    /// The text as the service last confirmed it (empty until a load).
    public private(set) var savedText: String = ""
    /// Largest personality the service accepts, in bytes.
    public private(set) var maxBytes: Int = AgentSoul.builtInMaxBytes
    /// True when the agent has no written personality yet (built-in default).
    public private(set) var isDefault: Bool = false

    public init() {}

    /// UTF-8 size of the text as the service would store it.
    public var byteCount: Int { text.utf8.count }

    /// True when the text is past the ceiling: saving is refused with a clear
    /// message instead of being sent.
    public var isOverLimit: Bool { byteCount > maxBytes }

    /// Whether there is something to save right now.
    public var canSave: Bool {
        switch state {
        case .loading, .saving:
            return false
        default:
            return !isOverLimit && text != savedText
        }
    }

    /// Load the agent's current personality. `load` is the store's
    /// `agentSoul(name:)`; injected so the tests never touch a socket.
    public func load(_ load: () async throws -> AgentSoul) async {
        state = .loading
        do {
            let soul = try await load()
            text = soul.soulMd
            savedText = soul.soulMd
            maxBytes = soul.maxBytes > 0 ? soul.maxBytes : AgentSoul.builtInMaxBytes
            isDefault = soul.isDefault
            state = .ready
        } catch {
            state = .failed(Self.failure(for: error, reading: true))
        }
    }

    /// Save the text as it is. `save` is the store's `updateAgentSoul(name:soul:)`.
    public func save(_ save: (String) async throws -> Void) async {
        guard state != .saving else { return }
        guard !isOverLimit else {
            state = .failed(.tooLong)
            return
        }
        let pending = text
        state = .saving
        do {
            try await save(pending)
            savedText = pending
            isDefault = false
            state = .saved
        } catch {
            // The text stays in the box: nothing is thrown away on a failure.
            state = .failed(Self.failure(for: error, reading: false))
        }
    }

    /// Map a transport error to the one honest reason the view can say. A 413
    /// is the service refusing an oversized body: say "too long", not "try
    /// again" (retrying the same text can never work).
    static func failure(for error: Error, reading: Bool) -> PersonalityFailure {
        if let auxd = error as? AuxdError, case .http(let status, _) = auxd, status == 413 {
            return .tooLong
        }
        return reading ? .readFailed : .saveFailed
    }
}
