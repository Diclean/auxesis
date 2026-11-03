import Foundation

/// One Go-menu destination: an agent conversation (⌘1–⌘5) or a Records page
/// (no shortcut). The title is not stored here; it comes from `L10n` so EN and
/// FR stay in the app's one copy table.
public struct GoMenuItem: Equatable, Identifiable {
    public let route: ShellModel.Route
    public let shortcut: String?

    public init(route: ShellModel.Route, shortcut: String? = nil) {
        self.route = route
        self.shortcut = shortcut
    }

    public var id: String { GoMenu.identifier(for: route) }
}

public enum GoMenuEntry: Equatable, Identifiable {
    case item(GoMenuItem)
    case separator

    public var id: String {
        switch self {
        case .item(let item): return item.id
        case .separator: return "separator"
        }
    }

    public var item: GoMenuItem? {
        if case .item(let item) = self { return item }
        return nil
    }
}

/// The Go menu, in menu order. The five items above the separator are
/// the sidebar's order — Aux, then the four built-in agents — with ⌘1–⌘5. The
/// v5 shell's Records pages sit below it with no shortcut: they are pages, not
/// conversations, and never steal a key from an agent.
public enum GoMenu {
    public static let agentItems: [GoMenuItem] = TeamMember.all.enumerated().map { index, member in
        GoMenuItem(route: .agent(member.id), shortcut: "⌘\(index + 1)")
    }

    public static let recordItems: [GoMenuItem] = ShellModel.recordsMenu
        .flatMap { $0 }
        .map { GoMenuItem(route: $0) }

    public static let entries: [GoMenuEntry] =
        agentItems.map(GoMenuEntry.item) + [.separator] + recordItems.map(GoMenuEntry.item)

    public static func title(for item: GoMenuItem, language: Language) -> String {
        title(for: item.route, language: language)
    }

    public static func title(for route: ShellModel.Route, language: Language) -> String {
        switch route {
        case .agent(let id): return TeamMember.displayName(id)
        case .today: return L10n.ui(.today, language)
        case .calendar: return L10n.ui(.calPage, language)
        case .waiting: return L10n.ui(.waitingForYou, language)
        case .sinceYouLeft: return L10n.ui(.sinceYouLeft, language)
        case .running: return L10n.ui(.running, language)
        case .clients: return L10n.ui(.clients, language)
        case .documents: return L10n.ui(.documents, language)
        case .ledger: return L10n.ui(.ledger, language)
        case .money: return L10n.ui(.money, language)
        case .memory: return L10n.ui(.whatAuxKnows, language)
        case .privacyRecord: return L10n.ui(.privacyRecord, language)
        case .agentsAndRules: return L10n.ui(.agentsRules, language)
        }
    }

    /// The one routing function the Go menu uses: the same `shell.go` the
    /// sidebar's selection binding calls. A closed main window disables every
    /// item, and the action refuses too, so a stale shortcut cannot navigate.
    @discardableResult
    @MainActor
    public static func select(_ item: GoMenuItem, hasMainWindow: Bool, in shell: ShellModel) -> Bool {
        guard hasMainWindow else { return false }
        shell.go(item.route)
        return true
    }

    /// Stable id for VoiceOver, UI drivers and the entry list.
    public static func identifier(for route: ShellModel.Route) -> String {
        switch route {
        case .agent(let id): return "agent-\(id)"
        case .today: return "today"
        case .calendar: return "calendar"
        case .waiting: return "waiting"
        case .sinceYouLeft: return "since-you-left"
        case .running: return "running"
        case .clients: return "clients"
        case .documents: return "documents"
        case .ledger: return "ledger"
        case .money: return "money"
        case .memory: return "what-aux-knows"
        case .privacyRecord: return "privacy-record"
        case .agentsAndRules: return "agents-and-rules"
        }
    }
}

public struct ProposalMenuAvailability: Equatable {
    public let edit: Bool
    public let notNow: Bool

    public static func evaluate(
        hasSelection: Bool,
        isEditing: Bool,
        stopped: Bool,
        textFieldFocused: Bool
    ) -> ProposalMenuAvailability {
        ProposalMenuAvailability(
            edit: hasSelection && !isEditing && !stopped && !textFieldFocused,
            notNow: hasSelection && !stopped && !textFieldFocused
        )
    }
}

/// Printable navigation keys are handled only by the view that owns their action,
/// and never while the user is editing text.
public enum ApprovalKeyboardPolicy {
    public enum Key: Equatable {
        case editProposal
        case nextWaiting
        case previousWaiting
    }

    public enum Focus: Equatable {
        case approvalProposal
        case waitingList
        case other
    }

    public static func shouldHandle(
        _ key: Key,
        focus: Focus,
        textFieldFocused: Bool,
        editingThisProposal: Bool = false
    ) -> Bool {
        guard !textFieldFocused else { return false }
        switch key {
        case .editProposal:
            return focus == .approvalProposal && !editingThisProposal
        case .nextWaiting, .previousWaiting:
            return focus == .waitingList
        }
    }
}
