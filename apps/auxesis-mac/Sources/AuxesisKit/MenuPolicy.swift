import Foundation

/// One Go-menu destination: an agent conversation (⌘1…) or a Records page
/// (no shortcut). A page title comes from `L10n` so EN and FR stay in the
/// app's one copy table; an agent item carries the name the sidebar shows.
public struct GoMenuItem: Equatable, Identifiable {
    public let route: ShellModel.Route
    public let shortcut: String?
    /// The agent's shown name (`display_name`, else its brand name).
    public let name: String?

    public init(route: ShellModel.Route, shortcut: String? = nil, name: String? = nil) {
        self.route = route
        self.shortcut = shortcut
        self.name = name
    }

    public var id: String { GoMenu.identifier(for: route) }
}

public enum GoMenuEntry: Equatable, Identifiable {
    case item(GoMenuItem)
    /// "Add an Agent…": opens the same sheet as the agents list.
    case addAgent
    case separator

    public var id: String {
        switch self {
        case .item(let item): return item.id
        case .addAgent: return "add-agent"
        case .separator: return "separator"
        }
    }

    public var item: GoMenuItem? {
        if case .item(let item) = self { return item }
        return nil
    }
}

/// The Go menu, in menu order. Above the separator: the agents that exist,
/// in the sidebar's order, the first nine with ⌘1–⌘9, then "Add an Agent…"
/// while a template is left. Below it: the Records pages, with no shortcut —
/// they are pages, not conversations, and never steal a key from an agent.
/// Until the daemon has listed its agents the menu shows the chief alone and
/// keeps its agent items disabled, so no shortcut can reach a missing agent.
public enum GoMenu {
    /// The daemon has not listed its agents yet (an install always has the chief).
    public static func loading(agents: [Agent]) -> Bool { agents.isEmpty }

    public static func agentItems(agents: [Agent]) -> [GoMenuItem] {
        let members = loading(agents: agents) ? [TeamMember.main] : TeamMember.roster(agents)
        return members.enumerated().map { index, member in
            GoMenuItem(route: .agent(member.id), shortcut: index < 9 ? "⌘\(index + 1)" : nil, name: member.name)
        }
    }

    /// A built-in template is not an agent yet.
    public static func canAddAgent(agents: [Agent]) -> Bool {
        let ids = Set(agents.map(\.id))
        return !loading(agents: agents) && TeamMember.domain.contains { !ids.contains($0.id) }
    }

    public static let recordItems: [GoMenuItem] = ShellModel.recordsMenu
        .flatMap { $0 }
        .map { GoMenuItem(route: $0) }

    /// While loading, "Add an Agent…" stays in place, disabled.
    public static func entries(agents: [Agent]) -> [GoMenuEntry] {
        let add: [GoMenuEntry] = loading(agents: agents) || canAddAgent(agents: agents) ? [.addAgent] : []
        return agentItems(agents: agents).map(GoMenuEntry.item) + add + [.separator] + recordItems.map(GoMenuEntry.item)
    }

    public static func title(for item: GoMenuItem, language: Language) -> String {
        item.name ?? title(for: item.route, language: language)
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

/// One line of Help ▸ Keyboard Shortcuts.
public struct MenuShortcut: Equatable {
    public let title: String
    public let keys: String
}

/// The shortcuts the app really binds, for the help sheet. `menu` mirrors
/// the menu bar (`TeamCommands`): ⌘1… belong to the Go menu's agents alone,
/// and the Records pages have no shortcut. `inView` are keys a view handles.
public enum MenuShortcuts {
    public static func menu(agents: [Agent], language: Language) -> [MenuShortcut] {
        let fr = language == .fr
        let go = GoMenu.agentItems(agents: agents).compactMap { item in
            item.shortcut.map { MenuShortcut(title: GoMenu.title(for: item, language: language), keys: $0) }
        }
        return [
            MenuShortcut(title: L10n.ui(.newConversation, language), keys: "⌘N"),
            MenuShortcut(title: L10n.ui(.settings, language) + "…", keys: "⌘,"),
            MenuShortcut(title: fr ? "Quitter Auxesis (les agents continuent)" : "Quit Auxesis (agents keep running)", keys: "⌘Q"),
        ] + go + [
            MenuShortcut(title: fr ? "Afficher ou masquer la barre latérale" : "Show or hide sidebar", keys: "⌃⌘S"),
            MenuShortcut(title: fr ? "Demander à Aux…" : "Ask Aux…", keys: "⌘K"),
            MenuShortcut(title: fr ? "Envoyer la proposition" : "Send proposal", keys: "⌘↩"),
            MenuShortcut(title: L10n.ui(.apNotNow, language), keys: "⌘D"),
            MenuShortcut(title: L10n.ui(.panelToggle, language), keys: "⌥⌘I"),
            MenuShortcut(title: L10n.ui(.back, language), keys: "⌘["),
            MenuShortcut(title: L10n.ui(.stopAll, language) + " / " + L10n.ui(.resume, language), keys: "⌘."),
            MenuShortcut(title: fr ? "Rechercher" : "Find", keys: "⌘F"),
        ]
    }

    public static func inView(language: Language) -> [MenuShortcut] {
        let fr = language == .fr
        return [
            MenuShortcut(title: fr ? "Modifier la proposition" : "Edit proposal", keys: "E"),
            MenuShortcut(title: fr ? "Parcourir les éléments en attente" : "Move through waiting items", keys: "↑ / ↓ · J / K"),
            MenuShortcut(title: fr ? "Ouvrir la ligne choisie" : "Open selected row", keys: "↩"),
            MenuShortcut(title: fr ? "Quitter la modification" : "Leave editing", keys: "Esc"),
        ]
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
