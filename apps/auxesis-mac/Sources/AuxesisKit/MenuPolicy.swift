import Foundation

/// One Go-menu destination: an agent conversation (⌘1…) or a Records page
/// (no shortcut). A page title comes from `L10n` so EN and FR stay in the
/// app's one copy table; an agent item carries the name the sidebar shows.
public struct GoMenuItem: Equatable, Identifiable {
    public let route: ShellModel.Route
    /// The one table row behind the item's chord, if it has one.
    public let binding: MenuShortcutBinding?
    /// The agent's shown name (`display_name`, else its brand name).
    public let name: String?

    public init(route: ShellModel.Route, binding: MenuShortcutBinding? = nil, name: String? = nil) {
        self.route = route
        self.binding = binding
        self.name = name
    }

    /// The chord as the menu bar and the help sheet print it, e.g. "⌘1".
    public var shortcut: String? { binding?.display }

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
            GoMenuItem(route: .agent(member.id), binding: MenuShortcutTable.agent(index + 1), name: member.name)
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

/// Which modifier keys a menu binding holds, printed in macOS's order.
public struct MenuShortcutModifiers: OptionSet, Hashable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let control = MenuShortcutModifiers(rawValue: 1 << 0)
    public static let option = MenuShortcutModifiers(rawValue: 1 << 1)
    public static let shift = MenuShortcutModifiers(rawValue: 1 << 2)
    public static let command = MenuShortcutModifiers(rawValue: 1 << 3)

    /// "⌃⌥⇧⌘": the order the menu bar prints the symbols in.
    public var symbols: String {
        (contains(.control) ? "⌃" : "")
            + (contains(.option) ? "⌥" : "")
            + (contains(.shift) ? "⇧" : "")
            + (contains(.command) ? "⌘" : "")
    }
}

/// Every action the menu bar can bind. The raw value is the stable action id
/// the app and the tests use; the declaration order is the menu order.
public enum MenuAction: String, CaseIterable {
    case newConversation = "new-conversation"
    case settings
    case quit
    case goAgent1 = "go-agent-1"
    case goAgent2 = "go-agent-2"
    case goAgent3 = "go-agent-3"
    case goAgent4 = "go-agent-4"
    case goAgent5 = "go-agent-5"
    case goAgent6 = "go-agent-6"
    case goAgent7 = "go-agent-7"
    case goAgent8 = "go-agent-8"
    case goAgent9 = "go-agent-9"
    case toggleSidebar = "toggle-sidebar"
    case askAux = "ask-aux"
    case sendProposal = "send-proposal"
    case notNow = "not-now"
    case togglePanel = "toggle-panel"
    case back
    case stopAll = "stop-all"
    case find

    /// ⌘1…⌘9, in order.
    public static let goAgents: [MenuAction] = [
        .goAgent1, .goAgent2, .goAgent3, .goAgent4, .goAgent5,
        .goAgent6, .goAgent7, .goAgent8, .goAgent9,
    ]

    /// 1…9 for an agent digit, `nil` for every other action.
    public var agentSlot: Int? {
        Self.goAgents.firstIndex(of: self).map { $0 + 1 }
    }
}

/// What one key prints as, before modifiers: "↩" for Return, "Esc" for Escape.
private func printedKey(_ key: Character) -> String {
    switch key {
    case "\r": return "↩"
    case "\u{1b}": return "Esc"
    default: return String(key).uppercased()
    }
}

/// One row of the menu-bar shortcut table: an action id, its key and its
/// modifiers. This is the only place the app's menu chords are written down.
public struct MenuShortcutBinding: Equatable, Hashable {
    public let action: MenuAction
    public let key: Character
    public let modifiers: MenuShortcutModifiers

    public init(action: MenuAction, key: Character, modifiers: MenuShortcutModifiers) {
        self.action = action
        self.key = key
        self.modifiers = modifiers
    }

    /// "⌘N", "⌃⌘S", "⌘↩": what the menu bar and the help sheet show.
    public var display: String {
        modifiers.symbols + printedKey(key)
    }

    /// The help sheet's EN/FR text for this action. Agent digits return `nil`:
    /// `GoMenu` prints the live agent's name for those rows.
    public func title(_ language: Language) -> String? {
        let fr = language == .fr
        switch action {
        case .newConversation:
            return L10n.ui(.newConversation, language)
        case .settings:
            return L10n.ui(.settings, language) + "…"
        case .quit:
            return fr ? "Quitter Auxesis (les agents continuent)" : "Quit Auxesis (agents keep running)"
        case .goAgent1, .goAgent2, .goAgent3, .goAgent4, .goAgent5,
             .goAgent6, .goAgent7, .goAgent8, .goAgent9:
            return nil
        case .toggleSidebar:
            return fr ? "Afficher ou masquer la barre latérale" : "Show or hide sidebar"
        case .askAux:
            return fr ? "Demander à Aux…" : "Ask Aux…"
        case .sendProposal:
            return fr ? "Envoyer la proposition" : "Send proposal"
        case .notNow:
            return L10n.ui(.apNotNow, language)
        case .togglePanel:
            return L10n.ui(.panelToggle, language)
        case .back:
            return L10n.ui(.back, language)
        case .stopAll:
            return L10n.ui(.stopAll, language) + " / " + L10n.ui(.resume, language)
        case .find:
            return fr ? "Rechercher" : "Find"
        }
    }
}

/// The one list of the menu bar's chords. `TeamCommands` binds these rows and
/// `MenuShortcuts.menu` prints them, so the help sheet cannot drift from the
/// real menu. Agent digits are listed once here; `GoMenu` fills them with the
/// agents that exist.
public enum MenuShortcutTable {
    public static func binding(for action: MenuAction) -> MenuShortcutBinding {
        switch action {
        case .newConversation:
            return MenuShortcutBinding(action: action, key: "n", modifiers: .command)
        case .settings:
            return MenuShortcutBinding(action: action, key: ",", modifiers: .command)
        case .quit:
            return MenuShortcutBinding(action: action, key: "q", modifiers: .command)
        case .goAgent1:
            return MenuShortcutBinding(action: action, key: "1", modifiers: .command)
        case .goAgent2:
            return MenuShortcutBinding(action: action, key: "2", modifiers: .command)
        case .goAgent3:
            return MenuShortcutBinding(action: action, key: "3", modifiers: .command)
        case .goAgent4:
            return MenuShortcutBinding(action: action, key: "4", modifiers: .command)
        case .goAgent5:
            return MenuShortcutBinding(action: action, key: "5", modifiers: .command)
        case .goAgent6:
            return MenuShortcutBinding(action: action, key: "6", modifiers: .command)
        case .goAgent7:
            return MenuShortcutBinding(action: action, key: "7", modifiers: .command)
        case .goAgent8:
            return MenuShortcutBinding(action: action, key: "8", modifiers: .command)
        case .goAgent9:
            return MenuShortcutBinding(action: action, key: "9", modifiers: .command)
        case .toggleSidebar:
            return MenuShortcutBinding(action: action, key: "s", modifiers: [.control, .command])
        case .askAux:
            return MenuShortcutBinding(action: action, key: "k", modifiers: .command)
        case .sendProposal:
            return MenuShortcutBinding(action: action, key: "\r", modifiers: .command)
        case .notNow:
            return MenuShortcutBinding(action: action, key: "d", modifiers: .command)
        case .togglePanel:
            return MenuShortcutBinding(action: action, key: "i", modifiers: [.option, .command])
        case .back:
            return MenuShortcutBinding(action: action, key: "[", modifiers: .command)
        case .stopAll:
            return MenuShortcutBinding(action: action, key: ".", modifiers: .command)
        case .find:
            return MenuShortcutBinding(action: action, key: "f", modifiers: .command)
        }
    }

    /// Every menu-bar row, in menu order.
    public static var menu: [MenuShortcutBinding] {
        MenuAction.allCases.map { binding(for: $0) }
    }

    /// The digit row for 1…9; `nil` beyond nine agents.
    public static func agent(_ slot: Int) -> MenuShortcutBinding? {
        guard MenuAction.goAgents.indices.contains(slot - 1) else { return nil }
        return binding(for: MenuAction.goAgents[slot - 1])
    }
}

/// EN/FR text for one help-sheet row.
public struct ShortcutCopy: Equatable, Hashable {
    public let en: String
    public let fr: String

    public init(en: String, fr: String) {
        self.en = en
        self.fr = fr
    }

    public func text(_ language: Language) -> String {
        language == .fr ? fr : en
    }
}

/// A chord a view binds with `.keyboardShortcut`. It fires only while that
/// view has focus, so two views can reuse a key; the menu bar's chords stay in
/// `MenuShortcutTable`.
public enum ViewAction: String, CaseIterable {
    case editClient = "client-edit"
    case saveClient = "client-save"
    case cancelClientEdit = "client-edit-cancel"
    case cancelSend = "cancel-send"
    case sendProposal = "send-proposal"
    case sendMessage = "send-message"
    case dismissSheet = "dismiss-sheet"
    case confirmSheet = "confirm-sheet"
    case editProposal = "edit-proposal"
    case moveWaiting = "move-waiting"
    case openRow = "open-row"
    case leaveEditing = "leave-editing"

    /// The rows Help ▸ Keyboard Shortcuts prints, in order.
    public static let helpRows: [ViewAction] = [.editProposal, .moveWaiting, .openRow, .leaveEditing]
}

/// One key a view binds: a printable key with modifiers, or one of SwiftUI's
/// two symbolic sheet keys.
public enum ViewShortcutKey: Equatable, Hashable {
    case character(Character, MenuShortcutModifiers)
    case cancel
    case defaultAction

    /// What the help sheet prints for the key itself.
    public var display: String {
        switch self {
        case .character(let key, let modifiers): return modifiers.symbols + printedKey(key)
        case .cancel: return "Esc"
        case .defaultAction: return "↩"
        }
    }

    /// The key and modifiers this chord consumes, for collision tests.
    public var chord: (key: Character, modifiers: MenuShortcutModifiers) {
        switch self {
        case .character(let key, let modifiers): return (key, modifiers)
        case .cancel: return ("\u{1b}", [])
        case .defaultAction: return ("\r", [])
        }
    }
}

/// One row of the in-view table: the action, the key the view binds, and the
/// help copy when the sheet prints it.
public struct ViewShortcutBinding: Equatable, Hashable {
    public let action: ViewAction
    public let key: ViewShortcutKey?
    /// Set for a row printed as several keys (the waiting list's arrow/J/K pair).
    public let printedKeys: String?
    /// Help-sheet copy; `nil` when the sheet does not print this chord.
    public let help: ShortcutCopy?

    public init(
        action: ViewAction,
        key: ViewShortcutKey?,
        printedKeys: String? = nil,
        help: ShortcutCopy? = nil
    ) {
        self.action = action
        self.key = key
        self.printedKeys = printedKeys
        self.help = help
    }

    public var display: String { printedKeys ?? key?.display ?? "" }
}

/// The one list of chords views bind by hand, plus the printable keys the help
/// sheet lists. Views map these rows through `viewShortcut` in `AuxesisMacApp`.
public enum ViewShortcutTable {
    public static func binding(for action: ViewAction) -> ViewShortcutBinding {
        switch action {
        case .editClient:
            return ViewShortcutBinding(action: action, key: .character("e", .command))
        case .saveClient:
            return ViewShortcutBinding(action: action, key: .character("s", .command))
        case .cancelClientEdit:
            return ViewShortcutBinding(action: action, key: .cancel)
        case .cancelSend:
            return ViewShortcutBinding(action: action, key: .character("z", .command))
        case .sendProposal:
            return ViewShortcutBinding(action: action, key: .character("\r", .command))
        case .sendMessage:
            return ViewShortcutBinding(action: action, key: .character("\r", .command))
        case .dismissSheet:
            return ViewShortcutBinding(action: action, key: .cancel)
        case .confirmSheet:
            return ViewShortcutBinding(action: action, key: .defaultAction)
        case .editProposal:
            return ViewShortcutBinding(
                action: action, key: .character("e", []),
                help: ShortcutCopy(en: "Edit proposal", fr: "Modifier la proposition"))
        case .moveWaiting:
            return ViewShortcutBinding(
                action: action, key: nil, printedKeys: "↑ / ↓ · J / K",
                help: ShortcutCopy(en: "Move through waiting items", fr: "Parcourir les éléments en attente"))
        case .openRow:
            return ViewShortcutBinding(
                action: action, key: .defaultAction,
                help: ShortcutCopy(en: "Open selected row", fr: "Ouvrir la ligne choisie"))
        case .leaveEditing:
            return ViewShortcutBinding(
                action: action, key: .cancel,
                help: ShortcutCopy(en: "Leave editing", fr: "Quitter la modification"))
        }
    }

    /// Every in-view row, in declaration order.
    public static var all: [ViewShortcutBinding] { ViewAction.allCases.map { binding(for: $0) } }

    /// The rows Help ▸ Keyboard Shortcuts prints, in order.
    public static var help: [ViewShortcutBinding] { ViewAction.helpRows.map { binding(for: $0) } }
}

/// One line of Help ▸ Keyboard Shortcuts.
public struct MenuShortcut: Equatable {
    public let title: String
    public let keys: String
}

/// The shortcuts the app really binds, for the help sheet. Menu rows come from
/// `MenuShortcutTable` and in-view rows from `ViewShortcutTable`. ⌘1…⌘9 belong
/// to the Go menu's agents alone; the Records pages have no shortcut.
public enum MenuShortcuts {
    public static func menu(agents: [Agent], language: Language) -> [MenuShortcut] {
        let agentRows = GoMenu.agentItems(agents: agents).compactMap { item in
            item.shortcut.map { MenuShortcut(title: GoMenu.title(for: item, language: language), keys: $0) }
        }
        var rows: [MenuShortcut] = []
        var addedAgents = false
        for binding in MenuShortcutTable.menu {
            if binding.action.agentSlot != nil {
                // All nine digits share one place in the menu; the live roster
                // decides which of them exist.
                if !addedAgents {
                    rows += agentRows
                    addedAgents = true
                }
                continue
            }
            guard let title = binding.title(language) else { continue }
            rows.append(MenuShortcut(title: title, keys: binding.display))
        }
        return rows
    }

    public static func inView(language: Language) -> [MenuShortcut] {
        ViewShortcutTable.help.compactMap { binding in
            binding.help.map { MenuShortcut(title: $0.text(language), keys: binding.display) }
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
