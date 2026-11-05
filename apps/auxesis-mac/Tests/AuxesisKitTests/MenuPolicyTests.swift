import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class MenuPolicyTests: XCTestCase {
    private func makeShell() -> ShellModel {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        return shell
    }

    private func agent(_ id: String, shown: String? = nil) -> Agent {
        Agent(id: id, name: id, hue: 0, glyph: "", state: .idle, status: "", threadKey: id, displayName: shown)
    }

    private var allFive: [Agent] { TeamMember.all.map { agent($0.id) } }

    func testWithFiveAgentsTheGoMenuListsThemInSidebarOrderWithCommandDigits() {
        let items = GoMenu.agentItems(agents: allFive.reversed())
        XCTAssertEqual(items.map(\.route), TeamMember.all.map { .agent($0.id) })
        XCTAssertEqual(items.map(\.shortcut), ["⌘1", "⌘2", "⌘3", "⌘4", "⌘5"])
        XCTAssertEqual(items.map { GoMenu.title(for: $0, language: .en) }, ["Aux", "Mail", "Calendar", "Clients", "Documents"])
        XCTAssertFalse(GoMenu.canAddAgent(agents: allFive), "no template is left")
        XCTAssertFalse(GoMenu.entries(agents: allFive).contains(.addAgent))
    }

    func testWithTheChiefAloneOnlyCommandOneExistsAndAddAnAgentIsOffered() {
        let agents = [agent("main", shown: "Aux")]
        let items = GoMenu.agentItems(agents: agents)
        XCTAssertEqual(items.map(\.route), [.agent("main")])
        XCTAssertEqual(items.map(\.shortcut), ["⌘1"])
        XCTAssertEqual(items.map { GoMenu.title(for: $0, language: .fr) }, ["Aux"])
        XCTAssertFalse(GoMenu.loading(agents: agents))
        XCTAssertTrue(GoMenu.canAddAgent(agents: agents))
        let entries = GoMenu.entries(agents: agents)
        XCTAssertEqual(Array(entries.prefix(3)), [.item(items[0]), .addAgent, .separator])
        XCTAssertEqual(L10n.ui(.addAgentMenu, .en), "Add an Agent…")
        XCTAssertEqual(L10n.ui(.addAgentMenu, .fr), "Ajouter un agent…")
    }

    func testNoShortcutLeadsToAMissingAgent() {
        let installs: [[Agent]] = [[], [agent("main")], [agent("main"), agent("calendar"), agent("documents")], allFive]
        for agents in installs {
            let existing = Set(agents.isEmpty ? [TeamMember.main.id] : agents.map(\.id))
            let shortcuts = GoMenu.entries(agents: agents).compactMap(\.item).filter { $0.shortcut != nil }
            for item in shortcuts {
                guard case .agent(let id) = item.route else { return XCTFail("a page has \(item.shortcut!)") }
                XCTAssertTrue(existing.contains(id), "\(item.shortcut!) leads to \(id)")
            }
            XCTAssertEqual(shortcuts.map(\.shortcut), (1...max(existing.count, 1)).map { "⌘\($0)" })
        }
        let three = GoMenu.agentItems(agents: [agent("documents"), agent("main"), agent("calendar")])
        XCTAssertEqual(three.map(\.route), [.agent("main"), .agent("calendar"), .agent("documents")])
    }

    func testWhileTheAgentsLoadTheMenuKeepsItsPlaceWithTheChiefAndAddAnAgent() {
        XCTAssertTrue(GoMenu.loading(agents: []))
        XCTAssertFalse(GoMenu.canAddAgent(agents: []))
        let entries = GoMenu.entries(agents: [])
        XCTAssertEqual(entries.compactMap(\.item).filter { $0.shortcut != nil }.map(\.route), [.agent(TeamMember.main.id)])
        XCTAssertTrue(entries.contains(.addAgent), "shown, and disabled by the menu while loading")
    }

    func testNoTwoMenuItemsShareAShortcutAndDigitsBelongToAgentsAlone() {
        for agents in [[], [agent("main")], allFive] {
            for language in [Language.en, .fr] {
                let keys = MenuShortcuts.menu(agents: agents, language: language).map(\.keys)
                XCTAssertEqual(keys.count, Set(keys).count, "a shortcut is bound twice: \(keys)")
            }
            let digits = MenuShortcuts.menu(agents: agents, language: .en).filter { $0.keys.dropFirst().allSatisfy(\.isNumber) && $0.keys.count == 2 }
            XCTAssertEqual(digits.map(\.title), GoMenu.agentItems(agents: agents).map { GoMenu.title(for: $0, language: .en) })
        }
        // The Clients and Documents pages share a name with their agents: check routes, not titles.
        let shortcuts = GoMenu.entries(agents: allFive).compactMap(\.item).filter { $0.shortcut != nil }
        XCTAssertTrue(shortcuts.allSatisfy { if case .agent = $0.route { return true } else { return false } }, "a Records page has no shortcut")
    }

    func testAddAnAgentWhileItsSheetIsOpenKeepsTheOpenSheet() {
        let shell = makeShell()
        XCTAssertTrue(shell.canAddAgents)
        shell.beginAddAgent()
        let open = shell.addingAgent
        XCTAssertNotNil(open)
        open?.selected = "documents"
        shell.beginAddAgent()
        XCTAssertTrue(shell.addingAgent === open, "a second call does not swap the open sheet")
        XCTAssertEqual(shell.addingAgent?.selected, "documents")
        shell.addingAgent = nil
        shell.beginAddAgent()
        XCTAssertNotNil(shell.addingAgent, "once closed it opens again")
        XCTAssertFalse(shell.addingAgent === open)
    }

    func testGoMenuRecordsFollowASeparatorWithoutShortcuts() {
        let records = ShellModel.recordsMenu.flatMap { $0 }
        XCTAssertEqual(GoMenu.recordItems.map(\.route), records)
        XCTAssertTrue(GoMenu.recordItems.allSatisfy { $0.shortcut == nil })

        let entries = GoMenu.entries(agents: allFive)
        XCTAssertEqual(entries.count, 5 + 1 + GoMenu.recordItems.count)
        XCTAssertEqual(entries[5], .separator)
        XCTAssertEqual(entries.dropFirst(6).compactMap(\.item), GoMenu.recordItems)
    }

    func testGoMenuTitlesFollowTheAppLanguage() {
        XCTAssertEqual(L10n.ui(.go, .en), "Go")
        XCTAssertEqual(L10n.ui(.go, .fr), "Aller")
        XCTAssertEqual(GoMenu.title(for: .waiting, language: .fr), "Vous attend")
        XCTAssertEqual(GoMenu.title(for: .sinceYouLeft, language: .fr), "Depuis votre départ")
        XCTAssertEqual(GoMenu.title(for: .agentsAndRules, language: .fr), "Agents et règles")
    }

    func testChoosingAGoItemSetsTheShellSelection() {
        let shell = makeShell()
        shell.go(.today)

        XCTAssertTrue(GoMenu.select(GoMenuItem(route: .agent(TeamMember.mail.id), shortcut: "⌘2"), hasMainWindow: true, in: shell))
        XCTAssertEqual(shell.route, .agent(TeamMember.mail.id))
        XCTAssertEqual(shell.selectedAgent, TeamMember.mail.id)

        let privacy = GoMenu.recordItems.first { $0.route == .privacyRecord }!
        XCTAssertTrue(GoMenu.select(privacy, hasMainWindow: true, in: shell))
        XCTAssertEqual(shell.route, .privacyRecord)
        XCTAssertNil(shell.selectedAgent)
    }

    func testGoMenuDoesNothingWithoutAMainWindow() {
        let shell = makeShell()
        XCTAssertFalse(GoMenu.select(GoMenuItem(route: .agent(TeamMember.aux.id), shortcut: "⌘1"), hasMainWindow: false, in: shell))
        XCTAssertEqual(shell.route, .today)
    }

    func testProposalMenuActionsRespectSelectionAndTextFocus() {
        let absent = ProposalMenuAvailability.evaluate(hasSelection: false, isEditing: false, stopped: false, textFieldFocused: false)
        XCTAssertFalse(absent.notNow)
        XCTAssertFalse(absent.edit)
        let available = ProposalMenuAvailability.evaluate(hasSelection: true, isEditing: false, stopped: false, textFieldFocused: false)
        XCTAssertTrue(available.notNow)
        XCTAssertTrue(available.edit)
        let focused = ProposalMenuAvailability.evaluate(hasSelection: true, isEditing: false, stopped: false, textFieldFocused: true)
        XCTAssertFalse(focused.notNow)
        XCTAssertFalse(focused.edit)
        XCTAssertFalse(ProposalMenuAvailability.evaluate(hasSelection: true, isEditing: true, stopped: false, textFieldFocused: false).edit)
        XCTAssertFalse(ProposalMenuAvailability.evaluate(hasSelection: true, isEditing: false, stopped: true, textFieldFocused: false).notNow)
    }

    func testApprovalPrintableKeysAreScopedToTheirViewAndNeverHandleTextInput() {
        XCTAssertTrue(ApprovalKeyboardPolicy.shouldHandle(.editProposal, focus: .approvalProposal, textFieldFocused: false))
        XCTAssertFalse(ApprovalKeyboardPolicy.shouldHandle(.editProposal, focus: .approvalProposal, textFieldFocused: true))
        XCTAssertFalse(ApprovalKeyboardPolicy.shouldHandle(.editProposal, focus: .approvalProposal, textFieldFocused: false, editingThisProposal: true))
        XCTAssertFalse(ApprovalKeyboardPolicy.shouldHandle(.editProposal, focus: .waitingList, textFieldFocused: false))

        XCTAssertTrue(ApprovalKeyboardPolicy.shouldHandle(.nextWaiting, focus: .waitingList, textFieldFocused: false))
        XCTAssertTrue(ApprovalKeyboardPolicy.shouldHandle(.previousWaiting, focus: .waitingList, textFieldFocused: false))
        XCTAssertFalse(ApprovalKeyboardPolicy.shouldHandle(.nextWaiting, focus: .waitingList, textFieldFocused: true))
        XCTAssertFalse(ApprovalKeyboardPolicy.shouldHandle(.previousWaiting, focus: .waitingList, textFieldFocused: true))
        XCTAssertFalse(ApprovalKeyboardPolicy.shouldHandle(.nextWaiting, focus: .approvalProposal, textFieldFocused: false))
    }
}

/// The fixture daemon serves no templates; here it lists none so the sheet can open.
extension FixtureDaemon: AgentTemplateClient {
    public func agentTemplates() async throws -> [AgentTemplate] { [] }
    public func createAgent(template: String) async throws {}
}
