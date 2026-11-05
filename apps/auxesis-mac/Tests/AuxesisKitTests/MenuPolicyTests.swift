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

    /// The table is the menu bar's copy: these are the chords the menu bound
    /// by hand before it moved here, so a rewrite cannot change the app.
    func testTheShortcutTableKeepsTheMenuBarChords() {
        let fixed = MenuShortcutTable.menu.filter { $0.action.agentSlot == nil }.map(\.display)
        XCTAssertEqual(fixed, ["⌘N", "⌘,", "⌘Q", "⌃⌘S", "⌘K", "⌘↩", "⌘D", "⌥⌘I", "⌘[", "⌘.", "⌘F"])
        XCTAssertEqual(MenuShortcutTable.agent(1)?.display, "⌘1")
        XCTAssertEqual(MenuShortcutTable.agent(9)?.display, "⌘9")
        XCTAssertNil(MenuShortcutTable.agent(10), "the Go menu stops at nine agents")
        XCTAssertEqual(GoMenu.agentItems(agents: allFive).map { $0.binding?.action }, [.goAgent1, .goAgent2, .goAgent3, .goAgent4, .goAgent5])
    }

    func testTheHelpSheetListsEveryMenuBarRowFromTheSameTable() {
        let fixed = MenuShortcutTable.menu.filter { $0.action.agentSlot == nil }.map(\.display)
        for agents in [[], [agent("main")], allFive] {
            let rows = MenuShortcuts.menu(agents: agents, language: .en).map(\.keys)
            let digits = GoMenu.agentItems(agents: agents).compactMap(\.shortcut)
            XCTAssertEqual(rows, Array(fixed.prefix(3)) + digits + Array(fixed.dropFirst(3)))
        }
    }

    func testNoTwoMenuBindingsShareAKeyAndModifiers() {
        var seen: [String: MenuAction] = [:]
        for binding in MenuShortcutTable.menu {
            let chord = "\(binding.modifiers.symbols)\(binding.key)"
            XCTAssertNil(seen[chord], "\(binding.action.rawValue) reuses \(chord)")
            seen[chord] = binding.action
        }
        let digits = MenuShortcutTable.menu.filter { $0.action.agentSlot != nil }
        XCTAssertEqual(digits.map(\.display), (1...9).map { "⌘\($0)" }, "⌘1…⌘9 belong to the agents")
    }

    /// Every view chord is read from a table. A raw `.keyboardShortcut` in a
    /// view is a chord the collision test below cannot see, so only the one
    /// bridge in `AuxesisMacApp.swift` may spell one out.
    func testEveryViewShortcutIsReadFromATable() throws {
        let tests = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let sources = tests.deletingLastPathComponent()
            .appendingPathComponent("Sources/AuxesisMac", isDirectory: true)
        let files = FileManager.default.enumerator(
            at: sources,
            includingPropertiesForKeys: nil
        )?.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" } ?? []
        XCTAssertFalse(files.isEmpty, "found no app sources at \(sources.path)")
        var offenders: [String] = []
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            for (index, line) in text.components(separatedBy: .newlines).enumerated() {
                guard line.contains(".keyboardShortcut("), file.lastPathComponent != "AuxesisMacApp.swift" else { continue }
                offenders.append("\(file.lastPathComponent):\(index + 1)")
            }
        }
        XCTAssertTrue(offenders.isEmpty, "bind these through the shortcut table: \(offenders)")
    }

    /// In-view chords may repeat across views (only the focused one fires), but
    /// none may shadow a menu-bar chord unless the table says it is deliberate.
    func testNoViewChordShadowsAMenuChordUnlessItIsTheSameAction() {
        // Deliberate overlaps, each with its reason:
        // - sendProposal is the same action: the proposal card's button and the
        //   menu item both call `shell.sendProposal`.
        // - sendMessage: while the composer has focus it owns ⌘↩; the menu's
        //   Send proposal needs a selected waiting card and is disabled otherwise,
        //   so the two never fire together.
        let allowed: [ViewAction: MenuAction] = [
            .sendProposal: .sendProposal,
            .sendMessage: .sendProposal,
        ]
        for view in ViewShortcutTable.all {
            guard let chord = view.key?.chord else { continue }
            for menu in MenuShortcutTable.menu
            where menu.key == chord.key && menu.modifiers == chord.modifiers {
                XCTAssertEqual(allowed[view.action], Optional(menu.action),
                               "\(view.action.rawValue) shadows menu \(menu.action.rawValue)")
            }
        }
    }

    /// The help sheet is the table's copy, row by row, in both languages.
    func testEveryHelpSheetRowMatchesItsTableEntryInEnglishAndFrench() {
        for language in [Language.en, .fr] {
            let agents = allFive
            let agentTitles = Set(GoMenu.agentItems(agents: agents).map { GoMenu.title(for: $0, language: language) })
            for row in MenuShortcuts.menu(agents: agents, language: language) {
                guard let binding = MenuShortcutTable.menu.first(where: { $0.display == row.keys }) else {
                    XCTFail("no menu table row prints \(row.keys)")
                    continue
                }
                if let title = binding.title(language) {
                    XCTAssertEqual(row.title, title, "\(language) \(row.keys)")
                } else {
                    XCTAssertTrue(agentTitles.contains(row.title), "\(language) \(row.keys) is not an agent title")
                }
            }
            for row in MenuShortcuts.inView(language: language) {
                guard let binding = ViewShortcutTable.help.first(where: { $0.display == row.keys }),
                      let copy = binding.help else {
                    XCTFail("no in-view table row prints \(row.keys)")
                    continue
                }
                XCTAssertEqual(row.title, copy.text(language), "\(language) \(row.keys)")
            }
        }
    }

    func testViewTableKeepsTheChordsViewsBoundByHand() {
        XCTAssertEqual(ViewShortcutTable.binding(for: .editClient).display, "⌘E")
        XCTAssertEqual(ViewShortcutTable.binding(for: .saveClient).display, "⌘S")
        XCTAssertEqual(ViewShortcutTable.binding(for: .cancelClientEdit).display, "Esc")
        XCTAssertEqual(ViewShortcutTable.binding(for: .cancelSend).display, "⌘Z")
        XCTAssertEqual(ViewShortcutTable.binding(for: .sendProposal).display, "⌘↩")
        XCTAssertEqual(ViewShortcutTable.binding(for: .sendMessage).display, "⌘↩")
        XCTAssertEqual(ViewShortcutTable.binding(for: .dismissSheet).display, "Esc")
        XCTAssertEqual(ViewShortcutTable.binding(for: .confirmSheet).display, "↩")
    }

    func testTheInViewHelpRowsKeepTheirCopy() {
        XCTAssertEqual(MenuShortcuts.inView(language: .en).map(\.keys), ["E", "↑ / ↓ · J / K", "↩", "Esc"])
        XCTAssertEqual(MenuShortcuts.inView(language: .en).map(\.title),
                       ["Edit proposal", "Move through waiting items", "Open selected row", "Leave editing"])
        XCTAssertEqual(MenuShortcuts.inView(language: .fr).map(\.title),
                       ["Modifier la proposition", "Parcourir les éléments en attente", "Ouvrir la ligne choisie", "Quitter la modification"])
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

        XCTAssertTrue(GoMenu.select(GoMenuItem(route: .agent(TeamMember.mail.id), binding: MenuShortcutTable.binding(for: .goAgent2)), hasMainWindow: true, in: shell))
        XCTAssertEqual(shell.route, .agent(TeamMember.mail.id))
        XCTAssertEqual(shell.selectedAgent, TeamMember.mail.id)

        let privacy = GoMenu.recordItems.first { $0.route == .privacyRecord }!
        XCTAssertTrue(GoMenu.select(privacy, hasMainWindow: true, in: shell))
        XCTAssertEqual(shell.route, .privacyRecord)
        XCTAssertNil(shell.selectedAgent)
    }

    func testGoMenuDoesNothingWithoutAMainWindow() {
        let shell = makeShell()
        XCTAssertFalse(GoMenu.select(GoMenuItem(route: .agent(TeamMember.aux.id), binding: MenuShortcutTable.binding(for: .goAgent1)), hasMainWindow: false, in: shell))
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
