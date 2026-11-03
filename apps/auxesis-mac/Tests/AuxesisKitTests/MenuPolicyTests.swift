import XCTest
import AuxesisKit

@objcMembers @MainActor final class MenuPolicyTests: XCTestCase {
    private func makeShell() -> ShellModel {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        return shell
    }

    func testGoMenuListsTheAgentsInSidebarOrderWithCommandDigits() {
        XCTAssertEqual(GoMenu.agentItems.map(\.route), TeamMember.all.map { .agent($0.id) })
        XCTAssertEqual(GoMenu.agentItems.map(\.shortcut), ["⌘1", "⌘2", "⌘3", "⌘4", "⌘5"])
        XCTAssertEqual(
            GoMenu.agentItems.map { GoMenu.title(for: $0, language: .en) },
            ["Aux", "Mail", "Calendar", "Clients", "Documents"]
        )
    }

    func testGoMenuRecordsFollowASeparatorWithoutShortcuts() {
        let records = ShellModel.recordsMenu.flatMap { $0 }
        XCTAssertEqual(GoMenu.recordItems.map(\.route), records)
        XCTAssertTrue(GoMenu.recordItems.allSatisfy { $0.shortcut == nil })

        XCTAssertEqual(GoMenu.entries.count, GoMenu.agentItems.count + 1 + GoMenu.recordItems.count)
        XCTAssertEqual(GoMenu.entries[GoMenu.agentItems.count], .separator)
        XCTAssertEqual(GoMenu.entries.prefix(GoMenu.agentItems.count).compactMap(\.item), GoMenu.agentItems)
        XCTAssertEqual(GoMenu.entries.dropFirst(GoMenu.agentItems.count + 1).compactMap(\.item), GoMenu.recordItems)
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

        XCTAssertTrue(GoMenu.select(GoMenu.agentItems[1], hasMainWindow: true, in: shell))
        XCTAssertEqual(shell.route, .agent(TeamMember.mail.id))
        XCTAssertEqual(shell.selectedAgent, TeamMember.mail.id)

        let privacy = GoMenu.recordItems.first { $0.route == .privacyRecord }!
        XCTAssertTrue(GoMenu.select(privacy, hasMainWindow: true, in: shell))
        XCTAssertEqual(shell.route, .privacyRecord)
        XCTAssertNil(shell.selectedAgent)
    }

    func testGoMenuDoesNothingWithoutAMainWindow() {
        let shell = makeShell()
        XCTAssertFalse(GoMenu.select(GoMenu.agentItems[0], hasMainWindow: false, in: shell))
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
