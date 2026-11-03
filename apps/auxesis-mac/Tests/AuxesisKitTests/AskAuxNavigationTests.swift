import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class AskAuxNavigationTests: XCTestCase {
    private func makeShell() -> (ShellModel, FixtureDaemon) {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        return (shell, daemon)
    }

    func testAskFieldSendsThroughStoreAndOpensAuxConversation() {
        let (shell, _) = makeShell()
        shell.submitAsk("  Check this locally  ")

        XCTAssertTrue(shell.conversationPresented)
        XCTAssertEqual(shell.conversationAgent, TeamMember.aux.id)
        XCTAssertEqual(shell.store.selectedAgentName, TeamMember.aux.id)
        XCTAssertTrue(shell.store.messages.contains { $0.author == .you && $0.text == "Check this locally" })
        XCTAssertEqual(shell.store.composerText, "")
    }

    func testEmptyAskOpensAuxConversationWithoutSending() {
        let (shell, _) = makeShell()
        shell.submitAsk("  \n ")

        XCTAssertTrue(shell.conversationPresented)
        XCTAssertEqual(shell.conversationAgent, TeamMember.aux.id)
        XCTAssertFalse(shell.store.isSendingMessage)
        XCTAssertFalse(shell.store.messages.contains { $0.author == .you })
    }

    func testSelectingAgentOpensConversationAndKeepsProfileInInspector() {
        let (shell, _) = makeShell()
        shell.go(.agentsAndRules)
        shell.openConversationFromAgents("mail")

        XCTAssertEqual(shell.route, .agentsAndRules)
        XCTAssertTrue(shell.conversationPresented)
        XCTAssertEqual(shell.conversationAgent, "mail")
        XCTAssertTrue(shell.inspectorOpen)
        XCTAssertTrue(ShellModel.SplitLayout.showsAgentProfileInInspector(
            for: shell.route, selectedAgent: "mail", conversationPresented: shell.conversationPresented
        ))
    }

    func testEnteringAgentsAndRulesOpensTheHighlightedAgentConversation() {
        let (shell, _) = makeShell()
        shell.go(.agentsAndRules)

        XCTAssertTrue(shell.openSelectedAgentConversationIfNeeded(TeamMember.aux.id))
        XCTAssertTrue(shell.conversationPresented)
        XCTAssertEqual(shell.conversationAgent, TeamMember.aux.id)
        XCTAssertTrue(shell.inspectorOpen)
        XCTAssertTrue(ShellModel.SplitLayout.showsAgentProfileInInspector(
            for: shell.route, selectedAgent: TeamMember.aux.id, conversationPresented: shell.conversationPresented
        ))
        let clearRequest = shell.agentSelectionClearRequest
        shell.closeConversation()
        XCTAssertEqual(shell.agentSelectionClearRequest, clearRequest + 1,
                       "returning to the list clears its selection so the detail can be empty")
    }

    func testEnteringRunningOpensTheHighlightedWorkingAgentConversation() {
        let (shell, _) = makeShell()
        _ = waitUntil { shell.workingAgents.contains("clients") }
        shell.go(.running)

        XCTAssertTrue(shell.workingAgents.contains("clients"))
        XCTAssertTrue(shell.openSelectedAgentConversationIfNeeded("clients"))
        XCTAssertTrue(shell.conversationPresented)
        XCTAssertEqual(shell.conversationAgent, "clients")
        XCTAssertTrue(shell.inspectorOpen)
    }

    func testEscapeClearsAskField() {
        let (shell, _) = makeShell()
        shell.askDraft = "draft"
        shell.escapeAskField()
        XCTAssertEqual(shell.askDraft, "")
    }

    func testAskBackRestoresAnExistingAgentConversation() {
        let (shell, _) = makeShell()
        shell.go(.agent("mail"))
        shell.submitAsk("Check this")
        XCTAssertEqual(shell.route, .today, "the detail pane stays available while Ask Aux is open")

        shell.closeConversation()

        XCTAssertEqual(shell.route, .agent("mail"))
        XCTAssertEqual(shell.store.selectedAgentName, "mail")
    }

    func testAskDuringARunKeepsTheDraft() {
        let (shell, _) = makeShell()
        shell.submitAsk("first")
        let busy = shell.store.isSendingMessage
        shell.askDraft = "second"
        shell.submitAsk("second")
        if busy {
            XCTAssertEqual(shell.askDraft, "second", "a send the store would drop must not clear the draft")
            XCTAssertFalse(shell.store.messages.contains { $0.author == .you && $0.text == "second" })
        } else {
            XCTAssertEqual(shell.askDraft, "")
        }
    }

    func testGoBackLeavesAnOpenConversationFirst() {
        let (shell, _) = makeShell()
        shell.go(.agent("mail"))
        shell.submitAsk("")
        XCTAssertTrue(shell.conversationPresented)
        shell.goBack()
        XCTAssertFalse(shell.conversationPresented)
        XCTAssertEqual(shell.route, .agent("mail"))
    }
}
