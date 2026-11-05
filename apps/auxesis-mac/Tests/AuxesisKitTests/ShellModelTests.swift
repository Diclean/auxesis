// The approval object's life in the shell, against the in-memory fixture
// daemon: a yes waits 10 seconds (Undo), Not now snoozes, Stop all cancels a
// pending send, and one id answered anywhere is answered everywhere.
// `tick()` drives the countdown so no test sleeps for ten seconds.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ShellModelTests: XCTestCase {
    private func makeShell(_ scenario: FixtureDaemon.Scenario = .team) -> (ShellModel, FixtureDaemon) {
        let daemon = FixtureDaemon(scenario: scenario)
        let store = Store(transport: daemon, language: .en)
        let shell = ShellModel(store: store, client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 && !shell.delegations.isEmpty }
        return (shell, daemon)
    }

    private func approval(_ shell: ShellModel, _ id: String) -> Approval? {
        shell.store.approvals.first { $0.id == id }
    }

    func testFixtureLoadsTheTeam() {
        let (shell, _) = makeShell()
        XCTAssertEqual(shell.store.approvals.count, 2)
        XCTAssertEqual(shell.waitingCount(), 2)
        XCTAssertEqual(shell.waitingCount(agent: "mail"), 2)
        XCTAssertEqual(shell.workingAgents, ["documents", "clients"])
    }

    func testPauseToggleStartsFromAgentStateAndRollsBackOnFailure() {
        let daemon = FixtureDaemon(scenario: .team)
        daemon.pausedAgents.insert("mail")
        daemon.pauseFailure = .http(status: 500, body: "fixture failure")
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.agents.contains { $0.id == "mail" } }

        XCTAssertTrue(shell.isPaused("mail"), "the toggle reads the agent's reported paused state")
        shell.setPaused("mail", false)
        XCTAssertFalse(shell.isPaused("mail"), "the toggle updates optimistically")
        XCTAssertTrue(waitUntil { shell.pauseFailures.contains("mail") })
        XCTAssertTrue(shell.isPaused("mail"), "a failed request restores the daemon-reported state")
        XCTAssertEqual(shell.pauseOverrides["mail"], true)
    }

    func testAgentProfileDetailUsesContractOrder() {
        XCTAssertEqual(AgentProfileSection.contractOrder, [.grants, .brain, .lastUse])
    }

    func testContractSidebarDestinationsStayInOrder() {
        XCTAssertEqual(ShellModel.sidebarSections.map(\.id), ["queue", "records", "agents"])
        XCTAssertEqual(
            ShellModel.sidebarSections.flatMap(\.destinations),
            [.today, .waiting, .sinceYouLeft, .clients, .documents, .money, .memory, .privacyRecord, .agentsAndRules]
        )
    }

    func testAgentsAndRulesKeepsTheThreeColumnDetailVisible() {
        XCTAssertFalse(ShellModel.SplitLayout.collapsesDetail(for: .agentsAndRules))
        XCTAssertTrue(ShellModel.SplitLayout.showsAgentProfileInInspector(
            for: .agentsAndRules, selectedAgent: "calendar", conversationPresented: false
        ))
        XCTAssertFalse(ShellModel.SplitLayout.showsAgentProfileInInspector(
            for: .agentsAndRules, selectedAgent: "notifications", conversationPresented: false
        ))
    }

    func testSidebarDestinationsNavigateToClientsAndDocuments() {
        let (shell, _) = makeShell()
        shell.go(.clients)
        XCTAssertEqual(shell.route, .clients)
        shell.go(.documents)
        XCTAssertEqual(shell.route, .documents)
    }

    func testAYesWaitsTenSecondsThenIsSent() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.approve(ask)
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: 10))
        XCTAssertEqual(shell.waitingCount(), 1, "a yes in flight leaves Waiting for you at once")
        for _ in 0..<9 { shell.tick() }
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: 1))
        XCTAssertTrue(approval(shell, "ap-camille")?.state.isPending ?? false, "nothing is sent before the end")
        shell.tick()
        XCTAssertTrue(waitUntil { self.approval(shell, "ap-camille")?.state.isPending == false })
        if let sent = approval(shell, "ap-camille") {
            XCTAssertEqual(shell.phase(for: sent), .sent)
            XCTAssertEqual(shell.card(for: sent).trailReached, 3)
        }
    }

    func testUndoInsideTheWindowSendsNothing() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.approve(ask)
        for _ in 0..<5 { shell.tick() }
        shell.undo(ask)
        for _ in 0..<12 { shell.tick() }
        XCTAssertEqual(shell.phase(for: ask), .open)
        XCTAssertTrue(approval(shell, "ap-camille")?.state.isPending ?? false)
        XCTAssertEqual(shell.waitingCount(), 2)
    }

    func testNotNowSnoozesAndReopenBringsItBack() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-jonas") else { return XCTFail("fixture approval") }
        shell.notNow(ask)
        XCTAssertEqual(shell.phase(for: ask), .notNow)
        XCTAssertEqual(shell.waitingCount(), 1)
        shell.reopen(ask)
        XCTAssertEqual(shell.phase(for: ask), .open)
        XCTAssertEqual(shell.waitingCount(), 2)
    }

    func testStopAllCancelsAPendingSend() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.approve(ask)
        shell.stopAll()
        XCTAssertTrue(waitUntil { shell.stopped })
        XCTAssertEqual(shell.phase(for: ask), .cancelledByStop)
        XCTAssertEqual(shell.cancelledSends, 1)
        for _ in 0..<12 { shell.tick() }
        XCTAssertTrue(approval(shell, "ap-camille")?.state.isPending ?? false, "nothing leaves while stopped")
        shell.approve(ask)
        XCTAssertEqual(shell.phase(for: ask), .cancelledByStop, "Send is refused while stopped")
        XCTAssertEqual(shell.row(for: .mail).line, "Paused by Stop")
        shell.resumeAll()
        XCTAssertTrue(waitUntil { !shell.stopped })
        shell.reopen(ask)
        XCTAssertEqual(shell.phase(for: ask), .open)
    }

    func testStoppedStateDisablesApprovalSendAction() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        XCTAssertTrue(shell.canSendProposal(ask))

        shell.stopAll()

        XCTAssertTrue(waitUntil { shell.stopped })
        XCTAssertFalse(shell.canSendProposal(ask), "the proposal Send action is disabled while stopped")
        shell.sendProposal(ask)
        XCTAssertTrue(approval(shell, "ap-camille")?.state.isPending ?? false, "Send does not resolve the approval")
    }

    func testOneIdIsOneObjectInEveryThread() {
        let (shell, _) = makeShell()
        let inChief = shell.approvals(inThreadOf: "aux").map(\.id)
        let inMail = shell.approvals(inThreadOf: "mail").map(\.id)
        let waiting = shell.waitingApprovals.map(\.id)
        XCTAssertEqual(Set(inChief), Set(inMail))
        XCTAssertEqual(Set(waiting), Set(inMail))
        guard let ask = approval(shell, "ap-jonas") else { return XCTFail("fixture approval") }
        shell.approve(ask)
        // The chief's mirror, Mail's thread and Waiting for you read one phase.
        XCTAssertEqual(shell.phase(for: shell.approvals(inThreadOf: "aux").first { $0.id == "ap-jonas" }!), .sending(secondsLeft: 10))
        XCTAssertFalse(shell.waitingApprovals.contains { $0.id == "ap-jonas" })
    }

    /// The editor holds the arguments as JSON; the card keeps showing what the
    /// daemon sent until the daemon rebuilds it from the edit.
    func testTheEditSendsTheEditedPayloadAndTheCardKeepsTheDaemonsText() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.beginEdit(ask)
        XCTAssertEqual(shell.phase(for: ask), .editing)
        XCTAssertTrue(shell.editDrafts[ask.id]?.contains("\"to\"") == true, "the editor holds the payload")
        shell.editDrafts[ask.id] = "{\"to\":[\"bob@example.test\"]}"
        shell.sendEdited(ask)
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: 10))
        XCTAssertNil(shell.editing)
        let proposal = shell.proposal(for: ask)
        XCTAssertTrue(proposal.body.contains("Hi Camille,"), "the card still shows the mail")
        XCTAssertTrue(proposal.boundaryLine.contains("to Camille Exemple <camille@exemple-sarl.test>"))
        XCTAssertTrue(proposal.boundaryLine.contains("Invoice NW-2026-031 and this text"))
        for _ in 0..<10 { shell.tick() }
        XCTAssertTrue(waitUntil { self.approval(shell, "ap-camille")?.state.isPending == false })
        guard let sent = approval(shell, "ap-camille") else { return XCTFail("sent approval") }
        XCTAssertEqual(shell.phase(for: sent), .sent)
        XCTAssertTrue(shell.proposal(for: sent).body.contains("Hi Camille,"))
        XCTAssertTrue(shell.proposal(for: sent).boundaryLine.contains("Invoice NW-2026-031 and this text"))
    }

    func testCancellingEditedSendRestoresWaitingWithTheOriginal() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "{\"to\":[\"bob@example.test\"]}"
        shell.sendProposal(ask)

        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: 10))
        shell.undo(ask)

        XCTAssertEqual(shell.phase(for: ask), .open)
        XCTAssertEqual(shell.waitingCount(), 2)
        XCTAssertNil(shell.editDrafts[ask.id], "Undo drops the edit: the card and the next Send are the daemon's text")
        XCTAssertTrue(shell.proposal(for: ask).body.contains("Hi Camille,"))
        XCTAssertTrue(shell.proposal(for: ask).boundaryLine.contains("Invoice NW-2026-031 and this text"))
    }

    func testSendCommandIsDisabledForInvalidEditAndDuringCountdown() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = " \n"
        XCTAssertFalse(shell.canSendProposal(ask))

        shell.editDrafts[ask.id] = "Edited message."
        XCTAssertTrue(shell.canSendProposal(ask))
        shell.sendProposal(ask)
        shell.sendProposal(ask)

        XCTAssertFalse(shell.canSendProposal(ask))
        XCTAssertNil(shell.selectedWaitingApproval, "a queued send is not a waiting selection")
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: 10), "re-entry must not start another countdown or POST")
    }

    func testSendShortcutOnlyActsOnTheWaitingPage() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.store.focus(ask.id)
        shell.go(.clients)
        XCTAssertNil(shell.selectedWaitingApproval, "⌘Return never sends an ask that is not on screen")
        shell.go(.waiting)
        XCTAssertEqual(shell.selectedWaitingApproval?.id, ask.id)
    }

    func testSendShortcutIsOffWhileAConversationCoversTheWaitingPage() {
        let (shell, _) = makeShell()
        guard let ask = approval(shell, "ap-camille") else { return XCTFail("fixture approval") }
        shell.go(.waiting)
        shell.store.focus(ask.id)
        XCTAssertEqual(shell.selectedWaitingApproval?.id, ask.id)

        shell.openConversation(agent: TeamMember.aux.id)
        XCTAssertEqual(shell.route, .waiting, "the page under the conversation stays Waiting")
        XCTAssertNil(shell.selectedWaitingApproval, "⌘Return in the composer must never send the hidden card")

        shell.closeConversation()
        XCTAssertEqual(shell.selectedWaitingApproval?.id, ask.id, "back on the page, the card is on screen again")
    }

    func testDelegationOpenAndReturnKeepsTheRow() {
        let (shell, _) = makeShell()
        shell.open(agent: "mail", fromDelegation: "dl-5")
        XCTAssertEqual(shell.route, .agent("mail"))
        XCTAssertEqual(shell.returnDelegation, "dl-5")
        shell.returnToChief()
        XCTAssertEqual(shell.route, .agent("aux"))
        XCTAssertTrue(shell.expanded.contains("dl-5"))
        XCTAssertNil(shell.returnDelegation)
    }

    func testReadsLoadFromTheFixture() {
        let (shell, _) = makeShell()
        shell.loadCoverage()
        shell.loadLedger()
        XCTAssertTrue(waitUntil { shell.coverage.value?.count == 53 && shell.ledger.value != nil })
        XCTAssertTrue(shell.ledger.value?.contains { $0.skillHash?.hasPrefix("sha256:") == true } ?? false)
    }

    /// The Today column was one read on appear, so a day
    /// that started empty stayed "Nothing has happened yet" while the day's
    /// runs streamed in as receipts. A finished run refreshes the ledger.
    func testTheLedgerPicksUpARunThatFinishesAfterItLoaded() {
        let daemon = FixtureDaemon(scenario: .team)
        daemon.ledgerEntries = []
        let store = Store(transport: daemon, language: .en)
        let shell = ShellModel(store: store, client: daemon)
        shell.start()
        XCTAssertTrue(waitUntil { store.phase == .live })
        shell.loadLedger()
        XCTAssertTrue(waitUntil { shell.ledger == .loaded([]) })

        daemon.ledgerEntries = [
            LedgerEntry(at: "2026-11-04 13:45:00", kind: "skill.action", agent: "clients",
                        summary: "Drafted the invoice reply to Camille")
        ]
        daemon.finishRun(Receipt(runId: "turn-1", agent: "clients", trigger: "owner_message"))
        XCTAssertTrue(waitUntil { shell.ledger.value?.count == 1 }, "the ledger refreshed when the run finished")
    }

    func testNoClientMeansUnavailableNotACrash() {
        let store = Store(transport: FixtureDaemon(), language: .en)
        let shell = ShellModel(store: store, client: nil)
        shell.loadCoverage()
        shell.loadLedger()
        XCTAssertEqual(shell.coverage, .unavailable)
        XCTAssertEqual(shell.ledger, .unavailable)
    }

    func testEmptyScenarioHasNoWaitingAndNoWork() {
        let daemon = FixtureDaemon(scenario: .empty)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.connection != .connecting }
        XCTAssertEqual(shell.waitingCount(), 0)
        XCTAssertTrue(shell.workingAgents.isEmpty)
    }

    /// The "Private" mark is green only when the brain is served from this
    /// Mac. Private mode alone says the text is tokenised, not where it ran.
    func testThePrivateMarkIsGreenOnlyForABrainOnThisMac() {
        func provider(_ id: String, model: String, baseURL: String) -> ProviderSummary {
            ProviderSummary(
                id: id, name: id, baseURL: baseURL, model: model,
                kind: "openai_compat", keyLocation: "none",
                keyPresent: false, keyRequired: false, keyError: nil, lastTest: ""
            )
        }
        let cloud = provider("deepseek", model: "deepseek-flash", baseURL: "https://api.deepseek.com/v1")
        let local = provider("ollama", model: "llama3.1", baseURL: "http://127.0.0.1:11434/v1")

        XCTAssertFalse(BrainPlace.isOnThisMac("deepseek-flash", providers: [cloud]))
        XCTAssertTrue(BrainPlace.isOnThisMac("llama3.1", providers: [local]))
        XCTAssertTrue(BrainPlace.isOnThisMac("ollama", providers: [local]))
        XCTAssertFalse(BrainPlace.isOnThisMac("llama3.1", providers: []))
        XCTAssertFalse(BrainPlace.isOnThisMac("unknown", providers: [local]))
        XCTAssertFalse(BrainPlace.isOnThisMac(nil, providers: [local]))
        XCTAssertFalse(BrainPlace.isOnThisMac("llama3.1", providers: [local, local]),
                       "an ambiguous provider is never called local")
        for lookalike in ["http://127.0.0.1.evil.com/v1", "http://localhost.example.com/v1",
                          "http://user@127.0.0.1@evil.com/v1", "http://evil.com\\@127.0.0.1/v1", "http:///v1", ""] {
            let fake = provider("fake", model: "m", baseURL: lookalike)
            XCTAssertFalse(BrainPlace.isOnThisMac("m", providers: [fake]), "\(lookalike) is not this Mac")
        }
    }
}
