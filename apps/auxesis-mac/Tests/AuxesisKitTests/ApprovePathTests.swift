// The yes path as the owner sees it: real states, one count, plain
// words only for mapped ids, no placeholder line, and Stop never loses a card.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ApprovePathTests: XCTestCase {
    private func ask(_ id: String, ts: Int64) -> Approval {
        Approval(id: id, auditId: 1, agent: "mail", threadId: "3", ts: ts, action: "run skill__follow-up",
                 headline: "Send follow-up to lea@example.test", fullPreview: "Hi Lea.",
                 detail: ["To: lea@example.test", "Subject: Re: quote"], scopeTool: "skill__follow-up", scopeRule: "ask")
    }

    private func started(_ approvals: [Approval]) -> (ShellModel, FakeTransport) {
        let transport = FakeTransport()
        transport.approvalsResult = .success(approvals)
        transport.agentsResult = .success([])
        let store = Store(transport: transport, language: .en)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.approvals.count == approvals.count })
        return (ShellModel(store: store, client: nil), transport)
    }

    func testADeclinedCardLeavesTheListAndTheNewCardIsTheOneShown() {
        let (shell, transport) = started([ask("ap-old", ts: 1)])
        guard let old = shell.store.approvals.first else { return XCTFail("the first card") }
        shell.store.focus("ap-old")
        transport.resolveResult = .success(.denied(by: "you"))
        shell.store.resolve(old, decision: .deny)
        XCTAssertTrue(waitUntil { shell.store.approvals.first?.state.isPending == false })

        transport.emit(.approvalNew(ask("ap-new", ts: 2)))
        XCTAssertTrue(waitUntil { shell.store.approvals.count == 2 })

        XCTAssertEqual(shell.waitingListApprovals.map(\.id), ["ap-new"], "the declined card is not listed as waiting")
        XCTAssertEqual(shell.store.focusedApprovalId, "ap-new", "the detail shows the card that waits, not the declined one")
        let new = shell.store.approvals[0], declined = shell.store.approvals[1]
        XCTAssertEqual([shell.proposal(for: declined).stateLabel, shell.proposal(for: new).stateLabel], ["Declined", "Waiting for you"])
        XCTAssertTrue(shell.canSendProposal(new) && !shell.proposal(for: declined).actions.send, "Send only on the card that waits")
        XCTAssertEqual(shell.rowStatus(for: new), "Waits for your yes")
    }

    func testARowNamesItsRealPhaseAndAnAllowedCardLeavesTheList() {
        let (shell, _) = started([ask("ap-a", ts: 2), ask("ap-b", ts: 1)])
        let first = shell.store.approvals[0], second = shell.store.approvals[1]
        shell.notNow(second)
        shell.approve(first)
        XCTAssertEqual(shell.rowStatus(for: first), "Sending in 10 s")
        XCTAssertEqual(shell.rowStatus(for: second), "Not now")
        XCTAssertEqual(shell.waitingListApprovals.count, 2, "the header counts the two rows listed")
        for _ in 0..<10 { shell.tick() }
        XCTAssertTrue(waitUntil { shell.store.approvals.first { $0.id == "ap-a" }?.state.isPending == false })
        XCTAssertEqual(shell.waitingListApprovals.map(\.id), ["ap-b"], "the allowed card is not listed as waiting")
    }

    func testSkillsToolsAndFieldsReadInPlainWords() {
        XCTAssertEqual(PlainLabel.field("apple_calendar_create_event.title"), "Event title")
        XCTAssertEqual(PlainLabel.field("apple_calendar_create_event.start_utc"), "Event start (UTC)")
        XCTAssertEqual(PlainLabel.field("apple_calendar_create_event.time_zone", language: .fr), "Fuseau horaire (événement)")
        XCTAssertEqual(PlainLabel.field("To", language: .fr), "À")
        XCTAssertEqual(PlainLabel.action("run skill__follow-up"), "Run “Follow-up” once, as shown")
        XCTAssertEqual(PlainLabel.action("run skill__send-invite", language: .fr), "Lancer « Invitation » une fois, tel qu’affiché")
        XCTAssertEqual(PlainLabel.action("run mail_send"), "Send this mail")
        // A calendar event with guests sends them invites: the label says so.
        XCTAssertEqual(PlainLabel.action("run google_calendar_create_event"), "Create this event and send its invites")
        XCTAssertEqual(PlainLabel.action("run apple_calendar_create_event", language: .fr), "Créer cet événement et envoyer les invitations")
        // A calendar move has its own words, in both languages.
        XCTAssertEqual(PlainLabel.action("run apple_calendar_update_event"), "Move this event")
        XCTAssertEqual(PlainLabel.action("run apple_calendar_update_event", language: .fr), "Déplacer cet événement")
        XCTAssertEqual(PlainLabel.action("run calendar_update_event"), "Move this event")
        XCTAssertEqual(PlainLabel.field("apple_calendar_update_event.title"), "Event title")
        XCTAssertEqual(PlainLabel.headline("Send send-invite to lea@example.test", tool: "skill__send-invite"),
                       "Send invite to lea@example.test")
    }

    /// An unlisted `send-email` could send more than "Send email" says: it stays visibly unknown.
    func testAnUnmappedToolIsShownAsUnknownWithItsRawId() {
        XCTAssertEqual(PlainLabel.action("run send-email", language: .fr), "Outil inconnu : send-email")
        XCTAssertEqual(PlainLabel.action("run skill__brand_new"), "Unknown tool: skill__brand_new")
        XCTAssertEqual(PlainLabel.field("brand_new_tool.some_key"), "brand_new_tool.some_key")
        let proposal = ProposalViewModel(approval: Approval(id: "ap-unknown", auditId: 4, agent: "mail", threadId: "3", ts: 1,
                                                            action: "run send-email", headline: "Send email", scopeTool: "send-email"))
        XCTAssertTrue(proposal.unknownTool)
        XCTAssertEqual(proposal.whatWillHappen, "Unknown tool: send-email", "never \"Send email\"")
        XCTAssertFalse(ProposalViewModel(approval: ask("ap-known", ts: 1)).unknownTool)
    }

    /// Stop cancels the countdowns; after Resume every card is listed and needs a new Send.
    func testStopThenResumeLeavesEveryPendingCardRecoverable() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        XCTAssertTrue(waitUntil { shell.store.approvals.count == 2 })
        let cards = shell.store.approvals
        for card in cards { shell.approve(card) }
        shell.stopAll()
        XCTAssertTrue(waitUntil { shell.stopped })
        shell.resumeAll()
        XCTAssertTrue(waitUntil { !shell.stopped && !shell.stopInFlight })
        for _ in 0..<12 { shell.tick() }
        XCTAssertEqual(Set(shell.waitingListApprovals.map(\.id)), Set(cards.map(\.id)), "every card is still listed")
        for card in cards {
            XCTAssertTrue(shell.store.approvals.first { $0.id == card.id }?.state.isPending == true, "Resume sent nothing")
            XCTAssertEqual(shell.phase(for: card), .cancelledByStop)
            XCTAssertEqual(shell.rowStatus(for: card), "Cancelled by Stop. Nothing was sent.")
            XCTAssertTrue(shell.canSendProposal(card), "Send is available again")
            shell.sendProposal(card)
            XCTAssertEqual(shell.phase(for: card), .sending(secondsLeft: 10), "a new Send starts a new countdown")
        }
    }

    func testTheInviteCardShowsNoRawLabelAndNoPlaceholderLine() {
        let invite = Approval(id: "ap-invite", auditId: 2, agent: "calendar", threadId: "4", ts: 1, action: "run skill__send-invite",
                              headline: "Send send-invite to lea@example.test", fullPreview: "Meeting tomorrow.",
                              detail: ["To: lea@example.test", "Subject: Meeting", "apple_calendar_create_event.title: Meeting",
                                       "apple_calendar_create_event.end_utc: 20261031T093000Z"], scopeTool: "skill__send-invite")
        let proposal = ProposalViewModel(approval: invite)
        XCTAssertEqual(proposal.title, "Send invite to lea@example.test")
        XCTAssertEqual(proposal.fields.map(\.label), ["To", "From", "Subject", "Event title", "Event end (UTC)"])
        XCTAssertTrue(proposal.leftThisMac == nil && proposal.stayedHere == nil)
        for line in [proposal.boundaryLine, proposal.grantLine, proposal.whatWillHappen] {
            XCTAssertFalse(line.lowercased().contains("unavailable") || line.contains("__"), line)
        }
        // A card with no mail line draws no empty mail rows.
        let event = Approval(id: "ap-event", auditId: 3, agent: "calendar", threadId: "4", ts: 1, action: "run apple_calendar_create_event",
                             headline: "Create event", detail: ["title: Focus"], scopeTool: "apple_calendar_create_event")
        XCTAssertEqual(ProposalViewModel(approval: event).fields.map(\.label), ["Title"])
    }
}
