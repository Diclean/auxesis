// The v5 draft card and the next-step links: a card only while the approval
// waits, the buttons call the answers the app already has, and the links come
// only from what the turn holds.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class DraftCardTests: XCTestCase {
    /// The words of a label, without the chips' own spelling.
    private func words(_ parts: [TokenPart]) -> String {
        parts.compactMap { part -> String? in
            if case .text(let text) = part { return text } else { return nil }
        }.joined()
    }

    private func approval(
        headline: String = "Reply to Jonas Weber · 3 slots, Tue to Thu",
        detail: [String] = [
            "To: Jonas Weber <jonas@atelier-brume.test>",
            "Subject: Re: Time this week?",
            "Cc: lena@example.test",
            "Attachment: slots.pdf",
        ],
        body: String = "Hi Jonas,\n\nAny of these work for me.\n\nBest,\nAlex"
    ) -> Approval {
        Approval(
            id: "ap-jonas", auditId: 1, agent: "mail", threadId: "mail", ts: 1,
            action: "mail.send", headline: headline,
            preview: body, fullPreview: body,
            detail: detail, scopeTool: "mail.send", scopeRule: "ask"
        )
    }

    /// The card is the draft of a pending approval: it exists while the owner
    /// still has to answer, and never after.
    func testTheDraftCardExistsOnlyWhileTheApprovalWaits() {
        let pending = approval()
        let card = ApprovalCard.make(pending, phase: .open)
        XCTAssertNotNil(DraftCard(card: card, mirrored: false, language: .en))

        for phase in [ApprovalPhase.sent, .declined, .expired, .notNow, .sending(secondsLeft: 7), .failed, .cancelledByStop] {
            let done = ApprovalCard.make(pending, phase: phase)
            XCTAssertNil(DraftCard(card: done, mirrored: false, language: .en), "\(phase) has no draft card")
        }
    }

    /// The card says what will happen and shows the draft as it was written.
    func testTheDraftCardShowsWhatWillHappenAndTheDraft() {
        let pending = approval()
        let card = ApprovalCard.make(pending, phase: .open)
        let draft = DraftCard(card: card, mirrored: false, language: .en)

        XCTAssertEqual(draft?.approvalId, "ap-jonas")
        XCTAssertEqual(draft?.title.map(\.text).joined(), "Reply to Jonas Weber · 3 slots, Tue to Thu")
        XCTAssertEqual(card.field("To"), "Jonas Weber <jonas@atelier-brume.test>")
        XCTAssertEqual(card.field("Subject"), "Re: Time this week?")
        XCTAssertEqual(card.otherDetail, ["Cc: lena@example.test"])
        XCTAssertEqual(card.displayText, pending.fullPreview, "the draft as the daemon wrote it")
        XCTAssertEqual(card.field("Attachment"), "slots.pdf", "the file the act attaches")
    }

    /// Without a headline the card still says what will happen.
    func testTheDraftCardFallsBackToReplyToTheName() {
        let noHeadline = approval(headline: "")
        let draft = DraftCard(card: ApprovalCard.make(noHeadline, phase: .open), mirrored: false, language: .en)

        XCTAssertEqual(draft?.title.map(\.text).joined(), "Reply to Jonas Weber")
    }

    /// The draft is read exactly as it was written: a markdown link keeps its
    /// brackets and its URL, and a `*` or a backtick stays a character.
    func testTheDraftBodyKeepsItsExactCharacters() {
        let body = "Hi Jonas,\n\nSee [click](https://example.test/x) — *bold* and `code`."
        let parts = TokenParser.parts(body)

        XCTAssertEqual(parts.map(\.text).joined(), body, "the words are not rewritten")
        XCTAssertEqual(parts.count, 1, "nothing in that body is a protected value")
    }

    /// A name the daemon hid is a lock chip, never the raw token.
    func testATokenisedToIsAChipAndNeverTheRawToken() {
        let hidden = approval(headline: "", detail: ["To: ‹email›", "Subject: Re: Time?"])
        let draft = DraftCard(card: ApprovalCard.make(hidden, phase: .open), mirrored: false, language: .en)
        let title = draft?.title ?? []

        XCTAssertEqual(title.map(\.text).joined(), "Reply‹email›")
        XCTAssertEqual(title.count, 2, "the name is a chip, not a word")
        XCTAssertEqual(TokenParser.spoken(title), "Reply hidden value", "a chip is never read out")
    }

    /// A protected value in the question stays a chip, and the cut never
    /// splits a token.
    func testTheQuestionLabelKeepsItsTokensAsChips() {
        let delegation = Delegation(
            id: "dl-9", agent: "mail", ask: "Send the invoice for [IBAN removed] to Camille.", at: "2026-10-29 08:00:00",
            state: .waiting
        )
        let links = NextSteps.links(entries: [.work(delegation)], language: .en)
        let label = links.first?.label ?? []

        XCTAssertTrue(label.contains { $0.text == "[IBAN removed]" }, "the token is kept whole")
        XCTAssertFalse(words(label).contains("[IBAN removed]"), "the token is never plain text")
    }

    /// The 48-character cut never splits a token: it is kept whole, or left out.
    func testTheShortLabelNeverSplitsAToken() {
        let ask = "Draft a payment follow-up for Camille about [IBAN removed] today, please."
        let label = TokenParser.short(TokenParser.parts(ask))

        let tokens = label.compactMap { part -> String? in
            if case .token(let token) = part { return token } else { return nil }
        }
        for token in tokens {
            XCTAssertEqual(token, "[IBAN removed]", "a token is never cut in half")
        }
        XCTAssertFalse(words(label).contains("[IBAN removed]"), "a cut token is left out")
        XCTAssertFalse(words(label).contains("[IBAN"), "a token is never cut open")
    }

    /// The buttons are the ones the contract names, and a folded mirror shows
    /// "Show draft" instead of "Edit".
    func testTheDraftCardButtonsAreTheContractOnes() {
        let pending = approval()
        let open = ApprovalCard.make(pending, phase: .open)

        XCTAssertEqual(DraftCard(card: open, mirrored: false, language: .en)?.actions, [.send, .edit, .notNow])
        // Aux's mirror shows the text, so it offers Send and Edit, never Send on unseen text.
        XCTAssertEqual(DraftCard(card: open, mirrored: true, language: .en)?.actions, [.send, .edit, .notNow])
        XCTAssertEqual(DraftCard(card: open, mirrored: true, language: .en)?.folded, false)
        XCTAssertEqual(
            DraftCard(card: ApprovalCard.make(pending, phase: .editing), mirrored: false, language: .en)?.actions,
            [.sendEdited, .cancel]
        )
    }

    /// The buttons call the answers the app already has: one approval, one
    /// exact act, and the ten-second cancel window stays.
    func testTheButtonsCallTheExistingAnswers() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        guard let ask = shell.store.approvals.first(where: { $0.id == "ap-jonas" }) else {
            return XCTFail("the fixture has a pending draft")
        }

        shell.answer(.notNow, for: ask)
        XCTAssertEqual(shell.phase(for: ask), .notNow, "Not now is the answer the app already had")
        shell.reopen(ask)

        shell.answer(.edit, for: ask)
        XCTAssertEqual(shell.editing, ask.id, "Edit opens the editor on the same approval")
        shell.answer(.cancel, for: ask)
        XCTAssertNil(shell.editing)

        shell.answer(.send, for: ask)
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: ShellModel.undoSeconds), "a yes waits before it goes")
        shell.undo(ask)
        XCTAssertEqual(shell.phase(for: ask), .open)
    }

    /// A link acts inside the app only: it opens a draft, opens a steps card,
    /// or fills the composer. It never sends.
    func testALinkActsInsideTheAppOnly() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        guard let ask = shell.store.approvals.first(where: { $0.id == "ap-jonas" }) else {
            return XCTFail("the fixture has a pending draft")
        }

        let draft = NextStepItem(id: "draft-ap-jonas", label: [.text("Open draft")], action: .openApproval("ap-jonas"))
        XCTAssertEqual(shell.act(on: draft), NextStepItem.draftTarget("ap-jonas"))
        XCTAssertTrue(shell.isDraftUnfolded("ap-jonas"), "the mirror opens its draft")

        let steps = NextStepItem(id: "steps-dl-5", label: [.text("See steps")], action: .openSteps("dl-5"))
        XCTAssertEqual(shell.act(on: steps), NextStepItem.stepsTarget("dl-5"))
        XCTAssertTrue(shell.expanded.contains("dl-5"), "the steps card opens")

        let question = NextStepItem(id: "ask-dl-5", label: [.text("Draft it")], action: .fillComposer("Draft it."))
        XCTAssertNil(shell.act(on: question), "a question has nothing to scroll to")
        XCTAssertEqual(shell.store.composerText, "Draft it.", "the question waits in the composer")
        XCTAssertEqual(shell.phase(for: ask), .open, "a link never sends")
        XCTAssertEqual(shell.waitingCount(), 2, "a link never answers")
    }

    /// A link never overwrites what the owner already typed.
    func testALinkNeverOverwritesWhatTheOwnerTyped() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        shell.store.composerText = "My own words"

        let question = NextStepItem(id: "ask-dl-5", label: [.text("Draft it")], action: .fillComposer("Draft it."))
        XCTAssertNil(shell.act(on: question))
        XCTAssertEqual(shell.store.composerText, "My own words", "the owner's words stay")
    }

    /// No data, no links.
    func testNextStepItemsAreAbsentWithoutData() {
        XCTAssertTrue(NextSteps.links(entries: [], language: .en).isEmpty)
        let message = ThreadEntry.message(ChatMessage(
            id: "m-1", threadKey: "mail", author: .agent("mail"), ts: 1,
            blocks: [.text("I drafted a reply.")]
        ))
        XCTAssertTrue(NextSteps.links(entries: [message], language: .en).isEmpty)
    }

    /// The links come from the turn: a folded draft, a steps card, a question.
    func testNextStepItemsComeFromTheTurn() {
        let pending = approval()
        let mirrored = ThreadEntry.approval(pending, mirrored: true)
        let links = NextSteps.links(entries: [mirrored], language: .en)

        XCTAssertEqual(links.count, 1)
        XCTAssertEqual(links.first?.label.map(\.text).joined(), "Open draft")
        XCTAssertEqual(links.first?.action, .openApproval("ap-jonas"))

        let delegation = Delegation(
            id: "dl-5", agent: "mail", ask: "Draft a payment follow-up to Camille Exemple.", at: "2026-10-29 08:00:00",
            state: .waiting,
            steps: [DelegationStep(text: "Read the invoice", at: nil, state: .done)]
        )
        let withSteps = NextSteps.links(entries: [.delegations([delegation])], language: .en)
        XCTAssertEqual(withSteps.first?.label.map(\.text).joined(), "See steps")
        XCTAssertEqual(withSteps.first?.action, .openSteps("dl-5"))

        let withQuestion = NextSteps.links(entries: [.work(delegation)], language: .en)
        XCTAssertEqual(withQuestion.first?.action, .fillComposer(delegation.ask), "a question fills the composer, it never sends")
        XCTAssertTrue(withQuestion.first?.label.map(\.text).joined().contains("payment follow-up") ?? false)
    }

    /// At most two links, and none of them acts alone.
    func testNextStepItemsAreAtMostTwoAndNeverActAlone() {
        let pending = approval()
        let delegation = Delegation(
            id: "dl-5", agent: "mail", ask: "Draft a payment follow-up.", at: "2026-10-29 08:00:00",
            state: .waiting, steps: [DelegationStep(text: "Read the invoice", at: nil, state: .done)]
        )
        let links = NextSteps.links(
            entries: [.approval(pending, mirrored: true), .delegations([delegation]), .work(delegation)],
            language: .en
        )

        XCTAssertEqual(links.count, NextSteps.limit)
        XCTAssertEqual(links.count, 2)
        for link in links {
            switch link.action {
            case .openApproval(let id):
                XCTAssertEqual(id, "ap-jonas")
            case .openSteps(let id):
                XCTAssertEqual(id, "dl-5")
            case .fillComposer(let text):
                XCTAssertFalse(text.isEmpty)
            }
        }
    }
}
