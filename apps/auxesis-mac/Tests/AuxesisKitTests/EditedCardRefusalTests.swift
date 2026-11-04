// A refused edited card shows why, not a generic error.
//
// The daemon refuses an edited card with `409` and the code
// `edited_card_unshowable`, and a reason a person can act on ("bcc is not
// supported for mail_send"). The ask was never taken: the card stays open and
// editable, the reason is shown on it, and nothing is sent. Every other failure
// keeps the generic service error.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class EditedCardRefusalTests: XCTestCase {
    /// The daemon's own answer for an edited card that cannot be shown.
    private static let refusalBody = #"{"error":{"code":"edited_card_unshowable","message":"the edited arguments cannot be shown for approval: bcc is not supported for mail_send"}}"#

    /// The reason the daemon gives, without its own explanation.
    private static let reason = "bcc is not supported for mail_send"

    /// An edit that adds a `bcc` to an SMTP send: the daemon cannot show it.
    private static let editedDraft = #"{"to":["camille@exemple-sarl.test"],"bcc":["hidden@example.test"],"subject":"Invoice NW-2026-031"}"#

    private func makeShell(language: Language = .en) -> (ShellModel, FixtureDaemon, Approval) {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: language), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        let ask = shell.store.approvals.first { $0.id == "ap-camille" }!
        return (shell, daemon, ask)
    }

    /// Runs the ten-second yes window out, so the answer reaches the daemon.
    private func runCountdown(_ shell: ShellModel) {
        for _ in 0..<ShellModel.undoSeconds { shell.tick() }
    }

    /// Edits a card, sends the edit, and lets the daemon refuse it.
    private func sendARefusedEdit(
        _ shell: ShellModel, _ daemon: FixtureDaemon, _ ask: Approval, failure: AuxdError
    ) {
        daemon.resolveFailure = failure
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = Self.editedDraft
        shell.answer(.sendEdited, for: ask)
        runCountdown(shell)
        XCTAssertTrue(waitUntil { shell.store.approvalErrors[ask.id] != nil })
        // The card can be answered again once the daemon's state is re-read.
        XCTAssertTrue(waitUntil { shell.store.canAct(ask) })
    }

    /// The refused edit shows the daemon's reason, in the app's own words, and
    /// the card stays open and editable. Nothing was sent.
    func testARefusedEditShowsTheReasonAndKeepsTheCardEditable() {
        let (shell, daemon, ask) = makeShell()
        sendARefusedEdit(shell, daemon, ask, failure: .http(status: 409, body: Self.refusalBody))
        XCTAssertTrue(waitUntil { shell.phase(for: ask) == .editing }, "the card stays open")

        let message = shell.store.approvalErrors[ask.id] ?? ""
        XCTAssertTrue(message.contains(Self.reason), "the daemon's reason is shown: \(message)")
        XCTAssertTrue(
            message.contains("Edit the card or cancel"),
            "the app's own words wrap the reason: \(message)"
        )
        XCTAssertFalse(message.contains("service"), "not the generic service error: \(message)")

        // The card is still a draft card, still open and still editable.
        XCTAssertTrue(shell.phase(for: ask).isDraft, "the card stays open")
        XCTAssertEqual(shell.phase(for: ask), .editing, "the editor is open again")
        XCTAssertEqual(shell.editDrafts[ask.id], Self.editedDraft, "the owner's text is still there")
        XCTAssertTrue(shell.canSendProposal(ask), "the card can be answered again")
        XCTAssertTrue(shell.store.canAct(ask))
        // The reason is the card's own line, and only a refused card carries one.
        XCTAssertEqual(shell.store.refusalReason(for: ask), message)

        // Nothing was sent: the ask was never taken.
        XCTAssertTrue(daemon.resolved.isEmpty, "no answer reached the daemon")
        XCTAssertTrue(shell.store.approvals.first { $0.id == ask.id }?.state.isPending == true)
    }

    /// A broken service keeps today's behaviour: the generic error, and the
    /// card leaves the draft state.
    func testAServerErrorStillShowsTheGenericError() {
        let (shell, daemon, ask) = makeShell()
        sendARefusedEdit(shell, daemon, ask, failure: .http(status: 500, body: #"{"error":{"code":"internal","message":"boom"}}"#))

        XCTAssertEqual(shell.store.approvalErrors[ask.id], L10n.t(.serviceError, .en))
        XCTAssertTrue(shell.store.refusedEdits.isEmpty, "a broken service is not a refused card")
        XCTAssertNil(shell.store.refusalReason(for: ask), "no reason on the card")
        XCTAssertTrue(waitUntil { shell.phase(for: ask) == .failed }, "the card leaves the draft state")
        XCTAssertFalse(shell.canSendProposal(ask))
        XCTAssertTrue(daemon.resolved.isEmpty)
    }

    /// The refusal reads in English and in French, and the reason is the
    /// daemon's own words in both.
    func testTheRefusalCopyIsInEnglishAndFrench() {
        XCTAssertEqual(
            L10n.f(.draftEditRefused, .en, Self.reason),
            "This change can't be sent as shown: bcc is not supported for mail_send. Edit the card or cancel."
        )
        XCTAssertEqual(
            L10n.f(.draftEditRefused, .fr, Self.reason),
            "Cette modification ne peut pas partir telle quelle : bcc is not supported for mail_send. Modifie la carte ou annule."
        )

        let (english, englishDaemon, englishAsk) = makeShell(language: .en)
        sendARefusedEdit(english, englishDaemon, englishAsk, failure: .http(status: 409, body: Self.refusalBody))
        XCTAssertEqual(
            english.store.approvalErrors[englishAsk.id],
            L10n.f(.draftEditRefused, .en, Self.reason)
        )

        let (french, frenchDaemon, frenchAsk) = makeShell(language: .fr)
        sendARefusedEdit(french, frenchDaemon, frenchAsk, failure: .http(status: 409, body: Self.refusalBody))
        XCTAssertEqual(
            french.store.approvalErrors[frenchAsk.id],
            L10n.f(.draftEditRefused, .fr, Self.reason)
        )
    }

    /// Only a `409` with the daemon's own code is a refused card: another
    /// code, another status, keeps the generic error.
    func testOnlyTheDaemonsRefusalCodeIsAReason() {
        let refused = AuxdError.http(status: 409, body: Self.refusalBody)
        XCTAssertEqual(refused.editedCardRefusalReason, Self.reason)

        let otherCode = AuxdError.http(
            status: 409,
            body: #"{"error":{"code":"thread_busy","message":"the edited arguments cannot be shown for approval: bcc is not supported for mail_send"}}"#
        )
        XCTAssertNil(otherCode.editedCardRefusalReason)

        let otherStatus = AuxdError.http(
            status: 500,
            body: #"{"error":{"code":"edited_card_unshowable","message":"the edited arguments cannot be shown for approval: bcc is not supported for mail_send"}}"#
        )
        XCTAssertNil(otherStatus.editedCardRefusalReason)

        let noEnvelope = AuxdError.http(status: 409, body: "")
        XCTAssertNil(noEnvelope.editedCardRefusalReason)
    }

    /// The reason is plain text: it is never markdown and never a link.
    func testTheReasonIsPlainText() {
        let message = L10n.f(.draftEditRefused, .en, "[click me](https://example.test) **bold**")
        XCTAssertTrue(message.contains("[click me](https://example.test)"))
        XCTAssertTrue(message.contains("**bold**"), "the daemon's words are never rewritten")
    }
}
