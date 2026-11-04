// The text a yes sends is always the text the card shows (EDIT-CANCEL-FIDELITY-1).
// Cancel, Undo, Not now and Stop drop an edit; a yes on the open editor sends
// exactly that edit; an edit made on another version of the draft is refused.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class EditFidelityTests: XCTestCase {
    private func makeShell() -> (ShellModel, FixtureDaemon, Approval) {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        let ask = shell.store.approvals.first { $0.id == "ap-camille" }!
        return (shell, daemon, ask)
    }

    private func runCountdown(_ shell: ShellModel) {
        for _ in 0..<ShellModel.undoSeconds { shell.tick() }
    }

    /// Editing Tuesday → Friday, Cancel, Send: the card shows
    /// Tuesday, so the daemon's own text must go, not Friday.
    func testCancelledEditIsNotWhatSendPosts() {
        let (shell, daemon, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.cancelEdit()
        XCTAssertEqual(shell.phase(for: ask), .open)
        XCTAssertTrue(shell.proposal(for: ask).body.contains("Hi Camille,"), "the card shows the original")

        shell.sendProposal(ask)
        runCountdown(shell)
        XCTAssertTrue(waitUntil { daemon.resolved.count == 1 })
        XCTAssertEqual(daemon.resolved.first?.decision, "allow_once", "the cancelled edit never goes")
        XCTAssertNil(daemon.resolved.first?.text)
    }

    /// The card's own Cancel button takes the same path.
    func testCardCancelDropsTheEdit() {
        let (shell, _, ask) = makeShell()
        shell.answer(.edit, for: ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.answer(.cancel, for: ask)
        XCTAssertNil(shell.editDrafts[ask.id])
        shell.answer(.edit, for: ask)
        XCTAssertEqual(shell.editDrafts[ask.id], shell.card(for: ask).editableText, "the editor reopens on the original")
    }

    func testUndoRestoresTheOriginalInTheCardAndInWhatSendPosts() {
        let (shell, daemon, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.sendProposal(ask)
        XCTAssertEqual(shell.queuedEdit(for: ask.id), "see you Friday", "the countdown shows the edit it will send")
        shell.undo(ask)
        XCTAssertEqual(shell.phase(for: ask), .open)
        XCTAssertNil(shell.queuedEdit(for: ask.id))
        XCTAssertNil(shell.editDrafts[ask.id])

        shell.sendProposal(ask)
        XCTAssertNil(shell.queuedEdit(for: ask.id))
        runCountdown(shell)
        XCTAssertTrue(waitUntil { daemon.resolved.count == 1 })
        XCTAssertEqual(daemon.resolved.first?.decision, "allow_once")
        XCTAssertNil(daemon.resolved.first?.text)
    }

    func testNotNowWhileEditingDropsTheEdit() {
        let (shell, daemon, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.notNow(ask)
        shell.reopen(ask)
        shell.sendProposal(ask)
        runCountdown(shell)
        XCTAssertTrue(waitUntil { daemon.resolved.count == 1 })
        XCTAssertNil(daemon.resolved.first?.text)
    }

    func testASavedEditIsTheExactTextSent() {
        let (shell, daemon, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.answer(.sendEdited, for: ask)
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: ShellModel.undoSeconds))
        XCTAssertEqual(shell.queuedEdit(for: ask.id), "see you Friday")
        runCountdown(shell)
        XCTAssertTrue(waitUntil { daemon.resolved.count == 1 })
        XCTAssertEqual(daemon.resolved.first?.decision, "edit")
        XCTAssertEqual(daemon.resolved.first?.text, "see you Friday")
    }

    /// An edit made on one version of the draft never goes on another.
    func testAnEditOnAStaleVersionIsRefusedAndNothingIsSent() {
        let (shell, daemon, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        let newer = Approval(
            id: ask.id, auditId: ask.auditId, agent: ask.agent, threadId: ask.threadId, ts: ask.ts,
            action: ask.action, headline: ask.headline, preview: ask.preview, fullPreview: ask.fullPreview,
            editPreview: "{\"body\":\"see you Monday\"}", detail: ask.detail, scopeTool: ask.scopeTool
        )
        shell.sendEdited(newer)
        XCTAssertEqual(shell.phase(for: newer), .failed)
        XCTAssertEqual(shell.store.approvalErrors[ask.id], L10n.t(.draftEditStale, .en))
        XCTAssertNil(shell.queuedEdit(for: ask.id))
        XCTAssertNil(shell.editDrafts[ask.id])
        runCountdown(shell)
        XCTAssertFalse(waitUntil(timeout: 0.5) { !daemon.resolved.isEmpty }, "nothing is sent without a yes on what is shown")
    }

    func testTheStaleEditCopyIsInEnglishAndFrench() {
        XCTAssertEqual(L10n.t(.draftEditStale, .en), "This draft changed since you edited it. Nothing was sent: edit it again.")
        XCTAssertEqual(L10n.t(.draftEditStale, .fr), "Ce brouillon a changé depuis ta modification. Rien n'est parti : modifie-le à nouveau.")
    }

    /// Every surface outside the editor reads one helper: in `.sending` with a
    /// queued edit it is the edit, never the text it replaced.
    func testTheSendingCardShowsWhatTheYesPosts() {
        let (shell, _, ask) = makeShell()
        XCTAssertEqual(shell.shownDraft(for: ask), ShownDraft(text: shell.card(for: ask).displayText, edited: false))
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.sendProposal(ask)
        XCTAssertEqual(shell.phase(for: ask), .sending(secondsLeft: ShellModel.undoSeconds))
        XCTAssertEqual(shell.shownDraft(for: ask), ShownDraft(text: "see you Friday", edited: true))
        shell.undo(ask)
        XCTAssertEqual(shell.shownDraft(for: ask).text, shell.card(for: ask).displayText)
    }

    /// Stop all cancels the countdowns before the daemon answers: a slow stop
    /// (15 s) never lets a tick post.
    func testASlowStopNeverLetsACountdownPost() {
        let (shell, daemon, ask) = makeShell()
        daemon.stopDelay = 15_000_000_000
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = "see you Friday"
        shell.sendProposal(ask)
        shell.stopAll()
        XCTAssertTrue(shell.stopInFlight)
        XCTAssertEqual(shell.phase(for: ask), .cancelledByStop, "cancelled at once, before the daemon answers")
        XCTAssertNil(shell.queuedEdit(for: ask.id))
        if let other = shell.store.approvals.first(where: { $0.id == "ap-jonas" }) {
            shell.sendProposal(other)
        }
        for _ in 0..<(ShellModel.undoSeconds + 2) { shell.tick() }
        XCTAssertFalse(waitUntil(timeout: 1) { !daemon.resolved.isEmpty }, "no approval is posted while the stop is on its way")
    }

    func testAWhitespaceLeftoverNeverBlocksSend() {
        let (shell, _, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = " \n"
        XCTAssertFalse(shell.canSendProposal(ask), "an empty open editor cannot send")
        shell.editing = nil
        XCTAssertTrue(shell.canSendProposal(ask), "a closed editor's leftover is not what goes")
    }
}
