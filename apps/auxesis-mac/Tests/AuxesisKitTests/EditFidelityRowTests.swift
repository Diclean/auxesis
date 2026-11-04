// The summary rows show the version a yes carries.
// While a countdown runs with an edit, the Today and Waiting rows name the
// edited recipient and the edited subject — the version the card will send —
// never the daemon's old headline. Cancel and Undo put the daemon's headline
// back; Not now snoozes the ask and drops only an open editor's edit.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class EditFidelityRowTests: XCTestCase {
    /// The owner's own text: the tool arguments as JSON, the only shape the
    /// daemon accepts as an edit (`crates/auxd/src/api/routes.rs:1632`). One
    /// `mail_send` is asked with its arguments flat — the account, the
    /// recipients, the subject (`crates/auxd/src/api/approval_preview.rs:188`).
    private let editedArguments = """
    {"account":"work","to":["nouvelle@exemple-sarl.test"],"subject":"Facture NW-2026-031 (rappel)"}
    """

    private func makeShell(_ language: Language = .en) -> (ShellModel, FixtureDaemon, Approval) {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: language), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        let ask = shell.store.approvals.first { $0.id == "ap-camille" }!
        return (shell, daemon, ask)
    }

    /// Edit, then say yes: the countdown runs with the edit queued.
    private func sendEdited(_ shell: ShellModel, _ ask: Approval) {
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = editedArguments
        shell.sendProposal(ask)
    }

    func testWithoutAnEditTheRowShowsTheDaemonHeadline() {
        let (shell, _, ask) = makeShell()
        XCTAssertEqual(shell.rowHeadline(for: ask), ask.headline,
                       "no edit: the row is the daemon's headline, as today")
    }

    func testWhileTheCountdownRunsTheRowShowsTheEditedRecipientAndSubject() {
        let (shell, _, ask) = makeShell()
        sendEdited(shell, ask)
        guard case .sending = shell.phase(for: ask) else {
            return XCTFail("the countdown runs")
        }
        let row = shell.rowHeadline(for: ask)
        XCTAssertTrue(row.contains("nouvelle@exemple-sarl.test"),
                      "the row shows the edited recipient: \(row)")
        XCTAssertTrue(row.contains("Facture NW-2026-031 (rappel)"),
                      "the row shows the edited subject: \(row)")
        XCTAssertFalse(row.contains("Camille Exemple"),
                       "the row never shows the recipient it replaced: \(row)")
        XCTAssertNotEqual(row, ask.headline, "the row is not the daemon's old headline")
    }

    func testUndoingTheYesPutsTheDaemonHeadlineBackInTheRow() {
        let (shell, _, ask) = makeShell()
        sendEdited(shell, ask)
        shell.undo(ask)
        XCTAssertNil(shell.queuedEdit(for: ask.id))
        XCTAssertEqual(shell.rowHeadline(for: ask), ask.headline,
                       "an undone yes goes back to the daemon's headline")
    }

    func testCancellingTheEditPutsTheDaemonHeadlineBackInTheRow() {
        let (shell, _, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = editedArguments
        shell.cancelEdit(ask)
        XCTAssertEqual(shell.rowHeadline(for: ask), ask.headline,
                       "a cancelled edit never reaches a row")
    }

    func testTheRowNamesTheEditedVersionInFrenchToo() {
        let (shell, _, ask) = makeShell(.fr)
        sendEdited(shell, ask)
        let row = shell.rowHeadline(for: ask)
        XCTAssertTrue(row.contains("\(L10n.ui(.apRowTo, .fr))nouvelle@exemple-sarl.test"),
                      "the French row names the edited recipient: \(row)")
        XCTAssertTrue(row.contains("\(L10n.ui(.apRowSubject, .fr))Facture NW-2026-031 (rappel)"),
                      "the French row names the edited subject: \(row)")
    }

    /// The daemon sends a skill's calls with their arguments under `real`
    /// (`crates/auxd/src/api/approval_preview.rs:492`) and reads only that
    /// one: the card it builds — and the one it will send — comes from it.
    /// The row must read it too. A call may also carry an `arguments` the
    /// daemon ignores, and naming that one would put a recipient in the row
    /// that never leaves the Mac.
    func testTheRowReadsTheRealArgumentsOfASkillCall() {
        let (shell, _, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = """
        {"calls":[{"tool":"mail_send","arguments":{"to":["decoy@x.test"],"subject":"Decoy"},"real":{"to":["real@x.test"],"subject":"Real"}}]}
        """
        shell.sendProposal(ask)
        let row = shell.rowHeadline(for: ask)
        XCTAssertEqual(row, "\(L10n.ui(.apRowTo, .en))real@x.test · \(L10n.ui(.apRowSubject, .en))Real",
                       "the row shows exactly the version the daemon sends")
        XCTAssertTrue(row.contains("real@x.test"),
                      "the row names the recipient the daemon sends: \(row)")
        XCTAssertTrue(row.contains("Real"),
                      "the row names the subject the daemon sends: \(row)")
        XCTAssertFalse(row.contains("decoy@x.test"),
                       "the row never names the arguments the daemon ignores: \(row)")
        XCTAssertFalse(row.contains("Decoy"),
                       "the row never names the arguments the daemon ignores: \(row)")
    }

    /// A skill's run is read only through its calls: a top-level `to` beside `calls` is ignored by
    /// the daemon's card, so the row must not name it either.
    func testTheRowIgnoresTopLevelFieldsBesideASkillsCalls() {
        let (shell, _, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = """
        {"to":["decoy@x.test"],"subject":"Decoy","calls":[{"tool":"mail_send","real":{"to":["real@x.test"],"subject":"Real"}}]}
        """
        shell.sendProposal(ask)
        let row = shell.rowHeadline(for: ask)
        XCTAssertFalse(row.contains("decoy@x.test"), "the row never names a top-level field beside calls: \(row)")
        XCTAssertTrue(row.contains("real@x.test"), "the row names the call's real recipient: \(row)")
    }

    /// A skill's run keeps its mail inside its calls, under `real` — the shape
    /// the daemon sends (`crates/auxd/src/api/approval_preview.rs:492`). The
    /// row names it: never the headline it replaced.
    func testTheRowReadsTheMailInsideASkillsCalls() {
        let (shell, _, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = """
        {"calls":[{"tool":"mail_send","real":{"to":["nouvelle@exemple-sarl.test"],"subject":"Facture"}}]}
        """
        shell.sendProposal(ask)
        let row = shell.rowHeadline(for: ask)
        XCTAssertTrue(row.contains("nouvelle@exemple-sarl.test"),
                      "the row names the edited recipient: \(row)")
        XCTAssertTrue(row.contains("Facture"),
                      "the row names the edited subject: \(row)")
        XCTAssertNotEqual(row, ask.headline, "the row is never the daemon's old headline")
    }

    /// An edit that names no recipient and no subject changed nothing the
    /// headline names: the row keeps the daemon's headline.
    func testAnEditWithoutARecipientKeepsTheDaemonHeadline() {
        let (shell, _, ask) = makeShell()
        shell.beginEdit(ask)
        shell.editDrafts[ask.id] = #"{"body":"a different body"}"#
        shell.sendProposal(ask)
        XCTAssertEqual(shell.rowHeadline(for: ask), ask.headline,
                       "the headline names no recipient and no subject: it is still the truth")
    }

    /// The countdown line (the thread's draft card and the Waiting detail)
    /// shows what the yes posts: the edited text, never the text it replaced.
    /// The Mac app is an executable target, so this is the view model's test:
    /// the helper the line reads is the one under test.
    func testTheCountdownLineShowsTheEditedTextWhileItCounts() {
        let (shell, _, ask) = makeShell()
        sendEdited(shell, ask)
        guard case .sending = shell.phase(for: ask) else {
            return XCTFail("the countdown runs")
        }
        XCTAssertEqual(shell.shownDraft(for: ask), ShownDraft(text: editedArguments, edited: true),
                       "the countdown line shows the edit it will send")
        XCTAssertNotEqual(shell.shownDraft(for: ask).text, shell.card(for: ask).displayText,
                          "the countdown line never shows the text the edit replaced")
    }

    /// One helper, every surface: the row and the countdown line read the
    /// same version, so they can never disagree about what a yes posts.
    func testTheRowAndTheCountdownLineReadTheSameVersion() {
        let (shell, _, ask) = makeShell()
        sendEdited(shell, ask)
        XCTAssertTrue(shell.rowHeadline(for: ask).contains("nouvelle@exemple-sarl.test"))
        XCTAssertEqual(shell.shownDraft(for: ask).text, editedArguments)
    }

    /// The row's field labels are the app's own copy, in both languages: the
    /// row never hard-codes "To" or "Objet".
    func testTheRowLabelsComeFromTheCopyTableInBothLanguages() {
        XCTAssertEqual(L10n.ui(.apRowTo, .en), "To: ")
        XCTAssertEqual(L10n.ui(.apRowTo, .fr), "À : ")
        XCTAssertEqual(L10n.ui(.apRowSubject, .en), "Subject: ")
        XCTAssertEqual(L10n.ui(.apRowSubject, .fr), "Objet : ")
    }

    /// Not now does not take back a yes that is already counting down: it
    /// snoozes the ask, and the edit the yes carries stays queued, so the row
    /// keeps naming it. Only Cancel and Undo put the daemon's headline back.
    func testNotNowDuringACountdownKeepsTheQueuedEditAndTheRowShowsIt() {
        let (shell, _, ask) = makeShell()
        sendEdited(shell, ask)
        shell.notNow(ask)
        XCTAssertEqual(shell.queuedEdit(for: ask.id), editedArguments,
                       "not now does not take back the queued edit")
        let row = shell.rowHeadline(for: ask)
        XCTAssertTrue(row.contains("nouvelle@exemple-sarl.test"),
                      "the row keeps naming the queued edit: \(row)")
    }
}
