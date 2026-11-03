// An edited skill-run card never shows the run's payload (2026-10-30):
// the editor holds the text of the run's one send, the edited card shows that
// text, and the yes posts the run rebuilt from the version the owner edited.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class RunEditTests: XCTestCase {
    private static let run = #"{"skill":"follow-up","skill_version":1,"skill_hash":"971d0c","level":"ask","calls":[{"tool":"mail_send","real":{"to":["lea@example.test"],"subject":"Re: quote","body":"Hi Lea, following up."},"model_saw":{"to":["⟦EMAIL_1⟧"]}}]}"#

    private func ask(editPreview: String) -> Approval {
        Approval(id: "ap-run", auditId: 1, agent: "mail", threadId: "3", ts: 1, action: "run skill__follow-up",
                 headline: "Send follow-up to lea@example.test", fullPreview: "Hi Lea, following up.",
                 editPreview: editPreview, detail: ["To: lea@example.test", "Subject: Re: quote"],
                 scopeTool: "skill__follow-up", scopeRule: "ask")
    }

    private func started(_ approval: Approval) -> (ShellModel, FakeTransport) {
        let transport = FakeTransport()
        transport.approvalsResult = .success([approval])
        transport.agentsResult = .success([])
        let store = Store(transport: transport, language: .en)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live && store.approvals.count == 1 })
        return (ShellModel(store: store, client: nil), transport)
    }

    func testTheEditedRunCardShowsTheTextAndPostsTheRebuiltRun() throws {
        let (shell, transport) = started(ask(editPreview: Self.run))
        let card = shell.store.approvals[0]
        shell.beginEdit(card)
        XCTAssertEqual(shell.editDrafts[card.id], "Hi Lea, following up.", "the editor holds the text, not the run")
        shell.editDrafts[card.id] = "Edited by the owner."
        shell.sendProposal(card)
        let shown = shell.shownDraft(for: card)
        XCTAssertTrue(shown.edited)
        XCTAssertEqual(shown.text, "Edited by the owner.")
        for text in [shown.text, shell.rowHeadline(for: card)] {
            XCTAssertFalse(text.contains("{\""), "no payload on screen: \(text)")
            XCTAssertFalse(text.contains("skill_hash"), "no payload on screen: \(text)")
        }

        for _ in 0..<ShellModel.undoSeconds { shell.tick() }
        XCTAssertTrue(waitUntil { transport.resolveTexts.count == 1 })
        let posted = try XCTUnwrapOptional(transport.resolveTexts.first ?? nil)
        let run = try XCTUnwrapOptional(JSONSerialization.jsonObject(with: Data(posted.utf8)) as? [String: Any])
        XCTAssertEqual(run["skill_hash"] as? String, "971d0c", "the run goes back whole")
        let call = try XCTUnwrapOptional((run["calls"] as? [[String: Any]])?.first)
        let real = try XCTUnwrapOptional(call["real"] as? [String: Any])
        XCTAssertEqual(real["body"] as? String, "Edited by the owner.")
        XCTAssertEqual(real["to"] as? [String], ["lea@example.test"])
        XCTAssertEqual(call["tool"] as? String, "mail_send")
    }

    func testARunWithNoSingleTextHasNothingToEdit() {
        let two = #"{"skill":"x","calls":[{"tool":"mail_send","real":{"body":"a"}},{"tool":"mail_send","real":{"body":"b"}}]}"#
        for payload in [#"{"skill":"x","calls":[]}"#, two] {
            let card = ApprovalCard.make(ask(editPreview: payload), phase: .open)
            XCTAssertEqual(card.editorText, "", "a run never puts its payload in the editor")
            XCTAssertEqual(RunEdit.posted("t", base: payload), "t")
        }
        // An ask that is not a run keeps its own editable text.
        let plain = #"{"to":["lea@example.test"],"body":"Hi"}"#
        XCTAssertEqual(ApprovalCard.make(ask(editPreview: plain), phase: .open).editorText, plain)
        XCTAssertEqual(RunEdit.posted("t", base: plain), "t")
    }
}
