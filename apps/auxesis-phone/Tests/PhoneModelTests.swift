import XCTest
@testable import AuxesisPhone

private struct StubAuth: DraftAuthenticating {
    let succeeds: Bool
    func authenticate(reason: String) async -> Bool { succeeds }
}

@MainActor
final class PhoneModelTests: XCTestCase {
    func testSharedCopyKeepsBothPhoneLanguages() {
        let expected: [(String, String, String)] = [
            ("newAgent", "New agent", "Nouvel agent"), ("cancel", "Cancel", "Annuler"),
            ("send", "Send", "Envoyer"), ("allowOnce", "Allow once", "Autoriser une fois"),
            ("deny", "Deny", "Refuser"), ("name", "Name", "Nom"),
        ]
        for (key, english, french) in expected {
            XCTAssertEqual(Copy(french: false)(key), english, key)
            XCTAssertEqual(Copy(french: true)(key), french, key)
        }
    }

    func testRequestStaysInWaitingUntilMacConfirms() {
        let model = PhoneModel(authenticator: StubAuth(succeeds: true), autoConfirm: false)
        XCTAssertEqual(model.waitingCount, 2)
        model.submit(.receipts, decision: .allow)
        XCTAssertEqual(model.waitingCount, 2)
        XCTAssertTrue(model.waiting.contains(.receipts))
        XCTAssertEqual(model.pending[.receipts], .allow)
        model.macConfirmed(.receipts)
        XCTAssertEqual(model.waitingCount, 1)
        XCTAssertFalse(model.waiting.contains(.receipts))
        XCTAssertNil(model.pending[.receipts])
        model.macConfirmed(.reminder) // An unsolicited confirmation changes nothing.
        XCTAssertTrue(model.waiting.contains(.reminder))
    }

    func testOnlyOneTimeDecisionsAreOffered() {
        let model = PhoneModel(autoConfirm: false)
        XCTAssertEqual(model.receiptDecisions, [.allow, .deny])
        for french in [false, true] {
            let copy = Copy(french: french)
            XCTAssertNotEqual(copy("allowOnce"), "Allow always")
            XCTAssertFalse([copy("allowOnce"), copy("deny")].contains("Toujours autoriser"))
        }
    }

    func testSendRequiresSuccessfulAuthenticationAndMacConfirmation() async {
        let denied = PhoneModel(authenticator: StubAuth(succeeds: false), autoConfirm: false)
        denied.openDraft(.jonas)
        await denied.send(reason: "Confirm")
        XCTAssertTrue(denied.authFailed)
        XCTAssertNil(denied.pending[.jonas])
        XCTAssertTrue(denied.waiting.contains(.jonas))
        let allowed = PhoneModel(authenticator: StubAuth(succeeds: true), autoConfirm: false)
        allowed.openDraft(.jonas)
        await allowed.send(reason: "Confirm")
        XCTAssertEqual(allowed.pending[.jonas], .send)
        XCTAssertTrue(allowed.waiting.contains(.jonas))
        XCTAssertNil(allowed.recent)
        allowed.macConfirmed(.jonas)
        XCTAssertFalse(allowed.waiting.contains(.jonas))
        XCTAssertNotNil(allowed.recent)
    }

    func testFailedAuthenticationKeepsDraftPendingAndShowsFailureCopy() async {
        let model = PhoneModel(authenticator: StubAuth(succeeds: false), autoConfirm: false)
        model.openDraft(.jonas)
        await model.send(reason: "Confirm")
        XCTAssertTrue(model.pending.isEmpty)
        XCTAssertNil(model.recent)
        XCTAssertTrue(model.waiting.contains(.jonas))
        XCTAssertEqual(model.screen, .review)
        XCTAssertTrue(model.authFailed) // ReviewScreen displays authFailed copy for this state.
        XCTAssertEqual(Copy(french: false)("authFailed"), "Authentication was not completed. Nothing was sent.")
    }

    func testCancelWindowEndsAtExactlyTenSeconds() async {
        let start = Date(timeIntervalSince1970: 1_000)
        let model = PhoneModel(authenticator: StubAuth(succeeds: true), now: { start }, autoConfirm: false)
        model.openDraft(.jonas)
        await model.send(reason: "Confirm")
        model.macConfirmed(.jonas)
        XCTAssertEqual(model.remaining(at: start), 10)
        XCTAssertEqual(model.remaining(at: start.addingTimeInterval(9.99)), 1)
        model.updateTime(at: start.addingTimeInterval(9.99))
        XCTAssertEqual(model.recent?.status, .cancelling(until: start.addingTimeInterval(10)))
        model.cancelSend(at: start.addingTimeInterval(10))
        XCTAssertEqual(model.recent?.status, .final)
        let cancellable = PhoneModel(authenticator: StubAuth(succeeds: true), now: { start }, autoConfirm: false)
        cancellable.openDraft(.jonas)
        await cancellable.send(reason: "Confirm")
        cancellable.macConfirmed(.jonas)
        cancellable.cancelSend(at: start.addingTimeInterval(9.99))
        XCTAssertEqual(cancellable.recent?.status, .cancelled)
    }

    func testRenameChangesDisplayOnly() {
        let model = PhoneModel(autoConfirm: false)
        let identity = model.chiefID, access = model.chiefAccess, history = model.chiefHistory
        let requests = model.waiting
        model.rename("Nova")
        XCTAssertEqual(model.displayName, "Nova")
        XCTAssertEqual(model.chiefID, identity)
        XCTAssertEqual(model.chiefAccess, access)
        XCTAssertEqual(model.chiefHistory, history)
        XCTAssertEqual(model.waiting, requests)
        model.rename("  ")
        XCTAssertEqual(model.displayName, "Aux")
    }
}
