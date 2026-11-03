import Foundation
import Testing
@testable import AuxesisKit

/// UI-V5-FINISH-4: the right panel's Privacy tab.
@objcMembers @MainActor final class PrivacyTabTests: XCTestCase {
    private let receipts = [
        Receipt(runId: "r1", agent: "mail", replacedValues: ["EMAIL": 2, "PHONE": 0], started: "2026-10-30 08:01:00",
                hostsContacted: ["https://api.example.test", "127.0.0.1"]),
        Receipt(runId: "r2", agent: "calendar", started: "2026-10-30 08:03:00", hostsContacted: ["http://localhost:11434"]),
        Receipt(runId: "r3", agent: "mail", started: "2026-10-30 08:05:00", receiptError: true),
        Receipt(runId: "r4", agent: "mail", started: "2026-10-29 23:59:00", hostsContacted: ["api.example.test"]),
        Receipt(runId: "r5", agent: "mail"),
    ]

    func testAnAgentSeesItsOwnRunsOfTheDay() {
        let model = PrivacyTabModel(receipts: receipts, agent: "mail", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.id), ["r1", "r3"])
        XCTAssertEqual(model.rows.map(\.place), [.left, .unknown])
        XCTAssertEqual(model.rows.first?.host, "https://api.example.test")
    }

    func testAuxSeesTheWholeTeam() {
        let model = PrivacyTabModel(receipts: receipts, agent: "aux", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.id), ["r1", "r2", "r3"])
        XCTAssertEqual(model.summary(.en), ["Runs that left this Mac: 1", "Runs with no outside host recorded: 1", "Runs not known where they ran: 1"])
        XCTAssertEqual(model.replaced.map(\.category), ["EMAIL"])
        XCTAssertEqual(model.replaced.map(\.count), [2])
    }

    func testAnErrorReceiptIsNeverCountedAsStayed() {
        let model = PrivacyTabModel(receipts: [receipts[2]], agent: "mail", day: "2026-10-30")
        XCTAssertEqual(model.count(.stayed), 0)
        XCTAssertEqual(model.count(.unknown), 1)
    }

    // No host evidence is ever drawn as on this Mac (#403).
    func testACloudRunThatListsNoHostIsNotCountedAsStayed() {
        let cloud = Receipt(runId: "c1", agent: "mail", started: "2026-10-30 09:00:00", hostsContacted: [])
        let model = PrivacyTabModel(receipts: [cloud], agent: "mail", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.place), [.noOutsideHost])
        XCTAssertEqual(model.count(.stayed), 0)
        XCTAssertEqual(model.summary(.en)[1], "Runs with no outside host recorded: 1")
    }

    func testAReceiptWithoutHostOrErrorFieldsIsNotCountedAsStayed() throws {
        let json = #"{"run_id":"m1","agent":"mail","started":"2026-10-30 09:10:00","status":"done"}"#
        let receipt = try JSONDecoder().decode(Receipt.self, from: Data(json.utf8))
        let model = PrivacyTabModel(receipts: [receipt], agent: "mail", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.place), [.noOutsideHost])
    }

    // PRIV-EMPTY-HOST-TEST: a receipt that lists no host is never drawn as on
    // this Mac. The shield is kept for a receipt that lists a local host; an
    // empty host list is "no outside host", and one that failed to read is
    // "not known where it ran" — neither is ever the shield.
    func testAReceiptThatListsNoHostIsNeverDrawnAsOnThisMac() {
        let empty = Receipt(runId: "e1", agent: "mail", started: "2026-10-30 09:20:00", hostsContacted: [])
        let failed = Receipt(runId: "e2", agent: "mail", started: "2026-10-30 09:25:00", hostsContacted: [], receiptError: true)
        let model = PrivacyTabModel(receipts: [empty, failed], agent: "mail", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.place), [.noOutsideHost, .unknown])
        XCTAssertEqual(model.count(.stayed), 0, "the shield is only for a receipt that lists a local host")
        // The words of that place never claim the run stayed on this Mac.
        XCTAssertFalse(L10n.ui(.privacyTabNoOutside, .en).lowercased().contains("this mac"))
        XCTAssertFalse(L10n.ui(.privacyTabNoOutside, .fr).lowercased().contains("ce mac"))
    }

    func testOnlyLocalHostEvidenceIsStayed() {
        let model = PrivacyTabModel(receipts: receipts, agent: "calendar", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.place), [.stayed], "every listed host is on this Mac")
    }

    // PRIV-EMPTY-HOST-TEST: an empty host shows no green privacy shield. The
    // place an empty host gets is the one the view draws without a shield,
    // and the tab paints no green at all.
    func testAnEmptyHostIsNeverDrawnWithTheShield() throws {
        let empty = Receipt(runId: "g1", agent: "mail", started: "2026-10-30 11:00:00", hostsContacted: [])
        let local = Receipt(runId: "g2", agent: "mail", started: "2026-10-30 11:05:00", hostsContacted: ["http://localhost:11434"])
        let model = PrivacyTabModel(receipts: [empty, local], agent: "mail", day: "2026-10-30")
        XCTAssertEqual(model.rows.map(\.place), [.noOutsideHost, .stayed], "only a local host is the shield")
        XCTAssertEqual(model.count(.stayed), 1)

        let source = try String(contentsOf: privacyTabView, encoding: .utf8)
        guard let withoutHost = branch(of: source, after: "case .noOutsideHost:") else {
            return XCTFail("the view draws the place of an empty host")
        }
        XCTAssertFalse(withoutHost.contains("shield"), "an empty host draws no shield")
        guard let stayed = branch(of: source, after: "case .stayed:") else {
            return XCTFail("the view draws the place of a local host")
        }
        XCTAssertTrue(stayed.contains("lock.shield"), "a local host keeps the shield")
        XCTAssertFalse(source.contains("palette.green"), "the privacy tab paints no green shield")
    }

    /// The view that draws the privacy tab, found from this file's own path.
    private var privacyTabView: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AuxesisMac/PrivacyTabView.swift")
    }

    /// The lines of one `case` of the view, up to the next one.
    private func branch(of source: String, after marker: String) -> String? {
        guard let start = source.range(of: marker) else { return nil }
        let rest = source[start.upperBound...]
        guard let end = rest.range(of: "case ") else { return String(rest) }
        return String(rest[..<end.lowerBound])
    }

    func testCopyMakesNoBlanketClaim() {
        for language in [Language.en, .fr] {
            let model = PrivacyTabModel(receipts: receipts, agent: "aux", day: "2026-10-30")
            let text = (model.summary(language) + [L10n.ui(.privacyTabNoOutside, language), L10n.ui(.composerHintChief, language)])
                .joined(separator: " ").lowercased()
            for banned in ["100 %", "100%", "anonym", "gdpr", "rgpd", "leak-free", "compliant", "conforme"] {
                XCTAssertFalse(text.contains(banned), "\(language): \(banned)")
            }
        }
    }

    func testComposerHintFollowsTheContract() {
        let privatePhrase = L10n.ui(.modePhrasePrivate, .en)
        XCTAssertEqual(L10n.uf(.composerHintChief, .en, privatePhrase),
                       "Aux asks before anything is sent, paid or deleted. Your message can go to the brain, tokenised in Private mode; the Steps card shows when.")
        XCTAssertTrue(L10n.uf(.composerHintAgent, .en, "DeepSeek V3.2", privatePhrase).contains("can go to DeepSeek V3.2, tokenised in Private mode"))
    }
}
