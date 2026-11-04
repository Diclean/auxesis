// The v4 messenger frame (WO UI-V4-1): the Steps card starts collapsed with a
// summary computed from its steps, the sidebar keeps Aux first then the four
// agents, and the "needs you" badge shows only where an approval waits.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class MessengerTests: XCTestCase {
    private func step(_ text: String, _ place: StepPlace?) -> DelegationStep {
        DelegationStep(text: text, state: .done, place: place)
    }

    private var sixSteps: [DelegationStep] {
        [.stayed, .stayed, .stayed, .stayed, .stayed, .left].enumerated().map { step("Step \($0.offset)", $0.element) }
    }

    func testStepsCardStartsCollapsedWithTheComputedSummary() {
        var card = StepsCardModel(steps: sixSteps)
        XCTAssertFalse(card.isExpanded, "the card is collapsed by default")
        XCTAssertEqual(card.summary(.en), "6 checks · 5 handled by a local brain")
        card.toggle()
        XCTAssertTrue(card.isExpanded, "a click expands it")
        XCTAssertEqual(card.summary(.en), "6 checks · 5 handled by a local brain", "the summary does not change with the state")
        card.toggle()
        XCTAssertFalse(card.isExpanded)
    }

    func testSummaryCountsOnlyWhatWasRecorded() {
        XCTAssertEqual(StepsCardModel(steps: [step("a", .stayed)]).summary(.en), "1 check · 1 handled by a local brain")
        XCTAssertEqual(StepsCardModel(steps: [step("a", .left), step("b", nil)]).summary(.en),
                       "2 checks · 0 handled by a local brain · 1 not recorded where they ran",
                       "a step that could not record where its data went is never counted as handled")
    }

    func testEveryStepNamesWhereItsDataWent() {
        let card = StepsCardModel(steps: [step("a", .stayed), step("b", .left), step("c", nil)])
        XCTAssertEqual(card.steps.map { StepsCardModel.placeLabel($0, .en) },
                       ["Handled by a brain on this Mac", "Left this Mac", "Not known where it ran"])
    }

    /// DELEG-WHERE-COPY: a step label says only what the Mac can prove. A
    /// `local` brain is reached over a loopback port the owner may have
    /// forwarded elsewhere, so the copy never says the data stayed here.
    func testStepLabelsSayOnlyWhatWeCanProve() throws {
        let json = #"[{"text":"a","state":"done","where":"local"},{"text":"b","state":"done","where":"out"},{"text":"c","state":"done","where":"unknown"}]"#
        let steps = try JSONDecoder().decode([DelegationStep].self, from: Data(json.utf8))
        XCTAssertEqual(steps.map { StepsCardModel.placeLabel($0, .en) },
                       ["Handled by a brain on this Mac", "Left this Mac", "Not known where it ran"])
        XCTAssertEqual(steps.map { StepsCardModel.placeLabel($0, .fr) },
                       ["Traité par un modèle sur ce Mac", "Sorti de ce Mac", "Lieu inconnu"])
        for step in steps {
            for language in Language.allCases {
                let label = StepsCardModel.placeLabel(step, language).lowercased()
                XCTAssertFalse(label.contains("stayed"), "\(language.rawValue) step label says it stayed: \(label)")
                XCTAssertFalse(label.contains("resté"), "\(language.rawValue) step label says it stayed: \(label)")
                XCTAssertFalse(label.contains("never left"), "\(language.rawValue) step label says it never left: \(label)")
                XCTAssertFalse(label.contains("jamais"), "\(language.rawValue) step label says it never left: \(label)")
                XCTAssertFalse(label.contains("tokenis"), "\(language.rawValue) step label claims tokenisation: \(label)")
            }
        }
        // The summary counts the same `local` steps, so it claims no more than
        // the step labels do. The Team map reuses this very string.
        XCTAssertEqual(StepsCardModel(steps: sixSteps).summary(.en), "6 checks · 5 handled by a local brain")
        XCTAssertEqual(StepsCardModel(steps: sixSteps).summary(.fr), "6 vérifications · 5 traitées par un modèle sur ce Mac")
        for language in Language.allCases {
            let summary = StepsCardModel(steps: sixSteps).summary(language).lowercased()
            XCTAssertFalse(summary.contains("stayed"), "\(language.rawValue) summary says it stayed: \(summary)")
            XCTAssertFalse(summary.contains("resté"), "\(language.rawValue) summary says it stayed: \(summary)")
            XCTAssertFalse(summary.contains("tokenis"), "\(language.rawValue) summary claims tokenisation: \(summary)")
        }
        // The sidebar footer counts the same steps, so it says the same thing.
        XCTAssertEqual(L10n.ui(.sidebarStayedOne, .en), "1 step handled by a local brain today")
        XCTAssertEqual(L10n.uf(.sidebarStayedMany, .en, 12), "12 steps handled by a local brain today")
        XCTAssertEqual(L10n.ui(.sidebarStayedOne, .fr), "1 étape traitée par un modèle sur ce Mac aujourd’hui")
        XCTAssertEqual(L10n.uf(.sidebarStayedMany, .fr, 12), "12 étapes traitées par un modèle sur ce Mac aujourd’hui")
        for language in Language.allCases {
            for line in [L10n.ui(.sidebarStayedOne, language), L10n.uf(.sidebarStayedMany, language, 12)] {
                let text = line.lowercased()
                XCTAssertFalse(text.contains("stayed"), "\(language.rawValue) sidebar footer says it stayed: \(line)")
                XCTAssertFalse(text.contains("resté"), "\(language.rawValue) sidebar footer says it stayed: \(line)")
            }
        }
    }

    func testStepPlaceDecodesFromTheDaemonAndStaysAbsentWhenMissing() throws {
        let json = #"[{"text":"a","state":"done","where":"local"},{"text":"b","state":"done","where":"out"},{"text":"c","state":"done"}]"#
        let steps = try JSONDecoder().decode([DelegationStep].self, from: Data(json.utf8))
        XCTAssertEqual(steps.map(\.place), [.stayed, .left, nil])
    }

    func testSidebarKeepsAuxFirstThenTheFourAgents() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        XCTAssertEqual(shell.sidebarEntries().map(\.row.member.id), ["aux", "mail", "calendar", "clients", "documents"])
    }

    func testNeedsYouBadgeShowsOnlyForTheAgentWhoseApprovalWaits() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 }
        let entries = shell.sidebarEntries()
        func badge(_ id: String) -> String? { entries.first { $0.row.member.id == id }?.badge }
        XCTAssertEqual(badge("mail"), "2 need you", "both fixture approvals belong to Mail")
        for id in ["aux", "calendar", "clients", "documents"] {
            XCTAssertNil(badge(id), "\(id) has no approval waiting, so no badge; Aux does not count Mail's decisions twice")
        }
    }

    func testBadgeLabelIsSingularForOneDecision() {
        XCTAssertEqual(MessengerText.needsYou(1, .en), "Needs you")
        XCTAssertNil(MessengerText.needsYou(0, .en))
    }
}
