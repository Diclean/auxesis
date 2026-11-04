import Foundation
import Testing
@testable import AuxesisKit

/// The v5 Steps card and the handoff line.
@objcMembers @MainActor final class StepsCardV5Tests: XCTestCase {
    private func step(_ text: String, _ place: StepPlace?) -> DelegationStep {
        DelegationStep(text: text, state: .done, place: place)
    }

    private func step(_ text: String, _ state: DelegationStep.State, _ place: StepPlace?) -> DelegationStep {
        DelegationStep(text: text, state: state, place: place)
    }

    func testHeaderCountsDoneAndSummaryCountsPlaces() {
        let card = StepsCardModel(steps: [step("a", .stayed), step("b", .left), step("c", .stayed), step("d", .stayed), step("e", .working, nil)])
        XCTAssertEqual(card.title(.en), "Steps · 4 done · 1 running")
        XCTAssertEqual(card.placeSummary(.en), "3 handled on this Mac · 1 left · 1 not known where")
        XCTAssertEqual(card.title(.fr), "Étapes · 4 terminées · 1 en cours")
        XCTAssertEqual(card.placeSummary(.fr), "3 traitées sur ce Mac · 1 sorties du Mac · 1 lieu inconnu")
    }

    func testAnUnrecordedPlaceIsNeverCountedAsStayed() {
        let card = StepsCardModel(steps: [step("a", nil), step("b", nil)])
        XCTAssertEqual(card.placeSummary(.en), "0 handled on this Mac · 0 left · 2 not known where")
    }

    func testRowsCarryTheAgentAsSourceAndATaskWithoutStepsGetsOneUnknownRow() {
        let mail = Delegation(id: "d1", agent: "mail", ask: "Sort mail", at: "2026-10-30T08:00:00Z", state: .done,
                              steps: [step("Read 42 mails", .stayed), step("Summarised", .left)])
        let docs = Delegation(id: "d2", agent: "documents", ask: "Match receipts", at: "2026-10-30T08:01:00Z", state: .working)
        let rows = StepsCardModel.rows([mail, docs], stopped: false)
        XCTAssertEqual(rows.map(\.source), ["Mail", "Mail", "Documents"])
        XCTAssertEqual(rows.last?.step.text, "Match receipts")
        XCTAssertNil(rows.last?.step.place)
        XCTAssertEqual(rows.last?.step.state, .working)
        XCTAssertFalse(rows.contains(where: \.halted))
    }

    func testStopMarksOnlyUnfinishedStepsAsHalted() {
        let task = Delegation(id: "d1", agent: "calendar", ask: "Find slots", at: "2026-10-30T08:00:00Z", state: .working,
                              steps: [step("Read week", .stayed), step("Pick 3", .working, nil)])
        let rows = StepsCardModel.rows([task], stopped: true)
        XCTAssertEqual(rows.map(\.halted), [false, true])
        XCTAssertEqual(StepsCardModel(steps: rows.map(\.step)).title(.en, halted: 1), "Steps · 1 done · 1 stopped")
    }

    func testHandoffLineNamesEachAgentOnce() {
        XCTAssertEqual(HandoffLine.text(agents: ["mail"], at: nil, language: .en), "Aux asked Mail")
        XCTAssertEqual(HandoffLine.text(agents: ["mail", "calendar", "mail"], at: nil, language: .en), "Aux asked Mail and Calendar")
        XCTAssertEqual(HandoffLine.text(agents: ["mail", "calendar", "clients"], at: nil, language: .fr),
                       "Aux a sollicité Mail, Calendar et Clients")
        let at = TimeText.parse("2026-10-30T08:58:00Z")!
        XCTAssertTrue(HandoffLine.text(agents: ["mail"], at: at, language: .en).hasPrefix("Aux asked Mail · "))
    }
}
