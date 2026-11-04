import Foundation
import Testing
@testable import AuxesisKit

/// The right panel's Work tab.
@objcMembers @MainActor final class WorkTabTests: XCTestCase {
    private let mira = Approval(
        id: "ap-1", auditId: 1, agent: "mail", threadId: "mail", ts: 1, action: "mail.send",
        headline: "Reply to Mira · Times for Tuesday", preview: "Hi", fullPreview: "Hi",
        detail: [], scopeTool: "mail.send", scopeRule: "ask"
    )

    private func task(_ id: String, _ agent: String, _ state: DelegationState, progress: (Int, Int)? = nil,
                      steps: [DelegationStep] = []) -> Delegation {
        Delegation(id: id, agent: agent, ask: "Task \(id)", at: "2026-10-30T08:00:00Z", state: state,
                   steps: steps, progress: progress.map { (n: $0.0, of: $0.1) })
    }

    func testActiveListsWaitingDraftsThenOpenTasksOnly() {
        let items = WorkTab.active(
            approvals: [mira],
            delegations: [task("d1", "calendar", .working, progress: (2, 3)), task("d2", "clients", .done),
                          task("d3", "documents", .working, steps: [DelegationStep(text: "a", state: .done), DelegationStep(text: "b", state: .working)])],
            stopped: false, language: .en)
        XCTAssertEqual(items.map(\.id), ["ap-1", "d1", "d3"])
        XCTAssertEqual(items[0].kind, .waiting)
        XCTAssertEqual(items[0].title, "Reply to Mira")
        XCTAssertEqual(items[0].line, "Mail · Needs you")
        XCTAssertNil(items[0].progress)
        XCTAssertEqual(items[1].line, "Calendar · 2 of 3 steps")
        XCTAssertEqual(items[1].progress ?? 0, 2.0 / 3.0, accuracy: 0.001)
        XCTAssertEqual(items[2].line, "Documents · 1 of 2 steps")
    }

    func testAfterStopNothingOffersSteerOrStop() {
        let items = WorkTab.active(approvals: [], delegations: [task("d1", "calendar", .working, progress: (1, 3))],
                                   stopped: true, language: .fr)
        XCTAssertEqual(items.first?.kind, .halted)
        XCTAssertEqual(items.first?.line, "Calendar · Arrêté")
        XCTAssertNil(items.first?.progress)
    }

    func testATaskWithoutACountSaysItIsWorking() {
        let item = WorkTab.active(approvals: [], delegations: [task("d1", "mail", .queued)], stopped: false, language: .en).first
        XCTAssertEqual(item?.line, "Mail · Working")
        XCTAssertNil(item?.progress)
    }

    func testUpNextIsSoonestFirstAndKeepsScheduleWordsWithoutATime() {
        let now = TimeText.parse("2026-10-30T09:00:00Z")!
        let tomorrow = "2026-10-31T09:30:00Z"
        let jobs = [
            PlannedJob(id: 2, agent: "mail", name: "Check payment", schedule: "after Camille's reply"),
            PlannedJob(id: 1, agent: "aux", name: "Morning brief", schedule: "weekdays", nextRunAt: tomorrow),
            PlannedJob(id: 3, agent: "aux", name: "Off", schedule: "daily", enabled: false, nextRunAt: tomorrow),
        ]
        let items = WorkTab.upNext(jobs, now: now, language: .en)
        XCTAssertEqual(items.map(\.id), [1, 2])
        XCTAssertTrue(items[0].line.hasPrefix("Aux · tomorrow "))
        XCTAssertEqual(items[1].line, "Mail · after Camille's reply")
    }

    func testSteerOpensTheAgentAndFocusesItsComposerWithoutSending() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        let sent = shell.store.messages.count
        shell.steer(TeamMember.calendar.id)
        XCTAssertEqual(shell.route, .agent(TeamMember.calendar.id))
        XCTAssertTrue(shell.consumeAskFocus())
        XCTAssertEqual(shell.store.messages.count, sent)
        XCTAssertFalse(shell.store.isSendingMessage)
    }
}
