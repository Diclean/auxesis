import Foundation
import Testing
@testable import AuxesisKit

/// UI-V5-FINISH-1: the v5 frame. The sidebar holds only the team; every page
/// that used to sit under "More" stays one click away in the Records menu and
/// one Go-menu item away (no shortcut); the four agents keep ⌘1–⌘5; a
/// conversation fills the main area alone.
@objcMembers @MainActor final class FrameV5Tests: XCTestCase {
    private let formerMorePages: [ShellModel.Route] = [
        .today, .waiting, .sinceYouLeft, .clients, .documents, .money, .memory, .privacyRecord, .agentsAndRules,
    ]

    private func makeShell() -> ShellModel {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        return shell
    }

    private func area(_ shell: ShellModel) -> ShellModel.SplitLayout.MainArea {
        ShellModel.SplitLayout.mainArea(for: shell.route, conversationPresented: shell.conversationPresented,
                                        conversationAgent: shell.conversationAgent)
    }

    func testEveryFormerMorePageIsInTheRecordsMenuOnce() {
        let items = ShellModel.recordsMenu.flatMap { $0 }
        XCTAssertEqual(items, formerMorePages)
        XCTAssertEqual(Set(items).count, items.count)
    }

    func testEveryFormerMorePageStaysInTheGoMenuWithoutAShortcut() {
        let records = Set(GoMenu.recordItems.map(\.route))
        for route in formerMorePages { XCTAssertTrue(records.contains(route), "\(route) lost its Go menu item") }
        XCTAssertTrue(GoMenu.recordItems.allSatisfy { $0.shortcut == nil })
    }

    func testEachRecordsItemOpensItsPageWithoutTheRightPanel() {
        let shell = makeShell()
        for route in ShellModel.recordsMenu.flatMap({ $0 }) {
            shell.go(.agent(TeamMember.mail.id))
            shell.go(route)
            XCTAssertEqual(shell.route, route)
            guard case .page = area(shell) else { return XCTFail("\(route) did not open as a page") }
            XCTAssertFalse(ShellModel.SplitLayout.showsRightPanel(area(shell)))
        }
    }

    func testOnlyWhatAuxKnowsIsOneWidePage() {
        for route in formerMorePages {
            let expected = ShellModel.SplitLayout.MainArea.page(detail: route != .memory)
            XCTAssertEqual(ShellModel.SplitLayout.mainArea(for: route, conversationPresented: false, conversationAgent: "aux"), expected)
        }
    }

    func testSidebarListsOnlyTheTeam() {
        let shell = makeShell()
        let ids = shell.sidebarEntries().map(\.row.member.id)
        XCTAssertEqual(ids, TeamMember.all.map(\.id))
        XCTAssertEqual(ids.first, TeamMember.aux.id)
    }

    func testAConversationFillsTheMainAreaWithTheRightPanel() {
        let shell = makeShell()
        shell.go(.agent(TeamMember.mail.id))
        XCTAssertEqual(area(shell), .conversation(TeamMember.mail.id))
        XCTAssertTrue(ShellModel.SplitLayout.showsRightPanel(area(shell)))

        // Opened from a page, a conversation never sits beside that page's list.
        shell.go(.agentsAndRules)
        shell.openConversationFromAgents(TeamMember.calendar.id)
        XCTAssertEqual(area(shell), .conversation(TeamMember.calendar.id))
    }

    func testAskAuxOpensAuxAndFocusesItsComposerOnce() {
        let shell = makeShell()
        shell.go(.clients)
        shell.askAux()
        XCTAssertEqual(shell.route, .agent(TeamMember.aux.id))
        XCTAssertTrue(shell.consumeAskFocus())
        XCTAssertFalse(shell.consumeAskFocus())

        // Already in Aux's conversation: stays, focuses again.
        let before = shell.askFocusRequest
        shell.askAux()
        XCTAssertEqual(shell.route, .agent(TeamMember.aux.id))
        XCTAssertEqual(shell.askFocusRequest, before &+ 1)
        XCTAssertTrue(shell.consumeAskFocus())
    }
}
