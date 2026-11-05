// The agent lists show the agents that exist, under the daemon's
// `display_name`. A fresh install has the chief alone (`main`, shown as
// "Aux"); an older install keeps all five. The five brand definitions stay a
// catalogue, never a promise that each one exists.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class AgentRosterTests: XCTestCase {
    private func agent(_ id: String, shown: String? = nil) -> Agent {
        Agent(id: id, name: id, hue: 0, glyph: "", state: .idle, status: "", threadKey: id, displayName: shown)
    }

    func testDisplayNameDecodesAndStaysAbsentOnAnOldDaemon() throws {
        let fresh = try JSONDecoder().decode(AgentSummary.self, from: Data(#"{"name":"main","display_name":"Aux"}"#.utf8))
        XCTAssertEqual(fresh.displayName, "Aux")
        XCTAssertEqual(Mapper.agent(from: fresh, live: nil).displayName, "Aux")
        let old = try JSONDecoder().decode(AgentSummary.self, from: Data(#"{"name":"mail"}"#.utf8))
        XCTAssertNil(old.displayName)
    }

    func testAChiefAloneInstallListsOnlyTheChief() {
        let roster = TeamMember.roster([agent("main", shown: "Aux")])
        XCTAssertEqual(roster.map(\.id), ["main"], "the id stays main")
        XCTAssertEqual(roster.map(\.name), ["Aux"])
        XCTAssertEqual(roster.first?.role, .chief)
    }

    func testAnOldInstallKeepsAllFiveInOrder() {
        let roster = TeamMember.roster(["documents", "aux", "clients", "mail", "calendar"].map { agent($0) })
        XCTAssertEqual(roster.map(\.id), TeamMember.all.map(\.id))
        XCTAssertEqual(roster.map(\.name), TeamMember.all.map(\.name), "no display name falls back to the brand name")
    }

    func testDisplayNameWinsOverTheBrandNameAndTemplateAgentsFollowTheChief() {
        let roster = TeamMember.roster([agent("zeta"), agent("mail", shown: "Post"), agent("main", shown: "Aux")])
        XCTAssertEqual(roster.map(\.id), ["main", "mail", "zeta"])
        XCTAssertEqual(roster.map(\.name), ["Aux", "Post", "zeta"])
        XCTAssertEqual(TeamMember.displayName("main"), "Aux")
    }

    func testBeforeTheDaemonListsAgentsTheCatalogueStandsIn() {
        XCTAssertEqual(TeamMember.roster([]).map(\.id), TeamMember.all.map(\.id))
    }

    func testTheStoreListsOnlyTheAgentsTheDaemonHas() {
        let transport = FakeTransport()
        transport.agentsResult = .success([AgentSummary(name: "main", displayName: "Aux")])
        let store = Store(transport: transport, language: .en)
        store.start()
        XCTAssertTrue(waitUntil { !store.agents.isEmpty })
        XCTAssertEqual(store.roster.map(\.id), ["main"])
        XCTAssertEqual(store.roster.map(\.name), ["Aux"])
        store.stop()
    }

    func testTheChiefsWorksWithLineNamesOnlyTheAgentsThatExist() {
        XCTAssertNil(TeamMember.worksWithLine(agents: [], .en), "no list until the daemon has listed its agents")
        XCTAssertNil(TeamMember.worksWithLine(agents: [], .fr))

        let alone = [agent("main", shown: "Aux")]
        XCTAssertEqual(TeamMember.worksWithLine(agents: alone, .en), "Add Mail, Calendar, Clients or Documents when you need them.")
        XCTAssertEqual(TeamMember.worksWithLine(agents: alone, .fr), "Ajoutez Mail, Calendar, Clients ou Documents quand vous en avez besoin.")

        let two = [agent("calendar"), agent("main", shown: "Aux"), agent("mail", shown: "Post")]
        XCTAssertEqual(TeamMember.worksWithLine(agents: two, .en), "Aux hands work to Post and Calendar.")
        XCTAssertEqual(TeamMember.worksWithLine(agents: two, .fr), "Aux confie du travail à Post et Calendar.")

        let four = ["main", "mail", "calendar", "clients", "documents"].map { agent($0) }
        XCTAssertEqual(TeamMember.worksWithLine(agents: four, .en), "Aux hands work to Mail, Calendar, Clients and Documents.")
        XCTAssertEqual(TeamMember.worksWithLine(agents: four, .fr), "Aux confie du travail à Mail, Calendar, Clients et Documents.")
    }

    func testThePausedBannerCountsNoAgents() {
        for language in [Language.en, .fr] {
            let body = L10n.ui(.stoppedBody, language)
            XCTAssertFalse(body.localizedCaseInsensitiveContains("five") || body.localizedCaseInsensitiveContains("cinq"), body)
        }
    }
}
