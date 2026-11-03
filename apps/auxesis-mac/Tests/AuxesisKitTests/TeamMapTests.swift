// The team map (WO UI-V4-3): node order, the four node states, and the today
// line. A step whose data place was not recorded is never counted as stayed.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class TeamMapTests: XCTestCase {
    private let now = Date()

    private func stamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    private func delegation(_ agent: String, _ state: DelegationState, steps: [DelegationStep] = [],
                            at: Date? = nil, progress: (n: Int, of: Int)? = nil, ask: String = "Do the thing\nmore") -> Delegation {
        Delegation(id: UUID().uuidString, agent: agent, ask: ask, at: stamp(at ?? now), state: state, steps: steps, progress: progress)
    }

    private func step(_ place: StepPlace?, _ state: DelegationStep.State = .done, _ text: String = "s") -> DelegationStep {
        DelegationStep(text: text, state: state, place: place)
    }

    private func agent(_ name: String, _ state: AgentState = .idle) -> Agent {
        Agent(id: name, name: name, hue: 0, glyph: "", state: state, status: "", threadKey: name)
    }

    func testNodeOrderIsAuxThenTheFourThenCustomAgentsByName() {
        let members = TeamMap.members(agents: [agent("zeta"), agent("mail"), agent("alpha"), agent("aux")])
        XCTAssertEqual(members.map(\.id), ["aux", "mail", "calendar", "clients", "documents", "alpha", "zeta"])
    }

    func testIdleWorkingNeedsYouAndStoppedStates() {
        let live = [delegation("calendar", .working, steps: [step(.stayed), step(nil, .working, "Finding 3 slots"), step(nil, .todo)])]
        XCTAssertEqual(TeamMap.state(agent: "clients", record: agent("clients"), delegations: live, waiting: 0, stopped: false), .idle)
        XCTAssertEqual(TeamMap.state(agent: "calendar", record: agent("calendar"), delegations: live, waiting: 0, stopped: false),
                       .working(task: "Finding 3 slots", progress: "1/3"))
        XCTAssertEqual(TeamMap.state(agent: "calendar", record: nil, delegations: [delegation("calendar", .working, progress: (2, 3))],
                                     waiting: 0, stopped: false),
                       .working(task: "Do the thing", progress: "2/3"), "the first line of the ask when no step is current")
        XCTAssertEqual(TeamMap.state(agent: "calendar", record: agent("calendar"), delegations: live, waiting: 2, stopped: false),
                       .needsYou(2), "a decision that waits for the owner outranks work")
        XCTAssertEqual(TeamMap.state(agent: "calendar", record: agent("calendar"), delegations: live, waiting: 2, stopped: true), .stopped)
        XCTAssertEqual(TeamMap.state(agent: "mail", record: agent("mail", .killed), delegations: [], waiting: 0, stopped: false), .stopped)
    }

    func testTodayCountsNeverCountUnknownAsStayed() {
        let list = [
            delegation("mail", .done, steps: [step(.stayed), step(.stayed), step(.left), step(nil), step(nil, .todo)]),
            delegation("mail", .done, steps: [step(.stayed)], at: now.addingTimeInterval(-3 * 86_400)),
            delegation("clients", .done, steps: [step(.left)]),
        ]
        let counts = TeamMap.today(agent: "mail", delegations: list, now: now)
        XCTAssertEqual(counts, TodayCounts(steps: 4, stayed: 2, left: 1, unknown: 1), "only today, only steps that ran")
        XCTAssertEqual(counts.line(.en), "4 steps · 2 handled by a local brain · 1 left · 1 unknown")
        XCTAssertEqual(TodayCounts(steps: 3, stayed: 3).line(.en), "3 steps · 3 handled by a local brain · 0 left")
        XCTAssertEqual(TodayCounts().line(.en), "No steps yet today")
    }

    func testInFlightLinesAreAuxsOpenRequestsOnly() {
        let list = [delegation("mail", .working, ask: "Sort mail\nlong"), delegation("documents", .done),
                    delegation("calendar", .waiting), delegation("clients", .queued)]
        XCTAssertEqual(TeamMap.inFlight(delegations: list, stopped: false).map { $0.agent }, ["clients", "mail"])
        XCTAssertEqual(TeamMap.inFlight(delegations: list, stopped: false).last?.task, "Sort mail")
        XCTAssertTrue(TeamMap.inFlight(delegations: list, stopped: true).isEmpty)
    }

    func testVoiceOverReadsOneElementPerNode() {
        let node = TeamNode(member: .mail, brain: "deepseek-flash",
                            state: .working(task: "Sort mail", progress: nil),
                            today: TodayCounts(steps: 12, stayed: 10, left: 2))
        XCTAssertEqual(node.spoken(.en),
                       "Mail, deepseek-flash, Working: Sort mail, Today: 12 steps · 10 handled by a local brain · 2 left")
        XCTAssertFalse(node.spoken(.en).contains("Private"), "a cloud brain is never announced as private: the daemon sends no mode")
        XCTAssertFalse(node.spoken(.fr).contains("Private"))
    }

    func testRightPanelRemembersItsTabAndItsOpenState() {
        let suite = "ui-v4-3-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let daemon = FixtureDaemon(scenario: .team)
        let first = ShellModel(store: Store(transport: daemon, language: .en), client: daemon, defaults: defaults)
        XCTAssertEqual(first.rightPanelTab, .work)
        XCTAssertFalse(first.rightPanelPreferred)
        first.rightPanelTab = .team
        first.toggleRightPanel()
        let second = ShellModel(store: Store(transport: daemon, language: .en), client: daemon, defaults: defaults)
        XCTAssertEqual(second.rightPanelTab, .team)
        XCTAssertTrue(second.rightPanelPreferred)
        second.setRightPanel(false)
        XCTAssertFalse(second.rightPanelPreferred)
    }

    func testTheFixtureTeamMapShowsFiveNodesWithMailNeedingYou() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 && !shell.delegations.isEmpty }
        let nodes = shell.teamNodes()
        XCTAssertEqual(nodes.map(\.id), ["aux", "mail", "calendar", "clients", "documents"])
        XCTAssertEqual(nodes[1].state, .needsYou(2))
        XCTAssertEqual(nodes[2].state, .idle)
    }

    func testNodesBuiltFromTheShellNeverClaimAPrivacyMode() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { shell.store.approvals.count == 2 && !shell.delegations.isEmpty }
        let nodes = shell.teamNodes()
        XCTAssertTrue(nodes.contains { $0.brain == "DeepSeek V3.2" }, "the fixture has a cloud brain")
        for node in nodes {
            XCTAssertFalse(node.spoken(.en).localizedCaseInsensitiveContains("private"), node.id)
            XCTAssertFalse(node.stateText(.en).localizedCaseInsensitiveContains("private"), node.id)
        }
    }

    func testTheTeamMapAndPanelWorkFromACustomAgentsConversation() {
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon)
        shell.start()
        _ = waitUntil { !shell.store.agents.isEmpty }
        let custom = TeamNode(member: .custom("zeta"), brain: nil, state: .idle, today: TodayCounts())
        shell.openTeamNode(custom)
        XCTAssertEqual(shell.route, .agent("zeta"))
        XCTAssertEqual(shell.rightPanelMember(selected: "")?.id, "zeta", "the panel is drawn for the open conversation's agent")
        shell.go(.agent("mail"))
        XCTAssertEqual(shell.rightPanelMember(selected: "")?.id, "mail")
        shell.go(.today)
        XCTAssertNil(shell.rightPanelMember(selected: "zeta"), "no panel where no agent is open")
    }

    func testAnOfflineDaemonShowsOfflineNotIdle() {
        let state = TeamMap.state(agent: "mail", record: nil, delegations: [], waiting: 0, stopped: false, online: false)
        XCTAssertEqual(state, .offline)
        let node = TeamNode(member: .mail, brain: nil, state: state, today: TodayCounts())
        XCTAssertEqual(node.stateText(.en), "Offline")
        XCTAssertEqual(node.shortText(.en), "Offline")
    }

    func testRowTextUnderANodeIsShort() {
        func node(_ state: TeamNodeState) -> TeamNode { TeamNode(member: .mail, brain: nil, state: state, today: TodayCounts()) }
        XCTAssertEqual(node(.idle).shortText(.en), "Idle")
        XCTAssertEqual(node(.working(task: "x", progress: "2/3")).shortText(.en), "2/3")
        XCTAssertEqual(node(.working(task: "x", progress: nil)).shortText(.en), "Working")
        XCTAssertEqual(node(.needsYou(2)).shortText(.en), "2")
        XCTAssertEqual(node(.stopped).shortText(.en), "Stopped")
    }

    func testDismissingThePanelRemembersItClosed() {
        let suite = "ui-v4-3-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let daemon = FixtureDaemon(scenario: .team)
        let shell = ShellModel(store: Store(transport: daemon, language: .en), client: daemon, defaults: defaults)
        shell.setRightPanel(true)
        shell.setRightPanel(false)   // what the inspector's dismiss binding calls
        XCTAssertFalse(shell.rightPanelPreferred)
    }

    func testCustomMemberDoesNotReuseAuxCopy() {
        let member = TeamMember.custom("zeta")
        XCTAssertNotEqual(member.roleKey, TeamMember.aux.roleKey)
        XCTAssertNotEqual(member.aboutKey, TeamMember.aux.aboutKey)
        XCTAssertFalse(L10n.ui(member.aboutKey, .en).isEmpty)
    }
}
