// The team map: one node per agent, built
// only from data the app already holds (agents, delegations, approvals).
// Aux first, then Mail, Calendar, Clients, Documents, then any other agent.
import Foundation

public enum TeamNodeState: Equatable {
    case idle
    /// `task` is the current step (else the delegation's first line); `progress` is "2/3".
    case working(task: String, progress: String?)
    case needsYou(Int)
    case stopped
    /// The daemon cannot be reached: nothing is known about the agent.
    case offline
}

/// Today's steps for one agent. A step whose place was not recorded counts as
/// unknown, never as stayed.
public struct TodayCounts: Equatable {
    public var steps = 0, stayed = 0, left = 0, unknown = 0

    public func parts(_ language: Language) -> [String] {
        guard steps > 0 else { return [L10n.ui(.teamNoSteps, language)] }
        var parts = [
            steps == 1 ? L10n.ui(.teamStepsOne, language) : L10n.uf(.teamStepsMany, language, steps),
            L10n.uf(.stepsStayed, language, stayed),
            L10n.uf(.teamLeft, language, left),
        ]
        if unknown > 0 { parts.append(L10n.uf(.teamUnknown, language, unknown)) }
        return parts
    }

    public func line(_ language: Language) -> String { parts(language).joined(separator: " · ") }
}

public struct TeamNode: Identifiable, Equatable {
    public let member: TeamMember
    public let brain: String?
    public let state: TeamNodeState
    public let today: TodayCounts
    public var id: String { member.id }

    public func stateText(_ language: Language) -> String {
        switch state {
        case .idle: return L10n.ui(.agentIdle, language)
        case .working(let task, let progress):
            return L10n.uf(.teamWorking, language, task) + (progress.map { " · " + $0 } ?? "")
        case .needsYou(let count): return L10n.uf(.teamNeedsYou, language, count)
        case .stopped: return L10n.ui(.agentStopped, language)
        case .offline: return L10n.ui(.teamOffline, language)
        }
    }

    /// Under the node in the map: "Idle", the progress "2/3", the count of decisions, "Stopped".
    public func shortText(_ language: Language) -> String {
        switch state {
        case .working(_, let progress): return progress ?? L10n.ui(.agentWorking, language)
        case .needsYou(let count): return "\(count)"
        default: return stateText(language)
        }
    }

    /// "Mail, deepseek-flash, Working: …, Today: 12 steps · 10 handled by a local brain · …". No privacy mode: the daemon sends none.
    public func spoken(_ language: Language) -> String {
        let today = today.steps == 0 ? [L10n.ui(.teamNoSteps, language)]
            : [L10n.ui(.teamToday, language) + ": " + self.today.line(language)]
        return ([member.name, brain, stateText(language)].compactMap { $0 } + today)
            .joined(separator: ", ")
    }
}

public enum TeamMap {
    public static func firstLine(_ text: String) -> String {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.first { !$0.isEmpty } ?? ""
    }

    /// Aux, the four built-ins, then every other agent by name.
    public static func members(agents: [Agent]) -> [TeamMember] {
        TeamMember.all + agents.map(\.name).filter { TeamMember.member($0) == nil }.sorted().map(TeamMember.custom)
    }

    public static func today(agent: String, delegations: [Delegation], now: Date, calendar: Calendar = .current) -> TodayCounts {
        var counts = TodayCounts()
        for delegation in delegations where delegation.agent == agent {
            guard let ms = Timestamps.unixMillis(from: delegation.at),
                  calendar.isDate(Date(timeIntervalSince1970: TimeInterval(ms) / 1000), inSameDayAs: now) else { continue }
            for step in delegation.steps where step.state != .todo {
                counts.steps += 1
                switch step.place {
                case .stayed: counts.stayed += 1
                case .left: counts.left += 1
                case nil: counts.unknown += 1
                }
            }
        }
        return counts
    }

    /// Stopped beats needs-you beats working beats idle: the loudest fact wins.
    public static func state(agent: String, record: Agent?, delegations: [Delegation], waiting: Int, stopped: Bool,
                             online: Bool = true, language: Language = .en) -> TeamNodeState {
        if !online { return .offline }
        if stopped || record?.state == .killed { return .stopped }
        if waiting > 0 { return .needsYou(waiting) }
        let open = delegations.last { $0.agent == agent && ($0.state == .working || $0.state == .queued) }
        let live = record?.state == .working || record?.state == .thinking
        guard open != nil || live else { return .idle }
        let steps = open?.steps ?? []
        // The current step names the tool in plain words,
        // never its id. A delegate step carries no target: the map says
        // "Asking an agent".
        let current = steps.last { $0.state == .working }.map {
            StepLabel.text($0.text, language: language)
        }
        let task = [current, open.map { firstLine($0.ask) }, record?.runningJob, record?.statusShort]
            .compactMap { $0 }.map(firstLine).first { !$0.isEmpty } ?? L10n.ui(.agentWorking, language)
        let progress = open?.progress.map { "\($0.n)/\($0.of)" }
            ?? (steps.isEmpty ? nil : "\(steps.filter { $0.state == .done }.count)/\(steps.count)")
        return .working(task: task, progress: progress)
    }

    /// Aux's open requests to agents, drawn as solid lines on the map.
    public static func inFlight(delegations: [Delegation], stopped: Bool) -> [(agent: String, task: String)] {
        guard !stopped else { return [] }
        var seen = Set<String>()
        return delegations.reversed().compactMap { delegation in
            guard delegation.state == .working || delegation.state == .queued,
                  delegation.agent != TeamMember.aux.id, seen.insert(delegation.agent).inserted else { return nil }
            return (delegation.agent, firstLine(delegation.ask))
        }
    }
}

extension TeamMember {
    /// An agent the owner added: a plain disc, named as the daemon names it.
    public static func custom(_ name: String) -> TeamMember {
        TeamMember(id: name, name: name, role: .domain, icon: .chat, roleKey: .roleCustom, aboutKey: .aboutCustom)
    }
}

public extension ShellModel {
    func teamNodes(now: Date = Date()) -> [TeamNode] {
        TeamMap.members(agents: store.agents).map { member in
            let record = store.agents.first { $0.name == member.id }
            return TeamNode(
                member: member,
                brain: brain(of: member.id),
                state: TeamMap.state(agent: member.id, record: record, delegations: delegations,
                                     waiting: member.id == TeamMember.aux.id ? 0 : waitingCount(agent: member.id), stopped: stopped,
                                     online: { if case .online = store.connection { return true } else { return false } }(),
                                     language: language),
                today: TeamMap.today(agent: member.id, delegations: delegations, now: now)
            )
        }
    }

    /// A click on a node opens that agent's conversation, built-in or not.
    func openTeamNode(_ node: TeamNode) { go(.agent(node.id)) }

    /// The agent the right panel is about: the open conversation's agent (any
    /// agent, not only the built-in five), else the list selection.
    func rightPanelMember(selected: String) -> TeamMember? {
        if case .agent(let id) = route { return TeamMember.member(id) ?? .custom(id) }
        return TeamMember.member(selected)
    }
}
