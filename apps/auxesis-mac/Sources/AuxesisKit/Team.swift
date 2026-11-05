// The team: Aux, the chief, and four domain agents. Pure presentation
// rules live here so the sidebar, the headers, the menu bar and Waiting for
// you all compute the same line and the same count (contract: "the same
// number everywhere"). No view decides a state on its own.
import Foundation

public enum AgentRole: String, Equatable {
    case chief, domain
}

public struct TeamMember: Identifiable, Equatable, Hashable {
    /// The daemon agent name; also the thread key.
    public let id: String
    public let name: String
    public let role: AgentRole
    public let icon: Icon
    public let roleKey: UIKey
    public let aboutKey: UIKey

    public static let aux = TeamMember(id: "aux", name: "Aux", role: .chief, icon: .mark, roleKey: .roleAux, aboutKey: .aboutAux)
    public static let mail = TeamMember(id: "mail", name: "Mail", role: .domain, icon: .mail, roleKey: .roleMail, aboutKey: .aboutMail)
    public static let calendar = TeamMember(id: "calendar", name: "Calendar", role: .domain, icon: .cal, roleKey: .roleCalendar, aboutKey: .aboutCalendar)
    public static let clients = TeamMember(id: "clients", name: "Clients", role: .domain, icon: .people, roleKey: .roleClients, aboutKey: .aboutClients)
    public static let documents = TeamMember(id: "documents", name: "Documents", role: .domain, icon: .receipt, roleKey: .roleDocuments, aboutKey: .aboutDocuments)

    /// Sidebar order; ⌘1–5 follow it.
    public static let all: [TeamMember] = [.aux, .mail, .calendar, .clients, .documents]
    public static let domain: [TeamMember] = [.mail, .calendar, .clients, .documents]

    /// A fresh install's chief: id `main`, shown as Aux. An older install
    /// keeps the `aux` chief and all five agents.
    public static let main = TeamMember(id: "main", name: "Aux", role: .chief, icon: .mark, roleKey: .roleAux, aboutKey: .aboutAux)

    public static func member(_ id: String) -> TeamMember? {
        all.first { $0.id == id } ?? (id == main.id ? main : nil)
    }

    /// The same agent under the name the daemon shows; the id never changes.
    public func named(_ shown: String?) -> TeamMember {
        guard let shown, !shown.isEmpty, shown != name else { return self }
        return TeamMember(id: id, name: shown, role: role, icon: icon, roleKey: roleKey, aboutKey: aboutKey)
    }

    /// The agents that exist, in sidebar order: the chief, the catalogue
    /// agents, then any other agent by id. Each shows the daemon's
    /// `display_name`, else its brand name, else its id. `all` is only the
    /// catalogue: until the daemon has listed its agents, it stands in.
    public static func roster(_ agents: [Agent]) -> [TeamMember] {
        guard !agents.isEmpty else { return all }
        let order = [main.id] + all.map(\.id)
        func rank(_ id: String) -> Int { order.firstIndex(of: id) ?? order.count }
        return agents
            .sorted { rank($0.id) != rank($1.id) ? rank($0.id) < rank($1.id) : $0.id < $1.id }
            .map { (member($0.id) ?? .custom($0.id)).named($0.displayName) }
    }

    /// The chief's "Works with" line: the other agents that exist, by the
    /// name the sidebar shows, or a neutral line when Aux works alone. Nil
    /// until the daemon has listed its agents (as the Go menu's loading
    /// state): the catalogue never stands in for agents that may not exist.
    public static func worksWithLine(agents: [Agent], _ language: Language) -> String? {
        guard !GoMenu.loading(agents: agents) else { return nil }
        let names = roster(agents).filter { $0.role != .chief }.map(\.name)
        guard let last = names.last else { return L10n.ui(.worksWithNone, language) }
        let list = names.count == 1 ? last
            : names.dropLast().joined(separator: ", ") + " " + L10n.ui(.listAnd, language) + " " + last
        return L10n.uf(.worksWithTeam, language, list)
    }

    /// Display name for any agent id (a non-team agent keeps its own name).
    public static func displayName(_ id: String) -> String {
        member(id)?.name ?? id
    }
}

/// The tone a status line takes. Each maps to exactly one palette meaning.
public enum LineTone: Equatable {
    case muted
    /// Blue: live work.
    case live
    /// Red: stopped or an error.
    case halt
}

/// One sidebar row, fully decided.
public struct TeamRowModel: Equatable {
    public let member: TeamMember
    public let line: String
    public let tone: LineTone
    public let time: String?
    public let timeIsLive: Bool
    public let count: Int
    public let unread: Bool
    public let working: Bool
}

public enum TeamPresenter {
    /// Approvals that wait for the owner, owned by `agent` (nil = everyone).
    /// The one count the sidebar, the pinned bar, Waiting for you and the menu
    /// bar all read. Snoozed ("Not now") approvals do not count.
    public static func waiting(_ approvals: [Approval], agent: String? = nil, snoozed: Set<String> = []) -> [Approval] {
        approvals.filter { approval in
            approval.state.isPending && !snoozed.contains(approval.id) && (agent == nil || approval.agent == agent)
        }
    }

    /// Agents with live work: an open working delegation or a live engine state.
    public static func workingAgents(agents: [Agent], delegations: [Delegation], stopped: Bool) -> Set<String> {
        guard !stopped else { return [] }
        var names = Set(delegations.filter { $0.state == .working || $0.state == .queued }.map(\.agent))
        for agent in agents where agent.state == .working || agent.state == .thinking {
            names.insert(agent.name)
        }
        return names
    }

    public static func row(
        member: TeamMember,
        agent: Agent?,
        delegations: [Delegation],
        working: Set<String>,
        waitingCount: Int,
        teamWaitingCount: Int,
        stopped: Bool,
        lastActivity: (text: String, at: Date?)?,
        unread: Bool,
        now: Date,
        language: Language
    ) -> TeamRowModel {
        let isWorking = working.contains(member.id)
        let live = delegations.last { $0.agent == member.id && $0.state.isOpen }
        let time = lastActivity?.at.map { TimeText.short($0, now: now, language: language) }

        if stopped {
            let line = member.role == .chief ? L10n.ui(.chiefStopped, language) : L10n.ui(.pausedByStop, language)
            return TeamRowModel(member: member, line: line, tone: .halt, time: time, timeIsLive: false, count: 0, unread: unread, working: false)
        }
        if member.role == .chief {
            let teamWorking = working.subtracting([member.id]).count
            var parts: [String] = []
            if teamWorking > 0 {
                parts.append(teamWorking == 1 ? L10n.ui(.chiefWorkingOne, language) : L10n.uf(.chiefWorkingMany, language, teamWorking))
            }
            if teamWaitingCount > 0 {
                parts.append(teamWaitingCount == 1 ? L10n.ui(.waitsForYesOne, language) : L10n.uf(.waitsForYesMany, language, teamWaitingCount))
            }
            if !parts.isEmpty {
                return TeamRowModel(member: member, line: parts.joined(separator: " · "), tone: .live, time: time, timeIsLive: unread, count: 0, unread: unread, working: isWorking)
            }
        } else if isWorking, let step = live?.steps.last(where: { $0.state == .working })?.text ?? live?.steps.last?.text {
            let progress = live?.progress.map { " · \($0.n) of \($0.of)" } ?? ""
            // The step names the tool in plain words (STEP-TOOL-LABELS), never
            // its id. No target is passed: a delegate step carries none, so the
            // row says "Asking an agent", never "Asking the Mail agent" on
            // Mail's own row.
            let words = StepLabel.text(step, language: language)
            return TeamRowModel(member: member, line: words + progress, tone: .live, time: L10n.ui(.now, language), timeIsLive: true, count: waitingCount, unread: unread, working: true)
        }
        let line = lastActivity?.text.isEmpty == false ? lastActivity!.text : L10n.ui(member.roleKey, language)
        return TeamRowModel(
            member: member, line: line, tone: .muted, time: time, timeIsLive: unread,
            count: member.role == .chief ? 0 : waitingCount, unread: unread, working: isWorking
        )
    }

    /// Delegation status text (row right side).
    public static func status(_ delegation: Delegation, stopped: Bool, language: Language) -> (text: String, tone: LineTone) {
        if stopped, delegation.state.isOpen { return (L10n.ui(.delegStopped, language), .halt) }
        switch delegation.state {
        case .done:
            let took = delegation.tookMs.map { TimeText.duration(ms: $0) } ?? ""
            return (took.isEmpty ? L10n.ui(.apTrailSent, language) : L10n.uf(.delegDone, language, took), .muted)
        case .waiting:
            return (L10n.ui(.delegNeedsYou, language), .live)
        case .stopped:
            return (L10n.ui(.delegStopped, language), .halt)
        case .failed:
            return (L10n.ui(.delegFailed, language), .halt)
        case .queued:
            return (L10n.ui(.delegQueued, language), .muted)
        case .working:
            if let progress = delegation.progress, progress.of > 0 {
                return (L10n.uf(.delegPercent, language, Int((Double(progress.n) / Double(progress.of) * 100).rounded())), .live)
            }
            return (L10n.ui(.delegWorking, language), .live)
        }
    }
}

/// Times and durations, tabular and short.
public enum TimeText {
    public static func short(_ date: Date, now: Date, language: Language) -> String {
        let calendar = Calendar.current
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language.localeIdentifier)
        if calendar.isDate(date, inSameDayAs: now) {
            formatter.dateFormat = "HH:mm"
        } else if let days = calendar.dateComponents([.day], from: calendar.startOfDay(for: date), to: calendar.startOfDay(for: now)).day, days < 7 {
            formatter.dateFormat = "EEE"
        } else {
            formatter.dateFormat = "d MMM"
        }
        return formatter.string(from: date)
    }

    public static func clock(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_GB")
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: date)
    }

    /// `48 s`, `3 min`, `1 h 05`.
    public static func duration(ms: Int) -> String {
        let seconds = max(0, ms / 1000)
        if seconds < 60 { return "\(seconds) s" }
        if seconds < 3600 { return "\(seconds / 60) min" }
        return String(format: "%d h %02d", seconds / 3600, (seconds % 3600) / 60)
    }

    /// Daemon timestamps: RFC 3339 or `YYYY-MM-DD HH:MM:SS` (UTC).
    public static func parse(_ text: String?) -> Date? {
        guard let text, !text.isEmpty else { return nil }
        if let millis = Timestamps.unixMillis(from: text), millis > 0 {
            return Date(timeIntervalSince1970: TimeInterval(millis) / 1000)
        }
        let iso = ISO8601DateFormatter()
        if let date = iso.date(from: text) { return date }
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return iso.date(from: text)
    }
}
