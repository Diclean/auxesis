// The v4 messenger frame, as pure rules: the Steps card
// that starts collapsed with a computed summary, and the sidebar rows with the
// amber "needs you" badge. Views read these; none decides a count on its own.
import Foundation

/// A Steps card: collapsed by default, one summary line from the step data.
public struct StepsCardModel: Equatable {
    public let steps: [DelegationStep]
    public private(set) var isExpanded = false

    public init(steps: [DelegationStep]) { self.steps = steps }

    public mutating func toggle() { isExpanded.toggle() }

    /// "6 checks · 5 handled by a local brain". A step whose data place was
    /// not recorded is never counted here; it is named instead.
    public func summary(_ language: Language) -> String {
        let stayed = steps.filter { $0.place == .stayed }.count
        let unrecorded = steps.filter { $0.place == nil }.count
        var parts = [
            steps.count == 1 ? L10n.ui(.stepsChecksOne, language) : L10n.uf(.stepsChecksMany, language, steps.count),
            L10n.uf(.stepsStayed, language, stayed),
        ]
        if unrecorded > 0 { parts.append(L10n.uf(.stepsUnrecorded, language, unrecorded)) }
        return parts.joined(separator: " · ")
    }

    /// The "where the data went" line of one step.
    public static func placeLabel(_ step: DelegationStep, _ language: Language) -> String {
        switch step.place {
        case .stayed: return L10n.ui(.stayedOnMac, language)
        case .left: return L10n.ui(.whereLeft, language)
        case nil: return L10n.ui(.whereUnavailable, language)
        }
    }
}

/// One row of a v5 Steps card: the step, the agent it ran for (the
/// source column), and whether Stop or a failure ended it before it finished.
public struct StepsCardRow: Equatable {
    public let step: DelegationStep
    public let source: String
    public let halted: Bool
}

public extension StepsCardModel {
    /// The rows of one card: each delegation's steps, or one row for the ask
    /// itself when the daemon sent no steps. A row's place is never invented.
    /// A daemon step is shown in plain words: the tool is
    /// named, never its id. The owner's own question is shown as it is.
    static func rows(_ delegations: [Delegation], stopped: Bool, language: Language = .en) -> [StepsCardRow] {
        delegations.flatMap { delegation -> [StepsCardRow] in
            let halted = delegation.state == .stopped || delegation.state == .failed || (stopped && delegation.state.isOpen)
            let source = TeamMember.displayName(delegation.agent)
            let steps: [DelegationStep] = delegation.steps.isEmpty
                ? [DelegationStep(text: delegation.ask, at: delegation.at, state: delegation.state == .done ? .done : .working)]
                : delegation.steps.map { step in
                    DelegationStep(text: StepLabel.text(step.text, language: language),
                                   at: step.at, state: step.state, place: step.place)
                }
            return steps.map { step in
                StepsCardRow(step: step, source: source, halted: halted && step.state != .done)
            }
        }
    }

    /// v5 header: "Steps · 4 done", plus what still runs.
    func title(_ language: Language, halted: Int = 0) -> String {
        let done = steps.filter { $0.state == .done }.count
        let open = steps.count - done - halted
        var parts = [L10n.uf(.stepsDoneV5, language, done)]
        if open > 0 { parts.append(L10n.uf(.stepsRunningV5, language, open)) }
        if halted > 0 { parts.append(L10n.uf(.stepsHaltedV5, language, halted)) }
        return parts.joined(separator: " · ")
    }

    /// v5 summary: "4 handled on this Mac · 1 left". A step whose place was
    /// not recorded is named as unknown, never counted as stayed.
    func placeSummary(_ language: Language) -> String {
        let stayed = steps.filter { $0.place == .stayed }.count
        let left = steps.filter { $0.place == .left }.count
        let unknown = steps.filter { $0.place == nil }.count
        var parts = [L10n.uf(.stepsHereV5, language, stayed), L10n.uf(.stepsLeftV5, language, left)]
        if unknown > 0 { parts.append(L10n.uf(.stepsUnknownV5, language, unknown)) }
        return parts.joined(separator: " · ")
    }
}

/// A handoff is a centred system line, "Aux asked Mail and Calendar · 08:58".
public enum HandoffLine {
    public static func text(agents: [String], at: Date?, language: Language) -> String {
        var names: [String] = []
        for agent in agents where !names.contains(TeamMember.displayName(agent)) { names.append(TeamMember.displayName(agent)) }
        let and = L10n.ui(.handoffAnd, language)
        let who = names.count < 2 ? (names.first ?? "") : names.dropLast().joined(separator: ", ") + and + names[names.count - 1]
        let line = L10n.uf(.handoffLineV5, language, who)
        return at.map { line + " · " + TimeText.clock($0) } ?? line
    }

    /// The line cut in front of each agent's name, in the order the names
    /// appear, so a mascot can sit before each name. A name the line does
    /// not carry gets no mascot; the pieces always join back to the line.
    public static func pieces(_ line: String, agents: [String]) -> [(agent: String?, text: String)] {
        var result: [(agent: String?, text: String)] = []
        var rest = Substring(line)
        var pending: String?
        var seen: Set<String> = []
        for agent in agents {
            let name = TeamMember.displayName(agent)
            guard seen.insert(name).inserted, let range = rest.range(of: name) else { continue }
            if pending != nil || range.lowerBound > rest.startIndex {
                result.append((pending, String(rest[..<range.lowerBound])))
            }
            pending = agent
            rest = rest[range.lowerBound...]
        }
        result.append((pending, String(rest)))
        return result
    }
}

public enum MessengerText {
    /// The badge text for `count` waiting decisions; nil when none wait.
    public static func needsYou(_ count: Int, _ language: Language) -> String? {
        switch count {
        case ..<1: return nil
        case 1: return L10n.ui(.needsYouOne, language)
        default: return L10n.uf(.needsYouMany, language, count)
        }
    }
}

/// One sidebar row: the shared row model plus its decision badge.
public struct SidebarEntry: Equatable {
    public let row: TeamRowModel
    public let badge: String?
    /// The second line and the short role beside the name.
    public let status: SidebarStatus
    public let role: String?
}

public extension ShellModel {
    /// Aux first, then Mail, Calendar, Clients, Documents. A decision counts
    /// once, on the agent that owns it; Aux's row carries no badge.
    func sidebarEntries(now: Date = Date()) -> [SidebarEntry] {
        TeamMember.all.map { member in
            let row = row(for: member, now: now)
            let what = waitingApprovals.first { $0.agent == member.id }?.headline
            return SidebarEntry(
                row: row, badge: MessengerText.needsYou(row.count, language),
                status: SidebarText.status(row: row, waitingWhat: what, language: language),
                role: SidebarText.role(member, language)
            )
        }
    }
}

/// The last line of a conversation, as a sidebar row says it: the daemon's
/// already-scrubbed `preview` of the newest owner or agent message. The owner's
/// own words say "You: " first. Tool rows and system lines are never a last
/// line. Swift renders the field as sent: it never derives a preview from raw
/// message text.
public struct ConversationPreview: Equatable {
    public let text: String
    public let ts: Int64
    public let fromOwner: Bool

    public static func latest(in rows: [ChatMessage]) -> ConversationPreview? {
        for message in rows.reversed() {
            if message.author == .tool || message.author == .system { continue }
            guard let preview = message.preview?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !preview.isEmpty
            else { continue }
            return ConversationPreview(text: preview, ts: message.ts, fromOwner: message.author == .you)
        }
        return nil
    }

    public func line(_ language: Language) -> String {
        fromOwner ? L10n.ui(.youPrefix, language) + text : text
    }

    public var date: Date? { ts > 0 ? Date(timeIntervalSince1970: TimeInterval(ts) / 1000) : nil }
}
