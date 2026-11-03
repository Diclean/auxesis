// The right panel's Work tab, as rules: "Active"
// (decisions that wait, then tasks that run) and "Up next" (planned runs).
// The view only draws these; Steer and Stop call the shell's existing acts.
import Foundation

/// One row under "Active".
public struct WorkItem: Equatable, Identifiable {
    public enum Kind: Equatable {
        /// A draft waits for the owner (amber hourglass, no Steer · Stop).
        case waiting
        /// A task runs: Steer · Stop.
        case running
        /// Stop or a failure ended it; nothing more runs.
        case halted
    }

    public let id: String
    public let kind: Kind
    public let title: String
    public let agent: String
    /// "Calendar · 2 of 3 steps", "Mail · Needs you", "Documents · Stopped".
    public let line: String
    /// 0…1 when the daemon reported a count; nil draws no bar.
    public let progress: Double?
}

/// One row under "Up next".
public struct UpNextItem: Equatable, Identifiable {
    public let id: Int
    public let title: String
    /// "Aux · tomorrow 08:00", or the job's own schedule words.
    public let line: String
}

public enum WorkTab {
    /// Rows shown before "n more" (the panel also holds the agent profile).
    public static let limit = 4

    public static func active(approvals: [Approval], delegations: [Delegation], stopped: Bool, language: Language) -> [WorkItem] {
        let waiting = approvals.map { approval in
            WorkItem(id: approval.id, kind: .waiting,
                     title: approval.headline.components(separatedBy: " · ").first ?? approval.headline,
                     agent: approval.agent,
                     line: TeamMember.displayName(approval.agent) + " · " + L10n.ui(.apNeedsYou, language),
                     progress: nil)
        }
        let running = delegations.filter(\.state.isOpen).map { delegation -> WorkItem in
            let name = TeamMember.displayName(delegation.agent)
            let count = delegation.progress ?? (delegation.steps.isEmpty ? nil
                : (delegation.steps.filter { $0.state == .done }.count, delegation.steps.count))
            let progress = count.flatMap { $0.of > 0 ? min(1, Double($0.n) / Double($0.of)) : nil }
            let line: String
            if stopped { line = name + " · " + L10n.ui(.stepMarkHalted, language) }
            else if let count { line = L10n.uf(.workStepsOf, language, name, count.n, count.of) }
            else { line = name + " · " + L10n.ui(.agentWorking, language) }
            return WorkItem(id: delegation.id, kind: stopped ? .halted : .running, title: delegation.ask,
                            agent: delegation.agent, line: line, progress: stopped ? nil : progress)
        }
        return waiting + running
    }

    /// Enabled jobs, soonest first; a job without a next time keeps its schedule words.
    public static func upNext(_ jobs: [PlannedJob], now: Date, language: Language) -> [UpNextItem] {
        let calendar = Calendar.current
        return jobs.filter(\.enabled)
            .sorted { (TimeText.parse($0.nextRunAt) ?? .distantFuture) < (TimeText.parse($1.nextRunAt) ?? .distantFuture) }
            .map { job in
                let when: String
                if let at = TimeText.parse(job.nextRunAt) {
                    let clock = TimeText.clock(at)
                    if calendar.isDate(at, inSameDayAs: now) { when = L10n.uf(.workToday, language, clock) }
                    else if let next = calendar.date(byAdding: .day, value: 1, to: now), calendar.isDate(at, inSameDayAs: next) {
                        when = L10n.uf(.workTomorrow, language, clock)
                    } else {
                        let day = DateFormatter()
                        day.locale = Locale(identifier: language.localeIdentifier)
                        day.dateFormat = "EEE d MMM"
                        when = day.string(from: at) + " " + clock
                    }
                } else {
                    when = job.schedule
                }
                return UpNextItem(id: job.id, title: job.name, line: TeamMember.displayName(job.agent) + " · " + when)
            }
    }
}
