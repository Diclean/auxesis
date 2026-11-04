// TODAY-SHAPE-1: what Today shows first, by plain rules over data the app
// already holds; no model call, no invented priority. Precedence: waiting
// approvals > failing, then late jobs > first event within 2 h > unread mail
// > calm. "What matters first" lists up to three rows in the same order.
import Foundation

/// A waiting approval as Today needs it: the view passes the row headline.
public typealias TodayFocusApproval = (id: String, headline: String, agent: String, at: Date?)

public enum TodayFocusLine: Equatable {
    case waiting(count: Int)
    case jobFailed(name: String)
    case jobLate(name: String)
    case eventSoon(title: String, start: String)
    case unread(count: Int, atLeast: Bool)
    case calm

    public func text(_ language: Language) -> String {
        switch self {
        case .waiting(let count):
            return count == 1 ? L10n.ui(.todayFocusWaitingOne, language) : L10n.uf(.todayFocusWaitingMany, language, count)
        case .jobFailed(let name): return L10n.uf(.todayFocusJobFailed, language, name)
        case .jobLate(let name): return L10n.uf(.todayFocusJobLate, language, name)
        case .eventSoon(let title, let start): return L10n.uf(.todayFocusEventSoon, language, title, start)
        case .unread(let count, let atLeast):
            if atLeast { return L10n.uf(.todayFocusUnreadAtLeast, language, count) }
            return count == 1 ? L10n.ui(.todayFocusUnreadOne, language) : L10n.uf(.todayFocusUnreadMany, language, count)
        case .calm: return L10n.ui(.todayFocusCalm, language)
        }
    }
}

/// One "What matters first" row. Every action already exists in the app.
public struct TodayTopItem: Equatable, Identifiable {
    /// The card in Today's detail; the Ledger's Planned tab; Calendar; the Mail thread.
    public enum Action: Equatable { case openApproval(String), openJob(Int), openCalendar, openMail }

    public enum Mark: Equatable { case waits, late, failed }

    public let id: String
    public let title: String
    /// One line: who and when.
    public let evidence: String
    public let action: Action
    /// Nil: a plain row, no hue.
    public let mark: Mark?
}

public enum TodayFocus {
    public static let soonWindow: TimeInterval = 2 * 3600
    public static let topLimit = 3

    public static func line(approvals: [TodayFocusApproval], jobs: [PlannedJob], brief: DailyBrief,
                            now: Date, calendar: Calendar = .current) -> TodayFocusLine {
        if !approvals.isEmpty { return .waiting(count: approvals.count) }
        let bad = troubled(jobs)
        if let job = bad.first { return job.health == .failing ? .jobFailed(name: job.name) : .jobLate(name: job.name) }
        if let (event, start) = nextEvent(brief, now: now, calendar: calendar), start.timeIntervalSince(now) <= soonWindow {
            return .eventSoon(title: event.title, start: event.start ?? "")
        }
        if let mail = brief.mail, !mail.isEmpty { return .unread(count: mail.count, atLeast: brief.mailTruncated) }
        return .calm
    }

    public static func top(approvals: [TodayFocusApproval], jobs: [PlannedJob], brief: DailyBrief,
                           now: Date, language: Language, calendar: Calendar = .current) -> [TodayTopItem] {
        var rows: [TodayTopItem] = approvals.map { approval in
            let who = TeamMember.displayName(approval.agent)
            let evidence = approval.at.map { L10n.uf(.todayTopAsked, language, who, TimeText.short($0, now: now, language: language)) } ?? who
            return TodayTopItem(id: "approval-" + approval.id, title: approval.headline, evidence: evidence,
                                action: .openApproval(approval.id), mark: .waits)
        }
        rows += troubled(jobs).map { job in
            TodayTopItem(id: "job-\(job.id)", title: job.name,
                         evidence: TeamMember.displayName(job.agent) + " · " + (job.reason ?? job.schedule),
                         action: .openJob(job.id), mark: job.health == .failing ? .failed : .late)
        }
        if let (event, _) = nextEvent(brief, now: now, calendar: calendar) {
            rows.append(TodayTopItem(id: "event", title: event.title,
                                     evidence: L10n.uf(.todayTopEventAt, language, CalendarEventPresentation.timeText(for: event, language: language)),
                                     action: .openCalendar, mark: nil))
        }
        // The daemon lists unread mail newest first: the last row is the oldest.
        if let oldest = brief.mail?.last {
            rows.append(TodayTopItem(id: "mail", title: oldest.subject,
                                     evidence: L10n.uf(.todayTopOldestUnread, language, oldest.sender),
                                     action: .openMail, mark: nil))
        }
        return Array(rows.prefix(topLimit))
    }

    /// Enabled jobs that failed, then those that are late; daemon order within each.
    static func troubled(_ jobs: [PlannedJob]) -> [PlannedJob] {
        let enabled = jobs.filter(\.enabled)
        return enabled.filter { $0.health == .failing } + enabled.filter { $0.health == .late }
    }

    /// The first timed event of the brief's day that has not started yet.
    static func nextEvent(_ brief: DailyBrief, now: Date, calendar: Calendar) -> (BriefEvent, Date)? {
        (brief.events ?? [])
            .compactMap { event -> (BriefEvent, Date)? in
                guard !CalendarEventPresentation.isAllDay(event), let start = startDate(event, day: brief.day, calendar: calendar),
                      start >= now else { return nil }
                return (event, start)
            }
            .min { $0.1 < $1.1 }
    }

    /// "yyyy-MM-dd" plus a local "H:mm" or "HH:mm"; nil when either does not parse.
    static func startDate(_ event: BriefEvent, day: String, calendar: Calendar) -> Date? {
        let dayParts = day.split(separator: "-").compactMap { Int($0) }
        let clock = (event.start ?? "").split(separator: ":").compactMap { Int($0) }
        guard dayParts.count == 3, clock.count == 2, (0..<24).contains(clock[0]), (0..<60).contains(clock[1]) else { return nil }
        return calendar.date(from: DateComponents(year: dayParts[0], month: dayParts[1], day: dayParts[2],
                                                  hour: clock[0], minute: clock[1]))
    }
}
