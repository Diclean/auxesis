// Today (M2): the morning brief auxd writes, read-only. `GET /v1/brief/today`
// answers it; a 404 (no route yet, or no brief) reads as the empty state.
// `notes` are the brief's own degradation lines ("Calendar: not available."),
// already in the owner's language.
import Foundation

public struct BriefEvent: Equatable, Decodable {
    public let title: String
    /// Local "HH:mm"; nil for an all-day or untimed event.
    public var start: String?
    public var end: String?
    public var allDay = false


    enum CodingKeys: String, CodingKey {
        case title, start, end
        case allDay = "all_day"
    }
}

extension BriefEvent {
    /// `all_day` may be absent (a timed event): synthesis would require it.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            title: try container.decode(String.self, forKey: .title),
            start: try container.decodeIfPresent(String.self, forKey: .start),
            end: try container.decodeIfPresent(String.self, forKey: .end),
            allDay: try container.decodeIfPresent(Bool.self, forKey: .allDay) ?? false
        )
    }
}

public struct BriefMail: Equatable, Decodable {
    public let sender: String
    public let subject: String

}

/// A sender today's brief suggests as a possible new client. `reason` is a
/// code (quote / availability / referral), never text from the mail; `date`
/// is the mail's own date header, as read.
public struct BriefProspect: Equatable, Decodable, Identifiable {
    public let account: String
    public var name: String = ""
    public let email: String
    public let reason: String
    public var date: String = ""

    /// What the daemon matches on: the account and the address, any case.
    public var id: String { account + "\n" + email.lowercased() }

    /// The row's first line: the name, else the address.
    public var title: String {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? email : trimmed
    }

    public var reasonKey: UIKey {
        switch reason {
        case "availability": return .prospectAvailability
        case "referral": return .prospectReferral
        default: return .prospectQuote
        }
    }

    /// "14 Oct, 09:00" in local time from an RFC 2822 date; the raw text when
    /// it does not parse.
    public func shortDate(_ language: Language, timeZone: TimeZone = .current) -> String {
        let parser = DateFormatter()
        parser.locale = Locale(identifier: "en_US_POSIX")
        let raw = date.trimmingCharacters(in: .whitespaces)
        for format in ["EEE, d MMM yyyy HH:mm:ss Z", "d MMM yyyy HH:mm:ss Z"] {
            parser.dateFormat = format
            if let parsed = parser.date(from: raw) {
                let out = DateFormatter()
                out.locale = Locale(identifier: language == .fr ? "fr_FR" : "en_GB")
                out.timeZone = timeZone
                out.dateFormat = "d MMM, HH:mm"
                return out.string(from: parsed)
            }
        }
        return raw
    }

    enum CodingKeys: String, CodingKey { case account, name, email, reason, date }
}

extension BriefProspect {
    /// `name` and `date` may be empty or absent.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            account: try container.decode(String.self, forKey: .account),
            name: try container.decodeIfPresent(String.self, forKey: .name) ?? "",
            email: try container.decode(String.self, forKey: .email),
            reason: try container.decode(String.self, forKey: .reason),
            date: try container.decodeIfPresent(String.self, forKey: .date) ?? ""
        )
    }
}

/// `POST /v1/brief/prospects/add` or `/ignore`, as the app reads it. `gone`
/// is a 404 `prospect_unknown`: already handled elsewhere, the row just leaves.
public enum ProspectOutcome: Equatable {
    case added(partyID: Int64)
    case ignored
    case gone
}

public struct DailyBrief: Equatable, Decodable {
    /// Local day, "yyyy-MM-dd".
    public let day: String
    /// When it was written, local "HH:mm".
    public var writtenAt: String?
    /// nil when the calendar could not be read (the reason is in `notes`).
    public let events: [BriefEvent]?
    /// Unread headers; nil when mail could not be read.
    public let mail: [BriefMail]?
    /// True when the inbox list reached its cap; its count is a lower bound.
    public var mailTruncated = false
    public var notes: [String] = []
    /// Possible new clients; absent on an older daemon.
    public var prospects: [BriefProspect] = []


    enum CodingKeys: String, CodingKey {
        case day, events, mail, notes, prospects
        case mailTruncated = "mail_truncated"
        case writtenAt = "written_at"
    }
}

extension DailyBrief {
    /// `notes` may be absent: a brief with no degradation lines omits it.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            day: try container.decode(String.self, forKey: .day),
            writtenAt: try container.decodeIfPresent(String.self, forKey: .writtenAt),
            events: try container.decodeIfPresent([BriefEvent].self, forKey: .events),
            mail: try container.decodeIfPresent([BriefMail].self, forKey: .mail),
            mailTruncated: try container.decodeIfPresent(Bool.self, forKey: .mailTruncated) ?? false,
            notes: try container.decodeIfPresent([String].self, forKey: .notes) ?? [],
            prospects: try container.decodeIfPresent([BriefProspect].self, forKey: .prospects) ?? []
        )
    }
}

/// `POST /v1/brief/run`: `written` carries the brief text.
public struct BriefRun: Equatable, Decodable {
    public let status: String
    public var brief: String?

}

public enum TodayGroup: String, CaseIterable, Hashable {
    case waiting, dueToday, sinceYouLeft, runningNow
}

public struct TodayQueueGroup: Equatable {
    public let kind: TodayGroup
    public let count: Int?
}

public enum TodaySelection: Equatable {
    case brief, group(TodayGroup), waiting(String), ledger(String), agent(String)
}

public enum TodayBriefCheckState: Equatable { case available, unavailable, notChecked }

public struct TodayBriefCheck: Equatable {
    public let source: UIKey
    public let state: TodayBriefCheckState
    public let note: String?
}

public struct TodayBriefChecksBlock: Equatable {
    public let heading: UIKey
    public let checks: [TodayBriefCheck]
}

public enum TodayBriefChecks {
    /// The brief has no source-specific freshness timestamps. Keep availability
    /// explicit and never infer a source timestamp from `writtenAt`.
    public static func block(for brief: DailyBrief) -> TodayBriefChecksBlock {
        let weatherNote = brief.notes.first { $0.range(of: "Weather:", options: [.anchored, .caseInsensitive]) != nil }
        return TodayBriefChecksBlock(heading: .whatBriefChecked, checks: [
            TodayBriefCheck(source: .todayCalendar, state: brief.events == nil ? .unavailable : .available, note: note(for: "Calendar", in: brief.notes)),
            TodayBriefCheck(source: .todayMail, state: brief.mail == nil ? .unavailable : .available, note: note(for: "Mail", in: brief.notes)),
            TodayBriefCheck(source: .todayWeather, state: weatherNote == nil ? .notChecked : .unavailable, note: weatherNote)
        ])
    }

    private static func note(for source: String, in notes: [String]) -> String? {
        notes.first { $0.range(of: source + ":", options: [.anchored, .caseInsensitive]) != nil }
    }
}

public enum TodayQueueModel {
    /// The order is part of the Today contract, including groups with no rows.
    public static func groups(waiting: Int, dueToday: Int, sinceYouLeft: Int?, runningNow: Int) -> [TodayQueueGroup] {
        [TodayQueueGroup(kind: .waiting, count: waiting), TodayQueueGroup(kind: .dueToday, count: dueToday),
         TodayQueueGroup(kind: .sinceYouLeft, count: sinceYouLeft), TodayQueueGroup(kind: .runningNow, count: runningNow)]
    }

    public static func resolvedSelection(_ selection: TodaySelection, waitingIDs: [String], ledgerIDs: [String], agentIDs: [String]) -> TodaySelection {
        switch selection {
        case .waiting(let id): return waitingIDs.contains(id) ? selection : .brief
        case .ledger(let id): return ledgerIDs.contains(id) ? selection : .brief
        case .agent(let id): return agentIDs.contains(id) ? selection : .brief
        case .brief, .group: return selection
        }
    }
}

/// What the Today view shows, decided here so it can be tested headlessly.
public enum TodayPresentation: Equatable {
    /// No brief for today yet: one sentence, the next run, a run button.
    case empty(nextRun: String)
    case brief(DailyBrief)

    public static let defaultRunTime = "08:00"

    public static func make(brief: DailyBrief?, today: String, jobs: [PlannedJob] = []) -> TodayPresentation {
        guard let brief, brief.day == today else { return .empty(nextRun: nextRunTime(jobs)) }
        return .brief(DailyBrief(
            day: brief.day,
            writtenAt: brief.writtenAt,
            events: brief.events.map { events in
                let unique = CalendarEventPresentation.deduplicated(
                    events,
                    title: { $0.title },
                    start: { $0.start },
                    end: { $0.end },
                    allDay: { CalendarEventPresentation.isAllDay($0) },
                    dayKey: { _ in brief.day }
                )
                return sorted(unique)
            },
            mail: brief.mail,
            mailTruncated: brief.mailTruncated,
            notes: brief.notes.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty },
            prospects: brief.prospects
        ))
    }

    /// All-day first, then by start time; untimed last. Stable for ties.
    public static func sorted(_ events: [BriefEvent]) -> [BriefEvent] {
        func rank(_ event: BriefEvent) -> (Int, String) {
            if CalendarEventPresentation.isAllDay(event) { return (0, "") }
            if let start = event.start { return (1, start.count == 4 ? "0" + start : start) }
            return (2, "")
        }
        return events.enumerated()
            .sorted { lhs, rhs in
                let (a, b) = (rank(lhs.element), rank(rhs.element))
                return a == b ? lhs.offset < rhs.offset : a < b
            }
            .map(\.element)
    }

    /// The brief job's "HH:mm" from `/v1/jobs` ("daily 08:00"), else 08:00.
    public static func nextRunTime(_ jobs: [PlannedJob]) -> String {
        let job = jobs.first { $0.name.localizedCaseInsensitiveContains("brief") }
        let time = job?.schedule.split(separator: " ").last.map(String.init)
        guard let time, time.range(of: #"^\d{1,2}:\d{2}$"#, options: .regularExpression) != nil else {
            return defaultRunTime
        }
        return time
    }

    /// Today's local day in the brief's format.
    public static func day(_ date: Date, calendar: Calendar = .current) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }
}
