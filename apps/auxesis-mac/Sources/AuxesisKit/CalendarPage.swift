// The Calendar page: the next 8 days from this Mac's EventKit
// read, the same data the app publishes to auxd, plus how fresh auxd's copy
// is and the "keep running at login" switch that keeps it fresh.
import Foundation
import ServiceManagement

/// `GET /v1/apple-eventkit/status`: the capture facts of auxd's copy, no event.
public struct CalendarSyncStatus: Decodable, Equatable {
    public var shared: Bool
    public var updatedAt: Date?
    public var fresh: Bool

    public init(shared: Bool, updatedAt: Date?, fresh: Bool) {
        self.shared = shared
        self.updatedAt = updatedAt
        self.fresh = fresh
    }

    enum CodingKeys: String, CodingKey { case shared, updatedAt = "updated_at", fresh }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        shared = try values.decode(Bool.self, forKey: .shared)
        fresh = try values.decode(Bool.self, forKey: .fresh)
        updatedAt = try values.decodeIfPresent(String.self, forKey: .updatedAt)
            .flatMap(ISO8601DateFormatter().date(from:))
    }
}

public protocol CalendarStatusClient: AnyObject {
    func calendarStatus() async throws -> CalendarSyncStatus
}

/// The one line at the top of the page. Only auxd's own `fresh` makes it fresh.
public enum CalendarSyncLine: Equatable {
    case fresh(Date)
    case stale(Date)
    /// A copy with no capture time (an older build), or no answer from auxd.
    case unknown
    case notShared

    public init(_ status: CalendarSyncStatus?) {
        guard let status else { self = .unknown; return }
        guard status.shared else { self = .notShared; return }
        switch (status.updatedAt, status.fresh) {
        case (let at?, true): self = .fresh(at)
        case (let at?, false): self = .stale(at)
        case (nil, _): self = .unknown
        }
    }

    /// Amber: a copy Aux answers from but that may be out of date.
    public var isStale: Bool {
        switch self {
        case .stale, .unknown: return true
        case .fresh, .notShared: return false
        }
    }

    public func text(now: Date = Date(), language: Language, timeZone: TimeZone = .current) -> String {
        switch self {
        case .fresh(let at):
            let minutes = max(0, Int(now.timeIntervalSince(at) / 60))
            if minutes < 1 { return L10n.ui(.calUpdatedNow, language) }
            if minutes < 60 { return String(format: L10n.ui(.calUpdatedMinutes, language), minutes) }
            return String(format: L10n.ui(.calUpdatedHours, language), minutes / 60)
        case .stale(let at):
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: language == .fr ? "fr_FR" : "en_GB")
            formatter.timeZone = timeZone
            formatter.dateFormat = "EEE d MMM, HH:mm"
            return String(format: L10n.ui(.calNotUpdatedSince, language), formatter.string(from: at))
        case .unknown: return L10n.ui(.calUpdateUnknown, language)
        case .notShared: return L10n.ui(.calNotShared, language)
        }
    }
}

public enum LoginItemState: Equatable { case enabled, requiresApproval, off, unavailable }

/// Test seam for `SMAppService.mainApp`.
public protocol LoginItemControlling: AnyObject {
    var state: LoginItemState { get }
    func setEnabled(_ on: Bool) throws
}

/// The real login item. Only the owner's switch on the page calls `setEnabled`.
public final class SystemLoginItem: LoginItemControlling {
    public init() {}
    public var state: LoginItemState {
        switch SMAppService.mainApp.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .unavailable
        default: return .off
        }
    }
    public func setEnabled(_ on: Bool) throws {
        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    }
}

/// Sandbox and fixture runs: never touches macOS login items.
public final class SandboxedLoginItem: LoginItemControlling {
    public private(set) var state: LoginItemState = .off
    public init() {}
    public func setEnabled(_ on: Bool) throws { state = on ? .enabled : .off }
}

public struct CalendarDay: Identifiable, Equatable {
    public let day: Date
    public let events: [AppleEventItem]
    public var id: Date { day }

    /// "Wednesday 21 October" / "Mercredi 21 octobre", led by "Today · " on today.
    public static func title(
        _ day: Date, language: Language, calendar: Calendar = .current, now: Date = Date()
    ) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language == .fr ? "fr_FR" : "en_GB")
        formatter.timeZone = calendar.timeZone
        formatter.setLocalizedDateFormatFromTemplate("EEEEdMMMM")
        let date = formatter.string(from: day)
        // FR day names are lowercase; a heading starts with a capital.
        let heading = date.prefix(1).uppercased() + date.dropFirst()
        return calendar.isDate(day, inSameDayAs: now) ? "\(L10n.ui(.today, language)) · \(heading)" : heading
    }
}

public enum CalendarEventPresentation {
    /// Uses EventKit's flag when present; otherwise recognizes local midnight
    /// through 23:59, including EventKit's exclusive midnight boundary.
    public static func isAllDay(_ event: AppleEventItem, calendar: Calendar = .current) -> Bool {
        if let allDay = event.allDay { return allDay }
        let iso = ISO8601DateFormatter()
        guard let start = iso.date(from: event.start), let end = iso.date(from: event.end), end > start,
              calendar.startOfDay(for: start) == start else { return false }
        let endHour = calendar.component(.hour, from: end)
        let endMinute = calendar.component(.minute, from: end)
        return calendar.startOfDay(for: end) == end
            || calendar.startOfDay(for: end.addingTimeInterval(1)) == end.addingTimeInterval(1)
            || (endHour == 23 && endMinute == 59)
    }

    public static func timeText(for event: BriefEvent, language: Language) -> String {
        timeText(start: event.start, end: event.end, allDay: isAllDay(event), language: language)
    }

    /// A brief event is all-day when flagged, or when it runs 00:00–23:59
    /// (briefs written before the flag existed).
    public static func isAllDay(_ event: BriefEvent) -> Bool {
        event.allDay || (event.start == "00:00" && event.end == "23:59")
    }

    /// Titles compare without case, apostrophe style or extra spaces, so two
    /// calendars spelling "Heure d'hiver" / "Heure d’hiver" count once.
    static func titleKey(_ title: String) -> String {
        title.replacingOccurrences(of: "\u{2019}", with: "'")
            .replacingOccurrences(of: "\u{2018}", with: "'")
            .split(whereSeparator: \.isWhitespace).joined(separator: " ")
            .lowercased()
    }

    public static func timeText(
        for event: AppleEventItem, language: Language, calendar: Calendar = .current
    ) -> String {
        timeText(
            start: localTime(event.start, calendar: calendar),
            end: localTime(event.end, calendar: calendar),
            allDay: isAllDay(event, calendar: calendar),
            language: language
        )
    }

    static func timeText(start: String?, end: String?, allDay: Bool, language: Language) -> String {
        if allDay { return L10n.ui(.todayAllDay, language) }
        guard let start else { return "" }
        return end.map { "\(start)–\($0)" } ?? start
    }

    static func deduplicated<T>(
        _ events: [T],
        title: (T) -> String,
        start: (T) -> String?,
        end: (T) -> String?,
        allDay: (T) -> Bool,
        dayKey: (T) -> String?
    ) -> [T] {
        var result: [T] = []
        for event in events {
            let duplicate = result.contains { first in
                guard titleKey(title(first)) == titleKey(title(event)) else { return false }
                if allDay(first), allDay(event),
                   let firstDay = dayKey(first), firstDay == dayKey(event) {
                    return true
                }
                guard let firstStart = start(first), let firstEnd = end(first),
                      let eventStart = start(event), let eventEnd = end(event) else { return false }
                return firstStart == eventStart && firstEnd == eventEnd
            }
            if !duplicate { result.append(event) }
        }
        return result
    }

    static func dayKey(from raw: String?, calendar: Calendar) -> String? {
        guard let raw, let date = ISO8601DateFormatter().date(from: raw) else { return nil }
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        guard let year = parts.year, let month = parts.month, let day = parts.day else { return nil }
        return String(format: "%04d-%02d-%02d", year, month, day)
    }

    private static func localTime(_ raw: String, calendar: Calendar) -> String? {
        guard let date = ISO8601DateFormatter().date(from: raw) else { return nil }
        let formatter = DateFormatter()
        formatter.timeZone = calendar.timeZone
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: date)
    }
}

public extension AppleEventItem {
    func isAllDay(calendar: Calendar = .current) -> Bool {
        CalendarEventPresentation.isAllDay(self, calendar: calendar)
    }

    /// The time column: "09:30–10:00", or "All day" as on Today.
    func timeText(language: Language, calendar: Calendar = .current) -> String {
        CalendarEventPresentation.timeText(for: self, language: language, calendar: calendar)
    }
}

@MainActor public final class CalendarPageModel: ObservableObject {
    @Published public private(set) var snapshot: AppleEventKitSnapshot?
    @Published public private(set) var status: CalendarSyncStatus?
    @Published public private(set) var refreshing = false
    @Published public private(set) var loginItem: LoginItemState
    @Published public private(set) var loginItemFailed = false
    /// Why the last cycle published nothing; nil once one publishes.
    @Published public private(set) var problem: CalendarAutoRefresher.Outcome?

    private let refresher: CalendarAutoRefresher
    private let loadStatus: () async throws -> CalendarSyncStatus
    private let login: LoginItemControlling
    private var loop: Task<Void, Never>?

    public init(
        refresher: CalendarAutoRefresher,
        status: @escaping () async throws -> CalendarSyncStatus,
        login: LoginItemControlling
    ) {
        self.refresher = refresher
        self.loadStatus = status
        self.login = login
        loginItem = login.state
        // Weak both ways: the refresher keeps this closure.
        refresher.didRefresh = { [weak self, weak refresher] outcome in
            guard let self, let refresher else { return }
            self.snapshot = refresher.lastRead
            self.problem = outcome == .published ? nil : outcome
            // The loop's cycles; "Refresh now" reloads the status itself.
            if !self.refreshing { Task { await self.reloadStatus() } }
        }
    }

    public var line: CalendarSyncLine { CalendarSyncLine(status) }

    /// Nothing to refresh until Calendar access is on: the page offers
    /// Settings instead of a button that can never work.
    public var needsCalendarAccess: Bool { line == .notShared || problem == .noAccess }

    /// The one red line under the sync line, or nil. Not shared already says
    /// the access is off, so it is not said twice.
    public func problemText(language: Language) -> String? {
        switch problem {
        case nil, .published?: return nil
        case .noAccess?: return line == .notShared ? nil : L10n.ui(.calErrNoAccess, language)
        case .offline?: return L10n.ui(.calErrOffline, language)
        case .failed?: return L10n.ui(.calErrFailed, language)
        }
    }

    /// The 30-minute loop, for the app's whole life (window or not). Idempotent.
    public func start() {
        guard loop == nil else { return }
        loop = Task { [refresher] in await refresher.run() }
    }

    /// "Refresh now": one cycle of the same refresher, then auxd's answer.
    public func refreshNow() async {
        guard !refreshing else { return }
        refreshing = true
        await refresher.refreshOnce()
        await reloadStatus()
        refreshing = false
    }

    public func reloadStatus() async {
        status = try? await loadStatus()
        reloadLoginItem()
    }

    /// Re-reads macOS's answer, e.g. when the owner comes back from approving
    /// it in System Settings.
    public func reloadLoginItem() {
        loginItem = login.state
    }

    /// The owner's switch. The page then shows what macOS says, not the switch.
    public func setLoginItem(_ on: Bool) {
        do {
            try login.setEnabled(on)
            loginItemFailed = false
        } catch {
            loginItemFailed = true
        }
        loginItem = login.state
    }

    /// Events by local day, in time order; a day with none is left out.
    public func days(calendar: Calendar = .current) -> [CalendarDay] {
        guard let snapshot else { return [] }
        return Self.days(in: snapshot, calendar: calendar)
    }

    static func days(in snapshot: AppleEventKitSnapshot, calendar: Calendar = .current) -> [CalendarDay] {
        let formatter = ISO8601DateFormatter()
        // An event that began before the window shows on its first day.
        let first = snapshot.coversFrom.flatMap(formatter.date(from:)) ?? .distantPast
        let events = CalendarEventPresentation.deduplicated(
            snapshot.events,
            title: { $0.title },
            start: { $0.start },
            end: { $0.end },
            allDay: { $0.isAllDay(calendar: calendar) },
            dayKey: { CalendarEventPresentation.dayKey(from: $0.start, calendar: calendar) }
        )
        let dated = events.compactMap { event in
            formatter.date(from: event.start).map { (max($0, first), event) }
        }
        let grouped = Dictionary(grouping: dated.sorted { $0.0 < $1.0 }) { calendar.startOfDay(for: $0.0) }
        return grouped.keys.sorted().map { CalendarDay(day: $0, events: grouped[$0]!.map(\.1)) }
    }
}
