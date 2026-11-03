import Darwin
import EventKit
import Foundation

public struct AppleEventItem: Codable, Equatable {
    public var title: String
    public var start: String
    public var end: String
    public var calendar: String
    public var location: String?
    public var calendarID: String? = nil
    public var allDay: Bool? = nil
    /// EventKit's event id and guest addresses (CAL-UPDATE-1): the daemon finds
    /// an event to move by them, and an event whose guests are unknown keeps
    /// its card. An event with no guests sends an empty list, never none.
    public var id: String? = nil
    public var attendees: [String]? = nil
    /// CAL-DEFAULT-ID (r2): the event is part of a recurring series, or a
    /// detached occurrence of one. Such an event never takes the
    /// approval-free path: EventKit's lookup can return the first occurrence,
    /// not the one the copy saw.
    public var recurring: Bool? = nil

    enum CodingKeys: String, CodingKey {
        case title, start, end, calendar, location, id, attendees, recurring
        case calendarID = "calendar_id"
        case allDay = "all_day"
    }
}

public struct AppleReminderItem: Codable, Equatable {
    public var title: String
    public var due: String?
    public var list: String
    public var completed: Bool
}

public struct AppleEventKitSnapshot: Codable, Equatable {
    public var authorized: Bool
    public var events: [AppleEventItem]
    public var reminders: [AppleReminderItem]
    /// When EventKit was read (UTC), so auxd never guesses from a write time.
    public var capturedAt: String? = nil
    /// The window that read queried, in UTC: the start of the local day, out 8 days.
    public var coversFrom: String? = nil
    public var coversTo: String? = nil
    /// The id of the calendar new events go to by default (CAL-DEFAULT-ID):
    /// auxd tells the owner's default calendar from a shared one by id, never
    /// by title. Absent when the owner has no default calendar.
    public var defaultCalendarID: String? = nil
    /// CAL-COMPLETE-DEDUP: the read found more items than the app keeps, so
    /// one may be missing. auxd never reads a cut list as a whole calendar.
    /// Absent on an older snapshot: then the list is not known to be cut.
    public var eventsTruncated: Bool = false
    public var remindersTruncated: Bool = false

    enum CodingKeys: String, CodingKey {
        case authorized, events, reminders
        case capturedAt = "captured_at", coversFrom = "covers_from", coversTo = "covers_to"
        case defaultCalendarID = "default_calendar_id"
        case eventsTruncated = "events_truncated", remindersTruncated = "reminders_truncated"
    }

    /// The app keeps at most this many events and reminders; the flags above
    /// say when it had to cut the list.
    private static let maxItems = 100

    /// Bounds the items to the window read. A second pass (the publish after
    /// the read) keeps the window and capture time the read wrote, so a read
    /// at 23:59 published at 00:01 still says what it covers.
    public func boundedAndCleaned(now: Date = Date(), calendar: Calendar = .current) -> AppleEventKitSnapshot {
        guard authorized else { return AppleEventKitSnapshot(authorized: false, events: [], reminders: []) }
        let formatter = ISO8601DateFormatter()
        let start = coversFrom.flatMap(formatter.date(from:)) ?? calendar.startOfDay(for: now)
        let end = coversTo.flatMap(formatter.date(from:)) ?? calendar.date(byAdding: .day, value: 8, to: start) ?? start
        let clean: (String) -> String = { text in
            String(text.unicodeScalars.filter {
                $0.properties.generalCategory != .format && !CharacterSet.controlCharacters.contains($0)
            }.prefix(240))
        }
        let eventsInWindow = events.filter { item in
            guard let begins = formatter.date(from: item.start), let finishes = formatter.date(from: item.end) else { return false }
            return finishes > start && begins < end
        }
        let events = eventsInWindow.prefix(Self.maxItems).map { item in
            AppleEventItem(title: clean(item.title), start: item.start, end: item.end,
                calendar: clean(item.calendar), location: item.location.map(clean),
                calendarID: item.calendarID.map(clean), allDay: item.allDay, id: item.id.map(clean),
                attendees: item.attendees.map { Array($0.map(clean).prefix(100)) },
                recurring: item.recurring)
        }
        let remindersInWindow = reminders.filter { item in
            guard let due = item.due else { return false }
            guard let date = formatter.date(from: due) else { return false }
            return date >= start && date < end
        }
        let reminders = remindersInWindow.prefix(Self.maxItems).map { item in
            AppleReminderItem(title: clean(item.title), due: item.due, list: clean(item.list), completed: item.completed)
        }
        return AppleEventKitSnapshot(authorized: true, events: Array(events), reminders: Array(reminders),
            capturedAt: capturedAt, coversFrom: formatter.string(from: start), coversTo: formatter.string(from: end),
            defaultCalendarID: defaultCalendarID.map(clean),
            eventsTruncated: eventsInWindow.count > Self.maxItems,
            remindersTruncated: remindersInWindow.count > Self.maxItems)
    }
}

public enum AppleEventKitAccess: Equatable {
    case notDetermined, denied, authorized, restricted
}

/// Test seam for the system EventKit adapter. Tests use a fake and never touch
/// the owner's calendars or reminders.
@MainActor public protocol AppleEventKitProviding: AnyObject {
    var access: AppleEventKitAccess { get }
    func requestAccessAndRead() async throws -> AppleEventKitSnapshot
    /// Reads only when access is already granted; never asks for it.
    func readIfAuthorized() async throws -> AppleEventKitSnapshot
}

/// Used in sandbox runs: never touches the real EventKit, so an app started
/// with `AUXESIS_SANDBOX=1` cannot read or publish the owner's calendar even
/// when this bundle id already holds Calendar access.
@MainActor public final class SandboxedAppleEventKit: AppleEventKitProviding {
    public init() {}
    public var access: AppleEventKitAccess { .denied }
    public func requestAccessAndRead() async throws -> AppleEventKitSnapshot {
        AppleEventKitSnapshot(authorized: false, events: [], reminders: [])
    }
    public func readIfAuthorized() async throws -> AppleEventKitSnapshot {
        try await requestAccessAndRead()
    }
}

/// The EventKit reads the publisher makes. `EKEventStore` is a system class
/// no test can build, so the publisher reads through this protocol: the
/// system adapter wraps the real store, a test uses a fake and never touches
/// the owner's calendars.
@MainActor public protocol AppleEventKitReading: AnyObject {
    var eventAccess: EKAuthorizationStatus { get }
    var reminderAccess: EKAuthorizationStatus { get }
    func requestEventAccess() async throws -> Bool
    func requestReminderAccess() async throws -> Bool
    /// The id of the calendar new events go to by default (CAL-DEFAULT-ID).
    var defaultCalendarID: String? { get }
    /// The events in the window, mapped for the snapshot.
    func events(from start: Date, to end: Date) -> [AppleEventItem]
    /// The incomplete reminders due in the window.
    func reminders(from start: Date, to end: Date) async -> [AppleReminderItem]
}

/// The real EventKit behind the publisher's seam.
@MainActor final class SystemEventKitReader: AppleEventKitReading {
    private let store: EKEventStore
    init(store: EKEventStore = EKEventStore()) { self.store = store }

    var eventAccess: EKAuthorizationStatus { EKEventStore.authorizationStatus(for: .event) }
    var reminderAccess: EKAuthorizationStatus { EKEventStore.authorizationStatus(for: .reminder) }
    func requestEventAccess() async throws -> Bool { try await store.requestFullAccessToEvents() }
    func requestReminderAccess() async throws -> Bool { try await store.requestFullAccessToReminders() }
    var defaultCalendarID: String? { store.defaultCalendarForNewEvents?.calendarIdentifier }

    func events(from start: Date, to end: Date) -> [AppleEventItem] {
        let predicate = store.predicateForEvents(withStart: start, end: end, calendars: nil)
        return store.events(matching: predicate).map { event in
            // CAL-DEFAULT-ID (r2): a recurring event, or a detached occurrence
            // of one, never takes the approval-free path.
            let recurring = event.hasRecurrenceRules || event.isDetached
            return AppleEventItem(title: event.title, start: Self.iso(event.startDate),
                end: Self.iso(event.endDate), calendar: event.calendar.title,
                location: event.location, calendarID: event.calendar.calendarIdentifier,
                allDay: event.isAllDay, id: event.eventIdentifier,
                attendees: (event.attendees ?? []).map(\.url.absoluteString),
                recurring: recurring ? true : nil)
        }
    }

    func reminders(from start: Date, to end: Date) async -> [AppleReminderItem] {
        let predicate = store.predicateForIncompleteReminders(withDueDateStarting: start, ending: end, calendars: nil)
        let items = await withCheckedContinuation { continuation in
            store.fetchReminders(matching: predicate) { items in
                continuation.resume(returning: items ?? [])
            }
        }
        return items.map { item in
            AppleReminderItem(title: item.title, due: item.dueDateComponents?.date.map(Self.iso),
                list: item.calendar.title, completed: item.isCompleted)
        }
    }

    private static func iso(_ date: Date) -> String { ISO8601DateFormatter().string(from: date) }
}

@MainActor public final class SystemAppleEventKit: AppleEventKitProviding {
    private let reader: AppleEventKitReading
    /// The publisher over the real EventKit, or over a reader a test fakes.
    public convenience init() { self.init(reader: SystemEventKitReader()) }
    public init(reader: AppleEventKitReading) { self.reader = reader }

    public var access: AppleEventKitAccess {
        Self.access(events: reader.eventAccess)
    }

    /// Calendar access alone decides: the brief needs events, and reminders
    /// are read only when they are granted too.
    nonisolated static func access(events: EKAuthorizationStatus) -> AppleEventKitAccess {
        switch events {
        case .fullAccess: return .authorized
        case .denied: return .denied
        case .restricted: return .restricted
        default: return .notDetermined
        }
    }

    public func requestAccessAndRead() async throws -> AppleEventKitSnapshot {
        let eventsGranted = try await reader.requestEventAccess()
        // Reminders are optional: a refusal never blocks the calendar.
        _ = try? await reader.requestReminderAccess()
        guard eventsGranted else {
            return AppleEventKitSnapshot(authorized: false, events: [], reminders: [])
        }
        return await read()
    }

    public func readIfAuthorized() async throws -> AppleEventKitSnapshot {
        guard access == .authorized else {
            return AppleEventKitSnapshot(authorized: false, events: [], reminders: [])
        }
        return await read()
    }

    private func read() async -> AppleEventKitSnapshot {
        let calendar = Calendar.current
        let captured = Date()
        let start = calendar.startOfDay(for: captured)
        let end = calendar.date(byAdding: .day, value: 8, to: start)!
        let events = reader.events(from: start, to: end)
        let reminders = reader.reminderAccess == .fullAccess
            ? await reader.reminders(from: start, to: end) : []
        return AppleEventKitSnapshot(authorized: true, events: events, reminders: reminders,
            capturedAt: Self.iso(captured), defaultCalendarID: reader.defaultCalendarID)
            .boundedAndCleaned(now: start, calendar: calendar)
    }

    private static func iso(_ date: Date) -> String { ISO8601DateFormatter().string(from: date) }
}

public protocol AppleEventKitSnapshotClient: AnyObject {
    func publishAppleEventKit(_ snapshot: AppleEventKitSnapshot) async throws
}

// MARK: - Mac bridge writes (A2b-app)

/// Owns the bridge's own `EKEventStore` and serialises every call on it through
/// this actor, so the main-actor snapshot store is never touched off-main and
/// no store is shared across isolation domains. The store is created on the
/// first op: a client that never serves a bridge request never builds one.
/// The bridge writer of a sandbox run: refuses every write, so an approved
/// calendar skill in a sandbox never reads or changes the owner's calendars.
final class SandboxedEventWriter: EventWriter {
    func createEvent(
        calendar: String?, title: String, start: String, end: String,
        location: String?, notes: String?, url: String?
    ) async throws -> BridgeEventResult { throw BridgeFailure.accessDenied }
    func updateEvent(
        eventId: String, calendar: String?, title: String?, start: String?,
        end: String?, location: String?, notes: String?, url: String?,
        expected: BridgeExpectations?
    ) async throws -> BridgeEventResult { throw BridgeFailure.accessDenied }
}

/// The bridge writer of a sandbox run (`AUXESIS_SANDBOX=1`): it records every
/// write in a file under the throwaway home and never touches EventKit, so a
/// sandbox run can prove that an approved event was written without ever
/// reading or changing the owner's calendars. The file is
/// `sandbox-calendar.jsonl` under `AUXESIS_HOME` (or `$HOME/.auxesis`), one
/// JSON object per line, inside the sandbox home the run deletes.
///
/// The record file is never followed and never grows without a bound:
///   - the sandbox home is opened once, `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|
///     O_CLOEXEC`, and the descriptor it yields is both the proof that the
///     home is a real directory and the anchor the record is opened from:
///     the home path is resolved once, so it cannot be swapped between a
///     check and an open;
///   - the record is opened relative to that descriptor, `openat`,
///     `O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, so it
///     always sits directly in the validated home: a symlink at the record
///     path fails with ELOOP instead of appending into the file it points at
///     — a link must never append into a file the sandbox run does not own —
///     and a FIFO at the path cannot block the open;
///   - `fstat` on the descriptor proves the file is a regular one, so a
///     directory, a FIFO or a device at the path is refused;
///   - the home path never traverses (`..`), the home is a real directory
///     and never a symlink;
///   - a record at the cap is refused, so the file cannot grow without a
///     bound.
/// Every refusal is a failure: the run must never say the event was created
/// when it was not.
final class SandboxRecordingEventWriter: EventWriter {
    /// The cap of the record file: 1 MiB, the same bound the daemon puts on a
    /// bridge answer body. A record at the cap is refused, never truncated.
    static let maxRecordBytes = 1024 * 1024
    /// The name of the record file inside the sandbox home.
    static let recordName = "sandbox-calendar.jsonl"

    /// The validated sandbox home; nil when no home is known.
    private let home: URL?

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        let raw = environment["AUXESIS_HOME"].flatMap { $0.isEmpty ? nil : $0 }
            ?? environment["HOME"].map { "\($0)/.auxesis" }
        // A home that traverses (`..`) is not a sandbox home: the record would
        // land outside the throwaway home the run deletes.
        guard let raw, !raw.split(separator: "/").contains("..") else {
            home = nil
            return
        }
        home = URL(fileURLWithPath: raw, isDirectory: true)
    }

    func createEvent(
        calendar: String?, title: String, start: String, end: String,
        location: String?, notes: String?, url: String?
    ) async throws -> BridgeEventResult {
        // CAL-BLANK-CREATE: a blank field is the absent field, so the sandbox
        // records the same default the real app would use.
        let named = calendar.flatMap { name -> String? in
            name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : name
        }
        return try record(["op": "create", "title": title, "start": start, "end": end,
                           "calendar": named ?? "Sandbox"])
    }

    func updateEvent(
        eventId: String, calendar: String?, title: String?, start: String?,
        end: String?, location: String?, notes: String?, url: String?,
        expected: BridgeExpectations?
    ) async throws -> BridgeEventResult {
        // The update keeps its event's id and records only what changed, so
        // the record still holds one event (CAL-UPDATE-1). A sandbox run
        // touches no real calendar, so there is no live event to check the
        // expectations against (CAL-DEFAULT-ID r1).
        let fields: [String: String?] = ["op": "update", "event_id": eventId, "title": title,
                                          "start": start, "end": end, "calendar": calendar]
        return try record(fields.compactMapValues { $0 })
    }

    /// One line of JSON, appended. A home that cannot be written is a refusal:
    /// the run must never say the event was created when it was not.
    private func record(_ fields: [String: String]) throws -> BridgeEventResult {
        guard let home else { throw BridgeFailure.accessDenied }
        var line = fields
        line["event_id"] = fields["event_id"] ?? "sandbox-" + UUID().uuidString
        guard let data = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { throw BridgeFailure.failed }
        try Self.append(text + "\n", under: home)
        return BridgeEventResult(eventId: line["event_id"] ?? "", calendar: line["calendar"] ?? "Sandbox")
    }

    /// Appends one line to the record file, refusing anything that is not a
    /// plain file inside the validated sandbox home.
    private static func append(_ line: String, under home: URL) throws {
        guard let fd = openRecordFile(under: home) else { throw BridgeFailure.failed }
        defer { Darwin.close(fd) }
        let data = Data(line.utf8)
        try data.withUnsafeBytes { raw -> Void in
            guard let base = raw.baseAddress else { throw BridgeFailure.failed }
            var written = 0
            while written < raw.count {
                let count = Darwin.write(fd, base.advanced(by: written), raw.count - written)
                if count < 0 {
                    if errno == EINTR { continue }
                    throw BridgeFailure.failed
                }
                written += count
            }
        }
    }

    /// Opens the record file for appending, or refuses it:
    ///   - the home is opened once, and the descriptor it yields is the
    ///     proof that the home is a real directory: `O_NOFOLLOW` refuses a
    ///     symlinked home with ELOOP, and the open is the only resolution of
    ///     the home path, so the home cannot be swapped between a check and
    ///     an open;
    ///   - the record is opened relative to that descriptor, so it always
    ///     sits directly in the validated home, never somewhere else;
    ///   - the open never follows a link: `O_NOFOLLOW` makes a symlink at
    ///     the path fail with ELOOP, and `O_NONBLOCK` keeps a FIFO at the
    ///     path from blocking the open;
    ///   - `fstat` on the descriptor proves the file is a regular one;
    ///   - the file is private (0600) and under the cap.
    private static func openRecordFile(under home: URL) -> Int32? {
        // The home, opened once: the descriptor is the anchor every later
        // step uses, so the home path is resolved exactly once.
        let homePath = home.standardizedFileURL.path
        let dirFD = homePath.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard dirFD >= 0 else { return nil }
        var homeInfo = stat()
        guard Darwin.fstat(dirFD, &homeInfo) == 0,
              (homeInfo.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
            Darwin.close(dirFD)
            return nil
        }

        // The record sits directly in that home: the open is relative to the
        // descriptor, so the resolved parent is the validated home.
        let fd = Self.recordName.withCString {
            Darwin.openat(dirFD, $0, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                          mode_t(S_IRUSR | S_IWUSR))
        }
        Darwin.close(dirFD)
        guard fd >= 0 else { return nil }

        // The descriptor decides: a regular file, private, and under the cap.
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              Darwin.fchmod(fd, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            Darwin.close(fd)
            return nil
        }
        guard info.st_size < off_t(maxRecordBytes) else {
            Darwin.close(fd)
            return nil
        }
        return fd
    }
}

/// The real EventKit writer only outside a sandbox run (`AUXESIS_SANDBOX=1`
/// or a HOME that is not the OS user's home).
///
/// A sandbox run with the flag records its writes under the throwaway home; a
/// sandbox without it (a HOME that is not the OS user's home) refuses every
/// write. The owner's own app is the only one that writes the owner's
/// calendars.
func bridgeEventWriter(environment: [String: String] = ProcessInfo.processInfo.environment) -> EventWriter {
    if environment["AUXESIS_SANDBOX"] == "1" {
        return SandboxRecordingEventWriter(environment: environment)
    }
    return EndpointResolver.isSandboxed(env: environment) ? SandboxedEventWriter() : EventKitBridgeWriter()
}

actor EventKitBridgeWriter: EventWriter {
    private var store: EKEventStore?

    init() {}

    private func eventStore() -> EKEventStore {
        if let store { return store }
        let created = EKEventStore()
        store = created
        return created
    }

    /// Event-only access: a bridge write never needs the reminder permission.
    private func accessAllowed() -> Bool {
        EKEventStore.authorizationStatus(for: .event) == .fullAccess
    }

    func createEvent(
        calendar: String?, title: String, start: String, end: String,
        location: String?, notes: String?, url: String?
    ) async throws -> BridgeEventResult {
        let store = eventStore()
        guard accessAllowed() else { throw BridgeFailure.accessDenied }
        let request = BridgeWriteRequest.create(CreateEventArgs(
            calendar: calendar, title: title, start: start, end: end,
            location: location, notes: notes, url: url))
        let calendars = store.calendars(for: .event)
        // The plan is computed and validated before any EKEvent exists.
        let plan = try resolvedPlan(request, existing: nil, calendars: calendars, store: store)
        let target = try resolvedTarget(plan.calendar, calendars: calendars, store: store)
        let event = EKEvent(eventStore: store)
        // Attendees are deliberately never set: EventKit cannot send invites;
        // the invite goes by mail with an `.ics` (docs/mail.md §5).
        apply(plan, to: event, target: target)
        try save(event, in: store)
        return BridgeEventResult(
            eventId: event.eventIdentifier ?? "",
            calendar: event.calendar?.title ?? "")
    }

    func updateEvent(
        eventId: String, calendar: String?, title: String?, start: String?,
        end: String?, location: String?, notes: String?, url: String?,
        expected: BridgeExpectations?
    ) async throws -> BridgeEventResult {
        let store = eventStore()
        guard accessAllowed() else { throw BridgeFailure.accessDenied }
        guard let event = store.event(withIdentifier: eventId),
              let existingStart = event.startDate, let existingEnd = event.endDate else {
            throw BridgeFailure(code: "not_found", message: "no such event")
        }
        // CAL-DEFAULT-ID (r1): the copy the approval rested on may be stale. The
        // live event is checked before anything is touched: a guest added, or a
        // calendar moved, refuses the write and saves nothing. A recurring
        // event refuses it too (r2): EventKit's lookup can return the first
        // occurrence, not the one the copy saw.
        if let expected {
            let facts = BridgeWriteFacts.decide(
                liveCalendarID: event.calendar?.calendarIdentifier ?? "",
                liveAttendees: event.attendees?.count ?? 0,
                recurring: event.hasRecurrenceRules || event.isDetached,
                expected: expected)
            guard facts == .save else {
                store.reset()
                throw BridgeFailure.factsChanged
            }
        }
        let request = BridgeWriteRequest.update(UpdateEventArgs(
            eventId: eventId, calendar: calendar, title: title, start: start,
            end: end, location: location, notes: notes, url: url,
            expectedCalendarID: expected?.calendarID,
            expectedAttendees: expected?.attendees))
        let existing = BridgeWritePlanner.Existing(
            title: event.title ?? "", start: existingStart, end: existingEnd,
            location: event.location, notes: event.notes, url: event.url?.absoluteString)
        let calendars = store.calendars(for: .event)
        // Nothing on the cached event is touched until the plan and the target
        // calendar both succeed; a refusal resets the store.
        let plan = try resolvedPlan(request, existing: existing, calendars: calendars, store: store)
        let target = try resolvedTarget(plan.calendar, calendars: calendars, store: store)
        apply(plan, to: event, target: target)
        try save(event, in: store)
        return BridgeEventResult(
            eventId: event.eventIdentifier ?? eventId,
            calendar: event.calendar?.title ?? "")
    }

    /// The planner's one decision; a refusal resets the store so no cache state
    /// can survive a rejected request.
    private func resolvedPlan(
        _ request: BridgeWriteRequest, existing: BridgeWritePlanner.Existing?,
        calendars: [EKCalendar], store: EKEventStore
    ) throws -> BridgeEventPlan {
        switch BridgeWritePlanner.plan(
            request, existing: existing, calendarNames: calendars.map(\.title)) {
        case .success(let plan):
            return plan
        case .failure(let failure):
            store.reset()
            throw failure
        }
    }

    /// Resolve the target calendar before mutating anything; a failure resets.
    private func resolvedTarget(
        _ choice: BridgeCalendarChoice, calendars: [EKCalendar], store: EKEventStore
    ) throws -> EKCalendar? {
        switch choice {
        case .defaultCalendar:
            guard let fallback = store.defaultCalendarForNewEvents else {
                store.reset()
                throw BridgeFailure.calendarNotFound
            }
            return fallback
        case .named(let index):
            guard calendars.indices.contains(index) else {
                store.reset()
                throw BridgeFailure.calendarNotFound
            }
            return calendars[index]
        case .unchanged:
            return nil
        }
    }

    private func apply(_ plan: BridgeEventPlan, to event: EKEvent, target: EKCalendar?) {
        event.title = plan.title
        event.startDate = plan.start
        event.endDate = plan.end
        event.location = plan.location
        event.notes = plan.notes
        event.url = plan.url.flatMap(URL.init(string:))
        if let target { event.calendar = target }
    }

    /// One save; a refusal resets the store and becomes a value-free failure.
    private func save(_ event: EKEvent, in store: EKEventStore) throws {
        do {
            try store.save(event, span: .thisEvent, commit: true)
        } catch {
            store.reset()
            throw BridgeFailure(code: "save_failed", message: "the calendar refused the event")
        }
    }
}
