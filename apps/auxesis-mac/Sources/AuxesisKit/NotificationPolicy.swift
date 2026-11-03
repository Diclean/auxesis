import Foundation
import CoreFoundation

/// Pure notification delivery rules, shared by the app callbacks and tests.
public enum NotificationPolicy {
    public static func isDeliveryTimeAllowed(_ date: Date, calendar: Calendar = .current) -> Bool {
        let hour = calendar.component(.hour, from: date)
        return hour >= 7 && hour < 22
    }
}

/// A persisted, timezone-independent rolling notification budget.
public final class NotificationBudget {
    public static let limit = 3
    public static let window: TimeInterval = 24 * 60 * 60
    private static let windowSeconds: Int64 = 86_400
    private static let earliestAcceptedEpochSecond: Int64 = 946_684_800 // 2000-01-01T00:00:00Z
    private static let latestAcceptedEpochSecond: Int64 = 7_258_118_400 // 2200-01-01T00:00:00Z
    private static let lock = NSLock()

    private let defaults: UserDefaults
    private let key: String

    public init(defaults: UserDefaults = .standard, key: String = "auxesis.notifications.deliveries") {
        self.defaults = defaults
        self.key = key
    }

    /// Prunes instants outside the trailing 24 hours and charges only if a slot remains.
    @discardableResult
    public func recordDeliveryIfAllowed(at instant: Date) -> Bool {
        // Convert once at the Date boundary. A rejected delivery date cannot
        // claim a slot, but persisted history must still be compacted.
        let deliverySecond = Self.acceptedEpochSecond(for: instant)

        Self.lock.lock()
        defer { Self.lock.unlock() }

        let now = deliverySecond ?? Self.acceptedEpochSecond(for: Date()) ?? Self.earliestAcceptedEpochSecond
        let compacted = compactedHistory(at: now)
        guard let deliverySecond else {
            defaults.set(compacted, forKey: key)
            return false
        }
        guard compacted.count < Self.limit else {
            defaults.set(compacted, forKey: key)
            return false
        }
        defaults.set(compacted + [deliverySecond], forKey: key)
        return true
    }

    public func deliveryInstants() -> [Date] {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        guard let values = defaults.array(forKey: key) else { return [] }
        return values.compactMap(Self.exactStoredSecond(from:)).map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }
    }

    /// Reads both current integer histories and the old Date-array format.
    /// Invalid entries consume a slot at `now`; a future value is also clamped
    /// to `now` so a clock rollback cannot make a prior delivery disappear.
    private func compactedHistory(at now: Int64) -> [Int64] {
        let storedValue = defaults.object(forKey: key)
        guard let values = storedValue as? [Any] else {
            guard storedValue != nil else { return [] }
            // A present non-array value is corrupt and fails closed.
            return Array(repeating: now, count: Self.limit)
        }

        let (maximumSaneSecond, overflow) = now.addingReportingOverflow(Self.windowSeconds)
        let maximumSaneSecondBound = overflow ? Int64.max : maximumSaneSecond
        let parsed = values.map { value -> Int64 in
            guard let second = Self.persistedSecond(from: value, maximum: maximumSaneSecondBound) else {
                return now
            }
            return min(second, now)
        }

        let (cutoff, cutoffOverflow) = now.subtractingReportingOverflow(Self.windowSeconds)
        let safeCutoff = cutoffOverflow ? Int64.min : cutoff
        let recent = parsed.filter { $0 > safeCutoff }.sorted()
        return Array(recent.suffix(Self.limit))
    }

    /// Accepts only whole seconds in the supported Date interval.
    private static func acceptedEpochSecond(for date: Date) -> Int64? {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite,
              seconds >= Double(earliestAcceptedEpochSecond),
              seconds <= Double(latestAcceptedEpochSecond) else {
            return nil
        }
        let wholeSeconds = seconds.rounded(.down)
        guard let value = Int64(exactly: wholeSeconds),
              value >= earliestAcceptedEpochSecond,
              value <= latestAcceptedEpochSecond else {
            return nil
        }
        return value
    }

    /// Converts an old Date entry to whole epoch seconds without overflowing.
    private static func wholeEpochSecond(from date: Date) -> Int64? {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite,
              seconds >= 0,
              seconds <= Double(Int64.max) else {
            return nil
        }
        return Int64(exactly: seconds.rounded(.down))
    }

    /// Validates one persisted item. NSNumber is handled element by element so
    /// fractional numbers, booleans, negative values, and huge values fail
    /// closed instead of being coerced into plausible timestamps.
    private static func persistedSecond(from value: Any, maximum: Int64) -> Int64? {
        if let date = value as? Date {
            guard let second = wholeEpochSecond(from: date), second <= maximum else { return nil }
            return second
        }
        guard let number = value as? NSNumber,
              CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID() else {
            return nil
        }

        let decimal = number.decimalValue
        guard !decimal.isNaN,
              decimal >= 0,
              decimal <= Decimal(maximum) else {
            return nil
        }
        var valueToRound = decimal
        var rounded = Decimal()
        NSDecimalRound(&rounded, &valueToRound, 0, .down)
        guard rounded == decimal else { return nil }
        return NSDecimalNumber(decimal: decimal).int64Value
    }

    private static func exactStoredSecond(from value: Any) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID() else {
            return nil
        }
        let decimal = number.decimalValue
        guard !decimal.isNaN,
              decimal >= 0,
              decimal <= Decimal(Int64.max) else {
            return nil
        }
        var valueToRound = decimal
        var rounded = Decimal()
        NSDecimalRound(&rounded, &valueToRound, 0, .down)
        guard rounded == decimal else { return nil }
        return NSDecimalNumber(decimal: decimal).int64Value
    }
}

public enum NotificationAuthorization: Equatable {
    case notDetermined
    case authorized
    case provisional
    case denied
}

/// Callback interface implemented by UserNotifications in the app and faked in tests.
public protocol NotificationCenterClient: AnyObject {
    func getAuthorization(_ completion: @escaping (NotificationAuthorization) -> Void)
    func requestAuthorization(_ completion: @escaping (Bool) -> Void)
    func add(title: String, body: String)
}

/// Re-checks local quiet hours and the rolling budget when authorization resolves.
/// No budget slot is reserved while waiting on either asynchronous callback.
public final class NotificationDeliveryCoordinator {
    private let center: NotificationCenterClient
    private let budget: NotificationBudget
    private let now: () -> Date
    private let isAllowedTime: (Date) -> Bool

    public init(
        center: NotificationCenterClient,
        budget: NotificationBudget,
        now: @escaping () -> Date = Date.init,
        isAllowedTime: @escaping (Date) -> Bool = { NotificationPolicy.isDeliveryTimeAllowed($0) }
    ) {
        self.center = center
        self.budget = budget
        self.now = now
        self.isAllowedTime = isAllowedTime
    }

    public func post(title: String, body: String) {
        center.getAuthorization { [weak self] authorization in
            guard let self else { return }
            switch authorization {
            case .notDetermined:
                self.center.requestAuthorization { [weak self] granted in
                    guard granted else { return }
                    self?.deliverIfEligible(title: title, body: body)
                }
            case .authorized, .provisional:
                self.deliverIfEligible(title: title, body: body)
            case .denied:
                break
            }
        }
    }

    private func deliverIfEligible(title: String, body: String) {
        let deliveryTime = now()
        guard isAllowedTime(deliveryTime), budget.recordDeliveryIfAllowed(at: deliveryTime) else {
            return
        }
        center.add(title: title, body: body)
    }
}

public enum QuickAskSubmission {
    public enum UnavailableReason: Equatable {
        case noAgent
        case offline
        case pauseStateUnknown
        case paused

        public func message(_ language: Language) -> String {
            switch self {
            case .noAgent: return L10n.t(.quickAskReasonNoAgent, language)
            case .offline: return L10n.t(.quickAskReasonOffline, language)
            case .pauseStateUnknown: return L10n.t(.quickAskReasonUnknown, language)
            case .paused: return L10n.t(.quickAskReasonPaused, language)
            }
        }
    }

    public enum Result: Equatable {
        case empty
        case unavailable(UnavailableReason)
        case send(String)
    }

    /// The menu-bar Return action and Send button use the same readiness rule.
    public static func evaluate(
        _ question: String,
        hasAgent: Bool,
        isConnected: Bool,
        isPaused: Bool?
    ) -> Result {
        let text = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .empty }
        guard hasAgent else { return .unavailable(.noAgent) }
        guard isConnected else { return .unavailable(.offline) }
        guard let isPaused else { return .unavailable(.pauseStateUnknown) }
        guard !isPaused else { return .unavailable(.paused) }
        return .send(text)
    }
}

/// Chooses the displayed pause state only from a successful engine read.
public enum GlobalPausePresentation {
    public static func refreshed(engineStates: [Bool], previous: Bool?) -> Bool? {
        guard let first = engineStates.first else { return previous }
        return engineStates.allSatisfy { $0 == first } ? first : previous
    }

    /// A failed write never changes the displayed state optimistically.
    public static func afterFailedRequest(previous: Bool?) -> Bool? { previous }
}
