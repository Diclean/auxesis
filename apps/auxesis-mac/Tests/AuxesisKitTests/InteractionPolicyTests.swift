import Foundation
import XCTest
import AuxesisKit

@objcMembers @MainActor final class InteractionPolicyTests: XCTestCase {
    func testQuietHoursAreInclusiveAtSevenAndExclusiveAtTen() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let formatter = ISO8601DateFormatter()
        let times = ["06:59", "07:00", "21:59", "22:00"].compactMap {
            formatter.date(from: "2026-01-02T\($0):00Z")
        }
        XCTAssertEqual(times.count, 4)
        guard times.count == 4 else { return }

        XCTAssertFalse(NotificationPolicy.isDeliveryTimeAllowed(times[0], calendar: calendar))
        XCTAssertTrue(NotificationPolicy.isDeliveryTimeAllowed(times[1], calendar: calendar))
        XCTAssertTrue(NotificationPolicy.isDeliveryTimeAllowed(times[2], calendar: calendar))
        XCTAssertFalse(NotificationPolicy.isDeliveryTimeAllowed(times[3], calendar: calendar))
    }

    func testRollingBudgetIsIdenticalAcrossTimeZonesForSameUTCInstant() {
        let instant = date("2026-03-10T01:30:00Z")
        var utc = Calendar(identifier: .gregorian)
        utc.timeZone = TimeZone(identifier: "UTC")!
        var losAngeles = Calendar(identifier: .gregorian)
        losAngeles.timeZone = TimeZone(identifier: "America/Los_Angeles")!
        XCTAssertEqual(utc.dateComponents([.year, .month, .day, .hour], from: instant).hour, 1)
        XCTAssertEqual(losAngeles.dateComponents([.year, .month, .day, .hour], from: instant).hour, 18)

        let utcBudget = budget("timezone-utc")
        let laBudget = budget("timezone-la")
        XCTAssertEqual(recordThree(utcBudget, at: instant), recordThree(laBudget, at: instant))
        XCTAssertFalse(utcBudget.recordDeliveryIfAllowed(at: instant))
        XCTAssertFalse(laBudget.recordDeliveryIfAllowed(at: instant))
    }

    func testRollingBudgetExpiresByElapsedTimeAcrossDSTAndClockChanges() {
        let dstBefore = date("2026-03-08T06:30:00Z")
        let dstAfter24Hours = date("2026-03-09T06:30:00Z")
        let dstBudget = budget("dst")
        XCTAssertTrue(dstBudget.recordDeliveryIfAllowed(at: dstBefore))
        XCTAssertTrue(dstBudget.recordDeliveryIfAllowed(at: dstAfter24Hours))

        let clockBudget = budget("clock-change")
        let latest = date("2026-11-01T08:30:00Z")
        XCTAssertTrue(clockBudget.recordDeliveryIfAllowed(at: latest.addingTimeInterval(-120)))
        XCTAssertTrue(clockBudget.recordDeliveryIfAllowed(at: latest.addingTimeInterval(-60)))
        XCTAssertTrue(clockBudget.recordDeliveryIfAllowed(at: latest))
        // A backwards wall-clock adjustment leaves future UTC instants in the rolling window.
        XCTAssertFalse(clockBudget.recordDeliveryIfAllowed(at: latest.addingTimeInterval(-3600)))
        XCTAssertTrue(clockBudget.recordDeliveryIfAllowed(at: latest.addingTimeInterval(24 * 60 * 60)))
        XCTAssertEqual(clockBudget.deliveryInstants().count, 1)
    }

    func testCorruptPersistedBudgetCannotResetTheDailyCap() {
        let instant = date("2026-05-04T12:00:00Z")
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.corrupt.\(UUID().uuidString)")!
        let key = "deliveries"
        defaults.set([
            instant.addingTimeInterval(-300),
            instant.addingTimeInterval(-200),
            instant.addingTimeInterval(-100),
            "malformed delivery",
        ], forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant))
        XCTAssertEqual(budget.deliveryInstants().count, NotificationBudget.limit)
    }

    func testNonFinitePersistedDatesFailClosed() {
        let instant = date("2026-05-04T12:00:00Z")

        for (suffix, corruptDate) in [
            ("nan", Date(timeIntervalSinceReferenceDate: .nan)),
            ("negative-infinity", Date(timeIntervalSinceReferenceDate: -.infinity)),
        ] {
            let defaults = UserDefaults(suiteName: "InteractionPolicyTests.nonfinite.\(suffix).\(UUID().uuidString)")!
            let key = "deliveries"
            defaults.set([
                instant.addingTimeInterval(-300),
                instant.addingTimeInterval(-200),
                corruptDate,
            ], forKey: key)
            let budget = NotificationBudget(defaults: defaults, key: key)

            XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant), "\(suffix) history must consume the last slot")
            XCTAssertEqual(budget.deliveryInstants().count, NotificationBudget.limit)
        }
    }

    func testSeparateBudgetInstancesCannotClaimTheSameLastSlot() {
        let instant = date("2026-05-04T12:00:00Z")
        let attemptsPerIteration = 32
        let iterations = 50

        for iteration in 0..<iterations {
            let suite = "InteractionPolicyTests.shared-lock.\(iteration).\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            let key = "deliveries"
            defaults.set([
                instant.addingTimeInterval(-300),
                instant.addingTimeInterval(-200),
            ], forKey: key)
            let first = NotificationBudget(defaults: defaults, key: key)
            let second = NotificationBudget(defaults: defaults, key: key)
            let resultLock = NSLock()
            var allowedCount = 0

            DispatchQueue.concurrentPerform(iterations: attemptsPerIteration) { index in
                let allowed = (index.isMultiple(of: 2) ? first : second).recordDeliveryIfAllowed(at: instant)
                if allowed {
                    resultLock.lock()
                    allowedCount += 1
                    resultLock.unlock()
                }
            }

            XCTAssertEqual(allowedCount, 1, "iteration \(iteration) must allow exactly one final slot")
        }
    }

    func testOversizedPersistedBudgetIsCompactedWhenRejected() {
        let instant = date("2026-05-04T12:00:00Z")
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.oversized.\(UUID().uuidString)")!
        let key = "deliveries"
        defaults.set((0..<10_000).map { instant.addingTimeInterval(-Double($0)) }, forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant))
        XCTAssertEqual(budget.deliveryInstants().count, NotificationBudget.limit)
    }

    func testFutureTimestampsAreClampedAndExpireWithinOneDay() {
        let instant = date("2026-05-04T12:00:00Z")
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.future.\(UUID().uuidString)")!
        let key = "deliveries"
        defaults.set(Array(repeating: date("2099-01-01T00:00:00Z"), count: 3), forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant))
        XCTAssertEqual(budget.deliveryInstants(), Array(repeating: instant, count: 3))
        XCTAssertTrue(budget.recordDeliveryIfAllowed(at: instant.addingTimeInterval(NotificationBudget.window)))
    }

    func testNonFiniteDeliveryDatesCannotBypassTheBudget() {
        let instant = Date()
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.nonfinite-delivery.\(UUID().uuidString)")!
        let key = "deliveries"
        let budget = NotificationBudget(defaults: defaults, key: key)
        XCTAssertEqual(recordThree(budget, at: instant), [true, true, true, false])
        let history = defaults.array(forKey: key) as? [Int64]
        XCTAssertEqual(history, Array(repeating: Int64(instant.timeIntervalSince1970), count: NotificationBudget.limit))

        let invalidInstants = [
            Date(timeIntervalSince1970: .nan),
            Date(timeIntervalSince1970: .infinity),
            Date(timeIntervalSince1970: -.infinity),
        ]
        for invalidInstant in invalidInstants {
            XCTAssertFalse(budget.recordDeliveryIfAllowed(at: invalidInstant))
            XCTAssertEqual(defaults.array(forKey: key) as? [Int64], history)
            XCTAssertTrue(budget.deliveryInstants().allSatisfy { $0.timeIntervalSince1970.isFinite })
        }
    }

    func testExtremeFiniteDeliveryDateCannotEvictAnEqualFullHistory() {
        let instant = Date()
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.extreme-delivery.\(UUID().uuidString)")!
        let key = "deliveries"
        let budget = NotificationBudget(defaults: defaults, key: key)
        XCTAssertEqual(recordThree(budget, at: instant), [true, true, true, false])
        let history = defaults.array(forKey: key) as? [Int64]

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: Date(timeIntervalSince1970: .greatestFiniteMagnitude)))
        XCTAssertEqual(defaults.array(forKey: key) as? [Int64], history)
        XCTAssertEqual(budget.deliveryInstants().count, NotificationBudget.limit)
    }

    func testInvalidDeliveryDateStillCompactsPersistedHistoryToNewestThree() {
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.invalid-date-compaction.\(UUID().uuidString)")!
        let key = "deliveries"
        let now = Int64(Date().timeIntervalSince1970.rounded(.down))
        let seededHistory = (0..<8).map { now - Int64(8 - $0) }
        defaults.set(seededHistory, forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)
        let invalidInstants = [
            Date(timeIntervalSince1970: .greatestFiniteMagnitude),
            Date(timeIntervalSince1970: .nan),
            Date(timeIntervalSince1970: .infinity),
            Date(timeIntervalSince1970: -.infinity),
        ]
        let newestThree = Array(seededHistory.suffix(NotificationBudget.limit))

        for invalidInstant in invalidInstants {
            XCTAssertFalse(budget.recordDeliveryIfAllowed(at: invalidInstant))
            XCTAssertEqual(defaults.array(forKey: key) as? [Int64], newestThree)
        }
    }

    func testPersistedNumberEdgesFailClosedWithoutTrapping() {
        let instant = date("2026-05-04T12:00:00Z")
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.persisted-number-edges.\(UUID().uuidString)")!
        let key = "deliveries"
        defaults.set([
            true,
            NSNumber(value: 1.5),
            NSNumber(value: Double.greatestFiniteMagnitude),
            NSNumber(value: Double(Int64.max)),
            "not a timestamp",
            Int64.max,
            Int64.min,
        ], forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant))
        XCTAssertEqual(
            defaults.array(forKey: key) as? [Int64],
            Array(repeating: Int64(instant.timeIntervalSince1970), count: NotificationBudget.limit)
        )
    }

    func testInt64ExtremesAndOutOfRangePersistedNumbersFailClosed() {
        let instant = date("2026-05-04T12:00:00Z")
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.integer-extremes.\(UUID().uuidString)")!
        let key = "deliveries"
        defaults.set([
            Int64.max,
            Int64.min,
            Int64(8_000_000_000), // beyond the supported [0, now + 24h] range
            Int64(-1),
            NSNumber(value: 42.5), // not an exact integer
        ], forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant))
        XCTAssertEqual(
            defaults.array(forKey: key) as? [Int64],
            Array(repeating: Int64(instant.timeIntervalSince1970), count: NotificationBudget.limit)
        )
    }

    func testLegacyDateArrayMigratesToIntegerStorage() {
        let instant = date("2026-05-04T12:00:00Z")
        let defaults = UserDefaults(suiteName: "InteractionPolicyTests.legacy-migration.\(UUID().uuidString)")!
        let key = "deliveries"
        let legacyDates = [
            instant.addingTimeInterval(-300.75),
            instant.addingTimeInterval(-200.5),
            instant.addingTimeInterval(-100.25),
        ]
        defaults.set(legacyDates, forKey: key)
        let budget = NotificationBudget(defaults: defaults, key: key)

        XCTAssertFalse(budget.recordDeliveryIfAllowed(at: instant))
        let expected = legacyDates.map { Int64($0.timeIntervalSince1970.rounded(.down)) }
        XCTAssertEqual(defaults.array(forKey: key) as? [Int64], expected)
        XCTAssertEqual(budget.deliveryInstants().map { Int64($0.timeIntervalSince1970) }, expected)
    }

    func testQuickAskKeepsQuestionUnavailableAndSharesSendGuard() {
        XCTAssertEqual(
            QuickAskSubmission.evaluate("  ma question  ", hasAgent: false, isConnected: true, isPaused: false),
            .unavailable(.noAgent)
        )
        XCTAssertEqual(
            QuickAskSubmission.evaluate("ma question", hasAgent: true, isConnected: true, isPaused: true),
            .unavailable(.paused)
        )
        XCTAssertEqual(
            QuickAskSubmission.evaluate("ma question", hasAgent: true, isConnected: false, isPaused: false),
            .unavailable(.offline)
        )
        if case .unavailable(let reason) = QuickAskSubmission.evaluate(
            "ma question", hasAgent: true, isConnected: false, isPaused: false
        ) {
            XCTAssertEqual(reason.message(.fr), "Auxesis est hors ligne. Ta question est conservée.")
        } else {
            XCTFail("offline quick ask should remain unavailable and preserve the question")
        }
        XCTAssertEqual(
            QuickAskSubmission.evaluate("ma question", hasAgent: true, isConnected: true, isPaused: nil),
            .unavailable(.pauseStateUnknown)
        )
        XCTAssertEqual(
            QuickAskSubmission.evaluate("  ma question  ", hasAgent: true, isConnected: true, isPaused: false),
            .send("ma question")
        )
    }

    func testAsyncNotificationCallbacksUseDeliveryTimeAndDoNotReserveSkippedSlots() {
        let center = FakeNotificationCenter()
        let budget = budget("async-time")
        let calendar = utcCalendar()
        var clock = date("2026-03-10T06:59:00Z")
        let coordinator = NotificationDeliveryCoordinator(
            center: center, budget: budget, now: { clock },
            isAllowedTime: { NotificationPolicy.isDeliveryTimeAllowed($0, calendar: calendar) })

        coordinator.post(title: "title", body: "first")
        XCTAssertTrue(budget.deliveryInstants().isEmpty, "post must not reserve a slot")
        clock = date("2026-03-10T07:00:00Z")
        center.resolveSettings(.authorized)
        XCTAssertEqual(center.deliveries.map(\.body), ["first"])
        XCTAssertEqual(budget.deliveryInstants(), [clock])

        coordinator.post(title: "title", body: "quiet")
        clock = date("2026-03-10T22:00:00Z")
        center.resolveSettings(.authorized)
        XCTAssertEqual(center.deliveries.count, 1)
        XCTAssertEqual(budget.deliveryInstants().count, 1, "quiet-hour skip must not charge")
    }

    func testAsyncAuthorizationCallbackRechecksQuietHoursBeforeCharging() {
        let center = FakeNotificationCenter()
        let budget = budget("async-authorization")
        let calendar = utcCalendar()
        var clock = date("2026-03-10T21:59:00Z")
        let coordinator = NotificationDeliveryCoordinator(
            center: center, budget: budget, now: { clock },
            isAllowedTime: { NotificationPolicy.isDeliveryTimeAllowed($0, calendar: calendar) })

        coordinator.post(title: "title", body: "moves to quiet hours")
        center.resolveSettings(.notDetermined)
        XCTAssertTrue(budget.deliveryInstants().isEmpty)
        clock = date("2026-03-10T22:00:00Z")
        center.resolveAuthorization(true)
        XCTAssertTrue(center.deliveries.isEmpty)
        XCTAssertTrue(budget.deliveryInstants().isEmpty)
    }

    func testPausePresentationUsesEngineReadAndDoesNotOptimisticallyFlipOnFailure() {
        XCTAssertEqual(GlobalPausePresentation.refreshed(engineStates: [true, true], previous: false), true)
        XCTAssertEqual(GlobalPausePresentation.refreshed(engineStates: [false, false], previous: true), false)
        XCTAssertEqual(GlobalPausePresentation.refreshed(engineStates: [], previous: true), true)
        XCTAssertEqual(GlobalPausePresentation.refreshed(engineStates: [true, false], previous: false), false)
        XCTAssertEqual(GlobalPausePresentation.afterFailedRequest(previous: false), false)
        XCTAssertNil(GlobalPausePresentation.afterFailedRequest(previous: nil))
    }

    private func date(_ value: String) -> Date {
        ISO8601DateFormatter().date(from: value)!
    }

    private func budget(_ suffix: String) -> NotificationBudget {
        let name = "InteractionPolicyTests.\(suffix).\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return NotificationBudget(defaults: defaults)
    }

    private func recordThree(_ budget: NotificationBudget, at instant: Date) -> [Bool] {
        (0..<4).map { _ in budget.recordDeliveryIfAllowed(at: instant) }
    }

    private func utcCalendar() -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }
}

private final class FakeNotificationCenter: NotificationCenterClient {
    private var settingsCallback: ((NotificationAuthorization) -> Void)?
    private var authorizationCallback: ((Bool) -> Void)?
    private(set) var deliveries: [(title: String, body: String)] = []

    func getAuthorization(_ completion: @escaping (NotificationAuthorization) -> Void) {
        settingsCallback = completion
    }

    func requestAuthorization(_ completion: @escaping (Bool) -> Void) {
        authorizationCallback = completion
    }

    func add(title: String, body: String) {
        deliveries.append((title, body))
    }

    func resolveSettings(_ authorization: NotificationAuthorization) {
        settingsCallback?(authorization)
    }

    func resolveAuthorization(_ granted: Bool) {
        authorizationCallback?(granted)
    }
}
