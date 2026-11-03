import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class CalendarAutoRefresherTests: XCTestCase {
    func testAuthorizedRefreshesAtStartAndEveryThirtyMinutes() async {
        let kit = AutoKit(access: .authorized)
        let store = AutoStore()
        let clock = AutoClock()
        let refresher = CalendarAutoRefresher(
            kit: kit, isReady: { true }, publish: { try await store.publish($0) },
            sleeper: { await clock.sleep($0) })
        let task = Task { @MainActor in await refresher.run() }

        await clock.waitForSleeper()
        XCTAssertEqual(store.snapshots.count, 1)
        XCTAssertEqual(clock.delays, [1800])

        clock.advance()
        await clock.waitForSleeper(count: 2)
        XCTAssertEqual(store.snapshots.count, 2)
        // Even with access granted, a refresh never takes the request path.
        XCTAssertEqual(kit.requests, 0)
        task.cancel()
        clock.advance()
        await task.value
    }

    func testWaitsUntilConnectedThenPublishesOnce() async {
        let kit = AutoKit(access: .authorized)
        let store = AutoStore()
        let clock = AutoClock()
        var ready = false
        let refresher = CalendarAutoRefresher(
            kit: kit, isReady: { ready }, publish: { try await store.publish($0) },
            sleeper: { await clock.sleep($0) })
        let task = Task { @MainActor in await refresher.run() }

        await clock.waitForSleeper()
        XCTAssertTrue(store.snapshots.isEmpty)
        XCTAssertEqual(clock.delays, [CalendarAutoRefresher.readyPoll])
        ready = true
        clock.advance()
        await clock.waitForSleeper(count: 2)
        XCTAssertEqual(store.snapshots.count, 1)
        task.cancel()
        clock.advance()
        await task.value
    }

    func testNotAuthorizedNeverAsksAndPublishesNothing() async {
        for access in [AppleEventKitAccess.notDetermined, .denied, .restricted] {
            let kit = AutoKit(access: access)
            let store = AutoStore()
            let refresher = CalendarAutoRefresher(
                kit: kit, isReady: { true }, publish: { try await store.publish($0) },
                sleeper: { _ in })
            let outcome = await refresher.refreshOnce()
            XCTAssertEqual(outcome, .noAccess)
            XCTAssertEqual(kit.requests, 0, "\(access) must not reach requestAccess")
            XCTAssertTrue(store.snapshots.isEmpty)
        }
    }

    func testFailuresAreSilentAndKeepGoing() async {
        let kit = AutoKit(access: .authorized)
        let store = AutoStore()
        store.fail = true
        let refresher = CalendarAutoRefresher(
            kit: kit, isReady: { true }, publish: { try await store.publish($0) },
            sleeper: { _ in })
        let outcome = await refresher.refreshOnce()
        XCTAssertEqual(outcome, .failed)
        XCTAssertEqual(refresher.published, 0)
        store.fail = false
        await refresher.refreshOnce()
        XCTAssertEqual(refresher.published, 1)
    }
}

@MainActor private final class AutoKit: AppleEventKitProviding {
    let access: AppleEventKitAccess
    private(set) var requests = 0
    init(access: AppleEventKitAccess) { self.access = access }
    func requestAccessAndRead() async throws -> AppleEventKitSnapshot {
        requests += 1
        return AppleEventKitSnapshot(authorized: true, events: [], reminders: [])
    }
    func readIfAuthorized() async throws -> AppleEventKitSnapshot {
        AppleEventKitSnapshot(authorized: access == .authorized, events: [], reminders: [])
    }
}

@MainActor private final class AutoStore {
    struct Refused: Error {}
    private(set) var snapshots: [AppleEventKitSnapshot] = []
    var fail = false
    func publish(_ snapshot: AppleEventKitSnapshot) async throws {
        if fail { throw Refused() }
        snapshots.append(snapshot)
    }
}

/// A manual clock: `sleep` parks until `advance()` releases it.
@MainActor private final class AutoClock {
    private(set) var delays: [TimeInterval] = []
    private var parked: CheckedContinuation<Void, Never>?

    func sleep(_ delay: TimeInterval) async {
        delays.append(delay)
        await withCheckedContinuation { parked = $0 }
    }

    func advance() {
        let waiting = parked
        parked = nil
        waiting?.resume()
    }

    func waitForSleeper(count: Int = 1) async {
        for _ in 0..<10_000 where delays.count < count || parked == nil {
            await Task.yield()
        }
    }
}
