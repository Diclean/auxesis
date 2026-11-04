import Foundation
import Testing
@testable import AuxesisKit

/// JOB-HEALTH-2: the app shows each planned job's health from `/v1/jobs`.
@objcMembers @MainActor final class JobHealthTests: XCTestCase {
    private func decode(_ extra: String) throws -> PlannedJob {
        let json = #"{"id":7,"agent":"aux","name":"Morning brief","schedule":"daily 07:00","enabled":true,"next_run_at":null"# + extra + "}"
        return try JSONDecoder().decode(PlannedJob.self, from: Data(json.utf8))
    }

    func testDecodesAllFourHealthValuesAndTheReason() throws {
        XCTAssertEqual(try decode(#","health":"ok","reason":null"#).health, .ok)
        XCTAssertEqual(try decode(#","health":"unknown""#).health, .unknown)
        let late = try decode(#","health":"late","reason":"Morning brief did not run at 07:00""#)
        XCTAssertEqual(late.health, .late)
        XCTAssertEqual(late.reason, "Morning brief did not run at 07:00")
        let failing = try decode(#","health":"failing","reason":"Morning brief failed at 07:02""#)
        XCTAssertEqual(failing.health, .failing)
        XCTAssertEqual(failing.reason, "Morning brief failed at 07:02")
    }

    func testOlderDaemonOrOddValueReadsAsUnknownNeverAFailure() throws {
        let old = try decode("")
        XCTAssertEqual(old.health, .unknown)
        XCTAssertNil(old.reason)
        XCTAssertEqual(try decode(#","health":"exploded""#).health, .unknown)
        XCTAssertEqual(try decode(#","health":42,"reason":7"#).health, .unknown)
        XCTAssertNil(try decode(#","health":"late","reason":"  ""#).reason)
        XCTAssertEqual(try decode(#","health":"LATE""#).health, .late)
    }

    func testHealthMapsToAQuietOrAttentionMark() {
        XCTAssertNil(JobHealthMark.make(.ok, reason: nil, language: .en))
        XCTAssertNil(JobHealthMark.make(.unknown, reason: "whatever", language: .en))

        let late = JobHealthMark.make(.late, reason: "Morning brief did not run at 07:00", language: .en)
        XCTAssertEqual(late?.tone, .wait)
        XCTAssertEqual(late?.text, "Late · Morning brief did not run at 07:00")
        XCTAssertEqual(late?.accessibilityLabel, "Late. Morning brief did not run at 07:00")

        let failing = JobHealthMark.make(.failing, reason: "Morning brief failed at 07:02", language: .fr)
        XCTAssertEqual(failing?.tone, .bad)
        XCTAssertEqual(failing?.label, "A échoué")
        XCTAssertEqual(failing?.accessibilityLabel, "A échoué. Morning brief failed at 07:02")

        XCTAssertEqual(JobHealthMark.make(.late, reason: nil, language: .fr)?.text, "En retard")
    }

    func testUpNextCarriesTheMarkAndTheFixtureShowsOneLateAndOneFailingJob() async throws {
        let jobs = try await FixtureDaemon(scenario: .team).plannedJobs()
        XCTAssertEqual(jobs.filter { $0.health == .late }.count, 1)
        XCTAssertEqual(jobs.filter { $0.health == .failing }.count, 1)
        let items = WorkTab.upNext(jobs, now: Date(), language: .en)
        XCTAssertEqual(items.compactMap(\.health?.tone).sorted { "\($0)" < "\($1)" }, [.bad, .wait])
        XCTAssertNil(items.first { $0.title == "Morning brief" }?.health)
    }
}
