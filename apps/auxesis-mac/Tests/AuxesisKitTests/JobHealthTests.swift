import Foundation
import Testing
@testable import AuxesisKit

/// JOB-HEALTH-3b: the app words a job's reason itself when the daemon sends
/// the structured kind, and keeps the daemon's English sentence otherwise.
@objcMembers @MainActor final class JobHealthTests: XCTestCase {
    private func decode(_ extra: String) throws -> PlannedJob {
        let json = #"{"id":7,"agent":"aux","name":"Morning brief","schedule":"daily 07:00","enabled":true,"next_run_at":null"# + extra + "}"
        return try JSONDecoder().decode(PlannedJob.self, from: Data(json.utf8))
    }

    private func mark(_ health: JobHealth, _ kind: JobReasonKind, at: String?, language: Language) -> JobHealthMark? {
        JobHealthMark.make(health, reason: "the daemon's English sentence", kind: kind, at: at,
                           name: "Morning brief", language: language)
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

    func testDecodesTheStructuredReasonKindAndTime() throws {
        let missed = try decode(#","health":"late","reason":"Morning brief did not run at 07:00","reason_kind":"missed","reason_at":"07:00""#)
        XCTAssertEqual(missed.reasonKind, .missed)
        XCTAssertEqual(missed.reasonAt, "07:00")

        let failed = try decode(#","health":"failing","reason":"Morning brief failed at 07:02","reason_kind":"failed","reason_at":"07:02""#)
        XCTAssertEqual(failed.reasonKind, .failed)
        XCTAssertEqual(failed.reasonAt, "07:02")

        let hung = try decode(#","health":"late","reason":"Morning brief started at 07:00 and has not finished","reason_kind":"hung","reason_at":"07:00""#)
        XCTAssertEqual(hung.reasonKind, .hung)
        XCTAssertEqual(hung.reasonAt, "07:00")

        let interrupted = try decode(#","health":"failing","reason":"Morning brief the last two runs were interrupted","reason_kind":"interrupted","reason_at":null"#)
        XCTAssertEqual(interrupted.reasonKind, .interrupted)
        XCTAssertNil(interrupted.reasonAt)
    }

    func testOlderDaemonMissingOrUnknownReasonFieldsStayLenient() throws {
        let old = try decode("")
        XCTAssertNil(old.reasonKind)
        XCTAssertNil(old.reasonAt)
        XCTAssertEqual(try decode(#","health":"late","reason":"kept""#).reason, "kept")
        XCTAssertNil(try decode(#","reason_kind":"exploded","reason_at":"07:00""#).reasonKind)
        XCTAssertNil(try decode(#","reason_kind":42,"reason_at":7"#).reasonKind)
        XCTAssertNil(try decode(#","reason_kind":"  ""#).reasonKind)
        XCTAssertNil(try decode(#","reason_kind":"missed","reason_at":"  ""#).reasonAt)
        XCTAssertEqual(try decode(#","reason_kind":"MISSED","reason_at":" 07:00 ""#).reasonKind, .missed)
        XCTAssertEqual(try decode(#","reason_kind":"missed","reason_at":" 07:00 ""#).reasonAt, "07:00")
    }

    func testOlderDaemonOrOddValueReadsAsUnknownNeverAFailure() throws {
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

    func testMissedWordingInEnglishAndFrenchWithAndWithoutTime() {
        XCTAssertEqual(mark(.late, .missed, at: "07:00", language: .en)?.text,
                       "Late · Morning brief didn't run at 07:00")
        XCTAssertEqual(mark(.late, .missed, at: nil, language: .en)?.text,
                       "Late · Morning brief didn't run")
        XCTAssertEqual(mark(.late, .missed, at: "07:00", language: .fr)?.text,
                       "En retard · Morning brief n’a pas tourné à 07:00")
        XCTAssertEqual(mark(.late, .missed, at: nil, language: .fr)?.text,
                       "En retard · Morning brief n’a pas tourné")
    }

    func testFailedWordingInEnglishAndFrenchWithAndWithoutTime() {
        XCTAssertEqual(mark(.failing, .failed, at: "07:02", language: .en)?.text,
                       "Failed · Morning brief failed at 07:02")
        XCTAssertEqual(mark(.failing, .failed, at: nil, language: .en)?.text,
                       "Failed · Morning brief failed")
        XCTAssertEqual(mark(.failing, .failed, at: "07:02", language: .fr)?.text,
                       "A échoué · Morning brief a échoué à 07:02")
        XCTAssertEqual(mark(.failing, .failed, at: nil, language: .fr)?.text,
                       "A échoué · Morning brief a échoué")
    }

    func testHungWordingSaysStartedAndNotFinished() {
        XCTAssertEqual(mark(.late, .hung, at: "07:00", language: .en)?.text,
                       "Late · Morning brief started at 07:00 and hasn't finished")
        XCTAssertEqual(mark(.late, .hung, at: nil, language: .en)?.text,
                       "Late · Morning brief started and hasn't finished")
        XCTAssertEqual(mark(.late, .hung, at: "07:00", language: .fr)?.text,
                       "En retard · Morning brief a démarré à 07:00 et n’a pas fini")
        XCTAssertEqual(mark(.late, .hung, at: nil, language: .fr)?.text,
                       "En retard · Morning brief a démarré et n’a pas fini")
    }

    func testInterruptedWordingInEnglishAndFrenchWithAndWithoutTime() {
        XCTAssertEqual(mark(.failing, .interrupted, at: "07:02", language: .en)?.text,
                       "Failed · Morning brief was interrupted twice, the last time at 07:02")
        XCTAssertEqual(mark(.failing, .interrupted, at: nil, language: .en)?.text,
                       "Failed · Morning brief was interrupted twice")
        XCTAssertEqual(mark(.failing, .interrupted, at: "07:02", language: .fr)?.text,
                       "A échoué · Morning brief a été interrompue deux fois, la dernière à 07:02")
        XCTAssertEqual(mark(.failing, .interrupted, at: nil, language: .fr)?.text,
                       "A échoué · Morning brief a été interrompue deux fois")
    }

    func testTheAccessibilityLabelCarriesTheSameLocalizedReason() {
        let english = mark(.late, .missed, at: "07:00", language: .en)
        XCTAssertEqual(english?.text, "Late · Morning brief didn't run at 07:00")
        XCTAssertEqual(english?.accessibilityLabel, "Late. Morning brief didn't run at 07:00")

        let french = mark(.failing, .failed, at: "07:02", language: .fr)
        XCTAssertEqual(french?.text, "A échoué · Morning brief a échoué à 07:02")
        XCTAssertEqual(french?.accessibilityLabel, "A échoué. Morning brief a échoué à 07:02")
    }

    func testKnownKindWithoutANameFallsBackToTheDaemonsSentence() {
        let mark = JobHealthMark.make(.late, reason: "the daemon's English sentence", kind: .missed,
                                      at: "07:00", name: "", language: .en)
        XCTAssertEqual(mark?.text, "Late · the daemon's English sentence")
    }

    func testUpNextWordingIsLocalizedAndTheFixtureCarriesKinds() async throws {
        let jobs = try await FixtureDaemon(scenario: .team).plannedJobs()
        let late = try XCTUnwrapOptional(jobs.first { $0.health == .late })
        XCTAssertEqual(late.reasonKind, .missed)
        XCTAssertEqual(late.reasonAt, "07:00")
        let failing = try XCTUnwrapOptional(jobs.first { $0.health == .failing })
        XCTAssertEqual(failing.reasonKind, .failed)
        XCTAssertEqual(failing.reasonAt, "07:32")

        let items = WorkTab.upNext(jobs, now: Date(), language: .en)
        XCTAssertEqual(items.compactMap(\.health?.tone).sorted { "\($0)" < "\($1)" }, [.bad, .wait])
        XCTAssertNil(items.first { $0.title == "Morning brief" }?.health)
        XCTAssertEqual(items.first { $0.title == "File receipts" }?.health?.text,
                       "Late · File receipts didn't run at 07:00")
        XCTAssertEqual(items.first { $0.title == "Inbox sweep" }?.health?.text,
                       "Failed · Inbox sweep failed at 07:32")
    }
}
