// SwiftPM's generated test runner calls `Testing.__swiftPMEntryPoint()` when
// the `swift-testing` library is selected. In this package "Testing" is the
// CLT-only runner (see Sources/XCTest/XCTest.swift), so `swift test` executes
// the suite and propagates its exit code.
@_exported import XCTest
import Foundation

// SwiftPM's generated runner invokes this from its async `main()`, which runs
// on the main thread. A plain `nonisolated` async function hops to the generic
// executor, so `runAll()` and every test body would run off-main while Store's
// `@MainActor` tasks run on main — unsynchronised access to the same Store /
// transport memory (TSan races, ASan heap aborts). `nonisolated(nonsending)`
// keeps this function on its caller's executor, so test bodies share the main
// executor with Store's `@MainActor` tasks. `runAll()` still drives
// `RunLoop.main` for async tests and `waitUntil`, which works because we are
// not inside a dispatched main-queue job.
//
// `await MainActor.run { XCTestRunner.runAll() }` does NOT work here: it
// enqueues a main-queue job, and the synchronous `RunLoop.main` waits test
// bodies use cannot drain the main actor from inside that job, so Store never
// reaches `.live`.
nonisolated(nonsending)
public func __swiftPMEntryPoint() async -> Never {
    let exitCode: Int32 = XCTestRunner.runAll()
    exit(exitCode)
}
