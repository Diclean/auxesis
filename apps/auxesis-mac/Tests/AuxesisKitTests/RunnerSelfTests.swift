// Self-tests for the in-repo CLT runner.
//
// The runner discovers tests through the ObjC runtime. Async test methods
// bridge to ObjC as `testXWithCompletionHandler:` and are run for real; if a
// future Swift version stops exposing them (or the runner regresses), the
// async probe below never sets its flag and `testAsyncProbeWasRun` — which
// sorts after it in the same suite — fails. A run that executes zero tests is
// also a failure (`verdict(total: 0, …) == 1`).
import Testing

@objcMembers @MainActor final class RunnerSelfTests: XCTestCase {
    nonisolated(unsafe) private static var probeRan = false
    private static let lock = NSLock()

    private static func noteProbeRan() {
        lock.lock()
        probeRan = true
        lock.unlock()
    }

    private static var probeCompleted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return probeRan
    }

    /// Display names sort "testAn…" < "testAs…", so this async method runs
    /// before `testAsyncProbeWasRun` below.
    func testAnAsyncProbeActuallyRuns() async {
        let value = await withCheckedContinuation { continuation in
            DispatchQueue.global().async { continuation.resume(returning: 41) }
        }
        XCTAssertEqual(value + 1, 42)
        Self.noteProbeRan()
    }

    func testAsyncProbeWasRun() {
        XCTAssertTrue(Self.probeCompleted, "the runner must run async test methods, not skip them")
    }

    /// `async throws` bridges a block that carries an NSError; it must run too.
    func testAnAsyncThrowIsAlsoRun() async throws {
        let value = try await asyncIdentity(7)
        XCTAssertEqual(value, 7)
    }

    func testVerdictRefusesAZeroTestRun() {
        XCTAssertEqual(XCTestRunner.verdict(total: 0, failures: 0), 1)
        XCTAssertEqual(XCTestRunner.verdict(total: 0, failures: 1), 1)
        XCTAssertEqual(XCTestRunner.verdict(total: 1, failures: 0), 0)
        XCTAssertEqual(XCTestRunner.verdict(total: 1, failures: 1), 1)
    }

    private func asyncIdentity(_ value: Int) async throws -> Int {
        try await Task.sleep(nanoseconds: 1_000_000)
        return value
    }
}
