// A minimal XCTest-compatible runner for builds with Command Line Tools only.
//
// The CLT toolchain ships neither XCTest.framework nor the Testing module, so
// the stock `swift test` harness silently skips every test. This module gives
// SwiftPM's generated runner something to call:
//
//   * `Testing.__swiftPMEntryPoint()` runs every `XCTestCase` subclass found
//     through the Objective-C runtime (`@objcMembers` exposes the `test…`
//     methods; see the note below).
//   * `swift test` (with or without `--enable-swift-testing`) then works and
//     propagates the exit code, because the entry point calls `exit()`.
//
// Conventions for tests using this runner:
//   * test classes are `@objcMembers @MainActor final class X: XCTestCase`;
//   * test methods take no arguments and may be `Void`, `throws`, `async` or
//     `async throws`; async methods are discovered through their ObjC
//     completion-handler bridge and run for real (a completion that never
//     fires fails the test);
//   * async work can also be driven with `XCTestExpectation` + `wait(...)`.
//
// A run that executes zero tests is a failure (exit 1), and the final line
// reports the real number of tests run, async included.
//
// This file exists only because the target machine has no Xcode. With a full
// toolchain, delete the `XCTest`/`Testing` targets and use real XCTest.
import Foundation

@_exported import Foundation

/// Base class for tests. Subclasses are discovered at runtime.
open class XCTestCase: NSObject {
    public required override init() {
        super.init()
    }

    open func setUp() {}
    open func tearDown() {}
}

/// A counted expectation driven by `fulfill()`; polled by `wait(for:timeout:)`.
public final class XCTestExpectation: NSObject {
    public let expectationDescription: String
    public var expectedFulfillmentCount: Int = 1
    public var assertForOverFulfill: Bool = false
    private let lock = NSLock()
    private var fulfillmentCount = 0

    public init(description: String) {
        self.expectationDescription = description
        super.init()
    }

    public override var description: String { expectationDescription }

    public func fulfill() {
        lock.lock()
        fulfillmentCount += 1
        lock.unlock()
    }

    public var isFulfilled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return fulfillmentCount >= expectedFulfillmentCount
    }
}

/// Failure recording shared by the assertion helpers below.
public enum XCTestReport {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var _executed = 0
    nonisolated(unsafe) private static var _failures = 0
    nonisolated(unsafe) private static var _currentTest = ""

    public static var failures: Int {
        lock.lock()
        defer { lock.unlock() }
        return _failures
    }

    public static var executed: Int {
        lock.lock()
        defer { lock.unlock() }
        return _executed
    }

    static func startTest(_ name: String) {
        lock.lock()
        _executed += 1
        _currentTest = name
        lock.unlock()
    }

    static func record(file: StaticString, line: UInt, message: String) {
        lock.lock()
        _failures += 1
        let test = _currentTest
        lock.unlock()
        print("FAIL [\(test)] \(file):\(line) \(message)")
    }

    static func run<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

public func XCTFail(_ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    XCTestReport.record(file: file, line: line, message: message.isEmpty ? "failure" : message)
}

public func XCTAssertTrue(_ expression: @autoclosure () throws -> Bool, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        if try expression() == false { XCTFail("expected true — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertFalse(_ expression: @autoclosure () throws -> Bool, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        if try expression() == true { XCTFail("expected false — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        let lhs = try a()
        let rhs = try b()
        if lhs != rhs { XCTFail("expected \(rhs), got \(lhs) — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertEqual<T: FloatingPoint>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, accuracy: T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        let lhs = try a()
        let rhs = try b()
        if abs(lhs - rhs) > accuracy {
            XCTFail("expected \(rhs) ± \(accuracy), got \(lhs) — \(message)", file: file, line: line)
        }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertNotEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        if try a() == b() { XCTFail("expected values to differ — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertNil(_ expression: @autoclosure () throws -> Any?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        if try expression() != nil { XCTFail("expected nil — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertNotNil(_ expression: @autoclosure () throws -> Any?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        if try expression() == nil { XCTFail("expected non-nil — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertGreaterThan<T: Comparable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        let lhs = try a()
        let rhs = try b()
        if !(lhs > rhs) { XCTFail("expected \(lhs) > \(rhs) — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertGreaterThanOrEqual<T: Comparable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        let lhs = try a()
        let rhs = try b()
        if !(lhs >= rhs) { XCTFail("expected \(lhs) >= \(rhs) — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertLessThan<T: Comparable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        let lhs = try a()
        let rhs = try b()
        if !(lhs < rhs) { XCTFail("expected \(lhs) < \(rhs) — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertLessThanOrEqual<T: Comparable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) {
    do {
        let lhs = try a()
        let rhs = try b()
        if !(lhs <= rhs) { XCTFail("expected \(lhs) <= \(rhs) — \(message)", file: file, line: line) }
    } catch {
        XCTFail("threw \(error) — \(message)", file: file, line: line)
    }
}

public func XCTAssertThrowsError<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line, _ handler: (Error) -> Void = { _ in }) {
    do {
        _ = try expression()
        XCTFail("expected a throw — \(message)", file: file, line: line)
    } catch {
        handler(error)
    }
}

/// Spin the main run loop until every expectation is fulfilled (or the
/// timeout fires). Only callable from the main thread — the runner guarantees
/// that.
@discardableResult
public func wait(for expectations: [XCTestExpectation], timeout: TimeInterval, file: StaticString = #filePath, line: UInt = #line) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if expectations.allSatisfy({ $0.isFulfilled }) { return true }
        RunLoop.main.run(until: Date().addingTimeInterval(0.005))
    }
    if !expectations.allSatisfy({ $0.isFulfilled }) {
        let names = expectations.filter { !$0.isFulfilled }.map(\.expectationDescription).joined(separator: ", ")
        XCTFail("timed out waiting for \(names)", file: file, line: line)
        return false
    }
    return true
}

/// The test runner itself: scans the ObjC runtime, runs `test…` methods.
public enum XCTestRunner {
    private struct TestMethod {
        /// Selector as exposed to ObjC (throwing methods get `AndReturnError:`,
        /// async methods get `WithCompletionHandler:`).
        let selectorName: String
        /// The Swift name shown in output.
        let displayName: String
        /// Throwing Swift methods return Bool + NSError**; plain ones Void.
        let isThrowing: Bool
        /// Async Swift methods bridge to ObjC with a completion-handler block;
        /// the runner invokes them and waits for the block (or fails loudly).
        let isAsync: Bool
        /// Async throws methods call the block with `(result, NSError)`.
        let asyncThrows: Bool

        init(selectorName: String, displayName: String, isThrowing: Bool, isAsync: Bool = false, asyncThrows: Bool = false) {
            self.selectorName = selectorName
            self.displayName = displayName
            self.isThrowing = isThrowing
            self.isAsync = isAsync
            self.asyncThrows = asyncThrows
        }
    }

    /// A verdict from raw counts: zero tests that ran is always a failure — a
    /// runner that runs nothing proves nothing.
    public static func verdict(total: Int, failures: Int) -> Int32 {
        guard total > 0 else { return 1 }
        return failures == 0 ? 0 : 1
    }

    /// Nonisolated on purpose: `Testing.__swiftPMEntryPoint()` inherits its
    /// caller's (main-thread) executor, so the runner is already on the main
    /// thread when it starts. It must stay a synchronous, unisolated call:
    /// dispatching it as a `MainActor` job would put it inside a main-queue
    /// block, from which the `RunLoop.main` waits test bodies use cannot drain
    /// the main actor. `@MainActor` test methods are executed through ObjC IMP
    /// calls on this same (main) thread.
    public static func runAll() -> Int32 {
        precondition(Thread.isMainThread, "XCTestRunner.runAll() must run on the main thread so test bodies share the main executor with @MainActor app code")
        setvbuf(stdout, nil, _IONBF, 0)
        let arguments = CommandLine.arguments
        let filter = value(after: "--filter", in: arguments) ?? value(after: "-filter", in: arguments)
        let skip = value(after: "--skip", in: arguments) ?? value(after: "-skip", in: arguments)

        let count = objc_getClassList(nil, 0)
        guard count > 0 else { return verdict(total: 0, failures: 0) }
        let classes = UnsafeMutablePointer<AnyClass?>.allocate(capacity: Int(count))
        defer { classes.deallocate() }
        let real = objc_getClassList(AutoreleasingUnsafeMutablePointer(classes), count)

        let targetName = NSStringFromClass(XCTestCase.self)
        var suiteNames: [String] = []
        for i in 0..<Int(real) {
            guard let cls = classes[i] else { continue }
            guard isSubclass(cls, ofNamed: targetName), NSStringFromClass(cls) != targetName else { continue }
            let name = NSStringFromClass(cls)
            guard accepts(name, filter: filter), !matches(name, pattern: skip) else { continue }
            suiteNames.append(name)
        }

        var total = 0
        var asyncCount = 0
        for suiteName in suiteNames.sorted() {
            guard let cls = NSClassFromString(suiteName) else { continue }
            let instance = (cls as! XCTestCase.Type).init()
            let methods = testMethods(of: cls).filter { method in
                let full = "\(suiteName).\(method.displayName)"
                return accepts(full, filter: filter) && !matches(full, pattern: skip)
            }.sorted { $0.displayName < $1.displayName }
            for method in methods {
                total += 1
                if method.isAsync { asyncCount += 1 }
                print("run \(suiteName).\(method.displayName)")
                XCTestReport.startTest("\(suiteName).\(method.displayName)")
                let before = XCTestReport.failures
                instance.setUp()
                invoke(method, on: instance, class: cls, suite: suiteName)
                instance.tearDown()
                let failed = XCTestReport.failures > before
                print("test \(suiteName).\(method.displayName) … \(failed ? "FAIL" : "pass")")
            }
        }
        let failures = XCTestReport.failures
        print("Executed \(total) tests (\(asyncCount) async), \(failures) failure(s)")
        if total == 0 {
            print("FAIL: zero tests ran — refusing a green result (filter: \(filter ?? "none"))")
        }
        return verdict(total: total, failures: failures)
    }

    // Nonisolated: invoked from the synchronous runner, which runs on the main
    // thread; @MainActor test methods are still dispatched through ObjC and
    // therefore execute on that same (main) thread.
    private static func invoke(_ method: TestMethod, on instance: XCTestCase, class cls: AnyClass, suite: String) {
        if method.isAsync {
            invokeAsync(method, on: instance, class: cls, suite: suite)
            return
        }
        let selector = NSSelectorFromString(method.selectorName)
        guard method.isThrowing else {
            _ = instance.perform(selector)
            return
        }
        guard let implementation = class_getMethodImplementation(cls, selector) else {
            XCTFail("no implementation for \(method.selectorName)")
            return
        }
        // Swift bridges `func testX() throws` to `- (BOOL)testXAndReturnError:(NSError **)`.
        typealias ThrowingIMP = @convention(c) (AnyObject, Selector, UnsafeMutablePointer<NSError?>?) -> Bool
        let call = unsafeBitCast(implementation, to: ThrowingIMP.self)
        var error: NSError?
        let before = XCTestReport.failures
        let succeeded = withUnsafeMutablePointer(to: &error) { pointer -> Bool in
            call(instance, selector, pointer)
        }
        if !succeeded, XCTestReport.failures == before {
            XCTFail("\(suite).\(method.displayName) threw \(error?.localizedDescription ?? "an error")")
        }
    }

    /// `func testX() async` bridges to `- testXWithCompletionHandler:` whose
    /// block is invoked when the async body returns (with an NSError for
    /// `async throws`). Invoke it, spin the main run loop so MainActor test
    /// bodies can run, and fail loudly if the completion never fires.
    private static func invokeAsync(_ method: TestMethod, on instance: XCTestCase, class cls: AnyClass, suite: String) {
        let selector = NSSelectorFromString(method.selectorName)
        guard let implementation = class_getMethodImplementation(cls, selector) else {
            XCTFail("no implementation for \(method.selectorName)")
            return
        }
        let completion = CompletionFlag()
        if method.asyncThrows {
            typealias AsyncThrowIMP = @convention(c) (AnyObject, Selector, @convention(block) (AnyObject?) -> Void) -> Void
            let call = unsafeBitCast(implementation, to: AsyncThrowIMP.self)
            let block: @convention(block) (AnyObject?) -> Void = { error in
                if let error {
                    XCTFail("\(suite).\(method.displayName) threw \(error)")
                }
                completion.fulfill()
            }
            call(instance, selector, block)
        } else {
            typealias AsyncIMP = @convention(c) (AnyObject, Selector, @convention(block) () -> Void) -> Void
            let call = unsafeBitCast(implementation, to: AsyncIMP.self)
            let block: @convention(block) () -> Void = {
                completion.fulfill()
            }
            call(instance, selector, block)
        }
        let deadline = Date().addingTimeInterval(30)
        while !completion.isDone, Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.005))
        }
        if !completion.isDone {
            XCTFail("\(suite).\(method.displayName): async test did not finish within 30 s")
        }
    }

    private static func value(after flag: String, in arguments: [String]) -> String? {
        guard let idx = arguments.firstIndex(of: flag), idx + 1 < arguments.count else { return nil }
        return arguments[idx + 1]
    }

    private static func accepts(_ name: String, filter: String?) -> Bool {
        guard let filter, !filter.isEmpty else { return true }
        return matches(name, pattern: filter)
    }

    private static func matches(_ name: String, pattern: String?) -> Bool {
        guard let pattern, !pattern.isEmpty else { return false }
        return name.range(of: pattern, options: .regularExpression) != nil
    }

    private static func isSubclass(_ cls: AnyClass, ofNamed name: String) -> Bool {
        var current: AnyClass? = cls
        while let c = current {
            if NSStringFromClass(c) == name { return true }
            current = class_getSuperclass(c)
        }
        return false
    }

    /// `test…` instance methods via the ObjC method list (`@objcMembers` test
    /// classes expose their methods). Plain methods take no arguments and
    /// return Void; throwing methods are bridged as `…AndReturnError:` with
    /// an NSError pointer; async methods as `…WithCompletionHandler:` with a
    /// completion block.
    private static func testMethods(of cls: AnyClass) -> [TestMethod] {
        var out: [TestMethod] = []
        var count: UInt32 = 0
        guard let list = class_copyMethodList(cls, &count) else { return out }
        defer { free(list) }
        for i in 0..<Int(count) {
            let selector = method_getName(list[i])
            let name = NSStringFromSelector(selector)
            let arguments = method_getNumberOfArguments(list[i])
            guard name.hasPrefix("test") else { continue }
            if arguments == 2 {
                out.append(TestMethod(selectorName: name, displayName: name, isThrowing: false))
            } else if arguments == 3, name.hasSuffix("AndReturnError:") {
                let display = String(name.dropLast("AndReturnError:".count))
                out.append(TestMethod(selectorName: name, displayName: display, isThrowing: true))
            } else if name.hasSuffix("WithCompletionHandler:") {
                let display = String(name.dropLast("WithCompletionHandler:".count))
                let encoding = method_getTypeEncoding(list[i]).map { String(cString: $0) } ?? ""
                // The bridged async method's block parameter is type-encoded
                // `@?<…>`; anything else with that name is not ours to run.
                if encoding.contains("@?<") {
                    out.append(TestMethod(
                        selectorName: name,
                        displayName: display,
                        isThrowing: false,
                        isAsync: true,
                        asyncThrows: encoding.contains("NSError")
                    ))
                }
            }
        }
        return out
    }
}

/// Lock-protected completion flag for async test invocation.
private final class CompletionFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    var isDone: Bool {
        lock.lock()
        defer { lock.unlock() }
        return done
    }

    func fulfill() {
        lock.lock()
        done = true
        lock.unlock()
    }
}
