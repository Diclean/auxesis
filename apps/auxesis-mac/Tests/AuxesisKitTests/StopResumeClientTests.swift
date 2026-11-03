import Foundation
import XCTest
@testable import AuxesisKit

@objcMembers @MainActor final class StopResumeClientTests: XCTestCase {
    func testResumeCallsTheResumeEndpoint() async throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-resume-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let token = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: token)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: token.path)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
             Data("{}".utf8))
        }
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
            tokenFile: token, lockPID: nil, source: "test")
        let client = AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)
        try await client.resumeAll()
        let record = try XCTUnwrapOptional(RecordingURLProtocol.recorded.last)
        XCTAssertEqual(record.method, "POST")
        XCTAssertTrue(record.url.hasSuffix("/v1/resume"), "Resume must POST /v1/resume, got \(record.url)")
    }
}
