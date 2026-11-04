import Foundation
import XCTest
@testable import AuxesisKit

/// A chat send waiting on an approval card must outlast the daemon's turn cap:
/// a 30 s client give-up cancelled the turn and cleared the card.
@objcMembers @MainActor final class ChatSendTimeoutTests: XCTestCase {
    func testChatSendOutlastsTheDaemonTurnCapWhileOtherCallsStayShort() throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-send-timeout-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!, home: home,
            tokenFile: tokenFile, lockPID: nil, source: "test")
        let client = AuxdClient(endpoint: endpoint, requestTimeout: 30, configuration: .ephemeral)

        let send = try client.sendRequest(thread: "aux", content: "hello")
        XCTAssertGreaterThan(send.timeoutInterval, 1800)
        XCTAssertGreaterThanOrEqual(client.chatResourceTimeout, send.timeoutInterval)
        // Every other call keeps the short whole-transfer cap.
        XCTAssertEqual(client.resourceTimeout, 120)
        XCTAssertEqual(send.httpMethod, "POST")
    }
}
