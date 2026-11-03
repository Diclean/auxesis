// The personality editor: load the agent's own text, count bytes against the
// ceiling, save through `soul_md`, and report success or an honest reason.
// Everything runs against the fake transport (no network) except the one
// request-shape test, which uses the recording URLProtocol.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class PersonalityEditorTests: XCTestCase {
    private func makeStore(_ transport: FakeTransport) -> Store {
        Store(transport: transport)
    }

    // MARK: - Loading

    func testLoadPrefillsTheEditorWithTheStoredPersonality() async {
        let transport = FakeTransport()
        transport.soulResult = .success(
            AgentSoul(soulMd: "be terse", maxBytes: AgentSoul.builtInMaxBytes, isDefault: false))
        let store = makeStore(transport)
        let editor = PersonalityEditor()

        await editor.load { try await store.agentSoul(name: "scout") }

        XCTAssertEqual(editor.state, .ready)
        XCTAssertEqual(editor.text, "be terse")
        XCTAssertEqual(editor.savedText, "be terse")
        XCTAssertEqual(editor.maxBytes, AgentSoul.builtInMaxBytes)
        XCTAssertFalse(editor.isDefault)
        XCTAssertFalse(editor.canSave, "a freshly loaded text has nothing to save")

        editor.text = "be brief"
        XCTAssertTrue(editor.canSave)
    }

    func testAnAgentWithoutAPersonalityShowsTheBuiltInDefault() async {
        let transport = FakeTransport()
        transport.soulResult = .success(
            AgentSoul(soulMd: "default text", maxBytes: AgentSoul.builtInMaxBytes, isDefault: true))
        let store = makeStore(transport)
        let editor = PersonalityEditor()

        await editor.load { try await store.agentSoul(name: "scout") }

        XCTAssertEqual(editor.state, .ready)
        XCTAssertTrue(editor.isDefault)
        XCTAssertEqual(editor.text, "default text")
    }

    func testAFailedReadIsReportedInsteadOfShowingAnEmptyBox() async {
        let transport = FakeTransport()
        transport.soulResult = .failure(AuxdError.transport("boom"))
        let store = makeStore(transport)
        let editor = PersonalityEditor()

        await editor.load { try await store.agentSoul(name: "scout") }

        XCTAssertEqual(editor.state, .failed(.readFailed))
    }

    // MARK: - Saving

    func testSaveSendsSoulMdAndConfirmsOnlyAfterItReachedTheService() async {
        let transport = FakeTransport()
        transport.soulResult = .success(AgentSoul(soulMd: "old", maxBytes: 1024))
        let store = makeStore(transport)
        let editor = PersonalityEditor()
        await editor.load { try await store.agentSoul(name: "scout") }

        editor.text = "new"
        await editor.save { try await store.updateAgentSoul(name: "scout", soul: $0) }

        XCTAssertEqual(editor.state, .saved)
        XCTAssertEqual(editor.savedText, "new")
        XCTAssertFalse(editor.canSave, "saved text is no longer a pending change")
        XCTAssertEqual(transport.soulSaves.count, 1)
        XCTAssertEqual(transport.soulSaves.first?.agent, "scout")
        XCTAssertEqual(transport.soulSaves.first?.soul, "new")
    }

    func testAFailedSaveKeepsTheTextAndSaysSo() async {
        let transport = FakeTransport()
        transport.soulResult = .success(AgentSoul(soulMd: "old", maxBytes: 1024))
        transport.updateSoulResult = .failure(AuxdError.transport("boom"))
        let store = makeStore(transport)
        let editor = PersonalityEditor()
        await editor.load { try await store.agentSoul(name: "scout") }

        editor.text = "new"
        await editor.save { try await store.updateAgentSoul(name: "scout", soul: $0) }

        XCTAssertEqual(editor.state, .failed(.saveFailed))
        XCTAssertEqual(editor.text, "new", "nothing is thrown away on a failure")
        XCTAssertEqual(editor.savedText, "old")
        XCTAssertTrue(editor.canSave, "the change is still pending, so it can be retried")
    }

    func testTheServiceRefusingTheBodySaysTooLongNotTryAgain() async {
        let transport = FakeTransport()
        transport.soulResult = .success(AgentSoul(soulMd: "old", maxBytes: 1024))
        transport.updateSoulResult = .failure(AuxdError.http(status: 413, body: "payload_too_large"))
        let store = makeStore(transport)
        let editor = PersonalityEditor()
        await editor.load { try await store.agentSoul(name: "scout") }

        editor.text = "new"
        await editor.save { try await store.updateAgentSoul(name: "scout", soul: $0) }

        XCTAssertEqual(editor.state, .failed(.tooLong))
        XCTAssertEqual(editor.text, "new")
    }

    // MARK: - Size ceiling

    func testTextPastTheCeilingIsCountedAndNeverSent() async {
        let transport = FakeTransport()
        transport.soulResult = .success(AgentSoul(soulMd: "ok", maxBytes: 4))
        let store = makeStore(transport)
        let editor = PersonalityEditor()
        await editor.load { try await store.agentSoul(name: "scout") }

        editor.text = "12345"
        XCTAssertEqual(editor.byteCount, 5)
        XCTAssertTrue(editor.isOverLimit)
        XCTAssertFalse(editor.canSave, "an oversized text cannot be saved")

        // The guard on `save` is belt-and-braces: even called directly it must
        // not send the text.
        await editor.save { _ in XCTFail("an oversized body must never be sent") }
        XCTAssertEqual(editor.state, .failed(.tooLong))
        XCTAssertTrue(transport.soulSaves.isEmpty)
    }

    func testTheCeilingCountsUtf8BytesNotCharacters() async {
        let transport = FakeTransport()
        transport.soulResult = .success(AgentSoul(soulMd: "", maxBytes: 3))
        let store = makeStore(transport)
        let editor = PersonalityEditor()
        await editor.load { try await store.agentSoul(name: "scout") }

        editor.text = "éé" // two characters, four UTF-8 bytes.
        XCTAssertEqual(editor.byteCount, 4)
        XCTAssertTrue(editor.isOverLimit)
    }

    // MARK: - The client's wire shape

    func testPluginToolToggleSendsTheSelectedAgentAndNamesWithPut() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(baseURL: URL(string: "http://127.0.0.1:2893")!, home: home, tokenFile: tokenFile, lockPID: nil, source: "test")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        let client = AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)
        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            let json = (try? JSONSerialization.jsonObject(with: self.requestBody(request))) as? [String: Any]
            XCTAssertEqual(json?["tools"] as? [String], ["search"])
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!, Data(#"{"ok":true}"#.utf8))
        }
        try await client.setMcpTools(id: "server", agent: "scout", tools: ["search"])
        let request = try XCTUnwrapOptional(RecordingURLProtocol.recorded.last)
        XCTAssertEqual(request.method, "PUT")
        XCTAssertTrue(request.url.hasSuffix("/v1/mcp/servers/server/agents/scout"))
    }

    func testTheClientSendsSoulMdToTheUpdateRoute() async throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let tokenFile = home.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: tokenFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        let endpoint = AuxdEndpoint(
            baseURL: URL(string: "http://127.0.0.1:2893")!,
            home: home,
            tokenFile: tokenFile,
            lockPID: nil,
            source: "test"
        )
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RecordingURLProtocol.self]
        let client = AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)

        RecordingURLProtocol.reset()
        defer { RecordingURLProtocol.reset() }
        RecordingURLProtocol.respond { request in
            let body = (try? JSONSerialization.jsonObject(with: self.requestBody(request)))
                as? [String: Any]
            XCTAssertEqual(body?["soul_md"] as? String, "be terse")
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data(#"{"changed":true}"#.utf8))
        }

        try await client.updateAgentSoul(name: "scout", soul: "be terse")

        let record = try XCTUnwrapOptional(RecordingURLProtocol.recorded.last)
        XCTAssertEqual(record.method, "PUT")
        XCTAssertEqual(record.url, "http://127.0.0.1:2893/v1/agents/scout")
        XCTAssertEqual(record.authorization, "Bearer deadbeef")
    }

    // MARK: - Helpers

    private func temporaryHome() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-soul-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// The request body, whether the session handed it over as `httpBody` or
    /// as a stream (URLProtocol commonly sees the stream).
    private func requestBody(_ request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let size = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: size)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}
