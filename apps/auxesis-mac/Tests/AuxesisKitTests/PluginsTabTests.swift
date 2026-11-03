import XCTest
@testable import AuxesisKit

/// M6-4: the Plugins tab's data path. Browse reads only; install stages and
/// previews; one approve sends the previewed hash back.
@objcMembers @MainActor final class PluginsTabTests: XCTestCase {
    private enum Unused: Error { case call }

    /// Records every plugin call; the chat transport is never used here.
    final class PluginsFake: AuxdTransport, PluginsClient {
        nonisolated(unsafe) var calls: [String] = []
        private let lock = NSLock()
        nonisolated(unsafe) var catalog: [McpCatalogEntry] = []
        nonisolated(unsafe) var servers: [McpServerView] = []
        nonisolated(unsafe) var preview: McpApprovalPreview?
        nonisolated(unsafe) var approved: (id: String, hash: String, agent: String)?
        /// r1: the daemon's hash binds the staged agent; the fake mirrors that per agent.
        nonisolated(unsafe) var hashPerAgent = false
        nonisolated(unsafe) var addFails = false
        /// M6-APP-APPROVE-ONLY: what the daemon answers to the next write (PUT, approve).
        nonisolated(unsafe) var writeError: Error?
        private func write() throws { if let error = writeError { writeError = nil; throw error } }
        private func log(_ call: String) { lock.lock(); calls.append(call); lock.unlock() }

        func mcpCatalog() async throws -> [McpCatalogEntry] { log("GET catalog"); return catalog }
        func mcpPacks() async throws -> [McpPack] { log("GET packs"); return [] }
        func mcpServers() async throws -> [McpServerView] { log("GET servers"); return servers }
        func enableMcpPack(id: String, agent: String) async throws { log("POST pack") }
        func addMcpServer(id: String, catalogID: String, agent: String) async throws -> McpApprovalPreview {
            log("POST add \(id) \(catalogID) \(agent)")
            if addFails { throw Unused.call }
            guard hashPerAgent, let preview else { return preview! }
            return try JSONDecoder().decode(McpApprovalPreview.self, from: Data(#"{"id":"\#(preview.id)","transport":"http","enabled":false,"network":true,"env":[],"data_class":"public","args":[],"tools":[],"hash":"hash-\#(agent)"}"#.utf8))
        }
        func mcpApproval(id: String) async throws -> McpApprovalPreview { log("GET approval \(id)"); return preview! }
        func approveMcpServer(id: String, hash: String, agent: String) async throws { log("POST approve \(id)"); try write(); approved = (id, hash, agent) }
        func testMcpServer(url: String) async throws -> McpConnectionTest { log("POST test"); throw Unused.call }
        func addMcpUrlServer(id: String, url: String, dataClass: String, testDigest: String) async throws { log("POST add-url") }
        func setMcpServer(id: String, enabled: Bool) async throws { log("PUT enabled \(enabled)"); try write() }
        func setMcpTools(id: String, agent: String, tools: [String]) async throws { log("PUT tools"); try write() }
        func deleteMcpServer(id: String) async throws { log("DELETE \(id)") }

        func health() async throws -> HealthResponse { throw Unused.call }
        func agents() async throws -> [AgentSummary] { throw Unused.call }
        func messages(thread: String, limit: Int) async throws -> MessagesPage { throw Unused.call }
        func pendingApprovals() async throws -> [Approval] { throw Unused.call }
        func receipts(agent: String?, limit: Int) async throws -> [Receipt] { [] }
        func send(thread: String, content: String) async throws -> SendResponse { throw Unused.call }
        func resolve(id: String, decision: String, scope: ApprovalScope?, text: String?) async throws -> ApprovalState { throw Unused.call }
        func events() throws -> AsyncThrowingStream<WireEvent, Error> { throw Unused.call }
    }

    private func fake() throws -> PluginsFake {
        let fake = PluginsFake()
        fake.catalog = try Fixtures.decode(McpCatalogResponse.self, "plugins-catalog.json").servers
        fake.servers = try Fixtures.decode(McpServersResponse.self, "plugins-servers.json").servers
        fake.preview = try Fixtures.decode(McpApprovalPreview.self, "plugins-preview.json")
        return fake
    }

    func testFixturesDecode() throws {
        let fake = try fake()
        XCTAssertEqual(fake.catalog.map(\.id), ["public-data", "notes-local", "law-reader"])
        XCTAssertEqual(PluginAccess(fake.catalog[0].access), .read)
        XCTAssertEqual(PluginAccess(fake.catalog[1].access), .readWrite)
        XCTAssertEqual(PluginText.connects(fake.catalog[0], .en), "mcp.data.example")
        XCTAssertEqual(PluginText.connects(fake.catalog[1], .en), "A program on this Mac")
        XCTAssertEqual(PluginText.connects(fake.catalog[2], .fr), "Non vérifié")
        XCTAssertEqual(PluginText.purpose(fake.catalog[0]), "Searches open public datasets with no key.")
        guard let preview = fake.preview else { return XCTFail("no preview") }
        XCTAssertEqual(preview.hash, "approval-hash-1")
        XCTAssertEqual(preview.env, ["PUBLIC_DATA_TOKEN"])
        XCTAssertEqual(preview.tools.map(\.access), ["read", "write"])
        XCTAssertEqual(PluginText.network(preview, .en), "mcp.data.example")
        XCTAssertEqual(PluginText.runs(preview), "https://mcp.data.example/mcp")
    }

    func testStatesMapAndOnlyNeedsYouIsAmber() throws {
        let states = try fake().servers.map(PluginState.init)
        XCTAssertEqual(states, [.on, .needsYou, .off, .error])
        XCTAssertEqual(states.filter(\.isAmber), [.needsYou])
        XCTAssertEqual(L10n.ui(PluginState.needsYou.key, .en), "Needs you")
        XCTAssertFalse(L10n.ui(PluginState.needsYou.key, .fr).isEmpty)
    }

    func testBrowseMakesNoAddOrApproveCall() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        await store.loadPlugins()
        XCTAssertEqual(store.mcpCatalog.count, 3)
        XCTAssertEqual(store.mcpServers.count, 4)
        XCTAssertNil(store.pluginPreview)
        XCTAssertTrue(fake.calls.allSatisfy { $0.hasPrefix("GET catalog") || $0.hasPrefix("GET servers") || $0.hasPrefix("GET packs") }, "\(fake.calls)")
    }

    func testInstallPreviewThenOneApprove() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        await store.loadPlugins()
        fake.calls.removeAll()

        await store.installPlugin(store.mcpCatalog[0])
        XCTAssertEqual(store.pluginPreview?.hash, "approval-hash-1", "install opens the preview")
        XCTAssertEqual(fake.calls.first, "POST add public-data public-data aux")
        XCTAssertFalse(fake.calls.contains { $0.hasPrefix("POST approve") }, "nothing is approved before the yes")

        await store.approvePluginPreview()
        XCTAssertEqual(fake.approved?.id, "public-data")
        XCTAssertEqual(fake.approved?.hash, "approval-hash-1", "the yes approves exactly the shown preview")
        XCTAssertEqual(fake.approved?.agent, "aux", "Aux by default, the agent the sheet names")
        XCTAssertEqual(L10n.ui(.pluginGivesTo, .en), "Gives these tools to %@")
        XCTAssertEqual(fake.calls.filter { $0.hasPrefix("POST approve") }.count, 1)
        XCTAssertNil(store.pluginPreview)
    }

    func testNotNowApprovesNothing() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        await store.reviewPlugin(fake.servers[1])
        XCTAssertEqual(fake.calls, ["GET approval notes"])
        store.cancelPluginPreview()
        await store.approvePluginPreview()
        XCTAssertNil(fake.approved)
    }

    /// #532 P2: the approve carries the chosen agent with the hash of the preview on screen.
    func testApproveSendsChosenAgentWithItsOwnPreviewHash() async throws {
        let fake = try fake()
        fake.hashPerAgent = true
        let store = Store(transport: fake, language: .en)
        await store.loadPlugins()
        await store.installPlugin(store.mcpCatalog[0])
        XCTAssertEqual(store.pluginPreview?.hash, "hash-aux")
        XCTAssertEqual(store.pluginPreviewAgent, "aux")
        fake.calls.removeAll()

        await store.choosePluginAgent("mail")
        XCTAssertEqual(fake.calls, ["DELETE public-data", "POST add public-data public-data mail"], "another agent stages a new preview")
        XCTAssertEqual(store.pluginPreview?.hash, "hash-mail")
        XCTAssertEqual(TeamMember.displayName(store.pluginAgent), "Mail")
        await store.approvePluginPreview()
        XCTAssertEqual(fake.approved?.agent, "mail")
        XCTAssertEqual(fake.approved?.hash, "hash-mail")
    }

    /// #532 P2: after a change of agent, the old hash never goes out with the new agent.
    func testChangedAgentNeverSendsTheOldHash() async throws {
        let fake = try fake()
        fake.hashPerAgent = true
        let store = Store(transport: fake, language: .en)
        await store.loadPlugins()
        await store.installPlugin(store.mcpCatalog[0])
        fake.addFails = true
        await store.choosePluginAgent("documents")
        XCTAssertEqual(store.pluginAgent, "documents")
        XCTAssertNil(store.pluginPreviewAgent, "no preview belongs to Documents yet")
        await store.approvePluginPreview()
        XCTAssertNil(fake.approved, "hash-aux is never sent for Documents")
        XCTAssertFalse(fake.calls.contains { $0.hasPrefix("POST approve") })
    }

    /// The daemon's `AddRequest` and `ApproveRequest` use
    /// `deny_unknown_fields`, so one stray key turns every install into a 400.
    /// Keep these lists equal to the Rust structs in
    /// `crates/auxd/src/api/mcp_plugins.rs` (including `agent`).
    func testAddAndApproveBodiesOnlySendKeysTheDaemonAccepts() throws {
        let addRequestFields: Set<String> = ["id", "catalog_id", "transport", "url", "command", "args", "env",
                                             "data_class", "network", "stdio_confirmed", "test_digest", "agent", "tools"]
        func keys<T: Encodable>(_ body: T) throws -> Set<String> {
            let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(body)) as? [String: Any]
            return Set((object ?? [:]).keys)
        }
        let add = try keys(McpAddBody(id: "files", catalogID: "files", agent: "aux"))
        XCTAssertEqual(add, ["id", "catalog_id", "agent"])
        XCTAssertTrue(add.isSubset(of: addRequestFields))
        let url = try keys(McpUrlBody(id: "web", url: "https://example.test/mcp", dataClass: "public", testDigest: "d"))
        XCTAssertTrue(url.isSubset(of: addRequestFields))
        XCTAssertEqual(try keys(McpApproveBody(hash: "h", agent: "aux")), ["hash", "agent"])
    }

    // MARK: M6-APP-APPROVE-ONLY: every turn-on goes through the preview and one approve.

    private static func conflict(_ code: String) -> AuxdError {
        .http(status: 409, body: #"{"error":{"code":"\#(code)","message":"x"}}"#)
    }

    func testNoFlowCallsLegacyConfirm() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        await store.loadPlugins()
        await store.installPlugin(store.mcpCatalog[1]); await store.approvePluginPreview()
        for server in fake.servers { await store.setPlugin(server, enabled: !server.enabled); await store.approvePluginPreview() }
        await store.reviewPlugin(fake.servers[1]); await store.approvePluginPreview()
        XCTAssertFalse(fake.calls.contains { $0.lowercased().contains("confirm") }, "\(fake.calls)")
        XCTAssertFalse(fake.calls.contains("PUT enabled true"), "turning on is never a bare PUT")
        let client = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../Sources/AuxesisKit/AuxdClient.swift")
        let source = try String(contentsOf: client, encoding: .utf8)
        XCTAssertFalse(source.contains("/confirm"), "the app never builds the legacy confirm route")
    }

    func testReEnablingAnOffServerPreviewsThenApprovesHashAndAgent() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        let off = fake.servers[2]
        XCTAssertEqual(PluginState(off), .off)
        await store.setPlugin(off, enabled: true)
        XCTAssertEqual(fake.calls.first, "GET approval old")
        XCTAssertNil(fake.approved, "nothing runs before the yes")
        XCTAssertEqual(store.pluginPreview?.hash, "approval-hash-1")
        await store.approvePluginPreview()
        XCTAssertEqual(fake.approved?.id, "public-data", "the approve names the previewed server")
        XCTAssertEqual(fake.approved?.hash, "approval-hash-1")
        XCTAssertEqual(fake.approved?.agent, "aux", "the agent the sheet showed")
    }

    func testUseApproveConflictOpensThePreviewNotAnError() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        fake.writeError = Self.conflict("use_approve")
        await store.setPluginTools(fake.servers[1], agent: "main", tools: ["LOOKUP"])
        XCTAssertEqual(store.pluginPreview?.hash, "approval-hash-1", "409 use_approve opens the preview")
        XCTAssertFalse(store.mcpFailed)
        XCTAssertNil(store.mcpFailureCode)
        XCTAssertTrue(fake.calls.contains("GET approval notes"))
    }

    func testStaleApproveRefetchesThePreview() async throws {
        let fake = try fake()
        let store = Store(transport: fake, language: .en)
        await store.reviewPlugin(fake.servers[2])
        fake.writeError = Self.conflict("approval_required")
        await store.approvePluginPreview()
        XCTAssertNil(fake.approved)
        XCTAssertNotNil(store.pluginPreview, "the sheet stays open on the fresh preview")
        XCTAssertNil(store.mcpFailureCode)
        XCTAssertEqual(fake.calls.filter { $0.hasPrefix("GET approval") }.count, 2, "a fresh preview, no error")
        await store.approvePluginPreview()
        XCTAssertEqual(fake.approved?.hash, "approval-hash-1")
    }
}
