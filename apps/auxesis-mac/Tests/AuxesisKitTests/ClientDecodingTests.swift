// Decoding the recorded daemon shapes (fixtures copied from the real
// auxd B-API contract): REST pages, approvals, WS frames, unknown frames.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ClientDecodingTests: XCTestCase {
    func testMcpCatalogAndInstalledServerDecodeWithoutRemoteDescriptions() throws {
        let catalog = try JSONDecoder().decode(McpCatalogResponse.self, from: Data(#"{"servers":[{"id":"example","name":"Example","region":"fr","category":"law","status":"official","tier":"recommended","data_class":"public","auth":"none","access":"read-only","transport":"http","endpoint":"https://example.invalid/mcp","repo_url":"https://example.invalid","notes":"plain text"}]}"#.utf8))
        XCTAssertEqual(catalog.servers.first?.id, "example")
        let installed = try JSONDecoder().decode(McpServersResponse.self, from: Data(#"{"servers":[{"id":"example","enabled":false,"state":"disabled","transport":"http","auth":"none","data_class":"public","tools":[{"name":"search","risk":"low"}],"agents":{"main":[]}}]}"#.utf8))
        XCTAssertEqual(installed.servers.first?.tools.first?.risk, "low")
        XCTAssertEqual(installed.servers.first?.agents["main"], [])
    }

    func testMcpServerReadsTheAgentsKeyAndTheLegacyDotsKey() throws {
        for key in ["agents", "dots"] {
            let json = #"{"servers":[{"id":"x","enabled":true,"state":"ok","transport":"http","auth":"none","data_class":"public","tools":[],"\#(key)":{"main":["a"]}}]}"#
            let installed = try JSONDecoder().decode(McpServersResponse.self, from: Data(json.utf8))
            XCTAssertEqual(installed.servers.first?.agents["main"], ["a"], key)
        }
    }

    func testHealthDecodes() throws {
        let health = try Fixtures.health()
        XCTAssertTrue(health.ok)
        XCTAssertEqual(health.version, "0.1.0")
        XCTAssertEqual(health.pid, 4242)
        XCTAssertTrue(health.firstRun)
        // A service without the Google connection field reads as not
        // connected instead of failing the whole snapshot.
        XCTAssertFalse(health.googleConnected)
    }

    func testHealthDecodesTheGoogleFlagWhenTheServiceAnswersIt() throws {
        let json = #"{"ok":true,"version":"0.1.0","pid":1,"first_run":false,"google_connected":true}"#
        let health = try JSONDecoder().decode(HealthResponse.self, from: Data(json.utf8))
        XCTAssertTrue(health.googleConnected)
        XCTAssertFalse(health.firstRun)
    }

    func testAgentsDecodeAllStates() throws {
        let agents = try Fixtures.agents()
        XCTAssertEqual(agents.count, 4)
        let scout = try XCTUnwrapOptional(agents.first { $0.name == "scout" })
        XCTAssertEqual(scout.threadId, "7")
        XCTAssertEqual(scout.jobsTotal, 1)
        XCTAssertEqual(scout.usageToday.tokensIn, 41000)
        XCTAssertEqual(scout.lastActivity?.summary, "researching Lightpanda")

        let mail = try XCTUnwrapOptional(agents.first { $0.name == "mail" })
        XCTAssertEqual(mail.runningJob, "triage")
        XCTAssertFalse(mail.enabled)

        let ledger = try XCTUnwrapOptional(agents.first { $0.name == "ledger" })
        XCTAssertTrue(ledger.stop)

        let coach = try XCTUnwrapOptional(agents.first { $0.name == "coach" })
        XCTAssertTrue(coach.paused)
    }

    func testMessagesPageDecodes() throws {
        let page = try Fixtures.messagesPage()
        XCTAssertEqual(page.thread?.id, 7)
        XCTAssertEqual(page.messages.count, 3)
        XCTAssertEqual(page.messages[0].role, "user")
        XCTAssertEqual(page.messages[1].role, "assistant")
        XCTAssertEqual(page.messages[2].role, "tool")
        XCTAssertFalse(page.hasMore)
        XCTAssertEqual(page.oldestId, 10)
    }

    func testLocalSkillsDecodeStatusAndIgnoredFileWarning() throws {
        let json = #"[{"name":"writing","description":"Write clearly","size":12,"status":{"state":"valid","warning":"other files are present and ignored"}},{"name":"linked","description":null,"size":0,"status":{"state":"ignored","reason":"symbolic link"}}]"#
        let skills = try JSONDecoder().decode([LocalSkill].self, from: Data(json.utf8))
        XCTAssertEqual(skills[0].warning, "other files are present and ignored")
        XCTAssertEqual(skills[1].warning, nil)
    }

    func testApprovalsDecodeTaintAndChecks() throws {
        let approvals = try Fixtures.approvals()
        XCTAssertEqual(approvals.count, 3)

        let shell = approvals[0]
        XCTAssertEqual(shell.id, "ap-1-1")
        XCTAssertEqual(shell.auditId, 4809)
        XCTAssertTrue(shell.destructive)
        XCTAssertNil(shell.taint)
        XCTAssertFalse(shell.unsandboxed)
        XCTAssertTrue(shell.state.isPending)

        let email = approvals[1]
        XCTAssertNotNil(email.taint)
        XCTAssertEqual(email.verifier?.agrees, true)
        XCTAssertEqual(email.verifier?.model, "Claude")
        XCTAssertEqual(email.scopeResource, "billing@acme-studio.test")
        XCTAssertNotNil(email.fullPreview)

        let unsandboxed = approvals[2]
        XCTAssertTrue(unsandboxed.unsandboxed)
    }

    func testResolveResponseDecodes() throws {
        let response = try Fixtures.decode(ResolveResponse.self, "resolve-response.json")
        XCTAssertEqual(response.state, .allowed(by: "you", always: false))
    }

    func testARehydrationBannerFlagReachesTheDeltaAndThePersistedMessage() throws {
        // The daemon renders the screen; the app only shows what it is sent.
        let delta = Data(#"{"type":"message.delta","thread_id":"7","message_id":"13","seq":1,"text":"Bonjour [référence inconnue]","agent":"scout","rehydration_unavailable":true}"#.utf8)
        guard case .messageDelta(_, _, let text, _, let unavailable) = try WireEventDecoder.decode(delta) else {
            return XCTFail("expected message.delta")
        }
        XCTAssertEqual(text, "Bonjour [référence inconnue]")
        XCTAssertTrue(unavailable)

        let persisted = Data(#"{"type":"message.new","message":{"id":"14","thread_id":"7","author":{"kind":"agent","id":"scout"},"ts":1,"blocks":[{"kind":"text","text":"⟦EMAIL_0123456789AB⟧"}],"streaming":false,"pending":false,"rehydration_unavailable":true}}"#.utf8)
        guard case .messageNew(let message) = try WireEventDecoder.decode(persisted) else {
            return XCTFail("expected message.new")
        }
        XCTAssertTrue(message.rehydrationUnavailable)
        XCTAssertEqual(message.text, "⟦EMAIL_0123456789AB⟧", "the app shows the frame text as sent")
    }

    func testEveryRecordedEventDecodes() throws {
        let events = try Fixtures.events()
        XCTAssertEqual(events.count, 12)

        guard case .messageNew(let first) = events[0] else { return XCTFail("expected message.new") }
        XCTAssertEqual(first.id, "11")
        XCTAssertEqual(first.author, .you)
        XCTAssertEqual(first.text, "Find out whether Lightpanda works.")

        guard case .messageNew(let second) = events[1] else { return XCTFail("expected message.new") }
        XCTAssertEqual(second.author, .agent("scout"))
        XCTAssertEqual(second.threadKey, "7")

        guard case .messageDelta(let threadId, let messageId, let text, let agent, let unavailable) = events[2] else {
            return XCTFail("expected message.delta")
        }
        XCTAssertEqual(threadId, "7")
        XCTAssertEqual(messageId, "13")
        XCTAssertEqual(text, "Working")
        XCTAssertEqual(agent, "scout")
        XCTAssertFalse(unavailable, "a delta without the flag is not a banner")

        guard case .messageDone(_, let doneId) = events[4] else { return XCTFail("expected message.done") }
        XCTAssertEqual(doneId, "13")

        guard case .toolStart(_, _, let start) = events[5] else { return XCTFail("expected tool.start") }
        XCTAssertEqual(start.tool, "web_search")
        XCTAssertNil(start.ok)

        guard case .toolEnd(_, _, let index, let end) = events[6] else { return XCTFail("expected tool.end") }
        XCTAssertEqual(index, 0)
        XCTAssertEqual(end.ok, true)
        XCTAssertEqual(end.resultPreview, "3 results")

        guard case .approvalNew(let approval) = events[7] else { return XCTFail("expected approval.new") }
        XCTAssertEqual(approval.id, "ap-1-1")

        guard case .approvalResolved(let id, let state) = events[8] else { return XCTFail("expected approval.resolved") }
        XCTAssertEqual(id, "ap-1-1")
        XCTAssertEqual(state, .allowed(by: "you", always: false))

        guard case .agentStateLive(let agent, let state) = events[9] else { return XCTFail("expected live agent.state") }
        XCTAssertEqual(agent, "scout")
        XCTAssertEqual(state, .working)

        guard case .agentSnapshot(let snapshot) = events[10] else { return XCTFail("expected polled agent.state") }
        XCTAssertEqual(snapshot.name, "scout")
        XCTAssertEqual(snapshot.threadId, "7")

        guard case .other(let unknown) = events[11] else { return XCTFail("expected .other") }
        XCTAssertEqual(unknown, "provider.upsert")
    }

    func testUnknownFramesBecomeOther() throws {
        let data = Data(#"{"type":"provider.upsert","provider":{"id":"p1"}}"#.utf8)
        guard case .other(let kind) = try WireEventDecoder.decode(data) else {
            return XCTFail("unknown frame must be .other")
        }
        XCTAssertEqual(kind, "provider.upsert")

        // An agent.state with neither shape is skipped as .other, never a crash.
        let odd = Data(#"{"type":"agent.state","agent":"x","state":42}"#.utf8)
        guard case .other = try WireEventDecoder.decode(odd) else {
            return XCTFail("odd agent.state must be .other")
        }
    }

    // MARK: Wire tolerance defaults

    func testAgentSummaryMissingEnabledDefaultsToEnabled() throws {
        let data = Data(#"{"name":"solo"}"#.utf8)
        let agent = try JSONDecoder().decode(AgentSummary.self, from: data)
        XCTAssertTrue(agent.enabled, "an agent without an explicit enabled flag is enabled (M4)")
        XCTAssertEqual(agent.jobsTotal, 0)
        XCTAssertFalse(agent.stop)
    }

    func testThePrivacyChipReadsTheDaemonsMode() throws {
        for (raw, mode, english, french) in [
            ("open", PrivacyMode.open, "Open", "Ouvert"),
            ("private", PrivacyMode.privateMode, "Private", "Privé"),
        ] {
            let data = Data("{\"name\":\"mail\",\"privacy_mode\":\"\(raw)\"}".utf8)
            let agent = try JSONDecoder().decode(AgentSummary.self, from: data)
            XCTAssertEqual(agent.privacyMode, mode)
            XCTAssertEqual(L10n.ui(agent.privacyMode.chipKey, .en), english)
            XCTAssertEqual(L10n.ui(agent.privacyMode.chipKey, .fr), french)
            XCTAssertEqual(Mapper.agent(from: agent, live: nil).privacyMode, mode)
        }
        XCTAssertTrue(L10n.ui(.modePhrasePrivate, .en).contains("tokenised"))
        XCTAssertFalse(L10n.ui(.modePhraseOpen, .en).lowercased().contains("tokenised"),
                       "Open never claims tokenisation")
    }

    func testAMissingOrUnknownPrivacyModeIsNeverPrivate() throws {
        for json in [#"{"name":"mail"}"#, #"{"name":"mail","privacy_mode":"future-mode"}"#] {
            let agent = try JSONDecoder().decode(AgentSummary.self, from: Data(json.utf8))
            XCTAssertEqual(agent.privacyMode, .unknown)
            XCTAssertNotEqual(L10n.ui(agent.privacyMode.chipKey, .en), "Private")
            XCTAssertNotEqual(L10n.ui(agent.privacyMode.chipKey, .fr), "Privé")
            XCTAssertFalse(L10n.ui(agent.privacyMode.composerKey, .en).lowercased().contains("tokenised"))
            XCTAssertEqual(Mapper.agent(from: agent, live: nil).privacyMode, .unknown)
        }
    }

    func testUnknownApprovalStatesDecodeToUnknownNotPending() throws {
        for raw in ["superseded", "deferred", "blocked", "what_ever"] {
            let data = Data("{\"state\":\"\(raw)\",\"by\":\"daemon\"}".utf8)
            let state = try JSONDecoder().decode(ApprovalState.self, from: data)
            XCTAssertEqual(state, .unknown(raw))
            XCTAssertFalse(state.isPending, "\(raw) must not decode as pending (F3)")
        }
        // Known states keep working.
        XCTAssertEqual(
            try JSONDecoder().decode(ApprovalState.self, from: Data(#"{"state":"pending"}"#.utf8)),
            .pending
        )
        XCTAssertEqual(
            try JSONDecoder().decode(ApprovalState.self, from: Data(#"{"state":"allowed","by":"you","always":true}"#.utf8)),
            .allowed(by: "you", always: true)
        )
    }

    func testReconnectBackoffSequenceIsPinned() {
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 0), 0)
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 1), 0.5)
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 2), 1.0)
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 3), 2.0)
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 4), 4.0)
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 5), 8.0)
        XCTAssertEqual(ReconnectPolicy.delay(attempt: 50), 8.0)
    }

    func testWebsocketURLMapping() {
        let http = URL(string: "http://127.0.0.1:2893")!
        XCTAssertEqual(AuxdClient.websocketURL(from: http)?.absoluteString, "ws://127.0.0.1:2893/v1/events")
        let https = URL(string: "https://example.test/base")!
        XCTAssertEqual(AuxdClient.websocketURL(from: https)?.absoluteString, "wss://example.test/v1/events")
    }

    func testThreadAliasesLearnAndMap() throws {
        var aliases = ThreadAliases()
        aliases.learn(agent: "scout", sessionId: "7")
        XCTAssertEqual(aliases.visible(threadId: "7", agent: "scout"), "scout")
        XCTAssertEqual(aliases.visible(threadId: "unknown", agent: "mail"), "mail")
        XCTAssertNil(aliases.visible(threadId: "", agent: nil))

        let page = try Fixtures.messagesPage()
        aliases.learn(page: page, agent: "scout")
        XCTAssertEqual(aliases.visible(threadId: "7", agent: nil), "scout")
    }

    func testAgentMappingFollowsDaemonState() throws {
        let agents = try Fixtures.agents()
        let scout = try XCTUnwrapOptional(agents.first { $0.name == "scout" })
        let thinking = Mapper.agent(from: scout, live: .thinking)
        XCTAssertEqual(thinking.state, .thinking)
        XCTAssertEqual(thinking.threadKey, "scout")

        let stopped = Mapper.agent(from: scout, live: .thinking)
        XCTAssertEqual(stopped.state, .thinking)
        let pausedAgent = try XCTUnwrapOptional(agents.first { $0.name == "coach" })
        XCTAssertEqual(Mapper.agent(from: pausedAgent, live: nil).state, .paused)
        let stoppedAgent = try XCTUnwrapOptional(agents.first { $0.name == "ledger" })
        XCTAssertEqual(Mapper.agent(from: stoppedAgent, live: nil).state, .paused)
        let workingAgent = try XCTUnwrapOptional(agents.first { $0.name == "mail" })
        XCTAssertEqual(Mapper.agent(from: workingAgent, live: nil).state, .working)
    }

    func testMessageMappingUsesWireIds() throws {
        let page = try Fixtures.messagesPage()
        let message = Mapper.message(from: page.messages[0], threadKey: "scout", agentName: "scout")
        XCTAssertEqual(message.id, "10")
        XCTAssertEqual(message.author, .you)
        let assistant = Mapper.message(from: page.messages[1], threadKey: "scout", agentName: "scout")
        XCTAssertEqual(assistant.author, .agent("scout"))
        let tool = Mapper.message(from: page.messages[2], threadKey: "scout", agentName: "scout")
        XCTAssertEqual(tool.author, .tool)
    }
}

/// `XCTUnwrapOptional` equivalent: the CLT shim has no throwing unwrap.
func XCTUnwrapOptional<T>(_ value: T?, file: StaticString = #filePath, line: UInt = #line) throws -> T {
    guard let value else {
        XCTFail("expected non-nil", file: file, line: line)
        throw TestError.unwrap
    }
    return value
}

enum TestError: Error {
    case unwrap
}
