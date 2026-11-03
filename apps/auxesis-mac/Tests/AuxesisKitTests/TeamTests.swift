// The E2 team shell: copy, icons, the sidebar rows, the thread timeline, the
// mail draft, and the decoders for the NEW routes (delegations, coverage,
// skill hash in the Ledger). No network: everything is built in memory.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class TeamCopyTests: XCTestCase {
    func testAgentsAndRulesRosterUsesContractOrderAndFiveMembers() {
        XCTAssertEqual(TeamMember.all.map(\.name), ["Aux", "Mail", "Calendar", "Clients", "Documents"])
    }

    func testWorkingCountCopyUsesSingularInEnglishAndFrench() {
        XCTAssertEqual(L10n.ui(.chiefWorkingOne, .en), "1 agent working")
        XCTAssertEqual(L10n.ui(.chiefWorkingOne, .fr), "1 agent en activité")
        XCTAssertEqual(L10n.uf(.chiefWorkingMany, .en, 2), "2 agents working")
        XCTAssertEqual(L10n.uf(.chiefWorkingMany, .fr, 2), "2 agents en activité")
        XCTAssertEqual(L10n.ui(.menuWorkingOne, .fr), "1 agent en activité")
        XCTAssertEqual(L10n.uf(.menuWorkingMany, .fr, 2), "2 agents en activité")
    }

    func testGrantTableDecodesLevelsAndKeepsUnavailableRouteDistinct() throws {
        let grants = try JSONDecoder().decode(AgentGrants.self, from: Data(#"{"see":[{"scope":"mail","via":"read_mail","level":"read"}],"do":[{"skill":"draft_reply","level":"ask"}],"never":["send"],"egress_note":"Stays local"}"#.utf8))
        XCTAssertEqual(grants.see.first?.level, "read")
        XCTAssertEqual(grants.canDo.first?.level, "ask")
        XCTAssertEqual(grants.never, ["send"])
        XCTAssertEqual(grants.egressNote, "Stays local")
    }

    func testEveryUIKeyHasEnglishCopy() {
        for key in UIKey.allCases {
            XCTAssertFalse(L10n.ui(key, .en).isEmpty, "\(key) has no English copy")
            if key != .now {
                XCTAssertNotEqual(L10n.ui(key, .en), key.rawValue, "\(key) falls back to its key")
            }
        }
    }

    func testCopyAvoidsJargonAndBannedTells() {
        // Owner copy: no daemon words, no taint, no emoji, no exclamation marks.
        for key in UIKey.allCases {
            let text = L10n.ui(key, .en).lowercased()
            for word in ["daemon", "auxd", "taint", "egress", "llm", "!"] {
                XCTAssertFalse(text.contains(word), "\(key) says \(word)")
            }
            XCTAssertFalse(text.unicodeScalars.contains { $0.properties.isEmojiPresentation }, "\(key) has an emoji")
        }
    }

    /// ACT-FREE-GRANTS-1: Settings says why an ACP brain's reads open a card,
    /// in both languages, with no privacy overclaim.
    func testSettingsExplainsWhyAnACPBrainAsksBeforeAReadInBothLanguages() {
        XCTAssertEqual(
            L10n.ui(.acpReadsAsk, .en),
            "A brain run by another app (ACP) reads only its own workspace through Auxesis; anything it asks permission for opens a card."
        )
        XCTAssertEqual(
            L10n.ui(.acpReadsAsk, .fr),
            "Un cerveau géré par une autre app (ACP) ne lit que son propre espace de travail via Auxesis ; ce pour quoi il demande la permission ouvre une carte."
        )
        for language in [Language.en, .fr] {
            let text = L10n.ui(.acpReadsAsk, language).lowercased()
            for claim in ["never leaves", "ne quitte jamais", "private", "privé", "100"] {
                XCTAssertFalse(text.contains(claim), "\(language) says \(claim)")
            }
        }
    }

    func testFrenchFallsBackToEnglishUntilTranslated() {
        XCTAssertEqual(L10n.ui(.waitingEmpty, .fr), L10n.ui(.waitingEmpty, .en))
    }

    func testE1EmptyStatesAreVerbatim() {
        XCTAssertEqual(L10n.ui(.waitingEmpty, .en), "Nothing waits for you. Agents ask here and in their own threads.")
        XCTAssertEqual(L10n.ui(.ledgerEmpty, .en), "Nothing has happened yet. Every action and every send will be listed here.")
        XCTAssertEqual(L10n.ui(.clientsEmpty, .en), "No clients yet. Import contacts, or tell Clients about someone.")
        XCTAssertEqual(L10n.ui(.providersEmpty, .en), "No brain yet. Add a provider to start.")
        XCTAssertEqual(L10n.uf(.memoryEmpty, .en, "Mail"), "Nothing remembered yet. Mail saves rules you give it, with the date.")
    }

    func testEveryIconParsesToAPathOnTheGrid() {
        for icon in Icon.allCases {
            let box = icon.path.boundingBoxOfPath
            XCTAssertFalse(icon.path.isEmpty, "\(icon) is empty")
            XCTAssertGreaterThanOrEqual(box.minX, -0.5, "\(icon) leaves the grid")
            XCTAssertLessThanOrEqual(box.maxX, 16.5, "\(icon) leaves the grid")
            XCTAssertLessThanOrEqual(box.maxY, 16.5, "\(icon) leaves the grid")
        }
    }

    func testAgentsSortByUrgencyThenName() {
        func agent(_ name: String, _ state: AgentState) -> Agent {
            Agent(id: name, name: name, hue: 0, glyph: "X", state: state, status: "", threadKey: name)
        }
        let sorted = Agent.sorted([
            agent("zed", .idle),
            agent("ann", .working),
            agent("max", .needsYou),
            agent("bob", .paused),
        ])
        XCTAssertEqual(sorted.map(\.name), ["max", "ann", "zed", "bob"])
    }
}

@objcMembers @MainActor final class TeamPresenterTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_760_000_000)

    private func row(_ member: TeamMember, working: Set<String> = [], delegations: [Delegation] = [], waiting: Int = 0, teamWaiting: Int = 0, stopped: Bool = false) -> TeamRowModel {
        TeamPresenter.row(
            member: member, agent: nil, delegations: delegations, working: working,
            waitingCount: waiting, teamWaitingCount: teamWaiting, stopped: stopped,
            lastActivity: nil, unread: false, now: now, language: .en
        )
    }

    func testChiefRowSaysWhoWorksAndWhatWaits() {
        let model = row(.aux, working: ["mail", "documents"], teamWaiting: 2)
        XCTAssertEqual(model.line, "2 agents working · 2 wait for your yes")
        XCTAssertEqual(model.tone, .live)
        XCTAssertEqual(model.count, 0, "the chief never carries the team's count")
    }

    func testWorkingAgentShowsItsLiveStepAndProgress() {
        let delegation = Delegation(
            id: "d", agent: "documents", ask: "Match receipts", at: "2026-10-12 08:01:00", state: .working,
            steps: [DelegationStep(text: "Read card lines", state: .done), DelegationStep(text: "Matching receipts", state: .working)],
            progress: (n: 34, of: 41)
        )
        let model = row(.documents, working: ["documents"], delegations: [delegation])
        XCTAssertEqual(model.line, "Matching receipts · 34 of 41")
        XCTAssertEqual(model.time, "now")
        XCTAssertTrue(model.working)
    }

    func testStopTurnsEveryRowRedAndHidesCounts() {
        let model = row(.mail, working: ["mail"], waiting: 2, stopped: true)
        XCTAssertEqual(model.line, "Paused by Stop")
        XCTAssertEqual(model.tone, .halt)
        XCTAssertEqual(model.count, 0)
        XCTAssertFalse(model.working)
    }

    func testDelegationStatusText() {
        func status(_ state: DelegationState, progress: (n: Int, of: Int)? = nil, took: Int? = nil, stopped: Bool = false) -> String {
            TeamPresenter.status(
                Delegation(id: "d", agent: "mail", ask: "x", at: "", state: state, progress: progress, tookMs: took),
                stopped: stopped, language: .en
            ).text
        }
        XCTAssertEqual(status(.done, took: 48_000), "Done · 48 s")
        XCTAssertEqual(status(.working, progress: (n: 34, of: 41)), "83%")
        XCTAssertEqual(status(.waiting), "Needs you")
        XCTAssertEqual(status(.working, stopped: true), "Stopped")
        XCTAssertEqual(status(.done, took: 48_000, stopped: true), "Done · 48 s", "finished work stays finished")
    }

    /// VAGUE-ASK-1: a task that attempted nothing is stopped, not a failure:
    /// the chip never says "couldn't finish" on a task that never ran.
    func testATaskThatAttemptedNothingIsNotAFailure() {
        let ran = Delegation(
            id: "d", agent: "calendar", ask: "look at what's pending", at: "", state: .stopped,
            steps: [DelegationStep(text: "asking its brain", state: .working)]
        )
        let never = Delegation(
            id: "d2", agent: "calendar", ask: "look at what's pending", at: "", state: .stopped
        )
        XCTAssertTrue(never.attemptedNothing, "no result and no step: nothing ran")
        XCTAssertFalse(ran.attemptedNothing, "a step ran")
        XCTAssertFalse(
            Delegation(id: "d3", agent: "calendar", ask: "x", at: "", state: .done, result: "One meeting.").attemptedNothing,
            "a result is work"
        )
        XCTAssertEqual(TeamPresenter.status(never, stopped: false, language: .en).text, "Stopped")
    }

    func testWaitingIgnoresSnoozedAndAnswered() throws {
        let approvals = try Fixtures.approvals()
        guard let first = approvals.first else { return XCTFail("fixture has approvals") }
        let all = TeamPresenter.waiting(approvals)
        let snoozed = TeamPresenter.waiting(approvals, snoozed: [first.id])
        XCTAssertEqual(snoozed.count, all.count - 1)
        XCTAssertTrue(all.allSatisfy { $0.state.isPending })
    }

    func testDurations() {
        XCTAssertEqual(TimeText.duration(ms: 12_000), "12 s")
        XCTAssertEqual(TimeText.duration(ms: 180_000), "3 min")
        XCTAssertEqual(TimeText.duration(ms: 3_900_000), "1 h 05")
    }
}

@objcMembers @MainActor final class ThreadTimelineTests: XCTestCase {
    private func message(_ id: String, _ author: Author, _ minute: Int64) -> ChatMessage {
        ChatMessage(id: id, threadKey: "aux", author: author, ts: 1_760_000_000_000 + minute * 60_000, blocks: [.text(id)])
    }

    private func stamp(_ minute: Int) -> String {
        let formatter = ISO8601DateFormatter()
        return formatter.string(from: Date(timeIntervalSince1970: 1_760_000_000 + TimeInterval(minute * 60)))
    }

    func testChiefThreadMergesConsecutiveDelegationsIntoOneList() {
        let items = ThreadTimeline.build(
            agent: "aux",
            messages: [message("hello", .agent("aux"), 0)],
            delegations: [
                Delegation(id: "d1", agent: "mail", ask: "a", at: stamp(1), state: .done),
                Delegation(id: "d2", agent: "calendar", ask: "b", at: stamp(1), state: .working),
            ],
            approvals: []
        )
        let groups = items.compactMap { item -> ThreadGroup? in
            if case .group(let group) = item { return group }
            return nil
        }
        XCTAssertEqual(groups.count, 1, "Aux's text and its delegations are one group")
        XCTAssertEqual(groups.first?.entries.count, 2)
        if case .delegations(let list)? = groups.first?.entries.last {
            XCTAssertEqual(list.map(\.id), ["d1", "d2"])
        } else {
            XCTFail("the delegations are one list")
        }
        if case .day? = items.first {} else { XCTFail("a thread opens with a date chip") }
    }

    func testCardsFromAnEarlierChatThreadAreHidden() {
        let start = Date(timeIntervalSince1970: 1_760_000_000 + 2 * 60)
        let items = ThreadTimeline.build(
            agent: "aux",
            messages: [message("current question", .you, 2), message("current answer", .agent("aux"), 4)],
            delegations: [
                Delegation(id: "old", agent: "mail", ask: "earlier thread", at: stamp(1), state: .done),
                Delegation(id: "current", agent: "calendar", ask: "this thread", at: stamp(3), state: .done),
            ],
            approvals: [],
            threadStartedAt: start
        )

        let visibleCards = items.flatMap { item -> [Delegation] in
            guard case .group(let group) = item else { return [] }
            return group.entries.flatMap { entry in
                if case .delegations(let list) = entry { return list }
                return []
            }
        }
        XCTAssertEqual(visibleCards.map(\.id), ["current"])
    }

    func testDomainThreadShowsTheHandoffThenTheWork() {
        let items = ThreadTimeline.build(
            agent: "mail",
            messages: [],
            delegations: [
                Delegation(id: "d1", agent: "mail", ask: "Sort the inbox", at: stamp(1), state: .done),
                Delegation(id: "d2", agent: "calendar", ask: "not mine", at: stamp(1), state: .done),
            ],
            approvals: []
        )
        let voices = items.compactMap { item -> ThreadVoice? in
            if case .group(let group) = item { return group.voice }
            return nil
        }
        XCTAssertEqual(voices, [.handoff, .agent("mail")])
    }

    func testAnUntimedMessageKeepsItsPlaceAfterThePreviousOne() {
        let items = ThreadTimeline.build(
            agent: "aux",
            messages: [message("asked", .agent("aux"), 0), ChatMessage(id: "-1", threadKey: "aux", author: .you, ts: 0, blocks: [.text("mine")]), message("reply", .agent("aux"), 2)],
            delegations: [],
            approvals: []
        )
        let voices = items.compactMap { item -> ThreadVoice? in
            if case .group(let group) = item { return group.voice }
            return nil
        }
        XCTAssertEqual(voices, [.agent("aux"), .owner, .agent("aux")])
    }

    func testAnUntimedFirstMessageReadsBeforeTheTimedReply() {
        let items = ThreadTimeline.build(
            agent: "aux",
            messages: [ChatMessage(id: "-1", threadKey: "aux", author: .you, ts: 0, blocks: [.text("mine")]), message("reply", .agent("aux"), 2)],
            delegations: [],
            approvals: []
        )
        let voices = items.compactMap { item -> ThreadVoice? in
            if case .group(let group) = item { return group.voice }
            return nil
        }
        XCTAssertEqual(voices, [.owner, .agent("aux")])
    }

    func testOwnerMessagesFarApartAreSeparateGroups() {
        let items = ThreadTimeline.build(
            agent: "mail",
            messages: [message("a", .you, 0), message("b", .you, 1), message("c", .you, 30)],
            delegations: [],
            approvals: []
        )
        let sizes = items.compactMap { item -> Int? in
            if case .group(let group) = item { return group.entries.count }
            return nil
        }
        XCTAssertEqual(sizes, [2, 1])
    }
}

@objcMembers @MainActor final class MailDraftTests: XCTestCase {
    func testParsesHeadersAndBody() {
        let draft = MailDraft.parse("To: Camille Exemple <camille@exemple-sarl.test>\nSubject: Invoice NW-2026-031\nAttachment: NW-2026-031.pdf\n\nHi Camille,\n\nA quick note.")
        XCTAssertEqual(draft?.to, "Camille Exemple <camille@exemple-sarl.test>")
        XCTAssertEqual(draft?.subject, "Invoice NW-2026-031")
        XCTAssertEqual(draft?.attachment, "NW-2026-031.pdf")
        XCTAssertEqual(draft?.body, "Hi Camille,\n\nA quick note.")
    }

    func testEditedBodyRoundTripsInTheSameShape() {
        var draft = MailDraft.parse("To: a@exemple.test\nSubject: Hi\n\nOld body")
        draft?.body = "New body"
        XCTAssertEqual(draft?.text, "To: a@exemple.test\nSubject: Hi\n\nNew body")
        XCTAssertEqual(MailDraft.parse(draft?.text)?.body, "New body")
    }

    func testPlainTextIsNotADraft() {
        XCTAssertNil(MailDraft.parse(nil))
        XCTAssertNil(MailDraft.parse("Create an event on Tuesday at 15:00")?.to)
    }
}

@objcMembers @MainActor final class TeamDecodingTests: XCTestCase {
    func testDelegationDecodesBothProgressShapes() throws {
        let json = """
        [{"id":"dl-1","agent":"documents","task":"Match receipts","created_at":"2026-10-12 08:01:00","state":"working",
          "steps":[{"text":"Read lines","state":"done"},{"text":"Matching","state":"working","at":"2026-10-12 08:02:00"}],
          "progress_n":34,"progress_of":41,"brain":{"provider":"ollama","model":"gpt-oss 120B"}},
         {"id":"dl-2","agent":"mail","ask":"Sort","at":"2026-10-12 08:00:00","state":"done","progress":{"n":14,"of":14},
          "result":"2 need you","took_ms":48000,"approval_id":"ap-1"}]
        """
        let list = try JSONDecoder().decode([Delegation].self, from: Data(json.utf8))
        XCTAssertEqual(list[0].ask, "Match receipts")
        XCTAssertEqual(list[0].progress?.n, 34)
        XCTAssertEqual(list[0].progress?.of, 41)
        XCTAssertEqual(list[0].steps.last?.state, .working)
        XCTAssertEqual(list[1].progress?.of, 14)
        XCTAssertEqual(list[1].tookMs, 48_000)
        XCTAssertEqual(list[1].approvalId, "ap-1")
    }

    func testCoverageDecodesTheNewRoute() throws {
        let json = """
        {"paths":[{"id":"A1","label":"Streaming chat","state":"covered","private":"allow","choke":"gate"},
                  {"id":"B3","label":"read_file","state":"missed","private":"off","choke":"none"}],
         "covered":1,"missed":1}
        """
        let coverage = try JSONDecoder().decode(CoverageResponse.self, from: Data(json.utf8))
        XCTAssertEqual(coverage.paths.map(\.id), ["A1", "B3"])
        XCTAssertEqual(coverage.paths.last?.state, .missed)
        XCTAssertEqual(coverage.paths.first?.privateMode, "allow")
    }

    func testLedgerRowsCarryTheSkillHash() throws {
        let json = """
        [{"at":"2026-10-12 08:14:00","kind":"skill.run","agent":"mail","summary":"Drafted the follow-up",
          "skill":"follow-up-email","skill_hash":"sha256:c03d8e5a"},
         {"at":"2026-10-12 08:00:00","kind":"daemon.started","summary":"Started"}]
        """
        let rows = try JSONDecoder().decode([LedgerEntry].self, from: Data(json.utf8))
        XCTAssertEqual(rows[0].skill, "follow-up-email")
        XCTAssertEqual(rows[0].skillHash, "sha256:c03d8e5a")
        XCTAssertNil(rows[1].skillHash)
        XCTAssertNil(rows[1].agent)
    }

    func testFixtureCoverageListsEveryKernelPath() async throws {
        let coverage = try await FixtureDaemon().coverage()
        XCTAssertEqual(coverage.paths.count, 53, "PathId::ALL at the pinned kernel")
        XCTAssertEqual(Set(coverage.paths.map(\.id)).count, 53)
    }
}

@objcMembers @MainActor final class DelegationBrainTests: XCTestCase {
    func testBrainObjectGivesTheModelName() throws {
        let json = #"{"id":"d","agent":"documents","ask":"x","at":"","state":"working","brain":{"provider":"ollama","model":"gpt-oss 120B"}}"#
        XCTAssertEqual(try JSONDecoder().decode(Delegation.self, from: Data(json.utf8)).brain, "gpt-oss 120B")
    }
}

@objcMembers @MainActor final class ProvisionalMessageTests: XCTestCase {
    private func message(_ id: String, _ text: String, _ author: Author = .agent("aux")) -> ChatMessage {
        ChatMessage(id: id, threadKey: "aux", author: author, ts: 0, blocks: [.text(text)])
    }

    func testTheSendResponseAndTheSocketAreOneMessage() {
        XCTAssertTrue(Store.isProvisional("-2"))
        XCTAssertFalse(Store.isProvisional("42"))
        XCTAssertFalse(Store.isProvisional("local-1"))
        XCTAssertTrue(Store.sameMessage(message("-2", "[fake:test] hi"), message("42", "[fake:test] hi")))
        XCTAssertFalse(Store.sameMessage(message("41", "hi"), message("42", "hi")), "two stored messages stay two")
        XCTAssertFalse(Store.sameMessage(message("-1", "hi", .you), message("42", "hi")), "the owner's words are not the agent's")
    }
}

@objcMembers @MainActor final class LedgerTextTests: XCTestCase {
    private func what(_ kind: String, _ summary: String, agent: String? = nil, skill: String? = nil, language: Language = .en) -> String {
        LedgerText.what(LedgerEntry(at: "", kind: kind, agent: agent, summary: summary, skill: skill), language: language)
    }

    func testRawPayloadsBecomeOneReadableLine() {
        XCTAssertEqual(what("daemon.started", "v0.1.0"), "Auxesis started · v0.1.0")
        XCTAssertEqual(
            what("run.finished", #"{"run_id":"turn-1","agent":"aux","status":"done","tokens_in":1031,"tokens_out":45}"#),
            "Aux answered · 1,031 tokens in, 45 out"
        )
        XCTAssertEqual(
            what("provider.created", #"{"provider":"test","kind":"fake","model":"echo","key_present":false}"#),
            "Provider test added · echo"
        )
        XCTAssertEqual(what("skill.approval", #"{"skill_name":"follow-up-email"}"#, skill: "follow-up-email"), "follow-up-email asked for your yes")
        XCTAssertEqual(what("skill.run", "Drafted the follow-up to Camille Exemple"), "Drafted the follow-up to Camille Exemple")
    }

    func testBracketedOrBarePlainTextIsNotTreatedAsJSON() {
        for summary in ["[Draft] Reply to the venue", "42", "true", "{not json"] {
            XCTAssertEqual(what("message.user", summary), summary)
            XCTAssertEqual(LedgerText.what(summary, agent: "mail", language: .en), summary)
        }
        XCTAssertEqual(what("future.event", #"{"agent":"mail","note":"cut sh…"#, agent: "mail"), "Recorded Mail activity")
    }

    func testSkillLineWithoutANameReadsNaturally() {
        let entry = LedgerEntry(at: "", kind: "skill.run", agent: "mail", summary: #"{"outcome":"done"}"#)
        XCTAssertEqual(LedgerText.what(entry, language: .en), "Skill ran · completed")
        XCTAssertEqual(LedgerText.what(entry, language: .fr), "Compétence exécutée · terminé")
    }

    func testPlainTextSummaryPassesThroughUnchanged() {
        let summary = " Daemon stopped by owner. "
        XCTAssertEqual(what("daemon.stopped", summary), summary)
        XCTAssertEqual(what("message.user", summary), summary)
    }

    func testJSONSummaryIsSanitisedInLedgerAndAgentStatusPaths() {
        let raw = #"{"agent":"mail","opaque":"private detail"}"#
        let ledgerLine = what("future.event", raw, agent: "mail")
        XCTAssertEqual(ledgerLine, "Recorded Mail activity")
        XCTAssertFalse(ledgerLine.contains(raw))

        let mapped = Mapper.agent(
            from: AgentSummary(name: "mail", lastActivity: ActivityEntry(kind: "future.event", agent: "mail", summary: raw)),
            live: nil,
            language: .en
        )
        XCTAssertEqual(mapped.status, "Recorded Mail activity")
        XCTAssertFalse(mapped.status.contains(raw))
        XCTAssertEqual(LedgerText.what(raw, agent: "mail", language: .en), "Recorded Mail activity")
    }

    func testSkillJSONSummaryShowsSkillAndOutcomeInEnglishAndFrench() {
        let entry = LedgerEntry(at: "", kind: "skill.run", agent: "mail", summary: #"{"skill_name":"follow-up","outcome":"failed"}"#)
        XCTAssertEqual(LedgerText.what(entry, language: .en), "Follow-up ran · failed")
        XCTAssertEqual(LedgerText.what(entry, language: .fr), "Relance exécutée · échec")
    }

    func testSkillJSONSummarySaysAMaybeSentMailInEnglishAndFrench() {
        let entry = LedgerEntry(at: "", kind: "skill.run", agent: "mail", summary: #"{"skill_name":"send-invite","outcome":"uncertain"}"#)
        XCTAssertEqual(LedgerText.what(entry, language: .en), "Meeting invite ran · maybe sent")
        XCTAssertEqual(LedgerText.what(entry, language: .fr), "Invitation exécutée · peut-être envoyé")
    }

    func testAgentResultKeyValuesBecomeHumanCopy() {
        let summary = "unread_count=5 total=5 (counts of the 5 messages listed below)"
        XCTAssertEqual(what("tool.result", summary, agent: "mail"), "Mail listed 5 unread messages")
        XCTAssertFalse(what("tool.result", summary, agent: "mail").contains("="))
        XCTAssertEqual(
            LedgerText.what(LedgerEntry(at: "", kind: "tool.result", agent: "mail", summary: summary), language: .fr),
            "Mail a listé 5 e-mails non lus"
        )
    }

    func testLedgerDetailOmitsFieldsUnavailableForEveryEntry() {
        let detail = SinceYouLeftDetail(entry: LedgerEntry(at: "2026-10-24 14:07:49", kind: "tool.result", agent: "mail", summary: "listed"))
        XCTAssertEqual(detail.visibleFields.map(\.0), ["When", "Agent"])
    }

    func testATruncatedPayloadStillReads() {
        XCTAssertEqual(
            what("run.finished", #"{"run_id":"turn-1","agent":"aux","tokens_in":1031,"tokens_out":45,"cost_cents"#),
            "Aux answered · 1,031 tokens in, 45 out"
        )
    }

    func testUnknownPayloadsNeverShowJSON() {
        let line = what("provider.key_updated", #"{"provider":"test"}"#, agent: "mail")
        XCTAssertEqual(line, "Provider key updated")
        XCTAssertEqual(what("provider.key_updated", #"{"provider":"test"}"#, agent: "mail", language: .fr), "Clé du fournisseur modifiée")
        XCTAssertFalse(line.contains("{"))
        let agentFromPayload = LedgerText.what(
            LedgerEntry(at: "", kind: "future.event", agent: nil, summary: #"{"agent":"clients","future":"value"}"#),
            language: .en
        )
        XCTAssertEqual(agentFromPayload, "Recorded Clients activity")
    }

    func testPolicyDecisionPayloadIsSummarisedInEveryLedgerSurface() {
        let raw = #"{"agent":"mail","tool":"mail_list","decision":"allow","by":"policy","always":false,"class":"read","tain…"#
        let entry = LedgerEntry(at: "", kind: "approval.answered", agent: "mail", summary: raw)
        let line = LedgerText.what(entry, language: .en)
        XCTAssertEqual(line, "Mail was allowed to list mail — no approval needed")
        XCTAssertFalse(line.contains("{"))
        XCTAssertEqual(LedgerText.what(entry, language: .fr), "Mail a été autorisé à lister les e-mails · sans demande")
    }

    func testEveryDaemonActivityKindHasReadableFallbackForRawPayloads() {
        let kinds = [
            "message.user", "message.assistant", "message.tool", "daemon.started", "daemon.stopped",
            "daemon.stop_all", "tool.decision", "approval.pending", "approval.answered", "approval.dropped",
            "skill.approval", "skill.run", "skill.action", "skill.load_error", "run.finished",
            "provider.created", "provider.key_updated", "provider.tested", "provider.fallback",
            "agent.created", "agent.updated", "agent.paused", "agent.resumed", "agent.killed",
            "agent.tool_reserved", "crm.party_updated", "contacts.imported", "brief.run", "notify.test",
            "routine.created", "routine.updated", "routine.deleted"
        ]
        for kind in kinds {
            let line = what(kind, #"{"opaque_field":"value"}"#, agent: "mail")
            let expected: (String, String)
            switch kind {
            case "daemon.stopped": expected = ("Aux stopped", "Aux s’est arrêté")
            case "daemon.stop_all": expected = ("Stop all requested", "Arrêt général demandé")
            case "approval.pending": expected = ("Approval is waiting", "Approbation en attente")
            case "approval.answered": expected = ("Approval answered", "Approbation traitée")
            case "approval.dropped": expected = ("Approval closed after restart", "Approbation abandonnée après le redémarrage")
            case "skill.run", "skill.action": expected = ("Skill ran", "Compétence exécutée")
            case "skill.load_error": expected = ("Skill could not be loaded", "Compétence non chargée")
            case "provider.fallback": expected = ("A backup provider took over", "Un autre fournisseur a pris le relais")
            case "provider.created": expected = ("Provider added", "Fournisseur ajouté")
            case "provider.key_updated": expected = ("Provider key updated", "Clé du fournisseur modifiée")
            case "provider.tested": expected = ("Provider checked", "Fournisseur vérifié")
            case "agent.created": expected = ("Mail agent added", "Agent Mail ajouté")
            case "agent.updated": expected = ("Mail agent updated", "Agent Mail modifié")
            case "agent.paused": expected = ("Mail agent paused", "Agent Mail mis en pause")
            case "agent.resumed": expected = ("Mail agent resumed", "Agent Mail repris")
            case "agent.killed": expected = ("Mail agent stopped", "Agent Mail arrêté")
            case "agent.tool_reserved": expected = ("Tool reserved for the agent", "Outil réservé à l’agent")
            case "crm.party_updated": expected = ("Client record updated", "Fiche client modifiée")
            case "contacts.imported": expected = ("Clients imported contacts", "Clients a importé des contacts")
            case "brief.run": expected = ("Today’s brief recorded", "Brief du jour enregistré")
            case "notify.test": expected = ("Test notification sent", "Notification de test envoyée")
            case "routine.created": expected = ("Routine added", "Routine créée")
            case "routine.updated": expected = ("Routine updated", "Routine modifiée")
            case "routine.deleted": expected = ("Routine removed", "Routine supprimée")
            default: expected = ("Recorded Mail activity", "Activité enregistrée · Mail")
            }
            XCTAssertEqual(line, expected.0, "kind: \(kind)")
            XCTAssertEqual(what(kind, #"{"opaque_field":"value"}"#, agent: "mail", language: .fr), expected.1, "kind: \(kind)")
            XCTAssertFalse(line.contains("{"), "kind: \(kind), line: \(line)")
        }
    }
}

@objcMembers @MainActor final class RequestInspectorDisclosureTests: XCTestCase {
    func testNotKeptLineShowsInBothLanguagesWithoutAWhatCameBackRow() {
        let model = RequestInspectorModel(receipt: Receipt(runId: "run", agent: "mail"))
        XCTAssertEqual(model.notKeptDisclosure(language: .en), "Not kept: unavailable, not missing.")
        XCTAssertEqual(model.notKeptDisclosure(language: .fr), "Réponse non conservée : indisponible, pas absente.")
        XCTAssertFalse(model.visibleSections.contains(.whatCameBack))
    }
}
