// FixtureDaemon — a fictional daemon for previews and the E2 screenshots,
// shaped like the round-4 prototype (a chief, four domain agents, two
// approvals, four delegations). It is used only when the app runs with
// `AUXESIS_SANDBOX=1 AUXESIS_MAC_FIXTURE=team` and in tests. Every name,
// address and amount is invented (Camille Exemple, Exemple SARL, `.test`).
import Foundation

/// Optional: a client that can show the exact tokenised text a provider
/// received. The fixture has it; auxd does not yet.
public protocol ModelSawProviding: AnyObject {
    func modelSaw(agent: String, messageIds: [String]) -> ModelSawRecord?
}

public final class FixtureDaemon: AuxdTransport, TeamClient, ModelSawProviding, ContactsImportClient {
    public enum Scenario: String {
        case team
        case stopped
        case empty
        /// The team, with the Clients routes failing (the card's error state).
        case clientsDown
        /// The team, with today's brief missing its calendar.
        case briefDegraded
        /// The team, with auxd's calendar copy four days old.
        case calendarStale
        /// The team, with one rich agent reply (table, list, code, hidden values).
        case rich
        /// The team, with an empty memory: "What Aux knows" shows only its
        /// empty lines (MEM-EMPTY-STATE).
        case memoryEmpty
        /// The team, with a Calendar answer that carries its calendar card.
        case calendarCard
    }

    public let scenario: Scenario
    private let base: Date
    private var threads: [String: [MessageJson]] = [:]
    private var approvalList: [Approval] = []
    private var delegationList: [Delegation] = []
    private var stoppedNow: Bool
    private var clientCards: [Int64: ClientCard] = [:]
    /// MEM-UI-1: the fixture's memory, in the daemon's four groups.
    private var memoryGroups: [String: [MemoryFact]] = [:]
    private var memorySuggestions: [MemorySuggestion] = []
    private var nextId: Int64 = 500
    private var briefWritten = false
    private var prospectsHandled: Set<String> = []
    private var continuation: AsyncThrowingStream<WireEvent, Error>.Continuation?
    /// Tests: awaited by `updateClient` before it answers, to hold a save in flight.
    public var clientSaveHold: (() async -> Void)?
    /// Tests: the counts a dry run answers with. A real import adds one invented
    /// client per party it creates, so the list reload has something to show.
    public var contactsPreview = FixtureDaemon.sampleContactsPreview
    /// Tests: thrown by the next contacts call instead of an answer.
    public var contactsFailure: AuxdError?
    /// Tests: current pause state and the optional failure for the next pause call.
    public var pausedAgents: Set<String> = []
    public var pauseFailure: AuxdError?
    /// How long Stop all takes, in nanoseconds (a slow daemon).
    public var stopDelay: UInt64 = 0
    /// Every answer posted, in order: what a yes would have sent.
    public private(set) var resolved: [(id: String, decision: String, text: String?)] = []
    /// Tests: the failure the next answer answers with instead of an answer
    /// (a refused edit, a broken service). Nothing is recorded as sent.
    public var resolveFailure: AuxdError?
    /// Tests: every contacts call, in order (a preview, then the import).
    public private(set) var contactsRequests: [ContactsImportRequest] = []

    public init(scenario: Scenario = .team, now: Date = Date()) {
        self.scenario = scenario
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        self.base = calendar.date(bySettingHour: 8, minute: 0, second: 0, of: now) ?? now
        self.stoppedNow = scenario == .stopped
        if scenario != .empty {
            seed()
            seedClients()
        }
    }

    // MARK: Time helpers

    private func at(_ minute: Double) -> Date { base.addingTimeInterval(minute * 60) }

    private func stamp(_ minute: Double) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: at(minute))
    }

    private func ms(_ minute: Double) -> Int64 { Int64(at(minute).timeIntervalSince1970 * 1000) }

    private func calendarToolRow() -> String {  // tomorrow: two fictional events
        let iso = ISO8601DateFormatter()
        func at(_ hours: Double) -> String { iso.string(from: base.addingTimeInterval((24 + hours - 8) * 3600)) }
        return #"[{"title":"Call with Sample Studio","start":"\#(at(13))","end":"\#(at(14))","calendar":"Work","location":null,"attendees":[]},"#
            + #"{"title":"Review the Northwind quote","start":"\#(at(15.5))","end":"\#(at(16))","calendar":"Work","location":null,"attendees":[]}]"#
    }

    private func message(_ id: Int64, _ role: String, _ text: String, _ minute: Double) -> MessageJson {
        MessageJson(id: id, threadId: id / 100, role: role, content: text, at: stamp(minute))
    }

    // MARK: Seed

    static let richReply = """
    Here are the three open invoices. **Sample Studio** is the one to chase first.

    | Invoice | Client | Due | Amount |
    |---|---|---|--:|
    | INV-2207 | Sample Studio | 12 Oct | €1,204.00 |
    | INV-2211 | Northwind Example | 20 Oct | €36.00 |
    | INV-2214 | Blueharbor | 3 Nov | €2,400.00 |

    What I would do next:
    - Remind Sample Studio, they were due *16 days* ago
    - Ask [Northwind](https://example.com/invoices) about the €36
    - Send nothing before you say so

    The reminder goes to [hidden], and the IBAN on file is [iban removed].

    ```
    aux mail remind --invoice INV-2207
    ```
    """

    private func seed() {
        threads["aux"] = [
            message(101, "assistant", "Three things need you today. You're free between 10:30 and 14:00. I handed the morning work to the team:", 0),
            message(102, "assistant", "As you asked on Friday: Exemple SARL still hasn't paid invoice NW-2026-031, €2,400.00, now 12 days late. Camille prefers email for money.", 0.5),
            message(103, "user", "Draft the follow-up.", 13),
            message(104, "assistant", "Asked Mail. It knows she prefers email for anything about money.", 13.08),
        ]
        if scenario == .rich {
            threads["aux"] = [message(105, "user", "Which invoices are open?", -3), message(106, "assistant", Self.richReply, -2.9)] + (threads["aux"] ?? [])
        }
        threads["mail"] = [
            message(201, "assistant", "Jonas Weber asks for a slot this week. I drafted a reply with three slots from Calendar.", 1.1),
        ]
        threads["calendar"] = [
            message(301, "assistant", "Free 10:30 to 14:00 today. For Jonas: Tue 15:00, Wed 10:00, Thu 16:30, Berlin time.", 0.25),
        ]
        if scenario == .calendarCard {
            threads["calendar"] = [
                message(302, "user", "What's free tomorrow afternoon?", 1),
                message(303, "assistant", "I'll check your calendar.", 1.02),
                MessageJson(id: 304, threadId: 3, role: "tool", content: calendarToolRow(), at: stamp(1.04), tool: "apple_calendar_list_events"),
                message(305, "assistant", "Tomorrow afternoon you're free 12:00–13:00, 14:00–15:30 and after 16:00.", 1.1),
            ]
        }
        threads["clients"] = []
        threads["documents"] = []

        memoryGroups = [
            "about_you": [MemoryFact(id: "m-1", text: "Short mails, first names, no exclamation marks. Signs \"Alex\".", source: "learned from a mail", savedAt: "2026-10-20T08:30:00Z")],
            "rules": [MemoryFact(id: "m-2", text: "Chase unpaid invoices 10 days after due, friendly tone.", source: "you told Aux", savedAt: "2026-10-20T08:30:00Z")],
            "people": [MemoryFact(id: "m-3", text: "Prefers Thursday mornings. Copy Léa on quotes.", source: "learned from a mail", savedAt: "2026-10-20T08:30:00Z")],
            "other": [MemoryFact(id: "m-4", text: "The studio address is 12 rue de l'Exemple.", source: "older note", savedAt: "2026-09-02T08:30:00Z")],
        ]
        memorySuggestions = [MemorySuggestion(id: "s-12", text: "Camille wants Léa copied on quotes", source: "learned from a mail")]
        if scenario == .memoryEmpty {
            // Nothing saved yet: the four sections stay and say so.
            memoryGroups = ["about_you": [], "rules": [], "people": [], "other": []]
            memorySuggestions = []
        }

        delegationList = [
            Delegation(
                id: "dl-1", agent: "mail", ask: "Sort the 14 emails since Friday and tell me what needs Alex.", at: stamp(0.02),
                state: .done,
                steps: [
                    DelegationStep(text: "Read 14 emails since Fri 18:02", at: stamp(0.1), state: .done, place: .stayed),
                    DelegationStep(text: "Filed 11: newsletters, receipts, notifications", at: stamp(0.6), state: .done, place: .stayed),
                    DelegationStep(text: "Drafted a slot reply to Jonas Weber", at: stamp(0.8), state: .done, place: .left),
                ],
                result: "2 need you: Jonas Weber asks for a slot this week (reply drafted), and Lina Okafor has a pitch deck for December. 11 filed, 1 spam.",
                tookMs: 48_000, brain: "DeepSeek V3.2"
            ),
            Delegation(
                id: "dl-2", agent: "calendar", ask: "Check today and find three 30-minute slots for Jonas this week.", at: stamp(0.03),
                state: .done,
                steps: [
                    DelegationStep(text: "Read today and the next 4 days", at: stamp(0.1), state: .done, place: .stayed),
                    DelegationStep(text: "Kept 30-minute gaps inside working hours", at: stamp(0.2), state: .done, place: .stayed),
                ],
                result: "Free 10:30 to 14:00 today. For Jonas: Tue 15:00, Wed 10:00, Thu 16:30, Berlin time.",
                tookMs: 12_000, brain: "DeepSeek V3.2"
            ),
            Delegation(
                id: "dl-3", agent: "documents", ask: "Match September card lines to receipts.", at: stamp(0.04),
                state: stoppedNow ? .stopped : .working,
                steps: [
                    DelegationStep(text: "Read 41 card lines from the bank export", at: stamp(0.2), state: .done),
                    DelegationStep(text: "Found 38 receipts in Mail and Downloads", at: stamp(1), state: .done),
                    DelegationStep(text: "Matching receipts to card lines", at: stamp(2), state: .working),
                    DelegationStep(text: "File the matched receipts, after your yes", state: .todo),
                ],
                progress: (34, 41), brain: "gpt-oss 120B"
            ),
            Delegation(
                id: "dl-4", agent: "clients", ask: "Prepare notes for the 14:00 brand review with Camille Exemple.", at: stamp(0.05),
                state: stoppedNow ? .stopped : .working,
                steps: [
                    DelegationStep(text: "Opened Camille Exemple's card", at: stamp(0.3), state: .done),
                    DelegationStep(text: "Reading her last 3 emails", at: stamp(1), state: .working),
                ],
                brain: "Claude Sonnet"
            ),
            Delegation(
                id: "dl-5", agent: "mail", ask: "Draft a payment follow-up to Camille Exemple for invoice NW-2026-031.", at: stamp(13.1),
                state: .waiting,
                steps: [
                    DelegationStep(text: "Read invoice NW-2026-031 from Documents", at: stamp(13.2), state: .done),
                    DelegationStep(text: "Checked her preference: email for money", at: stamp(13.3), state: .done),
                    DelegationStep(text: "Drafted the email", at: stamp(14), state: .done),
                ],
                result: "Draft ready. It waits for your yes.", brain: "DeepSeek V3.2", approvalId: "ap-camille"
            ),
        ]

        approvalList = [
            Approval(
                id: "ap-jonas", auditId: 4801, agent: "mail", threadId: "mail", ts: ms(1.2), action: "mail.send",
                headline: "Reply to Jonas Weber · 3 slots, Tue to Thu",
                fullPreview: """
                Hi Jonas,

                Happy to. Any of these work for me (Berlin time):

                  Tue 13 Oct, 15:00–15:30
                  Wed 14 Oct, 10:00–10:30
                  Thu 15 Oct, 16:30–17:00

                Pick one and I'll send the invite.

                Best,
                Alex
                """,
                editPreview: "{\"to\":[\"jonas@atelier-brume.test\"],\"subject\":\"Re: Time this week?\"}",
                detail: ["To: Jonas Weber <jonas@atelier-brume.test>",
                         "Subject: Re: Time this week?"],
                scopeTool: "mail.send", skill: "Slot reply", delegationId: "dl-1"
            ),
            Approval(
                id: "ap-camille", auditId: 4809, agent: "mail", threadId: "mail", ts: ms(14.1), action: "mail.send",
                headline: "Email to Camille Exemple · Invoice NW-2026-031",
                fullPreview: """
                Hi Camille,

                A quick note on invoice NW-2026-031 (€2,400.00), which was due on 30 September. I've attached it again in case it got lost.

                Could you let me know when it's scheduled for payment?

                See you at 14:00.

                Best,
                Alex
                """,
                editPreview: "{\"to\":[\"camille@exemple-sarl.test\"],\"subject\":\"Invoice NW-2026-031\"}",
                detail: ["To: Camille Exemple <camille@exemple-sarl.test>",
                         "Subject: Invoice NW-2026-031",
                         "Attachment: NW-2026-031.pdf"],
                scopeTool: "mail.send", skill: "Follow-up email", delegationId: "dl-5"
            ),
        ]
    }

    // MARK: AuxdTransport

    public func health() async throws -> HealthResponse {
        HealthResponse(ok: true, version: "fixture", pid: 1, firstRun: false)
    }

    public func agents() async throws -> [AgentSummary] {
        let lines: [String: (String, Double, String)] = [
            "aux": ("Asked Mail. It knows she prefers email for anything about money.", 13.08, "Claude Sonnet"),
            "mail": ("Email to Camille Exemple · Invoice NW-2026-031 · waits for your yes", 14.1, "DeepSeek V3.2"),
            "calendar": ("Free 10:30 to 14:00 today. For Jonas: Tue, Wed, Thu", 0.25, "DeepSeek V3.2"),
            "clients": ("Notes for the 14:00 brand review", 1, "Claude Sonnet"),
            "documents": ("38 receipts found for 41 card lines", 1, "gpt-oss 120B"),
        ]
        return TeamMember.all.map { member in
            let line = lines[member.id]
            return AgentSummary(
                name: member.id,
                stop: stoppedNow,
                paused: pausedAgents.contains(member.id),
                lastActivity: line.map { ActivityEntry(at: stamp($0.1), kind: "message.assistant", agent: member.id, summary: $0.0) },
                threadId: member.id,
                brain: line?.2
            )
        }
    }

    public func messages(thread: String, limit: Int) async throws -> MessagesPage {
        MessagesPage(thread: SessionJson(id: Int64(abs(thread.hashValue % 1000)), agent: thread), messages: threads[thread] ?? [])
    }

    public func pendingApprovals() async throws -> [Approval] {
        approvalList.filter { $0.state.isPending }
    }

    public func receipts(agent: String?, limit: Int) async throws -> [Receipt] {
        guard scenario != .empty else { return [] }
        let rows = [
            Receipt(runId: "fixture-run-1", agent: "scout", started: "2026-10-24 09:14:00",
                    finished: "2026-10-24 09:14:12", hostsContacted: ["api.example.test"]),
            Receipt(runId: "fixture-run-2", agent: "mail", started: "2026-10-24 08:42:00",
                    finished: "2026-10-24 08:42:04"),
            // Today (the right panel's Privacy tab): one run left with two
            // values replaced, one reached no outside host. Invented hosts only.
            Receipt(runId: "fixture-run-3", agent: "mail", replacedValues: ["EMAIL": 2], started: stamp(1),
                    finished: stamp(2), hostsContacted: ["api.example.test"]),
            Receipt(runId: "fixture-run-4", agent: "calendar", started: stamp(3), finished: stamp(4),
                    hostsContacted: ["127.0.0.1:11434"]),
        ].filter { agent == nil || $0.agent == agent }
        return Array(rows.prefix(limit))
    }

    public func send(thread: String, content: String) async throws -> SendResponse {
        nextId += 2
        let user = MessageJson(id: nextId, threadId: 9, role: "user", content: content, at: Self.nowStamp())
        let reply = MessageJson(id: nextId + 1, threadId: 9, role: "assistant", content: "On it. I'll post here when it's done.", at: Self.nowStamp())
        threads[thread, default: []].append(contentsOf: [user, reply])
        return SendResponse(messages: [user, reply])
    }

    public func resolve(id: String, decision: String, scope: ApprovalScope?, text: String?) async throws -> ApprovalState {
        if let failure = resolveFailure {
            resolveFailure = nil
            throw failure
        }
        resolved.append((id, decision, text))
        let state: ApprovalState = decision == "deny" ? .denied(by: "you") : .allowed(by: "you", always: false)
        if let index = approvalList.firstIndex(where: { $0.id == id }) {
            approvalList[index].state = state
        }
        continuation?.yield(.approvalResolved(id: id, state: state))
        return state
    }

    public func events() throws -> AsyncThrowingStream<WireEvent, Error> {
        AsyncThrowingStream { continuation in
            self.continuation = continuation
        }
    }

    /// Tests: deliver one live frame as the daemon's socket would.
    public func finishRun(_ receipt: Receipt) {
        continuation?.yield(.runFinished(receipt))
    }

    /// Tests: the rows `ledger(limit:)` answers with; `nil` keeps the
    /// scenario's sample, so a test can start empty and let work arrive.
    public var ledgerEntries: [LedgerEntry]?

    private static func nowStamp() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date())
    }

    // MARK: TeamClient

    public func delegations(thread: String) async throws -> [Delegation] { delegationList }

    public func stopDelegation(id: String) async throws {
        if let index = delegationList.firstIndex(where: { $0.id == id }) { delegationList[index].state = .stopped }
    }

    public func resumeDelegation(id: String) async throws {
        if let index = delegationList.firstIndex(where: { $0.id == id }) { delegationList[index].state = .working }
    }

    public func coverage() async throws -> CoverageResponse {
        CoverageResponse(paths: Self.coverageRows.map { CoverageRow(id: $0.0, label: $0.1, state: $0.2, privateMode: $0.3, choke: $0.4) })
    }

    public func ledger(limit: Int) async throws -> [LedgerEntry] {
        if let ledgerEntries { return ledgerEntries }
        guard scenario != .empty else { return [] }
        return [
            LedgerEntry(at: stamp(-2900), kind: "skill.run", agent: "mail", summary: "Quote Q-2026-014 to Jonas Weber, sent after your yes", skill: "quote-email", skillHash: "sha256:4be1c07d92aa"),
            LedgerEntry(at: stamp(-1520), kind: "skill.run", agent: "documents", summary: "Planned the Monday check of Exemple SARL's payment", skill: "plan-check", skillHash: "sha256:1f9e0b44c3d1"),
            LedgerEntry(at: stamp(0), kind: "turn.request", agent: "aux", summary: "Morning brief: 1 request, 7 names replaced"),
            LedgerEntry(at: stamp(0.8), kind: "skill.action", agent: "mail", summary: "Drafted a slot reply to Jonas Weber", skill: "slot-reply", skillHash: "sha256:9f2c41ab0e77"),
            LedgerEntry(at: stamp(14), kind: "skill.action", agent: "mail", summary: "Drafted the follow-up to Camille Exemple", skill: "follow-up-email", skillHash: "sha256:c03d8e5a19b2"),
            LedgerEntry(at: stamp(17), kind: "skill.run", agent: "documents", summary: "Filed 3 receipts on this Mac, one yes for 3", skill: "file-receipt", skillHash: "sha256:7a0d2f61e845"),
        ]
    }

    public func plannedJobs() async throws -> [PlannedJob] {
        guard scenario != .empty else { return [] }
        return [
            PlannedJob(id: 1, agent: "aux", name: "Morning brief", schedule: "weekdays 08:00", nextRunAt: stamp(24 * 60), health: .ok),
            PlannedJob(id: 2, agent: "mail", name: "Check Exemple SARL's payment", schedule: "after Camille's reply", nextRunAt: nil),
            // One late and one failing job, so the health marks show in previews.
            PlannedJob(id: 3, agent: "documents", name: "File receipts", schedule: "daily 07:00", nextRunAt: stamp(-60),
                       health: .late, reason: "File receipts did not run at 07:00",
                       reasonKind: .missed, reasonAt: "07:00"),
            PlannedJob(id: 4, agent: "mail", name: "Inbox sweep", schedule: "daily 07:30", nextRunAt: stamp(24 * 60 - 30),
                       health: .failing, reason: "Inbox sweep failed at 07:32",
                       reasonKind: .failed, reasonAt: "07:32"),
        ]
    }

    public func usageToday() async throws -> UsageDay {
        UsageDay(day: "today", total: UsageTotals(tokensIn: 18_240, tokensOut: 2_115, usdCents: 4))
    }

    public func providerList() async throws -> [ProviderSummary] {
        let json = """
        [{"id":"anthropic","name":"Anthropic","base_url":"https://api.anthropic.test/v1","model":"Claude Sonnet","kind":"openai_compat","key_location":"file","key_present":true,"key_required":true,"last_test":"ok"},
         {"id":"deepseek","name":"DeepSeek","base_url":"https://api.deepseek.test/v1","model":"DeepSeek V3.2","kind":"openai_compat","key_location":"file","key_present":true,"key_required":true,"last_test":"ok"},
         {"id":"ollama-cloud","name":"Ollama Cloud","base_url":"https://ollama.test/v1","model":"gpt-oss 120B","kind":"openai_compat","key_location":"file","key_present":true,"key_required":true,"last_test":"never"}]
        """
        return try JSONDecoder().decode([ProviderSummary].self, from: Data(json.utf8))
    }

    public func addProvider(_ request: CreateProviderRequest) async throws {}

    public func testProvider(id: String) async throws -> ProviderTest {
        try JSONDecoder().decode(ProviderTest.self, from: Data(#"{"ok":true,"reason":"ok","models":[],"key_required":true}"#.utf8))
    }

    public func skillList() async throws -> [LocalSkill] {
        let json = """
        [{"name":"follow-up-email","description":"Sends from your mail account, after your yes","size":2210,"status":{"state":"valid"}},
         {"name":"slot-reply","description":"Sends from your mail account, after your yes","size":1984,"status":{"state":"valid"}},
         {"name":"calendar-invite","description":"Writes to your calendar, after your yes","size":1702,"status":{"state":"valid"}},
         {"name":"file-receipt","description":"Writes to Documents on this Mac, grouped into one yes","size":1420,"status":{"state":"valid"}},
         {"name":"log-interaction","description":"Writes to the client card on this Mac","size":1105,"status":{"state":"valid"}}]
        """
        return try JSONDecoder().decode([LocalSkill].self, from: Data(json.utf8))
    }

    public func stopAll() async throws {
        if stopDelay > 0 { try await Task.sleep(nanoseconds: stopDelay) }
        stoppedNow = true
        for index in delegationList.indices where delegationList[index].state.isOpen {
            delegationList[index].state = .stopped
        }
    }

    public func resumeAll() async throws {
        stoppedNow = false
        for index in delegationList.indices where delegationList[index].state == .stopped {
            delegationList[index].state = .working
        }
    }

    public func setAgentPaused(_ name: String, paused: Bool) async throws {
        if let pauseFailure { throw pauseFailure }
        if paused { pausedAgents.insert(name) } else { pausedAgents.remove(name) }
    }

    public func grants(agent: String) async throws -> AgentGrants {
        switch agent {
        case "mail":
            return AgentGrants(
                see: [
                    .init(scope: "Inbox and Sent, alex@studio.test", via: "Through macOS Internet Accounts", level: "read"),
                    .init(scope: "Contacts: names and email addresses", via: "To address replies", level: "read"),
                    .init(scope: "Invoices and receipts", via: "Only the ones Documents hands over", level: "ask"),
                ],
                canDo: [
                    .init(skill: "Draft replies", level: "auto"),
                    .init(skill: "Send email", level: "ask"),
                    .init(skill: "File and label mail", level: "auto"),
                ],
                never: ["Your calendar, except free times from Calendar", "Bank lines", "Paying or moving money"],
                egressNote: "Your mail stays on this Mac. To DeepSeek, Mail sends email text with names, addresses and numbers replaced."
            )
        case "aux":
            return AgentGrants(
                see: [.init(scope: "Results the team sends back", via: "Never the mail, files or bank lines behind them", level: "read")],
                canDo: [.init(skill: "Hand work to an agent", level: "auto")],
                never: ["Your mail, files and bank lines", "Sending anything itself"],
                egressNote: "To Claude Sonnet, Aux sends your requests and the team's short results, with names replaced."
            )
        default:
            return AgentGrants(see: [], canDo: [], never: [], egressNote: "")
        }
    }

    public func memory(agent: String) async throws -> [MemoryItem] {
        agent == "mail"
            ? [
                MemoryItem(id: "1", text: "Camille Exemple prefers email for anything about money", at: "28 Aug"),
                MemoryItem(id: "2", text: "Sign as Alex, never with the full name", at: "2 Sep"),
            ]
            : []
    }

    public func forget(agent: String, item: String) async throws {}

    // MARK: Clients (E3)

    private func seedClients() {
        let camille = ClientParty(
            id: 1, displayName: "Camille Exemple", nameVariants: ["Camille", "C. Exemple"],
            emails: ["camille@exemple.test"], phones: ["+33600000011"],
            addresses: ["12 rue de l'Exemple, 69002 Lyon, France"], tags: ["client", "design"],
            notes: "Creative director at Exemple SARL. Brand refresh, two logo routes.",
            timeZone: "Europe/Paris",
            origin: "contacts:vcard"
        )
        let jonas = ClientParty(
            id: 2, displayName: "Jonas Weber", nameVariants: ["Jonas"],
            emails: ["jonas@weber.test"], phones: ["+33600000012"], tags: ["prospect"],
            notes: "Founder. Has the quote of 30 Sep, wants to start in November.",
            origin: "mail:studio"
        )
        let company = ClientParty(
            id: 3, kind: "company", displayName: "Exemple SARL",
            emails: ["compta@exemple.test"], phones: ["+33600000013"], tags: ["client"],
            origin: "owner"
        )
        clientCards[1] = ClientCard(
            party: camille,
            timeline: [
                ClientInteraction(id: 14, kind: "meeting", at: stamp(6 * 60), summary: "Brand review, video call", provenance: "calendar"),
                ClientInteraction(id: 13, kind: "mail", at: stamp(-10 * 24 * 60), summary: "Asked to move the review to the 12th", provenance: "mail"),
                ClientInteraction(id: 12, kind: "document", at: stamp(-27 * 24 * 60), summary: "Invoice NW-2026-031 sent, €2,400.00", provenance: "documents"),
                ClientInteraction(id: 11, kind: "call", at: stamp(-45 * 24 * 60), summary: "Kick-off call: logo refresh, two routes", provenance: "owner"),
            ],
            followups: [
                ClientFollowup(id: 21, due: stamp(6 * 60), reason: "Raise invoice NW-2026-031 at the end of the review", createdBy: "follow-up-email"),
                ClientFollowup(id: 22, due: stamp(7 * 24 * 60), reason: "Send the final logo files", createdBy: "owner"),
            ],
            memory: [
                ClientMemory(id: 31, body: "Prefers email to calls for anything about money.", source: "Your 28 Aug call note"),
                ClientMemory(id: 32, body: "Works Monday to Thursday.", source: "Email, 9 Jul"),
                ClientMemory(id: 33, body: "Pays late but always pays; the last two invoices were about two weeks late.", source: "Ledger"),
            ]
        )
        clientCards[2] = ClientCard(
            party: jonas,
            timeline: [
                ClientInteraction(id: 16, kind: "mail", at: stamp(-2 * 24 * 60), summary: "Asks for a slot this week", provenance: "mail"),
                ClientInteraction(id: 15, kind: "document", at: stamp(-12 * 24 * 60), summary: "Quote Q-2026-014 sent, €6,800.00", provenance: "documents"),
            ],
            followups: [ClientFollowup(id: 23, due: stamp(2.5 * 60), reason: "Call about the quote", createdBy: "owner")],
            memory: [ClientMemory(id: 34, body: "Decides fast once dates are clear.", source: "Your 22 Sep note")]
        )
        clientCards[3] = ClientCard(party: company)
    }

    private func failIfDown() throws {
        if scenario == .clientsDown { throw AuxdError.transport("fixture: clients are down") }
    }

    public func clients() async throws -> [ClientSummary] {
        try failIfDown()
        return clientCards.values
            .map { card in
                ClientSummary(
                    id: card.party.id, kind: card.party.kind, displayName: card.party.displayName,
                    emails: card.party.emails, phones: card.party.phones, tags: card.party.tags,
                    nextFollowup: card.followups.first, lastInteractionAt: card.timeline.first?.at
                )
            }
            .sorted { $0.displayName.lowercased() < $1.displayName.lowercased() }
    }

    public func client(id: Int64) async throws -> ClientCard {
        try failIfDown()
        guard let card = clientCards[id] else { throw AuxdError.http(status: 404, body: "") }
        return card
    }

    public func updateClient(id: Int64, _ edit: ClientEdit) async throws -> ClientCard {
        try failIfDown()
        if let hold = clientSaveHold { await hold() }
        guard var card = clientCards[id] else { throw AuxdError.http(status: 404, body: "") }
        if let bad = edit.phones.first(where: { !$0.hasPrefix("+") }) {
            throw AuxdError.http(status: 422, body: #"{"error":{"code":"client_invalid","message":"`\#(bad)` is a national phone number and no country is known"}}"#)
        }
        card.party.displayName = edit.displayName
        card.party.nameVariants = edit.nameVariants
        card.party.emails = edit.emails
        card.party.phones = edit.phones
        card.party.addresses = edit.addresses
        card.party.tags = edit.tags
        card.party.notes = edit.notes
        clientCards[id] = card
        return card
    }

    public func forgetClientMemory(client: Int64, item: Int64) async throws {
        try failIfDown()
        clientCards[client]?.memory.removeAll { $0.id == item }
    }

    // MARK: Contacts import (WO-CRMIO-2)

    /// A small vCard file: twelve contacts, one row skipped, a phone needing no country.
    public static let sampleContactsPreview = ContactsImportAnswer(
        dryRun: true, format: "vcard", contacts: 12, emails: 11, phones: 9,
        partiesCreated: 10, partiesUpdated: 2, partiesRefused: 0,
        skipped: ContactsImportSkipped(noNameOrContact: 1, repeatedInFile: 3, phoneInvalid: 1)
    )

    public func importContacts(path: String, dryRun: Bool, tag: String?, country: String?) async throws -> ContactsImportAnswer {
        contactsRequests.append(ContactsImportRequest(path: path, dryRun: dryRun, tag: tag, country: country))
        if let contactsFailure {
            self.contactsFailure = nil
            throw contactsFailure
        }
        let preview = contactsPreview
        if dryRun { return preview }
        for _ in 0..<preview.partiesCreated {
            nextId += 1
            clientCards[nextId] = ClientCard(party: ClientParty(id: nextId, displayName: "Imported contact \(nextId)", origin: "contacts:fixture"))
        }
        return ContactsImportAnswer(
            dryRun: false, contacts: preview.contacts, emails: preview.emails, phones: preview.phones,
            partiesCreated: preview.partiesCreated, partiesUpdated: preview.partiesUpdated,
            partiesRefused: preview.partiesRefused, skipped: preview.skipped
        )
    }

    // MARK: Today

    public func todayBrief() async throws -> DailyBrief? {
        guard scenario != .empty || briefWritten else { return nil }
        let day = TodayPresentation.day(base)
        if scenario == .briefDegraded {
            return DailyBrief(day: day, writtenAt: "08:00", events: nil, mail: Self.briefMail,
                              notes: ["Calendar: not available.", "Weather: no city set yet."])
        }
        return DailyBrief(day: day, writtenAt: "08:00", events: [
            BriefEvent(title: "Call with Jonas Weber", start: "15:00", end: "15:30"),
            BriefEvent(title: "Exemple SARL: invoice review", start: "10:30", end: "11:00"),
            BriefEvent(title: "Invoice NW-2026-031 due", allDay: true),
            BriefEvent(title: "Dentist", start: "08:45", end: "09:15"),
        ], mail: Self.briefMail, notes: ["Weather: no city set yet."],
           prospects: Self.prospects.filter { !prospectsHandled.contains($0.id) })
    }

    public func resolveProspect(account: String, email: String, add: Bool) async throws -> ProspectOutcome {
        guard let prospect = Self.prospects.first(where: {
            $0.account == account && $0.email.caseInsensitiveCompare(email) == .orderedSame
        }), prospectsHandled.insert(prospect.id).inserted else { return .gone }
        return add ? .added(partyID: 41) : .ignored
    }

    private static let prospects = [
        BriefProspect(account: "work", name: "Lena Okafor", email: "lena@okafor-studio.test",
                      reason: "quote", date: "Wed, 14 Oct 2026 09:12:00 +0200"),
        BriefProspect(account: "work", email: "hello@northfield.test",
                      reason: "availability", date: "Wed, 14 Oct 2026 16:40:00 +0200"),
        BriefProspect(account: "work", name: "Tomás Rivera", email: "tomas@rivera.test",
                      reason: "referral", date: "Thu, 15 Oct 2026 07:05:00 +0200"),
    ]

    public func runBrief() async throws -> BriefRun {
        if briefWritten || scenario != .empty { return BriefRun(status: "already_today") }
        briefWritten = true
        return BriefRun(status: "written", brief: "Today — \(TodayPresentation.day(base))")
    }

    private static let briefMail = [
        BriefMail(sender: "Camille Exemple", subject: "Re: Invoice NW-2026-031"),
        BriefMail(sender: "Jonas Weber", subject: "A slot this week?"),
        BriefMail(sender: "Hosting Test", subject: "Your October receipt"),
    ]

    // MARK: ModelSawProviding

    public func modelSaw(agent: String, messageIds: [String]) -> ModelSawRecord? {
        let tokens: [String: String] = [
            "101": "Three things need you today. You're free between 10:30 and 14:00. I handed the morning work to the team:",
            "102": "As you asked on Friday: [ORG_1] still hasn't paid invoice NW-2026-031, €2,400.00, now 12 days late. [PERSON_1] prefers email for money.",
            "104": "Asked Mail. It knows she prefers email for anything about money.",
            "201": "[PERSON_2] asks for a slot this week. I drafted a reply with three slots from Calendar.",
        ]
        let kept: [String: [String]] = [
            "aux": ["Camille Exemple", "Exemple SARL", "Jonas Weber", "Lina Okafor"],
            "mail": ["Jonas Weber", "jonas@atelier-brume.test"],
        ]
        return ModelSawRecord(
            agent: agent,
            at: at(0),
            kept: kept[agent] ?? [],
            sentSummary: "Times, amounts and subjects. 1 request.",
            tokenised: tokens.filter { messageIds.contains($0.key) }
        )
    }

    // MARK: Coverage rows (kernel registry at the pinned rev, for the fixture only)

    static let coverageRows: [(String, String, CoverageRow.State, String, String)] = [
        ("A1", "Streaming chat", .covered, "allow", "gate"),
        ("A2", "Non-streaming chat", .covered, "allow", "gate"),
        ("A3", "Endpoint probe", .covered, "off", "gate"),
        ("B1", "memory recall (storage, D24): results reach a provider only through the session gate", .covered, "allow", "gate"),
        ("B2", "remember and forget (storage, D24): session tokens rehydrated locally before the write", .covered, "allow", "gate"),
        ("B3", "read_file", .missed, "off", "mount"),
        ("B4", "write_file", .missed, "off", "mount"),
        ("B5", "shell", .missed, "off", "mount"),
        ("B6", "http_fetch", .partial, "off", "mount"),
        ("B7", "weather forecast and geocode", .partial, "off", "mount"),
        ("B8", "Gmail search, read and list", .missed, "off", "mount"),
        ("B9", "Gmail draft", .missed, "off", "mount"),
        ("B10", "Calendar list and get", .missed, "off", "mount"),
        ("B11", "EventKit read (calendar snapshot): results reach a provider only through the session gate", .covered, "allow", "gate"),
        ("B12", "invoice import", .missed, "off", "absent"),
        ("B13", "MCP HTTP servers", .partial, "off", "mount"),
        ("B14", "MCP stdio children", .missed, "off", "mount"),
        ("B15", "cloud connector middleman (absent)", .missed, "off", "absent"),
        ("B16", "deleted (Zoho, D22)", .missed, "off", "absent"),
        ("B17", "Gmail send, out to Google: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", .missed, "ask", "gate"),
        ("B18", "Calendar create with attendees, out to Google: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", .missed, "ask", "gate"),
        ("B19", "IMAP read: list, search, thread, read (tool results through the session gate)", .covered, "allow", "gate"),
        ("B20", "Mail send over SMTP: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", .missed, "ask", "gate"),
        ("B21", "EventKit create or update event through the Mac bridge: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", .missed, "ask", "absent"),
        ("B22", "IMAP attachment download into the local evidence registry (storage, local only)", .covered, "allow", "gate"),
        ("C1", "WhatsApp text in", .partial, "off", "absent"),
        ("C2", "WhatsApp text out", .missed, "off", "absent"),
        ("C3", "WhatsApp voice", .missed, "off", "absent"),
        ("C4", "Telegram in", .partial, "off", "mount"),
        ("C5", "Telegram out", .missed, "off", "mount"),
        ("C6", "mail IMAP and SMTP", .missed, "off", "absent"),
        ("C7", "chat input and event feed", .missed, "off", "gate"),
        ("C8", "Mac clipboard and caches", .partial, "off", "absent"),
        ("C9", "screenshots", .covered, "allow", "absent"),
        ("C10", "macOS notifications", .partial, "off", "gate"),
        ("D1", "ACP prompt", .missed, "off", "gate"),
        ("D2", "ACP host file read", .missed, "off", "gate"),
        ("D3", "ACP host terminal output", .missed, "off", "gate"),
        ("D4", "ACP agent permission params", .partial, "off", "gate"),
        ("E1", "TTS speak", .missed, "off", "absent"),
        ("E2", "STT", .missed, "off", "absent"),
        ("F1", "agent jobs", .missed, "off", "gate"),
        ("F2", "morning brief", .missed, "off", "gate"),
        ("G1", "chat history store", .missed, "off", "gate"),
        ("G2", "channel message store", .missed, "off", "gate"),
        ("G3", "memory store (SQLCipher, local only)", .covered, "allow", "gate"),
        ("G4", "mail archive (no table)", .covered, "off", "absent"),
        ("G5", "documents and proofs store", .missed, "off", "absent"),
        ("G6", "audit log", .missed, "off", "gate"),
        ("G7", "app logs", .partial, "off", "gate"),
        ("H1", "embeddings (none on main)", .covered, "off", "absent"),
        ("I1", "panic messages", .covered, "allow", "mitigation"),
        ("I2", "OS crash reports and core dumps", .missed, "off", "mitigation"),
    ]
}

/// Fixture runs take the Calendar page's publish and keep nothing.
extension FixtureDaemon: AppleEventKitSnapshotClient {
    public func publishAppleEventKit(_ snapshot: AppleEventKitSnapshot) async throws {}
}

/// The memory routes (MEM-UI-1): the same four answers as the daemon, over
/// the fixture's invented facts. Nothing here touches a real store.
extension FixtureDaemon: MemoryClient {
    public func memorySnapshot(agent: String) async throws -> MemorySnapshot {
        MemorySnapshot(agent: agent, groups: memoryGroups, suggestions: memorySuggestions)
    }

    public func updateMemory(agent: String, item: String, text: String) async throws -> MemoryFact {
        guard let key = memoryGroups.first(where: { $0.value.contains { $0.id == item } })?.key,
              let index = memoryGroups[key]?.firstIndex(where: { $0.id == item }) else {
            throw AuxdError.http(status: 404, body: "")
        }
        let fact = MemoryFact(id: item, text: text, source: "you told Aux", savedAt: memoryGroups[key]?[index].savedAt)
        memoryGroups[key]?[index] = fact
        return fact
    }

    public func forgetMemory(agent: String, item: String) async throws {
        guard let key = memoryGroups.first(where: { $0.value.contains { $0.id == item } })?.key else {
            throw AuxdError.http(status: 404, body: "")
        }
        memoryGroups[key]?.removeAll { $0.id == item }
    }

    public func acceptMemorySuggestion(agent: String, suggestion: String) async throws -> MemoryFact {
        guard let index = memorySuggestions.firstIndex(where: { $0.id == suggestion }) else {
            throw AuxdError.http(status: 404, body: "")
        }
        let kept = memorySuggestions.remove(at: index)
        let fact = MemoryFact(
            id: "m-kept-\(kept.id)", text: kept.text, source: "accepted suggestion", savedAt: "2026-10-27T09:00:00Z")
        memoryGroups["other", default: []].append(fact)
        return fact
    }

    public func rejectMemorySuggestion(agent: String, suggestion: String) async throws {
        guard memorySuggestions.contains(where: { $0.id == suggestion }) else {
            throw AuxdError.http(status: 404, body: "")
        }
        memorySuggestions.removeAll { $0.id == suggestion }
    }
}

extension FixtureDaemon: CalendarStatusClient {
    public func calendarStatus() async throws -> CalendarSyncStatus {
        switch scenario {
        case .empty: return CalendarSyncStatus(shared: false, updatedAt: nil, fresh: false)
        // Four days ago at 18:33: the app was closed since.
        case .calendarStale: return CalendarSyncStatus(shared: true, updatedAt: at(-4 * 1440 + 633), fresh: false)
        default: return CalendarSyncStatus(shared: true, updatedAt: Date().addingTimeInterval(-120), fresh: true)
        }
    }
}

/// Invented events over the next days, for the Calendar page in fixture runs.
/// Never the owner's calendar.
@MainActor public final class FixtureEventKit: AppleEventKitProviding {
    private let day: Date
    private let granted: Bool
    public init(now: Date = Date(), granted: Bool = true) {
        day = Calendar.current.startOfDay(for: now)
        self.granted = granted
    }
    public var access: AppleEventKitAccess { granted ? .authorized : .notDetermined }
    public func requestAccessAndRead() async throws -> AppleEventKitSnapshot { try await readIfAuthorized() }
    public func readIfAuthorized() async throws -> AppleEventKitSnapshot {
        guard granted else { return AppleEventKitSnapshot(authorized: false, events: [], reminders: []) }
        let iso = ISO8601DateFormatter()
        let event = { (days: Int, hour: Double, minutes: Double, title: String, location: String?) in
            let start = Calendar.current.date(byAdding: .day, value: days, to: self.day)!.addingTimeInterval(hour * 3600)
            return AppleEventItem(title: title, start: iso.string(from: start),
                end: iso.string(from: start.addingTimeInterval(minutes * 60)), calendar: "Work", location: location)
        }
        return AppleEventKitSnapshot(authorized: true, events: [
            event(0, 9.5, 30, "Stand-up with Lumen Studio", nil),
            event(0, 14, 60, "Quote review, Northwind", "Studio B"),
            event(1, 11, 45, "Call with Camille Exemple", nil),
            event(2, 0, 1440, "Invoice NW-2026-031 due", nil),
            event(3, 10, 90, "Site visit, Brightpath", "Brightpath office"),
            event(5, 16, 30, "Dentist", nil),
            event(6, 9, 60, "Invoice check with Jonas Weber", nil),
        ], reminders: [], capturedAt: iso.string(from: Date()))
    }
}

// M6-4: a short plugin catalog and two installed servers for the Plugins tab snapshot.
extension FixtureDaemon: PluginsClient {
    private static func decode<T: Decodable>(_ json: String) -> T { try! JSONDecoder().decode(T.self, from: Data(json.utf8)) }
    public func mcpCatalog() async throws -> [McpCatalogEntry] {
        Self.decode("""
        [{"id":"public-data","name":"Public data search","region":"eu","category":"gov-data","status":"official","tier":"recommended","auth":"none","access":"read-only","transport":"http","endpoint":"https://mcp.data.example/mcp","data_class":"public","notes":"Searches open public datasets with no key. Experimental."},
         {"id":"notes-local","name":"Local notes","region":"eu","category":"files","status":"community","tier":"recommended","auth":"none","access":"read-write","transport":"stdio","data_class":"sensitive","notes":"Reads and writes plain notes in one folder on this Mac."},
         {"id":"invoices-hub","name":"Invoices hub","region":"eu","category":"finance","status":"community","tier":"recommended","auth":"api-key","access":"read-only","transport":"http","endpoint":"https://api.invoices.example/mcp","data_class":"sensitive","notes":"Lists received invoices and their due dates."}]
        """)
    }
    public func mcpServers() async throws -> [McpServerView] {
        Self.decode("""
        [{"id":"weather","enabled":true,"state":"ready","transport":"http","auth":"none","data_class":"public","tools":[{"name":"forecast","risk":"low"}],"agents":{"main":["forecast"]}},
         {"id":"invoices-hub","enabled":true,"state":"needs_approval","transport":"http","auth":"api-key","data_class":"sensitive","tools":[],"agents":{},"reason":"approval_required"}]
        """)
    }
    public func mcpPacks() async throws -> [McpPack] { [] }
    public func addMcpServer(id: String, catalogID: String, agent: String) async throws -> McpApprovalPreview { try await mcpApproval(id: id) }
    public func mcpApproval(id: String) async throws -> McpApprovalPreview {
        Self.decode(#"{"id":"\#(id)","transport":"http","enabled":false,"network":true,"env":[],"data_class":"public","endpoint":"https://mcp.data.example/mcp","args":[],"tools":[{"name":"search","risk":"low","access":"read"}],"hash":"fixture"}"#)
    }
    public func testMcpServer(url: String) async throws -> McpConnectionTest { throw AuxdError.transport("fixture") }
    public func enableMcpPack(id: String, agent: String) async throws {}
    public func approveMcpServer(id: String, hash: String, agent: String) async throws {}
    public func addMcpUrlServer(id: String, url: String, dataClass: String, testDigest: String) async throws {}
    public func setMcpServer(id: String, enabled: Bool) async throws {}
    public func setMcpTools(id: String, agent: String, tools: [String]) async throws {}
    public func deleteMcpServer(id: String) async throws {}
}
