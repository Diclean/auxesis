// The reads and actions the new shell needs beyond `AuxdTransport` (the
// screen contract). `AuxdClient` implements it against auxd; the fixture
// daemon implements it for previews and screenshots. A route the running
// daemon does not have yet answers 404/501: the
// shell treats that as "not available from this Auxesis yet", never as a
// crash and never as an empty success.
import Foundation

public protocol TeamClient: AnyObject {
    /// `GET /v1/delegations?thread=`.
    func delegations(thread: String) async throws -> [Delegation]
    /// `POST /v1/delegations/{id}/stop`.
    func stopDelegation(id: String) async throws
    /// `POST /v1/delegations/{id}/resume`.
    func resumeDelegation(id: String) async throws
    /// `GET /v1/privacy/coverage`: one row per `PathId::ALL` entry.
    func coverage() async throws -> CoverageResponse
    /// `GET /v1/activity`, newest last, with skill hashes.
    func ledger(limit: Int) async throws -> [LedgerEntry]
    /// `GET /v1/jobs`: the Planned tab.
    func plannedJobs() async throws -> [PlannedJob]
    /// `GET /v1/usage`: today's spend.
    func usageToday() async throws -> UsageDay
    /// `GET /v1/providers`.
    func providerList() async throws -> [ProviderSummary]
    /// `POST /v1/providers`.
    func addProvider(_ request: CreateProviderRequest) async throws
    /// `POST /v1/providers/{id}/test`.
    func testProvider(id: String) async throws -> ProviderTest
    /// `GET /v1/skills`.
    func skillList() async throws -> [LocalSkill]
    /// `POST /v1/stop-all`.
    func stopAll() async throws
    /// `POST /v1/resume`.
    func resumeAll() async throws
    /// `POST /v1/agents/{id}/pause|resume`.
    func setAgentPaused(_ name: String, paused: Bool) async throws
    /// `GET /v1/agents/{id}/grants`.
    func grants(agent: String) async throws -> AgentGrants
    /// `GET /v1/agents/{id}/memory`.
    func memory(agent: String) async throws -> [MemoryItem]
    /// `DELETE /v1/agents/{id}/memory/{item}`.
    func forget(agent: String, item: String) async throws
    /// `GET /v1/clients`.
    func clients() async throws -> [ClientSummary]
    /// `GET /v1/clients/{id}`: identity, timeline, follow-ups, memory.
    func client(id: Int64) async throws -> ClientCard
    /// `PUT /v1/clients/{id}`: edit the party; answers the new card.
    func updateClient(id: Int64, _ edit: ClientEdit) async throws -> ClientCard
    /// `DELETE /v1/clients/{id}/memory/{item}`.
    func forgetClientMemory(client: Int64, item: Int64) async throws
    /// Today's stored brief, nil when none is written yet. `GET /v1/brief/today`
    /// answers 404 on an auxd without that route: the live client reads that as
    /// nil, the fixture daemon serves one.
    func todayBrief() async throws -> DailyBrief?
    /// `POST /v1/brief/run`: run the morning brief once, now.
    func runBrief() async throws -> BriefRun
    /// `POST /v1/brief/prospects/add` (add) or `/ignore`; a 404 is `.gone`.
    func resolveProspect(account: String, email: String, add: Bool) async throws -> ProspectOutcome
    /// `GET /v1/private/answers`: held answers, newest first; `[]` outside Private mode.
    func privateAnswers() async throws -> [PrivateAnswer]
    /// `POST /v1/private/answers/{id}/dismiss`: 204, or 404 when already gone.
    func dismissPrivateAnswer(id: String) async throws
}

/// Daemons and fixtures without the Private answers route hold none.
public extension TeamClient {
    func privateAnswers() async throws -> [PrivateAnswer] { [] }
    func dismissPrivateAnswer(id: String) async throws {}
}

public extension AuxdError {
    /// The route is not on this daemon yet (404 / 405 / 501).
    var isUnavailableRoute: Bool {
        if case .http(let status, _) = self { return status == 404 || status == 405 || status == 501 }
        return false
    }
}
