// Thin auxd client: HTTP + WebSocket on loopback, bearer token, no custom
// Origin, no CORS games. It decodes the daemon's JSON and skips unknown
// frames.
//
// Two hard rules (F1): the bearer token is attached only after the final
// request URL is re-checked as loopback (`LoopbackURL.isSafeRequestURL`), and
// redirects are refused — a 3xx is surfaced as an HTTP error, never followed
// to a foreign host with the Authorization header still attached.
import Foundation

/// Refuses every redirect: the daemon is a loopback service; a redirect is
/// either a bug or an attack, and following one could carry the bearer token
/// off-box.
private final class RedirectRefuser: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// One capped loopback download for the docs blob route. The declared
/// `Content-Length` is checked before the first body byte, and the task is
/// cancelled as soon as more than `limit` bytes have arrived, so a lying size
/// or a hostile body can never pull an unbounded blob into memory. Task-level
/// delegate, so the session's redirect refusal still applies.
private final class CappedBlobDelegate: NSObject, URLSessionDataDelegate {
    private let limit: Int
    private let lock = NSLock()
    private var data = Data()
    private var continuation: CheckedContinuation<Data, Error>?
    private var finished = false

    init(limit: Int) { self.limit = limit }

    func fetch(_ task: URLSessionDataTask) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            lock.lock()
            self.continuation = continuation
            lock.unlock()
            task.delegate = self
            task.resume()
        }
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Same no-redirect rule as the session delegate: a 3xx must never carry
        // the bearer token to a foreign host.
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let http = response as? HTTPURLResponse else {
            finish(.failure(AuxdError.transport("no HTTP response")))
            completionHandler(.cancel)
            return
        }
        guard (200..<300).contains(http.statusCode) else {
            finish(.failure(Self.statusError(http.statusCode)))
            completionHandler(.cancel)
            return
        }
        if http.expectedContentLength > Int64(limit) {
            finish(.failure(Self.tooLarge))
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        lock.lock()
        let over = finished || data.count + chunk.count > limit
        if !over { data.append(chunk) }
        lock.unlock()
        guard over else { return }
        finish(.failure(Self.tooLarge))
        dataTask.cancel()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // Idempotent: our own cap cancellation has already finished the call.
        if let error {
            finish(.failure(AuxdError.transport(error.localizedDescription)))
        } else {
            finish(.success(data))
        }
    }

    private func finish(_ result: Result<Data, Error>) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        let continuation = self.continuation
        self.continuation = nil
        let payload: Result<Data, Error>
        switch result {
        case .success: payload = .success(data)
        case .failure(let error): payload = .failure(error)
        }
        lock.unlock()
        continuation?.resume(with: payload)
    }

    private static let tooLarge = AuxdError.http(status: 413, body: "")

    private static func statusError(_ status: Int) -> Error {
        status == 401 ? AuxdError.unauthorized : AuxdError.http(status: status, body: "")
    }
}

/// The first-run setup surface (B-API v4, PR #70). It is a protocol of its
/// own — not a `AuxdTransport` requirement — so tests can script the four
/// setup routes without a network while the shell keeps its existing
/// transport. `Store` adopts the real client when it conforms
/// (`transport as? FirstRunClient`), which keeps the app entry point unchanged.
///
/// The key travels only inside `CreateProviderRequest` / `ProviderTestRequest`
/// / the update-key path and is never repeated back: every response carries
/// booleans, never a key.
public protocol FirstRunClient: AnyObject {
    /// `GET /v1/providers`: configured services and key presence only.
    func providers() async throws -> [ProviderSummary]
    /// `POST /v1/providers`: save the non-secret entry and the key (`0600`).
    func saveProvider(_ request: CreateProviderRequest) async throws -> ProviderSaved
    /// `PUT /v1/providers/{name}/key`: store a key for a service the daemon
    /// already knows (the "exists but has no key" path).
    func updateProviderKey(name: String, apiKey: String) async throws -> ProviderSaved
    /// `POST /v1/providers/test`: the spend-free check (no completion).
    func testProvider(_ request: ProviderTestRequest) async throws -> ProviderTest
    /// `GET /v1/first-run`: the guided flow's step states.
    func firstRunStatus() async throws -> FirstRunStatus
    /// `POST /v1/agents`: create one agent.
    func createAgent(_ request: CreateAgentRequest) async throws -> AgentCreateResponse
    /// `POST /v1/first-run/complete`: create the default agent / clear the gate.
    func completeFirstRun(_ request: FirstRunCompleteRequest) async throws -> FirstRunComplete
}

/// The contacts import (WO-CRMIO-2). A protocol of its own, like `PackClient`,
/// so the sheet's model is tested without a network. The daemon reads the file
/// where it is; the path is only ever sent, never shown.
public protocol ContactsImportClient: AnyObject {
    /// `POST /v1/contacts/import`. `dryRun` counts what the file would do and
    /// writes nothing; a real import answers with the same counts.
    func importContacts(path: String, dryRun: Bool, tag: String?, country: String?) async throws -> ContactsImportAnswer
}

public protocol PackClient: AnyObject {
    func agentTools(name: String) async throws -> AgentToolsDetail
    func updateAgentTools(name: String, tools: [String]?) async throws
}

public protocol SkillsClient: AnyObject {
    func skills() async throws -> [LocalSkill]
    func updateAgentSkills(name: String, skills: [String]) async throws
}

/// The owner's personality editing (B-API v3). A protocol of its own, like
/// `PackClient`, so tests script the read/save without a network. The read is
/// the dedicated whole-text route; the save is the same `PUT /v1/agents/{id}`
/// that writes every other agent field, through the one secure write path.
public protocol PersonalityClient: AnyObject {
    /// `GET /v1/agents/{id}/soul`: the personality exactly as stored.
    func agentSoul(name: String) async throws -> AgentSoul
    /// `PUT /v1/agents/{id}` with `soul_md`.
    func updateAgentSoul(name: String, soul: String) async throws
}

/// The owner's Google connection (G4). A protocol of its own, like
/// `FirstRunClient`, so tests can script the two routes without a network.
///
/// Nothing here opens a page on its own: `startGoogleConnection` is only ever
/// called from the « Connecter Google » button, and the daemon opens the
/// browser from that one request.
public protocol GoogleConnectionClient: AnyObject {
    /// `POST /v1/google/connect`: ask the service to start the sign-in.
    func startGoogleConnection() async throws -> GoogleConnection
    /// `POST /v1/google/reconnect`: renew an existing Google authorization.
    func updateGooglePermissions() async throws -> GoogleConnection
    /// `POST /v1/google/disconnect`: revoke and delete the authorization.
    func disconnectGoogle() async throws -> GoogleConnection
}

public protocol TelegramSettingsClient: AnyObject {
    func telegramSettings() async throws -> TelegramSettings
    func setTelegramEnabled(_ enabled: Bool) async throws -> TelegramSettings
    func saveTelegramSecret(_ secret: String) async throws -> TelegramSettings
    func createTelegramPairing() async throws -> TelegramPairingCode
}

public protocol PluginsClient: AnyObject {
    func mcpCatalog() async throws -> [McpCatalogEntry]
    func mcpPacks() async throws -> [McpPack]
    func enableMcpPack(id: String, agent: String) async throws
    func mcpServers() async throws -> [McpServerView]
    /// `agent` is the agent the staged allowlist (and so the preview hash) is for.
    func addMcpServer(id: String, catalogID: String, agent: String) async throws -> McpApprovalPreview
    func mcpApproval(id: String) async throws -> McpApprovalPreview
    func approveMcpServer(id: String, hash: String, agent: String) async throws
    func testMcpServer(url: String) async throws -> McpConnectionTest
    func addMcpUrlServer(id: String, url: String, dataClass: String, testDigest: String) async throws
    func setMcpServer(id: String, enabled: Bool) async throws
    func setMcpTools(id: String, agent: String, tools: [String]) async throws
    func deleteMcpServer(id: String) async throws
    /// Item 12: the exact launch preview and the owner's confirmation.
    func mcpConfirmation(id: String) async throws -> McpConfirmationDetails
    func confirmMcpServer(id: String, hash: String) async throws
}

/// A client that can pick up the local access token written *after* it was
/// created. The app starts the service it ships, and the service writes
/// `api.token` at startup: without this the app would stay stuck on the
/// "clé d'accès introuvable" screen until the owner relaunched it.
///
/// `refreshToken()` re-reads the *same* verified path with the *same* refusal
/// rules as `init` (never a token when there is no endpoint or the sandbox
/// refused the home), so it adds no new trust: whoever can place that file
/// could already have placed it before launch.
public protocol TokenRefreshing {
    func refreshToken()
}

/// A transport that tags every request with the owner's language (`X-Auxesis-Lang:
/// en|fr`), so the service can answer in it once it learns to. A service that
/// does not know the header ignores it; the app's own copy never depends on it.
public protocol LanguageReporting: AnyObject {
    var language: Language { get set }
}

extension AuxdError {
    /// The exact `.transport` text `AuxdClient` folds a `URLError.timedOut`
    /// into. A stable, non-visible token (never a sentence): user-facing wording
    /// lives in `L10n`, and the first-run card turns this marker into a retry
    /// card, never the "quit and relaunch" service-down card (a slow answer is
    /// not a dead service).
    public static let timedOutMessage = "auxd.request.timeout"
}

/// Late-bound weak reference to the client, so `bridgeHandler` can be an
/// immutable `let` built in `init` without passing `self` before all stored
/// properties exist. `weak` breaks the client → handler → box cycle.
private final class WeakBridgeClient: BridgeAnswerPosting, DocumentBytesFetching {
    weak var client: AuxdClient?

    func postBridgeAnswer(id: String, body: Data) async throws -> Int {
        guard let client else { throw AuxdError.transport("the bridge client is gone") }
        return try await client.postBridgeAnswer(id: id, body: body)
    }

    func documentBytes(sha256: String) async throws -> Data {
        guard let client else { throw AuxdError.transport("the bridge client is gone") }
        return try await client.documentBytes(sha256: sha256)
    }
}

public final class AuxdClient: AuxdTransport, FirstRunClient, PackClient, SkillsClient, GoogleConnectionClient, PersonalityClient, TelegramSettingsClient, PluginsClient, TokenRefreshing, LanguageReporting, AppleEventKitSnapshotClient, BridgeAnswerPosting, DocumentBytesFetching, DocsExtractionClient, ContactsImportClient {
    public let endpoint: AuxdEndpoint
    /// The language every request is tagged with. `Store` keeps this in sync
    /// with the owner's choice.
    public var language: Language = .default
    /// The Mac bridge handler (A2b), built in `init`; `events()` hands it every
    /// real `bridge.request` frame. Its EventKit store is created lazily on the
    /// first op (inside `EventKitBridgeWriter`), so a client that never serves
    /// one — including every test — builds no EKEventStore. The test seam
    /// passes `systemBridge: false` and gets no handler at all.
    private let bridgeHandler: BridgeHandler?
    /// The token as last read. Reads and writes take `tokenLock`, so
    /// `refreshToken()` after the app started the service is visible to the next
    /// request without racing an in-flight one.
    public var token: String {
        tokenLock.lock()
        defer { tokenLock.unlock() }
        return lockedToken
    }
    /// Non-nil when the token file was missing or unsafe; every call then
    /// fails with `AuxdError.token(problem)` — the honest offline state.
    public var tokenProblem: TokenFileProblem? {
        tokenLock.lock()
        defer { tokenLock.unlock() }
        return lockedTokenProblem
    }
    /// The guarded storage behind `token` / `tokenProblem`. Never read without
    /// holding `tokenLock` (except during `init`, before any sharing).
    private var lockedToken = ""
    private var lockedTokenProblem: TokenFileProblem?
    private let tokenLock = NSLock()
    private let session: URLSession
    /// The chat send's own session: same idle timeout, but a whole-transfer
    /// cap that outlasts the daemon's turn cap. Every other call stays on
    /// `session` and its short cap.
    private let chatSession: URLSession
    private let requestTimeout: TimeInterval
    private let redirectRefuser = RedirectRefuser()

    public convenience init(endpoint: AuxdEndpoint, requestTimeout: TimeInterval = 30) {
        self.init(endpoint: endpoint, requestTimeout: requestTimeout, configuration: nil, systemBridge: true)
    }

    /// Internal seam for tests: a configuration with a mock URLProtocol, and no
    /// system bridge (no EKEventStore, no Vision).
    convenience init(endpoint: AuxdEndpoint, requestTimeout: TimeInterval, configuration: URLSessionConfiguration?) {
        self.init(
            endpoint: endpoint, requestTimeout: requestTimeout,
            configuration: configuration, systemBridge: false)
    }

    private init(
        endpoint: AuxdEndpoint, requestTimeout: TimeInterval,
        configuration: URLSessionConfiguration?, systemBridge: Bool
    ) {
        self.endpoint = endpoint
        self.requestTimeout = requestTimeout
        // J-02 round 6 (security review P1): with no endpoint, or with a sandbox-refused
        // home, the token file is NEVER read — a Foundation-derived real home
        // must not leak its token into the client.
        if endpoint.baseURL == nil || endpoint.homeRefused {
            self.lockedToken = ""
            self.lockedTokenProblem = .missing
        } else {
            switch TokenFile.read(at: endpoint.tokenFile) {
            case .ok(let value):
                self.lockedToken = value
                self.lockedTokenProblem = nil
            case .problem(let problem):
                self.lockedToken = ""
                self.lockedTokenProblem = problem
            }
        }
        let config = configuration ?? URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = requestTimeout
        config.timeoutIntervalForResource = requestTimeout * 4
        config.waitsForConnectivity = false
        // A chat send may wait for an approval card: its transfer cap must
        // outlast the daemon's own turn cap, so the daemon ends the turn.
        let chatConfig = config.copy() as! URLSessionConfiguration
        chatConfig.timeoutIntervalForResource = Self.chatSendTimeout
        self.chatSession = URLSession(configuration: chatConfig, delegate: redirectRefuser, delegateQueue: nil)
        // Session-level task delegate: HTTP data tasks and the WebSocket
        // handshake both route through `willPerformHTTPRedirection`.
        self.session = URLSession(configuration: config, delegate: redirectRefuser, delegateQueue: nil)
        // Last stored property: after this assignment `self` is fully built, so
        // the weak back-reference can be set.
        if systemBridge {
            let bridge = WeakBridgeClient()
            self.bridgeHandler = BridgeHandler(
                writer: bridgeEventWriter(),
                recognizer: VisionDocumentRecognizer(fetch: bridge),
                answers: bridge)
            bridge.client = self
        } else {
            self.bridgeHandler = nil
        }
    }

    deinit {
        session.invalidateAndCancel()
        chatSession.invalidateAndCancel()
    }

    private func tokenOrThrow() throws -> String {
        tokenLock.lock()
        let problem = lockedTokenProblem
        let value = lockedToken
        tokenLock.unlock()
        if let problem {
            throw AuxdError.token(problem)
        }
        return value
    }

    /// Re-read the local access token from the same verified path. The app
    /// starts the service itself, so the file can appear (or be re-written by a
    /// restarted service) after launch: `Store` calls this before each reconnect
    /// attempt instead of asking the owner to relaunch Auxesis.
    ///
    /// The `init` refusal rules are repeated here: with no endpoint, or with a
    /// sandbox-refused home, nothing is ever read.
    public func refreshToken() {
        guard endpoint.baseURL != nil, !endpoint.homeRefused else { return }
        let value: String
        let problem: TokenFileProblem?
        switch TokenFile.read(at: endpoint.tokenFile) {
        case .ok(let token):
            value = token
            problem = nil
        case .problem(let issue):
            value = ""
            problem = issue
        }
        tokenLock.lock()
        lockedToken = value
        lockedTokenProblem = problem
        tokenLock.unlock()
    }

    // MARK: - HTTP

    private func request(_ method: String, _ path: String, body: Data? = nil) throws -> URLRequest {
        guard let baseURL = endpoint.baseURL,
              let url = URL(string: path, relativeTo: baseURL) else { throw AuxdError.badURL }
        // Re-assert the loopback property on the final URL before the token
        // is attached (defence in depth over the resolver).
        guard LoopbackURL.isSafeRequestURL(url) else { throw AuxdError.offLoopback }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(try tokenOrThrow())", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(language.rawValue, forHTTPHeaderField: "X-Auxesis-Lang")
        // Deliberately no Origin header and no CORS preflight: the daemon is
        // loopback + native-client only (crates/auxd/src/api/mod.rs).
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        return request
    }

    private func perform<T: Decodable>(
        _ request: URLRequest, as type: T.Type, on session: URLSession? = nil
    ) async throws -> T {
        try Self.decodeBody(T.self, from: try await send(request, on: session))
    }

    /// One round trip: the body of a 2xx answer, or the typed error for the rest.
    private func send(_ request: URLRequest, on chosen: URLSession? = nil) async throws -> Data {
        let session = chosen ?? self.session
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError where urlError.code == .timedOut {
            throw AuxdError.transport(AuxdError.timedOutMessage)
        } catch {
            throw AuxdError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw AuxdError.transport("no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 { throw AuxdError.unauthorized }
            throw AuxdError.http(status: http.statusCode, body: String(data: data, encoding: .utf8) ?? "")
        }
        return data
    }

    private static func decodeBody<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw AuxdError.decode(String(describing: error))
        }
    }

    private static func encodedPath(_ segment: String) -> String {
        segment.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? segment
    }

    /// A query-value encoder: `&`, `=` and `+` are separators in a query
    /// string, so they must be percent-encoded inside one value.
    private static func encodedQuery(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&+=?")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    public func health() async throws -> HealthResponse {
        try await perform(request("GET", "/v1/health"), as: HealthResponse.self)
    }

    public func agents() async throws -> [AgentSummary] {
        try await perform(request("GET", "/v1/agents"), as: [AgentSummary].self)
    }

    public func agentTools(name: String) async throws -> AgentToolsDetail {
        let path = "/v1/agents/\(Self.encodedPath(name))"
        return try await perform(request("GET", path), as: AgentDetailResponse.self).agent
    }

    public func updateAgentTools(name: String, tools: [String]?) async throws {
        let data = try JSONEncoder().encode(AgentToolsUpdate(tools: tools))
        let path = "/v1/agents/\(Self.encodedPath(name))"
        let _: AgentToolsUpdateResponse = try await perform(request("PUT", path, body: data), as: AgentToolsUpdateResponse.self)
    }

    public func skills() async throws -> [LocalSkill] {
        try await perform(request("GET", "/v1/skills"), as: [LocalSkill].self)
    }

    public func updateAgentSkills(name: String, skills: [String]) async throws {
        let data = try JSONEncoder().encode(AgentSkillsUpdate(skills: skills))
        let path = "/v1/agents/\(Self.encodedPath(name))"
        let _: AgentSkillsUpdateResponse = try await perform(request("PUT", path, body: data), as: AgentSkillsUpdateResponse.self)
    }

    // MARK: - Personality (B-API v3)

    /// `GET /v1/agents/{id}/soul`: the personality whole, for the editor. An
    /// older service without the route answers 404 and the editor says the
    /// read failed rather than showing a truncated text.
    public func agentSoul(name: String) async throws -> AgentSoul {
        let path = "/v1/agents/\(Self.encodedPath(name))/soul"
        return try await perform(request("GET", path), as: AgentSoul.self)
    }

    /// `PUT /v1/agents/{id}` with the app's `soul_md` field.
    public func updateAgentSoul(name: String, soul: String) async throws {
        let data = try JSONEncoder().encode(AgentSoulUpdate(soulMd: soul))
        let path = "/v1/agents/\(Self.encodedPath(name))"
        let _: AgentToolsUpdateResponse = try await perform(request("PUT", path, body: data), as: AgentToolsUpdateResponse.self)
    }

    public func messages(thread: String, limit: Int = 200) async throws -> MessagesPage {
        let path = "/v1/threads/\(Self.encodedPath(thread))/messages?limit=\(limit)"
        return try await perform(request("GET", path), as: MessagesPage.self)
    }

    public func pendingApprovals() async throws -> [Approval] {
        try await perform(request("GET", "/v1/approvals?state=pending"), as: [Approval].self)
    }

    /// Recent run receipts, newest first (`GET /v1/receipts`). `agent` is the
    /// daemon's agent name; `nil` returns every agent's receipts.
    public func receipts(agent: String? = nil, limit: Int = 50) async throws -> [Receipt] {
        try await perform(request("GET", Self.receiptsPath(agent: agent, limit: limit)), as: [Receipt].self)
    }

    /// The `GET /v1/receipts` query, pure so it is testable without a socket.
    static func receiptsPath(agent: String?, limit: Int) -> String {
        var path = "/v1/receipts?limit=\(limit)"
        if let agent, !agent.isEmpty {
            path += "&agent=\(encodedQuery(agent))"
        }
        return path
    }

    /// How long a chat send waits for its answer: the daemon's default turn
    /// cap (`turn_timeout_secs`, 1800 s) plus a margin, so a turn waiting on an
    /// approval card ends with the daemon's `turn_timeout`, never a client
    /// give-up that cancels the turn and clears the card.
    static let chatSendTimeout: TimeInterval = 1800 + 60

    public func send(thread: String, content: String) async throws -> SendResponse {
        try await perform(sendRequest(thread: thread, content: content), as: SendResponse.self, on: chatSession)
    }

    public func newThread(thread: String) async throws -> SessionJson {
        try await perform(request("POST", "/v1/threads/\(Self.encodedPath(thread))/new"), as: SessionJson.self)
    }

    public func conversations() async throws -> [ConversationSummary] {
        try await perform(request("GET", "/v1/conversations"), as: [ConversationSummary].self)
    }


    func sendRequest(thread: String, content: String) throws -> URLRequest {
        struct Body: Encodable { let content: String }
        let data = try JSONEncoder().encode(Body(content: content))
        let path = "/v1/threads/\(Self.encodedPath(thread))/messages"
        var request = try request("POST", path, body: data)
        request.timeoutInterval = Self.chatSendTimeout
        return request
    }

    /// Whole-transfer caps of the shared and chat sessions (tests).
    var resourceTimeout: TimeInterval { session.configuration.timeoutIntervalForResource }
    var chatResourceTimeout: TimeInterval { chatSession.configuration.timeoutIntervalForResource }

    public func resolve(id: String, decision: String, scope: ApprovalScope? = nil, text: String? = nil) async throws -> ApprovalState {
        let data = try JSONEncoder().encode(ResolveRequest(decision: decision, scope: scope, text: text))
        let path = "/v1/approvals/\(Self.encodedPath(id))"
        let response = try await perform(request("POST", path, body: data), as: ResolveResponse.self)
        return response.state
    }

    // MARK: - First run (B-API v4)

    private func post<P: Encodable, T: Decodable>(_ path: String, _ payload: P, as type: T.Type) async throws -> T {
        let data = try JSONEncoder().encode(payload)
        return try await perform(request("POST", path, body: data), as: type)
    }

    public func providers() async throws -> [ProviderSummary] {
        try await perform(request("GET", "/v1/providers"), as: [ProviderSummary].self)
    }

    public func saveProvider(_ payload: CreateProviderRequest) async throws -> ProviderSaved {
        try await post("/v1/providers", payload, as: ProviderSaved.self)
    }

    public func updateProviderKey(name: String, apiKey: String) async throws -> ProviderSaved {
        let data = try JSONEncoder().encode(UpdateProviderKeyRequest(apiKey: apiKey))
        let path = "/v1/providers/\(Self.encodedPath(name))/key"
        return try await perform(request("PUT", path, body: data), as: ProviderSaved.self)
    }

    public func testProvider(_ payload: ProviderTestRequest) async throws -> ProviderTest {
        try await post("/v1/providers/test", payload, as: ProviderTest.self)
    }

    public func firstRunStatus() async throws -> FirstRunStatus {
        try await perform(request("GET", "/v1/first-run"), as: FirstRunStatus.self)
    }

    public func createAgent(_ payload: CreateAgentRequest) async throws -> AgentCreateResponse {
        try await post("/v1/agents", payload, as: AgentCreateResponse.self)
    }

    public func completeFirstRun(_ payload: FirstRunCompleteRequest) async throws -> FirstRunComplete {
        try await post("/v1/first-run/complete", payload, as: FirstRunComplete.self)
    }

    // MARK: - Google connection (G4)

    /// Ask the service to start the browser sign-in. Called only from an owner
    /// click on « Connecter Google ».
    public func startGoogleConnection() async throws -> GoogleConnection {
        struct Empty: Encodable {}
        return try await post("/v1/google/connect", Empty(), as: GoogleConnection.self)
    }

    public func updateGooglePermissions() async throws -> GoogleConnection {
        struct Empty: Encodable {}
        return try await post("/v1/google/reconnect", Empty(), as: GoogleConnection.self)
    }

    /// Revoke and delete this Mac's Google authorization.
    public func disconnectGoogle() async throws -> GoogleConnection {
        struct Empty: Encodable {}
        return try await post("/v1/google/disconnect", Empty(), as: GoogleConnection.self)
    }

    public func publishAppleEventKit(_ snapshot: AppleEventKitSnapshot) async throws {
        let data = try JSONEncoder().encode(snapshot)
        let req = try request("POST", "/v1/apple-eventkit/snapshot", body: data)
        let (_, response): (Data, URLResponse)
        do { (_, response) = try await session.data(for: req) }
        catch { throw AuxdError.transport(error.localizedDescription) }
        guard let http = response as? HTTPURLResponse else { throw AuxdError.transport("no HTTP response") }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 { throw AuxdError.unauthorized }
            throw AuxdError.http(status: http.statusCode, body: "")
        }
    }

    public func telegramSettings() async throws -> TelegramSettings {
        try await perform(request("GET", "/v1/telegram"), as: TelegramSettings.self)
    }

    public func mcpCatalog() async throws -> [McpCatalogEntry] { try await perform(request("GET", "/v1/mcp/catalog"), as: McpCatalogResponse.self).servers }
    public func mcpPacks() async throws -> [McpPack] { try await perform(request("GET", "/v1/mcp/packs"), as: McpPacksResponse.self).packs }
    public func enableMcpPack(id: String, agent: String) async throws { _ = try await perform(request("POST", "/v1/mcp/packs/\(id)/enable", body: JSONEncoder().encode(McpPackEnableBody(agent: agent))), as: McpAck.self) }
    public func mcpServers() async throws -> [McpServerView] { try await perform(request("GET", "/v1/mcp/servers"), as: McpServersResponse.self).servers }
    public func addMcpServer(id: String, catalogID: String, agent: String) async throws -> McpApprovalPreview { try await perform(request("POST", "/v1/mcp/servers", body: JSONEncoder().encode(McpAddBody(id: id, catalogID: catalogID, agent: agent))), as: McpApprovalPreview.self) }
    public func mcpApproval(id: String) async throws -> McpApprovalPreview { try await perform(request("GET", "/v1/mcp/servers/\(id)/approval"), as: McpApprovalPreview.self) }
    public func approveMcpServer(id: String, hash: String, agent: String) async throws { _ = try await perform(request("POST", "/v1/mcp/servers/\(id)/approve", body: JSONEncoder().encode(McpApproveBody(hash: hash, agent: agent))), as: McpAck.self) }
    public func testMcpServer(url: String) async throws -> McpConnectionTest { try await perform(request("POST", "/v1/mcp/servers/test", body: JSONEncoder().encode(McpTestBody(url: url))), as: McpConnectionTest.self) }
    public func addMcpUrlServer(id: String, url: String, dataClass: String, testDigest: String) async throws { _ = try await perform(request("POST", "/v1/mcp/servers", body: JSONEncoder().encode(McpUrlBody(id: id, url: url, dataClass: dataClass, testDigest: testDigest))), as: McpAck.self) }
    public func setMcpServer(id: String, enabled: Bool) async throws { _ = try await perform(request("PUT", "/v1/mcp/servers/\(id)", body: JSONEncoder().encode(McpEnabledBody(enabled: enabled))), as: McpAck.self) }
    public func setMcpTools(id: String, agent: String, tools: [String]) async throws { _ = try await perform(request("PUT", "/v1/mcp/servers/\(id)/agents/\(agent)", body: JSONEncoder().encode(McpToolsBody(tools: tools))), as: McpAck.self) }
    public func deleteMcpServer(id: String) async throws { _ = try await perform(request("DELETE", "/v1/mcp/servers/\(id)"), as: McpAck.self) }
    // Item 12: the confirmation preview / confirm calls. NOTE: not compiled.
    public func mcpConfirmation(id: String) async throws -> McpConfirmationDetails { try await perform(request("GET", "/v1/mcp/servers/\(id)/confirmation"), as: McpConfirmationDetails.self) }
    public func confirmMcpServer(id: String, hash: String) async throws { _ = try await perform(request("POST", "/v1/mcp/servers/\(id)/confirm", body: JSONEncoder().encode(McpConfirmBody(hash: hash))), as: McpAck.self) }

    public func setTelegramEnabled(_ enabled: Bool) async throws -> TelegramSettings {
        struct Body: Encodable { let enabled: Bool }
        let data = try JSONEncoder().encode(Body(enabled: enabled))
        return try await perform(request("PUT", "/v1/telegram", body: data), as: TelegramSettings.self)
    }

    public func saveTelegramSecret(_ secret: String) async throws -> TelegramSettings {
        struct Body: Encodable { let secret: String }
        return try await post("/v1/telegram/secret", Body(secret: secret), as: TelegramSettings.self)
    }

    public func createTelegramPairing() async throws -> TelegramPairingCode {
        struct Empty: Encodable {}
        return try await post("/v1/telegram/pair", Empty(), as: TelegramPairingCode.self)
    }

    // MARK: - WebSocket

    /// `http://host:port` → `ws://host:port`, `https` → `wss`.
    static func websocketURL(from base: URL) -> URL? {
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else { return nil }
        switch components.scheme?.lowercased() {
        case "http": components.scheme = "ws"
        case "https": components.scheme = "wss"
        case "ws", "wss": break
        default: return nil
        }
        components.path = "/v1/events"
        components.query = nil
        components.fragment = nil
        return components.url
    }

    public func events() throws -> AsyncThrowingStream<WireEvent, Error> {
        // Same loopback re-check as `request`: the WS handshake carries the
        // bearer token, so a non-loopback target never gets it.
        guard let baseURL = endpoint.baseURL,
              let url = Self.websocketURL(from: baseURL), LoopbackURL.isSafeRequestURL(url) else {
            throw AuxdError.offLoopback
        }
        // A2b: the app is the only side that can run EventKit/Vision. The
        // handler is resolved once per socket; a bridge frame is answered,
        // never surfaced as a `WireEvent`.
        let bridge = bridgeHandler
        var request = URLRequest(url: url)
        request.setValue("Bearer \(try tokenOrThrow())", forHTTPHeaderField: "Authorization")
        request.setValue(language.rawValue, forHTTPHeaderField: "X-Auxesis-Lang")
        let task = session.webSocketTask(with: request)
        task.resume()

        return AsyncThrowingStream { continuation in
            let receive = Task {
                do {
                    while !Task.isCancelled {
                        let message = try await task.receive()
                        switch message {
                        case .string(let text):
                            if let data = text.data(using: .utf8) {
                                Self.yield(data, to: continuation, bridge: bridge)
                            }
                        case .data(let data):
                            Self.yield(data, to: continuation, bridge: bridge)
                        @unknown default:
                            break
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: AuxdError.transport(error.localizedDescription))
                }
            }
            continuation.onTermination = { _ in
                receive.cancel()
                task.cancel(with: .goingAway, reason: nil)
            }
        }
    }

    /// Decodable frames are yielded; a real bridge request goes to the handler
    /// instead (a ledger echo has no top-level `id`, so it is not a request);
    /// malformed JSON is skipped (forward compatibility). Internal so a test
    /// can drive one raw frame through it.
    static func yield(
        _ data: Data,
        to continuation: AsyncThrowingStream<WireEvent, Error>.Continuation,
        bridge: BridgeHandler?
    ) {
        switch BridgeFrame.route(data) {
        case .request(let request):
            if let bridge { Task { await bridge.handle(request) } }
        case .event(let event):
            continuation.yield(event)
        case .skip:
            break
        }
    }

    // MARK: - Mac bridge (A2b)

    /// `POST /v1/bridge/{id}`: the app's answer to one pending bridge call.
    /// Returns the raw status so the handler can drop a `404`/`409` replay.
    public func postBridgeAnswer(id: String, body: Data) async throws -> Int {
        let path = "/v1/bridge/\(Self.encodedPath(id))"
        let req = try request("POST", path, body: body)
        do {
            let (_, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                throw AuxdError.transport("no HTTP response")
            }
            return http.statusCode
        } catch let error as AuxdError {
            throw error
        } catch {
            throw AuxdError.transport(error.localizedDescription)
        }
    }

    /// `GET /v1/documents/{sha256}/bytes`: the registry bytes for `vision.ocr`.
    public func documentBytes(sha256: String) async throws -> Data {
        // The hash is validated before any URL is built, so a bad value can
        // never reach the network.
        guard BridgeSHA256.isValid(sha256) else { throw AuxdError.badURL }
        let path = "/v1/documents/\(Self.encodedPath(sha256))/bytes"
        var req = try request("GET", path)
        req.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                throw AuxdError.transport("no HTTP response")
            }
            guard (200..<300).contains(http.statusCode) else {
                if http.statusCode == 401 { throw AuxdError.unauthorized }
                throw AuxdError.http(status: http.statusCode, body: "")
            }
            return data
        } catch let error as AuxdError {
            throw error
        } catch {
            throw AuxdError.transport(error.localizedDescription)
        }
    }

    // MARK: - Documents extraction bridge (C2c)

    /// `GET /v1/docs/extract/pending?limit=N`: claim up to N documents. The
    /// answer is `{hash, mime, size}` only — never a name and never a body.
    public func pendingDocuments(limit: Int) async throws -> [PendingDocument] {
        let clamped = max(1, min(limit, 256))
        let path = "/v1/docs/extract/pending?limit=\(clamped)"
        return try await perform(request("GET", path), as: [PendingDocument].self)
    }

    /// `GET /v1/docs/{hash}/blob`: the original bytes, only while the document
    /// is claimed. The hash is validated before any URL is built, and the body
    /// is capped at `DocumentExtractor.maxInputBytes` (header first, then the
    /// stream) so an oversize blob is refused before it is buffered.
    public func documentBlob(sha256: String) async throws -> Data {
        guard BridgeSHA256.isValid(sha256) else { throw AuxdError.badURL }
        let path = "/v1/docs/\(Self.encodedPath(sha256))/blob"
        var req = try request("GET", path)
        req.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
        let task = session.dataTask(with: req)
        return try await CappedBlobDelegate(limit: DocumentExtractor.maxInputBytes).fetch(task)
    }

    /// `POST /v1/docs/{hash}/extraction` with `{extractor, text, pages}`. The
    /// daemon parses the fields and caps the text at 1 MiB.
    public func postExtraction(
        sha256: String, extractor: ExtractionKind, text: String, pages: Int
    ) async throws {
        guard BridgeSHA256.isValid(sha256) else { throw AuxdError.badURL }
        struct Body: Encodable {
            let extractor: String
            let text: String
            let pages: Int
        }
        struct Ack: Decodable {
            let documentId: Int
            enum CodingKeys: String, CodingKey { case documentId = "document_id" }
        }
        let body = try JSONEncoder().encode(
            Body(extractor: extractor.rawValue, text: text, pages: pages))
        let path = "/v1/docs/\(Self.encodedPath(sha256))/extraction"
        let _: Ack = try await perform(request("POST", path, body: body), as: Ack.self)
    }
}

// MARK: - TeamClient (E2 shell)

extension AuxdClient: TeamClient {
    private struct Empty: Decodable {}
    private struct NoBody: Encodable {}

    /// An auxd without the route (404) holds no answers, as outside Private mode.
    public func privateAnswers() async throws -> [PrivateAnswer] {
        do {
            return try await perform(request("GET", "/v1/private/answers"), as: [PrivateAnswer].self)
        } catch AuxdError.http(status: 404, _) {
            return []
        }
    }

    /// A 204 has no body, so the answer is not decoded.
    public func dismissPrivateAnswer(id: String) async throws {
        _ = try await send(request("POST", "/v1/private/answers/\(Self.encodedPath(id))/dismiss"))
    }

    public func delegations(thread: String) async throws -> [Delegation] {
        try await perform(request("GET", "/v1/delegations?thread=\(Self.encodedQuery(thread))"), as: [Delegation].self)
    }

    public func stopDelegation(id: String) async throws {
        _ = try await post("/v1/delegations/\(Self.encodedPath(id))/stop", NoBody(), as: Empty.self)
    }

    public func resumeDelegation(id: String) async throws {
        _ = try await post("/v1/delegations/\(Self.encodedPath(id))/resume", NoBody(), as: Empty.self)
    }

    public func coverage() async throws -> CoverageResponse {
        try await perform(request("GET", "/v1/privacy/coverage"), as: CoverageResponse.self)
    }

    public func ledger(limit: Int) async throws -> [LedgerEntry] {
        try await perform(request("GET", "/v1/activity?limit=\(max(1, min(limit, 200)))"), as: [LedgerEntry].self)
    }

    public func plannedJobs() async throws -> [PlannedJob] {
        try await perform(request("GET", "/v1/jobs"), as: [PlannedJob].self)
    }

    public func usageToday() async throws -> UsageDay {
        try await perform(request("GET", "/v1/usage"), as: UsageDay.self)
    }

    public func providerList() async throws -> [ProviderSummary] {
        try await providers()
    }

    public func addProvider(_ request: CreateProviderRequest) async throws {
        _ = try await saveProvider(request)
    }

    public func testProvider(id: String) async throws -> ProviderTest {
        try await post("/v1/providers/\(Self.encodedPath(id))/test", NoBody(), as: ProviderTest.self)
    }

    public func skillList() async throws -> [LocalSkill] {
        try await skills()
    }

    public func stopAll() async throws {
        _ = try await post("/v1/stop-all", NoBody(), as: Empty.self)
    }

    public func resumeAll() async throws {
        _ = try await post("/v1/resume", NoBody(), as: Empty.self)
    }

    public func setAgentPaused(_ name: String, paused: Bool) async throws {
        let path = "/v1/agents/\(Self.encodedPath(name))/\(paused ? "pause" : "resume")"
        _ = try await post(path, NoBody(), as: Empty.self)
    }

    public func grants(agent: String) async throws -> AgentGrants {
        try await perform(request("GET", "/v1/agents/\(Self.encodedPath(agent))/grants"), as: AgentGrants.self)
    }

    public func memory(agent: String) async throws -> [MemoryItem] {
        try await perform(request("GET", "/v1/agents/\(Self.encodedPath(agent))/memory"), as: [MemoryItem].self)
    }

    public func forget(agent: String, item: String) async throws {
        let path = "/v1/agents/\(Self.encodedPath(agent))/memory/\(Self.encodedPath(item))"
        _ = try await perform(request("DELETE", path), as: Empty.self)
    }

    public func clients() async throws -> [ClientSummary] {
        try await perform(request("GET", "/v1/clients"), as: [ClientSummary].self)
    }

    public func client(id: Int64) async throws -> ClientCard {
        try await perform(request("GET", "/v1/clients/\(id)"), as: ClientCard.self)
    }

    public func updateClient(id: Int64, _ edit: ClientEdit) async throws -> ClientCard {
        let data = try JSONEncoder().encode(edit)
        return try await perform(request("PUT", "/v1/clients/\(id)", body: data), as: ClientCard.self)
    }

    public func forgetClientMemory(client: Int64, item: Int64) async throws {
        _ = try await perform(request("DELETE", "/v1/clients/\(client)/memory/\(item)"), as: Empty.self)
    }

    public func importContacts(path: String, dryRun: Bool, tag: String?, country: String?) async throws -> ContactsImportAnswer {
        let body = try JSONEncoder().encode(ContactsImportRequest(path: path, dryRun: dryRun, tag: tag, country: country))
        return try await perform(request("POST", "/v1/contacts/import", body: body), as: ContactsImportAnswer.self)
    }

    /// `GET /v1/brief/today`: today's stored brief. Nil when none is written
    /// yet, which is also what a 404 means (an auxd without the route yet) and
    /// an empty body. A 401 or any other failure is thrown as usual.
    public func todayBrief() async throws -> DailyBrief? {
        do {
            let data = try await send(request("GET", "/v1/brief/today"))
            guard !data.isEmpty else { return nil }
            return try Self.decodeBody(DailyBrief.self, from: data)
        } catch AuxdError.http(status: 404, _) {
            return nil
        }
    }

    public func runBrief() async throws -> BriefRun {
        try await perform(request("POST", "/v1/brief/run"), as: BriefRun.self)
    }

    public func resolveProspect(account: String, email: String, add: Bool) async throws -> ProspectOutcome {
        struct Body: Encodable { let account: String; let email: String }
        struct Answer: Decodable {
            let status: String
            var party_id: Int64?
        }
        let path = "/v1/brief/prospects/\(add ? "add" : "ignore")"
        do {
            let answer = try await post(path, Body(account: account, email: email), as: Answer.self)
            if answer.status == "added", let id = answer.party_id { return .added(partyID: id) }
            return .ignored
        } catch AuxdError.http(status: 404, _) {
            return .gone
        }
    }
}

extension AuxdClient: MemoryClient {
    /// `GET /v1/agents/{id}/memory/view`: the sections and the suggestions.
    public func memorySnapshot(agent: String) async throws -> MemorySnapshot {
        let path = "/v1/agents/\(Self.encodedPath(agent))/memory/view"
        return try await perform(request("GET", path), as: MemorySnapshot.self)
    }

    /// `PATCH /v1/agents/{id}/memory/{item}` with `{"text": …}`. The daemon
    /// supersedes the old fact and answers the new one.
    public func updateMemory(agent: String, item: String, text: String) async throws -> MemoryFact {
        struct Body: Encodable { let text: String }
        let data = try JSONEncoder().encode(Body(text: text))
        let path = "/v1/agents/\(Self.encodedPath(agent))/memory/\(Self.encodedPath(item))"
        return try await perform(request("PATCH", path, body: data), as: MemoryFact.self)
    }

    /// `DELETE /v1/agents/{id}/memory/{item}`.
    public func forgetMemory(agent: String, item: String) async throws {
        let path = "/v1/agents/\(Self.encodedPath(agent))/memory/\(Self.encodedPath(item))"
        _ = try await perform(request("DELETE", path), as: Empty.self)
    }

    /// `POST /v1/agents/{id}/memory/suggestions/{id}/accept` — the new fact.
    public func acceptMemorySuggestion(agent: String, suggestion: String) async throws -> MemoryFact {
        let path = "/v1/agents/\(Self.encodedPath(agent))/memory/suggestions/\(Self.encodedPath(suggestion))/accept"
        return try await perform(request("POST", path, body: Data("{}".utf8)), as: MemoryFact.self)
    }

    /// `POST /v1/agents/{id}/memory/suggestions/{id}/reject` — 204, no body.
    public func rejectMemorySuggestion(agent: String, suggestion: String) async throws {
        let path = "/v1/agents/\(Self.encodedPath(agent))/memory/suggestions/\(Self.encodedPath(suggestion))/reject"
        _ = try await send(request("POST", path, body: Data("{}".utf8)))
    }
}

extension AuxdClient: CalendarStatusClient {
    /// How fresh auxd's calendar copy is (CAL-PAGE-1); capture facts only.
    public func calendarStatus() async throws -> CalendarSyncStatus {
        try await perform(request("GET", "/v1/apple-eventkit/status"), as: CalendarSyncStatus.self)
    }
}

extension AuxdClient: DocumentsClient {
    /// `GET /v1/docs` (M5-1): fields, client and status only, newest 500.
    public func documents(_ filter: DocumentsFilter) async throws -> [DocumentRow] {
        try await perform(request("GET", "/v1/docs?limit=500\(filter.query)"), as: [DocumentRow].self)
    }

    /// `POST /v1/docs/{hash-prefix}/party?party=ID|none` (M5-1b).
    public func linkDocument(hash: String, client: Int64?) async throws {
        let party = client.map(String.init) ?? "none"
        _ = try await send(request("POST", "/v1/docs/\(Self.encodedPath(hash))/party?party=\(party)"))
    }

    /// `POST /v1/docs/export` (M5-2): the CSV and originals, in a new folder inside `out`.
    public func exportDocuments(_ export: DocumentsExport) async throws -> DocumentsExportResult {
        struct Answer: Decodable { let status: String; var folder: String?; var rows: Int?; var missing: Int? }
        let query = export.queryItems.map { "\($0.name)=\(Self.encodedQuery($0.value ?? ""))" }.joined(separator: "&")
        let answer = try await perform(request("POST", "/v1/docs/export?\(query)"), as: Answer.self)
        guard answer.status == "written", let folder = answer.folder else { return .empty }
        return .written(folder: folder, rows: answer.rows ?? 0, missing: answer.missing ?? 0)
    }
}
