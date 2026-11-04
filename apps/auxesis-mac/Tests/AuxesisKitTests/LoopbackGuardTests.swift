// The bearer token must never be sent off-box.
//
// Two layers, both tested here:
//   * the resolver refuses every non-loopback/malformed override and falls back
//     to the default with a friendly, host-only rejection notice;
//   * the client re-checks the final request URL before attaching the token,
//     refuses redirects (a real loopback server answers 302 to a second local
//     port, which must never be contacted), and refuses a non-loopback WS.
import Darwin
import Testing
@testable import AuxesisKit

// MARK: - Real loopback HTTP server (redirect test)

/// A one-request-at-a-time HTTP server on 127.0.0.1:0. No TLS, no keep-alive;
/// enough to prove a redirect is (not) followed.
final class TinyHTTPServer: @unchecked Sendable {
    let port: UInt16
    private let listenFD: Int32
    private let lock = NSLock()
    private var handled: [String] = []
    private var responder: ((String) -> String)?
    private var acceptThread: Thread?

    init?() {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(fd, 8) == 0 else {
            close(fd)
            return nil
        }
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &actual) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        guard named == 0 else {
            close(fd)
            return nil
        }
        self.port = UInt16(bigEndian: actual.sin_port)
        self.listenFD = fd
    }

    var requests: [String] { lock.withLock { handled } }

    func start(_ responder: @escaping (String) -> String) {
        self.responder = responder
        let thread = Thread { [weak self] in self?.acceptLoop() }
        acceptThread = thread
        thread.start()
    }

    func stop() {
        close(listenFD)
    }

    private func acceptLoop() {
        while true {
            var clientAddr = sockaddr()
            var length = socklen_t(MemoryLayout<sockaddr>.size)
            let clientFD = accept(listenFD, &clientAddr, &length)
            if clientFD < 0 { break }
            var buffer = [UInt8](repeating: 0, count: 8192)
            let count = recv(clientFD, &buffer, buffer.count, 0)
            if count > 0 {
                let request = String(decoding: buffer[0..<Int(count)], as: UTF8.self)
                lock.withLock { handled.append(request) }
                let head = request.split(separator: "\r\n", maxSplits: 1).first.map(String.init) ?? ""
                let response = responder?(head)
                    ?? "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                _ = response.withCString { send(clientFD, $0, strlen($0), 0) }
            }
            close(clientFD)
        }
    }
}

// MARK: - URLProtocol mock (token path, no packets)

/// Records every request a URLSession actually attempted.
final class RecordingURLProtocol: URLProtocol {
    struct Record: Equatable {
        let url: String
        let host: String?
        let method: String
        let authorization: String?
        let language: String?
    }

    nonisolated(unsafe) private static var _records: [Record] = []
    nonisolated(unsafe) private static var responder: ((URLRequest) -> (HTTPURLResponse, Data))?
    private static let lock = NSLock()

    static func reset() {
        lock.withLock {
            _records = []
            responder = nil
        }
    }

    static var recorded: [Record] { lock.withLock { _records } }

    static func respond(_ responder: @escaping (URLRequest) -> (HTTPURLResponse, Data)) {
        lock.withLock { self.responder = responder }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let record = Record(
            url: request.url?.absoluteString ?? "",
            host: request.url?.host,
            method: request.httpMethod ?? "GET",
            authorization: request.value(forHTTPHeaderField: "Authorization"),
            language: request.value(forHTTPHeaderField: "X-Auxesis-Lang")
        )
        Self.lock.withLock { Self._records.append(record) }
        guard let (response, data) = Self.responder?(request) else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// Thread-safe async result capture for `@MainActor` tests.
final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Result<Any, Error>?

    var result: Result<Any, Error>? { lock.withLock { stored } }

    func set(_ result: Result<Any, Error>) { lock.withLock { stored = result } }
}

// MARK: - Tests

@objcMembers @MainActor final class LoopbackGuardTests: XCTestCase {
    private func tempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-loopback-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func endpoint(baseURL: URL, home: URL, token: String? = "deadbeef") throws -> AuxdEndpoint {
        let tokenFile = home.appendingPathComponent("api.token")
        if let token {
            try Data(token.utf8).write(to: tokenFile)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenFile.path)
        }
        return AuxdEndpoint(baseURL: baseURL, home: home, tokenFile: tokenFile, lockPID: nil, source: "test")
    }

    private func makeClient(_ endpoint: AuxdEndpoint, mock: Bool = true) -> AuxdClient {
        let config = URLSessionConfiguration.ephemeral
        if mock { config.protocolClasses = [RecordingURLProtocol.self] }
        return AuxdClient(endpoint: endpoint, requestTimeout: 5, configuration: config)
    }

    /// Runs an async operation, spinning the main run loop until it finishes.
    private func run<T>(_ operation: @escaping () async throws -> T) -> Result<T, Error>? {
        let box = ResultBox()
        Task {
            do { box.set(.success(try await operation())) }
            catch { box.set(.failure(error)) }
        }
        return waitUntil { box.result != nil } ? box.result.map { $0.map { $0 as! T } } : nil
    }

    // MARK: Resolver: refused overrides fall back to the documented default

    func testEveryOffLoopbackOverrideIsRefusedWithAHostOnlyNotice() throws {
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let tricks = [
            "http://127.0.0.1@evil.work",           // userinfo trick
            "http://user:pw@localhost:2893",        // credentials + loopback name
            "http://localhost.evil.com",            // suffix trick
            "http://127.0.0.1.evil.com",            // suffix trick, bare IP
            "http://localhost.",                    // trailing agent
            "http://127.0.0.1.:2893",               // trailing agent + port
            "http://ⅼocalhost:2893",                // IDN lookalike (URL normalises it)
            "http://0x7f.1",                        // hex IP
            "http://2130706433",                    // decimal IP
            "http://[::ffff:127.0.0.1]:2893",       // IPv4-mapped IPv6
            "http://[::1%25lo0]:2893",              // IPv6 zone id
            "http://[::0001]:2893",                 // non-canonical IPv6
            "http://127.0.0.1%2eevil.com:2893",     // percent-encoded host
            "http://127.0.0.1:0",                   // port 0
            "http://127.0.0.1:65536",               // port above range
            "http://127.0.0.1:99999",
            "http://127.0.0.1:02893",               // leading-zero port
            "http://127.0.0.1:",                    // empty port
            "http://127.0.0.1:2893:4",              // double colon
            "http://127.0.0.1:2893/path",           // path beyond /
            "http://127.0.0.1:2893/../junk",        // traversal
            "http://127.0.0.1:2893?x=1",            // query
            "http://127.0.0.1:2893#frag",           // fragment
            "http://127.0.0.1:2893 trailing",       // junk
            "http://127.0.0.1:2893\tjunk",          // hidden junk
            "https://127.0.0.1:2893",               // scheme
            "ftp://127.0.0.1:2893",
            "ws://localhost.evil.com:2893",
            "https://relay.tailnet.example:2893",
        ]
        let fallback = "http://127.0.0.1:2893"
        for trick in tricks {
            let endpoint = EndpointResolver.resolve(
                env: ["AUXESIS_API_BASE": trick],
                homeDirectory: home
            )
            XCTAssertEqual(endpoint.baseURL?.absoluteString, fallback, "must refuse \(trick)")
            XCTAssertNil(LoopbackURL.parse(trick), "parse must refuse \(trick)")
            XCTAssertEqual(endpoint.rejectedOverride?.source, "AUXESIS_API_BASE", trick)
            let notice = OfflinePresentation.overrideNotice(endpoint.rejectedOverride!, language: .en)
            XCTAssertTrue(notice.contains("AUXESIS_API_BASE"), trick)
            if !fallback.hasPrefix(trick) {
                XCTAssertFalse(notice.contains(trick), "never echo the whole refused value: \(trick)")
            }
        }
    }

    func testUserinfoTrickNoticeNamesTheRealHostOnly() throws {
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = EndpointResolver.resolve(
            env: ["AUXESIS_API_BASE": "http://127.0.0.1@evil.work/secret?tok=1"],
            homeDirectory: home
        )
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:2893")
        XCTAssertEqual(endpoint.rejectedOverride?.host, "evil.work")
        let notice = OfflinePresentation.overrideNotice(endpoint.rejectedOverride!, language: .en)
        XCTAssertTrue(notice.contains("evil.work"))
        XCTAssertFalse(notice.contains("127.0.0.1@"))
        XCTAssertFalse(notice.contains("secret"))
        XCTAssertFalse(notice.contains("tok=1"))
    }

    func testApiEnvIsAlsoRefusedAndFallsBack() throws {
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = EndpointResolver.resolve(
            env: ["AUXESIS_API": "https://relay.tailnet.example"],
            homeDirectory: home
        )
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:2893")
        XCTAssertEqual(endpoint.rejectedOverride?.source, "AUXESIS_API")
        // A refused override never silently falls through to the port override.
        let withPort = EndpointResolver.resolve(
            env: ["AUXESIS_API": "https://relay.tailnet.example", "AUXESIS_API_PORT": "4123"],
            homeDirectory: home
        )
        XCTAssertEqual(withPort.baseURL?.absoluteString, "http://127.0.0.1:2893")
        XCTAssertEqual(withPort.rejectedOverride?.source, "AUXESIS_API")
    }

    func testAcceptedLoopbackFormsAreCanonicalised() {
        let accepted: [(String, String)] = [
            ("http://127.0.0.1:2893", "http://127.0.0.1:2893"),
            ("http://127.0.0.1:2893/", "http://127.0.0.1:2893"),
            ("ws://127.0.0.1:5555", "ws://127.0.0.1:5555"),
            ("http://localhost:5555", "http://localhost:5555"),
            ("HTTP://LOCALHOST:5555", "http://localhost:5555"),
            ("http://[::1]:5555", "http://[::1]:5555"),
            ("http://127.0.0.1:65535", "http://127.0.0.1:65535"),
            ("http://127.0.0.1", "http://127.0.0.1"),
        ]
        for (raw, expected) in accepted {
            XCTAssertEqual(LoopbackURL.parse(raw)?.absoluteString, expected, raw)
        }
        XCTAssertFalse(LoopbackURL.isSafeRequestURL(URL(string: "http://evil.work/")!))
        XCTAssertFalse(LoopbackURL.isSafeRequestURL(URL(string: "https://127.0.0.1/")!))
        XCTAssertFalse(LoopbackURL.isSafeRequestURL(URL(string: "http://[::ffff:127.0.0.1]/")!))
        XCTAssertTrue(LoopbackURL.isSafeRequestURL(URL(string: "http://127.0.0.1:2893/v1/health")!))
        XCTAssertTrue(LoopbackURL.isSafeRequestURL(URL(string: "ws://[::1]:2893/v1/events")!))
    }

    // MARK: Client: request-time guard, redirects, WS

    func testNonLoopbackEndpointIsRefusedBeforeTheTokenIsAttached() throws {
        RecordingURLProtocol.reset()
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(
            baseURL: URL(string: "http://evil.work:8080")!,
            home: home,
            token: "deadbeef"
        )
        let client = makeClient(endpoint)
        guard let result = run({ try await client.health() }) else { return XCTFail("no result") }
        guard case .failure(let error) = result else { return XCTFail("a remote endpoint must fail") }
        XCTAssertEqual(error as? AuxdError, .offLoopback)
        XCTAssertTrue(RecordingURLProtocol.recorded.isEmpty, "no request, so no token, ever")
    }

    func testLoopbackRequestAttachesTheTokenToTheDaemonOnly() throws {
        RecordingURLProtocol.reset()
        RecordingURLProtocol.respond { request in
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil
            )!
            return (response, Data(#"{"ok":true,"version":"0.1.0","pid":1,"first_run":false}"#.utf8))
        }
        defer { RecordingURLProtocol.reset() }
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(baseURL: URL(string: "http://127.0.0.1:2893")!, home: home)
        let client = makeClient(endpoint)
        guard let result = run({ try await client.health() }) else { return XCTFail("no result") }
        if case .failure(let error) = result { XCTFail("expected success, got \(error)") }
        XCTAssertEqual(RecordingURLProtocol.recorded.count, 1)
        let record = RecordingURLProtocol.recorded[0]
        XCTAssertEqual(record.host, "127.0.0.1")
        XCTAssertEqual(record.authorization, "Bearer deadbeef")
    }

    /// Every request carries the owner's language so the service can answer in
    /// it once it learns to; an older service ignores the extra header.
    func testEveryRequestCarriesTheLanguageHeader() throws {
        RecordingURLProtocol.reset()
        RecordingURLProtocol.respond { request in
            let response = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil
            )!
            return (response, Data(#"{"ok":true,"version":"0.1.0","pid":1,"first_run":false}"#.utf8))
        }
        defer { RecordingURLProtocol.reset() }
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(baseURL: URL(string: "http://127.0.0.1:2893")!, home: home)
        let client = makeClient(endpoint)
        client.language = .fr
        guard let result = run({ try await client.health() }) else { return XCTFail("no result") }
        if case .failure(let error) = result { XCTFail("expected success, got \(error)") }
        XCTAssertEqual(RecordingURLProtocol.recorded.count, 1)
        XCTAssertEqual(RecordingURLProtocol.recorded[0].language, "fr")

        client.language = .en
        guard let second = run({ try await client.health() }) else { return XCTFail("no result") }
        if case .failure(let error) = second { XCTFail("expected success, got \(error)") }
        XCTAssertEqual(RecordingURLProtocol.recorded.count, 2)
        XCTAssertEqual(RecordingURLProtocol.recorded[1].language, "en")
    }

    func testRedirectToAnotherLoopbackPortIsNeverFollowed() throws {
        guard let daemon = TinyHTTPServer(), let sink = TinyHTTPServer() else {
            return XCTFail("could not start loopback test servers")
        }
        defer { daemon.stop(); sink.stop() }
        daemon.start { _ in
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:\(sink.port)/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        sink.start { _ in
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        }
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(baseURL: URL(string: "http://127.0.0.1:\(daemon.port)")!, home: home)
        let client = makeClient(endpoint, mock: false)
        guard let result = run({ try await client.health() }) else { return XCTFail("no result") }
        guard case .failure(let error) = result else { return XCTFail("a 302 must surface as an error") }
        XCTAssertEqual(error as? AuxdError, .http(status: 302, body: ""))
        XCTAssertEqual(daemon.requests.count, 1, "exactly one request reached the daemon")
        XCTAssertTrue(daemon.requests[0].contains("Bearer deadbeef"))
        XCTAssertTrue(sink.requests.isEmpty, "the redirect target must never be contacted")
    }

    func testRedirectToARemoteHostIsRefusedWithoutConnecting() throws {
        guard let daemon = TinyHTTPServer() else {
            return XCTFail("could not start loopback test server")
        }
        defer { daemon.stop() }
        // TEST-NET-1 (RFC 5737), non-routable: if the redirect were followed
        // the connect would hang/fail instead of the 302 coming back at once.
        daemon.start { _ in
            "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1:9/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(baseURL: URL(string: "http://127.0.0.1:\(daemon.port)")!, home: home)
        let client = makeClient(endpoint, mock: false)
        let started = Date()
        guard let result = run({ try await client.health() }) else { return XCTFail("no result") }
        guard case .failure(let error) = result else { return XCTFail("a 302 must surface as an error") }
        XCTAssertEqual(error as? AuxdError, .http(status: 302, body: ""))
        XCTAssertLessThan(Date().timeIntervalSince(started), 2, "the remote target must never be contacted")
        XCTAssertEqual(daemon.requests.count, 1)
    }

    func testWebSocketHandshakeRefusesANonLoopbackHost() throws {
        RecordingURLProtocol.reset()
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(baseURL: URL(string: "http://evil.work:8080")!, home: home)
        let client = makeClient(endpoint)
        XCTAssertThrowsError(try client.events()) { error in
            XCTAssertEqual(error as? AuxdError, .offLoopback)
        }
        XCTAssertTrue(RecordingURLProtocol.recorded.isEmpty, "no WS handshake, so no token")
    }

    func testBrokenTokenFileMeansHonestOfflineAndNoRequest() throws {
        RecordingURLProtocol.reset()
        let home = try tempDir()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = try endpoint(baseURL: URL(string: "http://127.0.0.1:2893")!, home: home, token: nil)
        let client = makeClient(endpoint)
        XCTAssertEqual(client.tokenProblem, .missing)
        XCTAssertEqual(client.token, "")

        // HTTP: fails on the token before any packet.
        guard let result = run({ try await client.health() }) else { return XCTFail("no result") }
        guard case .failure(let error) = result else { return XCTFail("missing token must fail") }
        XCTAssertEqual(error as? AuxdError, .token(.missing))
        XCTAssertTrue(RecordingURLProtocol.recorded.isEmpty)

        // Store + real client: the honest offline screen, never `Bearer `.
        let store = Store(transport: client, endpoint: endpoint)
        store.start()
        XCTAssertTrue(waitUntil { store.connection != .connecting })
        XCTAssertEqual(store.offlineCause, .tokenMissing)
        if case .offline(let reason) = store.connection {
            XCTAssertFalse(reason.isEmpty)
        } else {
            XCTFail("expected offline, got \(store.connection)")
        }
        XCTAssertTrue(RecordingURLProtocol.recorded.isEmpty, "no request may carry an empty Bearer")
        store.stop()
    }
}
