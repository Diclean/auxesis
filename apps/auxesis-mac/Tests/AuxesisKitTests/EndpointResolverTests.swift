// Where the app looks for auxd: env overrides, config.toml, default; and the
// token path under AUXESIS_HOME. No test ever touches the real HOME.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class EndpointResolverTests: XCTestCase {
    private func tempHome() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-endpoint-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func testDefaultIsTheDocumentedLoopbackEndpoint() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = EndpointResolver.resolve(env: [:], homeDirectory: home)
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:2893")
        XCTAssertEqual(endpoint.home.path, home.appendingPathComponent(".auxesis").path)
        XCTAssertEqual(endpoint.tokenFile.lastPathComponent, "api.token")
        XCTAssertTrue(endpoint.source.contains("default"))
        XCTAssertNil(endpoint.lockPID)
    }

    func testApiBaseWinsAndIsNormalized() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = EndpointResolver.resolve(
            env: ["AUXESIS_API_BASE": "http://127.0.0.1:5555/"],
            homeDirectory: home
        )
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:5555")
        XCTAssertEqual(endpoint.source, "AUXESIS_API_BASE")
    }

    func testApiEnvIsTheCliConvention() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = EndpointResolver.resolve(
            env: ["AUXESIS_API": "http://127.0.0.1:4444"],
            homeDirectory: home
        )
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:4444")
        XCTAssertEqual(endpoint.source, "AUXESIS_API")
    }

    func testPortEnvIsUsedWhenNoFullUrl() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = EndpointResolver.resolve(
            env: ["AUXESIS_API_PORT": "4123"],
            homeDirectory: home
        )
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:4123")
        XCTAssertEqual(endpoint.source, "AUXESIS_API_PORT")
    }

    func testPortZeroAndInvalidPortMeanNoEndpoint() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        for raw in ["0", "not-a-port", "99999"] {
            let endpoint = EndpointResolver.resolve(env: ["AUXESIS_API_PORT": raw], homeDirectory: home)
            XCTAssertNil(endpoint.baseURL, "port \(raw) must not become the default 2893")
            XCTAssertFalse(endpoint.hasEndpoint, "port \(raw)")
        }
        let zero = EndpointResolver.resolve(env: ["AUXESIS_API_PORT": "0"], homeDirectory: home)
        XCTAssertTrue(zero.source.contains("no endpoint"), zero.source)
    }

    // MARK: - Sandbox (J-02 round 4)

    func testSandboxRefusesApiUrlsAndDefaultPort() throws {
        let home = try tempHome()
        let real = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: real)
        }
        let endpoint = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": home.path,
                "AUXESIS_HOME": home.appendingPathComponent(".auxesis").path,
                "AUXESIS_API": "http://127.0.0.1:2893",
            ],
            homeDirectory: home,
            realHomeDirectory: real
        )
        XCTAssertNil(endpoint.baseURL, "AUXESIS_API must be refused while sandboxed")
        XCTAssertEqual(endpoint.rejectedOverride?.source, "AUXESIS_API")
        let port = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": home.path,
                "AUXESIS_HOME": home.appendingPathComponent(".auxesis").path,
                "AUXESIS_API_PORT": "2893",
            ],
            homeDirectory: home,
            realHomeDirectory: real
        )
        XCTAssertNil(port.baseURL, "the real daemon port must be refused")
        XCTAssertEqual(port.rejectedOverride?.source, "AUXESIS_API_PORT")
    }

    func testSandboxPortZeroMeansNoEndpointAndExplicitPortIsUsed() throws {
        let home = try tempHome()
        let real = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: real)
        }
        let none = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": home.path,
                "AUXESIS_HOME": home.appendingPathComponent(".auxesis").path,
                "AUXESIS_API_PORT": "0",
            ],
            homeDirectory: home,
            realHomeDirectory: real
        )
        XCTAssertNil(none.baseURL)
        XCTAssertTrue(none.source.contains("no endpoint"), none.source)

        let explicit = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": home.path,
                "AUXESIS_HOME": home.appendingPathComponent(".auxesis").path,
                "AUXESIS_API_PORT": "4123",
            ],
            homeDirectory: home,
            realHomeDirectory: real
        )
        XCTAssertEqual(explicit.baseURL?.absoluteString, "http://127.0.0.1:4123")
        XCTAssertEqual(explicit.source, "AUXESIS_API_PORT")
    }

    func testSandboxIgnoresAuxesisHomeOutsideTheSandboxHome() throws {
        let home = try tempHome()
        let real = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: real)
        }
        let outside = real.appendingPathComponent(".auxesis", isDirectory: true)
        let endpoint = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": home.path,
                "AUXESIS_HOME": outside.path,
                "AUXESIS_API_PORT": "0",
            ],
            homeDirectory: home,
            realHomeDirectory: real
        )
        XCTAssertEqual(endpoint.home.path, home.appendingPathComponent(".auxesis").path)
        XCTAssertNil(endpoint.baseURL)
    }

    func testAHomeDifferentFromThePasswdHomeIsSandboxed() throws {
        let home = try tempHome()
        let real = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: real)
        }
        let endpoint = EndpointResolver.resolve(
            env: ["HOME": home.path, "AUXESIS_API": "http://127.0.0.1:2893"],
            homeDirectory: home,
            realHomeDirectory: real
        )
        XCTAssertNil(endpoint.baseURL, "a HOME override arms the sandbox rules")
    }

    func testConfigPortIsReadTolerantly() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let auxHome = home.appendingPathComponent(".auxesis", isDirectory: true)
        try FileManager.default.createDirectory(at: auxHome, withIntermediateDirectories: true)
        try Data("# api_port = 1\napi_port = 4321\n".utf8)
            .write(to: auxHome.appendingPathComponent("config.toml"))
        let endpoint = EndpointResolver.resolve(env: [:], homeDirectory: home)
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:4321")
        XCTAssertTrue(endpoint.source.contains("config.toml"))
    }

    func testAuxesisHomeEnvWins() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let custom = home.appendingPathComponent("sandbox")
        let endpoint = EndpointResolver.resolve(
            env: ["AUXESIS_HOME": custom.path],
            homeDirectory: home
        )
        XCTAssertEqual(endpoint.home.path, custom.path)
        XCTAssertEqual(endpoint.tokenFile.path, custom.appendingPathComponent("api.token").path)
    }

    func testLockPidIsDiagnosticOnly() throws {
        let home = try tempHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let auxHome = home.appendingPathComponent(".auxesis", isDirectory: true)
        try FileManager.default.createDirectory(at: auxHome, withIntermediateDirectories: true)
        try Data("4242\n".utf8).write(to: auxHome.appendingPathComponent("auxd.lock"))
        let endpoint = EndpointResolver.resolve(env: [:], homeDirectory: home)
        XCTAssertEqual(endpoint.lockPID, 4242)
        // The lock has no port: the base URL stays the default.
        XCTAssertEqual(endpoint.baseURL?.absoluteString, "http://127.0.0.1:2893")
    }

    // MARK: - Sandbox home comes from the environment (security review P1, J-02 r6)

    /// The security review's exact repro: Foundation keeps returning the real home even when
    /// HOME is overridden. The sandbox home must come from env HOME /
    /// AUXESIS_HOME, and a fake real token must never be read.
    func testSandboxHomeComesFromEnvAndNeverFoundation() throws {
        let fakeReal = try tempHome()
        let sandbox = try tempHome()
        let auxHome = sandbox.appendingPathComponent(".auxesis", isDirectory: true)
        try FileManager.default.createDirectory(at: auxHome, withIntermediateDirectories: true)
        // A decoy token in the fake real home that must never be read.
        let realAux = fakeReal.appendingPathComponent(".auxesis", isDirectory: true)
        try FileManager.default.createDirectory(at: realAux, withIntermediateDirectories: true)
        let realToken = realAux.appendingPathComponent("api.token")
        try Data("real-secret-token".utf8).write(to: realToken)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: realToken.path)
        defer {
            try? FileManager.default.removeItem(at: fakeReal)
            try? FileManager.default.removeItem(at: sandbox)
        }

        let env = [
            "AUXESIS_SANDBOX": "1",
            "HOME": sandbox.path,
            "AUXESIS_HOME": auxHome.path,
            "AUXESIS_API_PORT": "0",
        ]
        let endpoint = EndpointResolver.resolve(
            env: env,
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertEqual(endpoint.home.path, auxHome.path)
        XCTAssertNil(endpoint.baseURL)
        XCTAssertFalse(endpoint.homeRefused)
        let client = AuxdClient(endpoint: endpoint)
        XCTAssertTrue(client.token.isEmpty, "the real token must never be read")
        XCTAssertFalse(client.token.contains("real-secret-token"))

        // With an explicit loopback port the env home is still the only home.
        var withPort = env
        withPort["AUXESIS_API_PORT"] = "4123"
        let endpoint2 = EndpointResolver.resolve(
            env: withPort,
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertEqual(endpoint2.baseURL?.absoluteString, "http://127.0.0.1:4123")
        XCTAssertEqual(endpoint2.home.path, auxHome.path)
        let client2 = AuxdClient(endpoint: endpoint2)
        XCTAssertTrue(client2.token.isEmpty, "no sandbox token exists; the real one is off-limits")
    }

    func testSandboxRefusesAuxesisHomeResolvingIntoTheOsHome() throws {
        let fakeReal = try tempHome()
        let sandbox = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: fakeReal)
            try? FileManager.default.removeItem(at: sandbox)
        }
        let realAux = fakeReal.appendingPathComponent(".auxesis", isDirectory: true)
        try FileManager.default.createDirectory(at: realAux, withIntermediateDirectories: true)
        let realToken = realAux.appendingPathComponent("api.token")
        try Data("real-secret-token".utf8).write(to: realToken)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: realToken.path)

        let endpoint = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": sandbox.path,
                "AUXESIS_HOME": realAux.path,
                "AUXESIS_API_PORT": "0",
            ],
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertTrue(endpoint.homeRefused)
        XCTAssertNil(endpoint.baseURL)
        let client = AuxdClient(endpoint: endpoint)
        XCTAssertTrue(client.token.isEmpty, "a refused home never yields a token")
    }

    func testSandboxRefusesAuxesisHomeOutsideTheSandboxHome() throws {
        let fakeReal = try tempHome()
        let sandbox = try tempHome()
        let elsewhere = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: fakeReal)
            try? FileManager.default.removeItem(at: sandbox)
            try? FileManager.default.removeItem(at: elsewhere)
        }
        let endpoint = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": sandbox.path,
                "AUXESIS_HOME": elsewhere.appendingPathComponent(".auxesis").path,
                "AUXESIS_API_PORT": "0",
            ],
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertTrue(endpoint.homeRefused)
        XCTAssertNil(endpoint.baseURL)
    }

    /// A HOME override alone (no flag) is the incident mode: same rules.
    func testHomeOverrideWithoutFlagUsesTheEnvHome() throws {
        let fakeReal = try tempHome()
        let sandbox = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: fakeReal)
            try? FileManager.default.removeItem(at: sandbox)
        }
        let endpoint = EndpointResolver.resolve(
            env: ["HOME": sandbox.path, "AUXESIS_API_PORT": "0"],
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertEqual(endpoint.home.path, sandbox.appendingPathComponent(".auxesis").path)
        XCTAssertNil(endpoint.baseURL)
    }

    // MARK: - Sandbox requires an explicit AUXESIS_HOME (security review r6 P1)

    /// The security review's repro: flag + HOME + port 4123, AUXESIS_HOME unset — the app
    /// must refuse (offline) and never read `<HOME>/.auxesis/api.token`.
    func testSandboxRequiresAuxesisHome() throws {
        let fakeReal = try tempHome()
        let sandbox = try tempHome()
        defer {
            try? FileManager.default.removeItem(at: fakeReal)
            try? FileManager.default.removeItem(at: sandbox)
        }
        // A decoy token at the derived path that must never be read.
        let derived = sandbox.appendingPathComponent(".auxesis", isDirectory: true)
        try FileManager.default.createDirectory(at: derived, withIntermediateDirectories: true)
        let derivedToken = derived.appendingPathComponent("api.token")
        try Data("derived-secret".utf8).write(to: derivedToken)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: derivedToken.path)

        let endpoint = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": sandbox.path,
                "AUXESIS_API_PORT": "4123",
            ],
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertTrue(endpoint.homeRefused)
        XCTAssertNil(endpoint.baseURL)
        let client = AuxdClient(endpoint: endpoint)
        XCTAssertTrue(client.token.isEmpty, "no AUXESIS_HOME means no token read")
    }

    /// HOME resolving into the OS-database home is refused even with a valid
    /// AUXESIS_HOME elsewhere.
    func testSandboxRefusesHomeResolvingIntoTheOsHome() throws {
        let fakeReal = try tempHome()
        let nested = fakeReal.appendingPathComponent("inside", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: fakeReal) }

        let endpoint = EndpointResolver.resolve(
            env: [
                "AUXESIS_SANDBOX": "1",
                "HOME": nested.path,
                "AUXESIS_HOME": nested.appendingPathComponent(".auxesis").path,
                "AUXESIS_API_PORT": "0",
            ],
            homeDirectory: fakeReal,
            realHomeDirectory: fakeReal
        )
        XCTAssertTrue(endpoint.homeRefused)
        XCTAssertNil(endpoint.baseURL)
    }
}
