// Where the app finds auxd: base URL + token file.
//
// Resolution order (first wins), honest about what each source can know:
//   1. AUXESIS_API_BASE  — full loopback URL, used by scripts/tests (app-specific);
//   2. AUXESIS_API       — full loopback URL, the `aux` CLI convention;
//   3. AUXESIS_API_PORT  — port on 127.0.0.1 (`0` = no endpoint);
//   4. config.toml in the Auxesis home — an optional `api_port = N` key;
//   5. the documented default: http://127.0.0.1:2893.
//
// While the sandbox guard is active
// (`AUXESIS_SANDBOX=1`, or an environment `HOME` different from the OS user
// database home) **Foundation is never trusted for the home**: macOS
// `FileManager.homeDirectoryForCurrentUser` / `NSHomeDirectory` / `getpwuid`
// keep returning the real `/Users/<me>` even when `HOME` is overridden. The
// sandbox home therefore comes from `env["HOME"]` only, `AUXESIS_HOME` must
// be inside it, and an `AUXESIS_HOME` that resolves into the OS-database home
// refuses the whole endpoint (`homeRefused`, no token read, offline screen).
// `AUXESIS_API_PORT=0` means no endpoint AND no token read.
//
// Outside a sandbox the two URL overrides are hostile input (any script can
// set them): only `LoopbackURL.parse` values are accepted; a refused override
// is surfaced as `rejectedOverride` for the Settings/offline screens. The
// bearer token must never be sent off-box.
import Foundation

#if canImport(Darwin)
import Darwin
#endif

public struct AuxdEndpoint: Equatable {
    /// Base URL, or `nil` when there is no endpoint (`AUXESIS_API_PORT=0`, a
    /// sandbox without an explicit port, or a refused home). Never connect
    /// when nil.
    public let baseURL: URL?
    public let home: URL
    public let tokenFile: URL
    /// Pid recorded in `<home>/auxd.lock`, when present.
    public let lockPID: Int32?
    /// Which rule chose `baseURL` (diagnostics; never secrets).
    public let source: String
    /// Non-nil when an override was set but refused (non-loopback /
    /// malformed / sandbox-refused).
    public let rejectedOverride: EndpointOverrideRejection?
    /// True when the sandbox refused the configured home (an `AUXESIS_HOME`
    /// resolving into the OS-database home, outside the sandbox `HOME`, or a
    /// sandbox without an environment `HOME`). The app must stay offline and
    /// must NOT read a token.
    public let homeRefused: Bool

    public init(
        baseURL: URL?,
        home: URL,
        tokenFile: URL,
        lockPID: Int32?,
        source: String,
        rejectedOverride: EndpointOverrideRejection? = nil,
        homeRefused: Bool = false
    ) {
        self.baseURL = baseURL
        self.home = home
        self.tokenFile = tokenFile
        self.lockPID = lockPID
        self.source = source
        self.rejectedOverride = rejectedOverride
        self.homeRefused = homeRefused
    }

    /// Whether the app has anywhere to connect.
    public var hasEndpoint: Bool { baseURL != nil }
}

public enum EndpointResolver {
    /// Port the auxd local API listens on by default (T9 for `auxd`).
    public static let defaultPort = 2893

    public static func resolve(
        env: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL,
        realHomeDirectory: URL? = nil,
        fileManager: FileManager = .default
    ) -> AuxdEndpoint {
        // `realHomeDirectory == nil` means "the injected home IS the OS
        // database home" (tests / non-app callers); the app passes the
        // passwd home explicitly so a sandboxed HOME is detected.
        let realHome = realHomeDirectory ?? homeDirectory
        let envHome = nonEmpty(env["HOME"]).map { URL(fileURLWithPath: $0, isDirectory: true) }

        var source = "default (port \(defaultPort))"
        var base: URL? = nil
        var rejected: EndpointOverrideRejection? = nil
        var noEndpoint = false
        var homeRefused = false
        let home: URL

        // Sandbox when the flag is set, or when the environment HOME differs
        // from the OS database home (the incident mode). Foundation's
        // `homeDirectory` is NOT a sandbox home.
        let sandboxed = nonEmpty(env["AUXESIS_SANDBOX"]) == "1"
            || (envHome.map { canonical($0) != canonical(realHome) } ?? false)

        if sandboxed {
            // The sandbox home comes from the environment only.
            guard let sandboxHome = envHome else {
                homeRefused = true
                home = homeDirectory
                noEndpoint = true
                source = "sandbox: no HOME in the environment (offline)"
                return endpoint(
                    base: nil,
                    home: home,
                    source: source,
                    rejected: rejected,
                    homeRefused: homeRefused
                )
            }
            let fallbackHome = sandboxHome.appendingPathComponent(".auxesis", isDirectory: true)
            if isUnder(sandboxHome, realHome) {
                // HOME itself resolves into the OS database home (the incident
                // mode): refuse entirely, never derive a home from it.
                homeRefused = true
                home = fallbackHome
                noEndpoint = true
                source = "sandbox: HOME resolves into the OS home (offline)"
            } else if let raw = nonEmpty(env["AUXESIS_HOME"]) {
                let custom = URL(fileURLWithPath: raw, isDirectory: true)
                if isUnder(custom, realHome) {
                    // Resolving into the OS database home: refuse entirely.
                    homeRefused = true
                    home = fallbackHome
                    noEndpoint = true
                    source = "sandbox: AUXESIS_HOME resolves into the OS home (offline)"
                } else if !isUnder(custom, sandboxHome) {
                    // Outside the sandbox HOME: refuse entirely.
                    homeRefused = true
                    home = fallbackHome
                    noEndpoint = true
                    source = "sandbox: AUXESIS_HOME is outside HOME (offline)"
                } else {
                    home = custom
                }
            } else {
                // Sandbox mode REQUIRES an explicit AUXESIS_HOME (security review r6
                // P1): never fall back to <HOME>/.auxesis.
                homeRefused = true
                home = fallbackHome
                noEndpoint = true
                source = "sandbox: AUXESIS_HOME is required (offline)"
            }

            if !homeRefused {
                // Only AUXESIS_API_PORT is trusted under the guard.
                for key in ["AUXESIS_API_BASE", "AUXESIS_API"] {
                    if let raw = nonEmpty(env[key]) {
                        rejected = EndpointOverrideRejection(
                            source: key,
                            host: LoopbackURL.displayHost(of: raw)
                        )
                    }
                }
                if let raw = nonEmpty(env["AUXESIS_API_PORT"]),
                   let port = Int(raw),
                   (0...65535).contains(port) {
                    if port == 0 {
                        source = "AUXESIS_API_PORT=0 (no endpoint)"
                        noEndpoint = true
                    } else if port == defaultPort {
                        rejected = EndpointOverrideRejection(
                            source: "AUXESIS_API_PORT",
                            host: "127.0.0.1:\(port)"
                        )
                        source = "AUXESIS_API_PORT refused (real daemon port)"
                        noEndpoint = true
                    } else {
                        base = URL(string: "http://127.0.0.1:\(port)")
                        source = "AUXESIS_API_PORT"
                    }
                } else {
                    source = "sandboxed: no endpoint (set AUXESIS_API_PORT)"
                    noEndpoint = true
                }
            }
        } else {
            home = auxesisHome(env: env, homeDirectory: homeDirectory, sandboxed: false)
            if let raw = nonEmpty(env["AUXESIS_API_BASE"]) {
                if let url = LoopbackURL.parse(raw) {
                    base = url
                    source = "AUXESIS_API_BASE"
                } else {
                    rejected = EndpointOverrideRejection(
                        source: "AUXESIS_API_BASE",
                        host: LoopbackURL.displayHost(of: raw)
                    )
                }
            } else if let raw = nonEmpty(env["AUXESIS_API"]) {
                if let url = LoopbackURL.parse(raw) {
                    base = url
                    source = "AUXESIS_API"
                } else {
                    rejected = EndpointOverrideRejection(
                        source: "AUXESIS_API",
                        host: LoopbackURL.displayHost(of: raw)
                    )
                }
            } else if let raw = nonEmpty(env["AUXESIS_API_PORT"]),
                      let port = Int(raw),
                      (0...65535).contains(port) {
                if port == 0 {
                    source = "AUXESIS_API_PORT=0 (no endpoint)"
                    noEndpoint = true
                } else {
                    base = URL(string: "http://127.0.0.1:\(port)")
                    source = "AUXESIS_API_PORT"
                }
            } else if let port = configPort(home: home), port != 0 {
                base = URL(string: "http://127.0.0.1:\(port)")
                source = "config.toml api_port"
            } else if nonEmpty(env["AUXESIS_API_PORT"]) != nil {
                source = "AUXESIS_API_PORT invalid (no endpoint)"
                noEndpoint = true
            } else {
                base = URL(string: "http://127.0.0.1:\(defaultPort)")
            }
            // A refused URL override falls back to the documented default (it
            // is not an explicit "no endpoint" decision).
            if base == nil && !noEndpoint {
                base = URL(string: "http://127.0.0.1:\(defaultPort)")
            }
        }

        return endpoint(
            base: base,
            home: home,
            source: source,
            rejected: rejected,
            homeRefused: homeRefused
        )
    }

    private static func endpoint(
        base: URL?,
        home: URL,
        source: String,
        rejected: EndpointOverrideRejection?,
        homeRefused: Bool
    ) -> AuxdEndpoint {
        AuxdEndpoint(
            baseURL: base,
            home: home,
            tokenFile: home.appendingPathComponent("api.token"),
            lockPID: lockPID(home: home),
            source: source,
            rejectedOverride: rejected,
            homeRefused: homeRefused
        )
    }

    /// The OS user database home (`getpwuid`), never `$HOME`.
    public static func osHomeDirectory() -> URL? {
        #if canImport(Darwin)
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return nil }
        return URL(fileURLWithPath: String(cString: dir), isDirectory: true)
        #else
        return nil
        #endif
    }

    /// `isSandboxed` for this process: the one predicate every owner-data
    /// guard (EventKit reads, bridge writes) uses.
    public static func isSandboxed(env: [String: String] = ProcessInfo.processInfo.environment) -> Bool {
        isSandboxed(
            env: env,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            realHomeDirectory: osHomeDirectory())
    }

    /// Active when `AUXESIS_SANDBOX=1`, or when the environment HOME is not
    /// the OS user database home (the incident mode).
    public static func isSandboxed(
        env: [String: String],
        homeDirectory: URL,
        realHomeDirectory: URL?
    ) -> Bool {
        if nonEmpty(env["AUXESIS_SANDBOX"]) == "1" {
            return true
        }
        let realHome = realHomeDirectory ?? homeDirectory
        if let envHome = nonEmpty(env["HOME"]).map({ URL(fileURLWithPath: $0, isDirectory: true) }) {
            return canonical(envHome) != canonical(realHome)
        }
        return canonical(homeDirectory) != canonical(realHome)
    }

    /// `AUXESIS_HOME` wins when set and non-blank, else `~/.auxesis`.
    ///
    /// While sandboxed the home comes from the environment HOME (never
    /// Foundation) and an `AUXESIS_HOME` outside it is ignored; callers that
    /// need the refusal signal use [`EndpointResolver.resolve`], which sets
    /// `homeRefused`.
    public static func auxesisHome(
        env: [String: String],
        homeDirectory: URL,
        sandboxed: Bool = false
    ) -> URL {
        if let custom = nonEmpty(env["AUXESIS_HOME"]) {
            let url = URL(fileURLWithPath: custom, isDirectory: true)
            let base = sandboxed
                ? nonEmpty(env["HOME"]).map { URL(fileURLWithPath: $0, isDirectory: true) }
                : nil
            if !sandboxed || base.map({ isUnder(url, $0) }) == true {
                return url
            }
        }
        if sandboxed, let envHome = nonEmpty(env["HOME"]) {
            return URL(fileURLWithPath: envHome, isDirectory: true)
                .appendingPathComponent(".auxesis", isDirectory: true)
        }
        return homeDirectory.appendingPathComponent(".auxesis", isDirectory: true)
    }

    static func isUnder(_ url: URL, _ parent: URL) -> Bool {
        let child = canonical(url)
        let base = canonical(parent)
        return child == base || child.hasPrefix(base.hasSuffix("/") ? base : base + "/")
    }

    static func canonical(_ url: URL) -> String {
        url.resolvingSymlinksInPath().standardizedFileURL.path
    }

    /// Tolerant scan for `api_port = N` in `<home>/config.toml`.
    static func configPort(home: URL) -> Int? {
        let path = home.appendingPathComponent("config.toml").path
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("#") else { continue }
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            let key = trimmed[..<eq].trimmingCharacters(in: .whitespaces)
            guard key == "api_port" else { continue }
            let value = trimmed[trimmed.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if let port = Int(value), (1...65535).contains(port) { return port }
        }
        return nil
    }

    static func lockPID(home: URL) -> Int32? {
        let path = home.appendingPathComponent("auxd.lock").path
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        return Int32(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private static func nonEmpty(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
