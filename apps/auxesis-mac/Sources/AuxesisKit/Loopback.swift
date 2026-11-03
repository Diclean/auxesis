// The loopback-only contract: the bearer token never leaves this machine.
//
// `AUXESIS_API_BASE` / `AUXESIS_API` are environment variables that any
// script, CI job or leaked shell rc can set, so they are treated as hostile
// input. `parse` accepts a value only when all of this holds:
//
//   * scheme is `http` or `ws` (no TLS, no other schemes);
//   * no userinfo (`user@host` is refused — it only *looks* like loopback);
//   * the textual authority — the exact bytes between `://` and the first
//     `/`, `?` or `#` — is host `127.0.0.1`, `localhost` or `[::1]`,
//     optionally followed by `:port` with port 1...65535 and no leading
//     zeros. Suffix tricks (`localhost.evil.com`), trailing dots
//     (`localhost.`), IDN lookalikes (`ⅼocalhost`), decimal/hex IP forms
//     (`2130706433`, `0x7f.1`), IPv6-mapped forms (`[::ffff:127.0.0.1]`) and
//     userinfo all fail this test;
//   * URLComponents parsed the same textual host (so percent-encoded
//     authorities like `127.0.0.1%2eevil.com` cannot hide a different host);
//   * there is no path beyond `/`, and no query or fragment.
//
// `isSafeRequestURL` re-checks the final request URL right before the
// Authorization header is attached (HTTP and WebSocket), so a hand-built
// `AuxdEndpoint` cannot bypass the resolver — defence in depth.
import Foundation

/// A refused `AUXESIS_API_BASE` / `AUXESIS_API` override, safe to show: the
/// env var name and at most the host (never userinfo, path or query).
public struct EndpointOverrideRejection: Equatable {
    /// The env var that was refused, e.g. `AUXESIS_API_BASE`.
    public let source: String
    /// The sanitised host of the refused value, or nil when it had none.
    public let host: String?

    public init(source: String, host: String?) {
        self.source = source
        self.host = host
    }
}

public enum LoopbackHost {
    /// The only hosts the bearer token may ever reach.
    public static let hosts: Set<String> = ["127.0.0.1", "localhost", "::1"]
}

public enum LoopbackURL {
    /// Strict parse of an override; nil means "refused".
    public static func parse(_ raw: String) -> URL? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while text.hasSuffix("/") { text.removeLast() }
        guard !text.isEmpty else { return nil }
        // No whitespace and no C0/C1 controls anywhere: kills "junk appended"
        // values that URL(string:) might otherwise percent-encode.
        guard text.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value != 0x7F && !(0x80...0x9F).contains($0.value) }) else {
            return nil
        }
        guard var components = URLComponents(string: text),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "ws",
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/"
        else { return nil }

        guard let marker = text.range(of: "://") else { return nil }
        let afterScheme = text[marker.upperBound...]
        let authority = afterScheme.prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        guard !authority.isEmpty, !authority.contains("@") else { return nil }

        let hostPart: Substring
        let portPart: Substring?
        if authority.hasPrefix("[") {
            // IPv6: the textual host is inside the brackets; nothing follows
            // except an optional `:port`.
            guard let close = authority.firstIndex(of: "]") else { return nil }
            hostPart = authority[authority.index(after: authority.startIndex)..<close]
            let rest = authority[authority.index(after: close)...]
            if rest.isEmpty {
                portPart = nil
            } else if rest.hasPrefix(":") {
                portPart = rest.dropFirst()
            } else {
                return nil
            }
            guard components.host?.lowercased() == "[\(hostPart.lowercased())]" else { return nil }
        } else {
            let pieces = authority.split(separator: ":", omittingEmptySubsequences: false)
            guard pieces.count <= 2 else { return nil }
            hostPart = pieces[0]
            portPart = pieces.count == 2 ? pieces[1] : nil
            guard components.host?.lowercased() == hostPart.lowercased() else { return nil }
        }
        guard LoopbackHost.hosts.contains(hostPart.lowercased()) else { return nil }

        var port: Int?
        if let portPart {
            guard !portPart.isEmpty,
                  portPart.allSatisfy(\.isNumber),
                  let value = Int(portPart),
                  (1...65535).contains(value),
                  String(value) == portPart
            else { return nil }
            port = value
        }
        guard components.port == port else { return nil }

        components.scheme = scheme
        if !authority.hasPrefix("[") {
            components.host = hostPart.lowercased()
        }
        components.port = port
        components.path = ""
        return components.url
    }

    /// The host to name in the friendly rejection notice: the real destination
    /// of the refused value (after userinfo), sanitised and capped. Never the
    /// full value.
    public static func displayHost(of raw: String) -> String? {
        guard let marker = raw.range(of: "://") else { return nil }
        var hostish = raw[marker.upperBound...].prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        guard !hostish.isEmpty else { return nil }
        if let at = hostish.lastIndex(of: "@") {
            hostish = hostish[hostish.index(after: at)...]
        }
        if hostish.hasPrefix("[") {
            hostish = hostish.dropFirst()
            if let close = hostish.firstIndex(of: "]") { hostish = hostish[..<close] }
        } else if let colon = hostish.firstIndex(of: ":") {
            hostish = hostish[..<colon]
        }
        let cleaned = ServerText.clean(String(hostish), maxLength: ServerText.Limits.hostNotice)
        return cleaned.isEmpty ? nil : cleaned
    }

    /// The request-time guard used right before the Authorization header is
    /// attached (HTTP and WebSocket).
    public static func isSafeRequestURL(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "ws" else { return false }
        guard url.user == nil, url.password == nil else { return false }
        guard let host = url.host?.lowercased(), LoopbackHost.hosts.contains(host) else { return false }
        if let port = url.port, !(1...65535).contains(port) { return false }
        return true
    }
}
