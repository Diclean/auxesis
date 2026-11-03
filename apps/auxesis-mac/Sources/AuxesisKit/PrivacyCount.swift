// The privacy record, counted for the sidebar footer.
//
// The number comes from the run receipts the privacy record page already
// lists (`GET /v1/receipts`, merged with the live `run.finished` frames).
//
// The unit counted is the run receipt: one receipt is one run, and it says
// which hosts that run reached, not how many provider requests it made. The
// owner-facing word is the one the contract uses ("Requests that left the
// Mac", and the prototype footer), so the line says "requests"
// while the number underneath stays run receipts.
//
// Three states, never mixed: the record is still being read (no number, no
// claim), the record could not be read (the count is unavailable), or the
// record was read and the number is known.
import Foundation

/// What the app knows about the privacy record it read from the service.
public enum PrivacyRecordRead: Equatable {
    /// The record is still being read: no number yet.
    case loading
    /// The record was read: it holds what the service sent.
    case loaded
    /// The record could not be read: the count is unavailable.
    case unavailable
}

/// The count the sidebar footer shows.
public enum PrivacyRecordCount: Equatable {
    /// The record is still being read: a neutral line, no number.
    case loading
    /// The record could not be read: the count is unavailable.
    case unavailable
    /// The number of requests that left the Mac today.
    case count(Int)
}

/// The count and the line that carries it, pure so a test can prove both
/// without a window and without a service.
public enum PrivacyRecordCounter {
    /// The run receipts of `day` (a local day, "yyyy-MM-dd") that reached
    /// outside: the requests that left the Mac that day.
    ///
    /// Only the records of that day count, and only the ones that reached
    /// outside: a run that stayed on this Mac left nothing. A record without
    /// a day is never attributed to today.
    public static func count(_ receipts: [Receipt], day: String) -> Int {
        receipts.filter { receipt in
            guard let started = receipt.started, String(started.prefix(10)) == day else { return false }
            return reachedOutside(receipt.hostsContacted)
        }.count
    }

    /// True when at least one host was outside this Mac. A local brain (the
    /// Ollama preset points at `http://127.0.0.1:11434`) is on this Mac: a
    /// run that only reached it never left.
    public static func reachedOutside(_ hosts: [String]) -> Bool {
        hosts.contains { !isLoopback($0) }
    }

    /// True for a host that stays on this Mac: `localhost`, `127.0.0.0/8` and
    /// `::1`, with or without a scheme, a port or IPv6 brackets.
    static func isLoopback(_ value: String) -> Bool {
        var authority = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = authority.range(of: "://") { authority = String(authority[range.upperBound...]) }
        // A browser reads `\` as `/`: "http://evil.com\@127.0.0.1" goes to evil.com.
        for separator in ["/", "\\", "?", "#"] {
            if let range = authority.range(of: separator) { authority = String(authority[..<range.lowerBound]) }
        }
        if let range = authority.range(of: "@", options: .backwards) { authority = String(authority[range.upperBound...]) }
        var host = authority
        if host.hasPrefix("[") {
            if let end = host.firstIndex(of: "]") { host = String(host[host.index(after: host.startIndex)..<end]) }
        } else if host.filter({ $0 == ":" }).count == 1, let range = host.range(of: ":") {
            host = String(host[..<range.lowerBound])
        }
        let name = host.lowercased()
        if name == "localhost" || name == "::1" { return true }
        let parts = name.split(separator: ".")
        return parts.count == 4 && parts[0] == "127" && parts.allSatisfy(isIPv4Octet)
    }

    /// One IPv4 octet: ASCII digits only, no sign and no space.
    ///
    /// `Int("+0")` is 0, so a signed octet would pass the range test and make
    /// "127.+0.0.1" look like this Mac. Only plain digits are an octet.
    static func isIPv4Octet(_ part: Substring) -> Bool {
        guard !part.isEmpty, part.utf8.allSatisfy({ (UInt8(48)...UInt8(57)).contains($0) }) else { return false }
        guard let value = Int(part) else { return false }
        return (0...255).contains(value)
    }

    /// The state the footer shows, from the read outcome and the record.
    public static func state(
        read: PrivacyRecordRead,
        receipts: [Receipt],
        day: String
    ) -> PrivacyRecordCount {
        switch read {
        case .loading: return .loading
        case .unavailable: return .unavailable
        case .loaded: return .count(count(receipts, day: day))
        }
    }

    /// The state the footer shows at `now`: the day comes from the clock, so
    /// a new day starts at zero the next time the footer is drawn.
    public static func state(
        read: PrivacyRecordRead,
        receipts: [Receipt],
        now: Date,
        calendar: Calendar = .current
    ) -> PrivacyRecordCount {
        state(read: read, receipts: receipts, day: TodayPresentation.day(now, calendar: calendar))
    }

    /// The one line under the sidebar: the number, or why there is none.
    public static func label(_ state: PrivacyRecordCount, _ language: Language) -> String {
        switch state {
        case .loading: return L10n.ui(.privacyCountPending, language)
        case .unavailable: return L10n.ui(.requestCountUnavailable, language)
        case .count(0): return L10n.ui(.privacyCountNone, language)
        case .count(1): return L10n.ui(.privacyCountOne, language)
        case .count(let many): return L10n.uf(.privacyCountMany, language, many)
        }
    }
}
