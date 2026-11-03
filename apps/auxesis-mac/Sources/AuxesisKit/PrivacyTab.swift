// The right panel's Privacy tab: today's privacy record for
// the open conversation, from the run receipts the privacy record page lists.
// Aux's conversation covers the whole team (Aux hands the work out); another
// agent's covers its own runs. A run "left this Mac" when a host outside this
// Mac is recorded (the sidebar footer's rule). It ran on this Mac only when
// its receipt was read without error and lists hosts, all on this Mac. A
// receipt read without error that lists no host at all "recorded no outside
// host": no evidence either way, never drawn as on this Mac (SOBER-1). An
// error receipt's place is not known. A receipt lists hosts, not every request.
import Foundation

public struct PrivacyTabRow: Equatable, Identifiable {
    public enum Place: Equatable { case left, stayed, noOutsideHost, unknown }
    public let id: String
    public let time: String
    public let agent: String
    public let place: Place
    /// The first outside host, for a run that left.
    public let host: String?
}

public struct PrivacyTabModel: Equatable {
    public let rows: [PrivacyTabRow]
    /// Values replaced before a request left, by category, summed over the rows.
    public let replaced: [(category: String, count: UInt32)]

    public static func == (a: PrivacyTabModel, b: PrivacyTabModel) -> Bool {
        a.rows == b.rows && a.replaced.map(\.category) == b.replaced.map(\.category) && a.replaced.map(\.count) == b.replaced.map(\.count)
    }

    public init(receipts: [Receipt], agent: String, day: String) {
        let mine = receipts.filter { receipt in
            guard let started = receipt.started, String(started.prefix(10)) == day else { return false }
            return agent == TeamMember.aux.id || receipt.agent == agent
        }
        rows = mine.map { receipt in
            let outside = receipt.hostsContacted.filter { !PrivacyRecordCounter.isLoopback($0) }
            let place: PrivacyTabRow.Place = !outside.isEmpty ? .left
                : receipt.receiptError ? .unknown
                : receipt.hostsContacted.isEmpty ? .noOutsideHost : .stayed
            let time = TimeText.parse(receipt.started).map(TimeText.clock) ?? ""
            return PrivacyTabRow(id: receipt.runId, time: time, agent: TeamMember.displayName(receipt.agent),
                                 place: place, host: outside.first)
        }
        var sums: [String: UInt32] = [:]
        for receipt in mine { for (category, count) in receipt.replacedValues { sums[category, default: 0] += count } }
        replaced = sums.filter { $0.value > 0 }.sorted { $0.key < $1.key }.map { (category: $0.key, count: $0.value) }
    }

    public func count(_ place: PrivacyTabRow.Place) -> Int { rows.filter { $0.place == place }.count }

    /// "Runs that left this Mac: 2", "Runs with no outside host recorded: 3"
    /// (the local runs and the ones that list no host), plus the unknown ones.
    public func summary(_ language: Language) -> [String] {
        let noOutside = count(.stayed) + count(.noOutsideHost)
        var lines = [L10n.uf(.privacyTabLeft, language, count(.left)), L10n.uf(.privacyTabStayed, language, noOutside)]
        if count(.unknown) > 0 { lines.append(L10n.uf(.privacyTabUnknown, language, count(.unknown))) }
        return lines
    }
}
