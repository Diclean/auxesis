import Foundation
public enum SinceYouLeftFilter: String, CaseIterable, Identifiable {
    case all, failed, waiting, leftThisMac, changedHere
    public var id: String { rawValue }
    public func selecting(from entries: [LedgerEntry]) -> [LedgerEntry] {
        guard self != .all else { return entries }
        return entries.filter { entry in
            let text = entry.summary.lowercased()
            switch self {
            case .all:
                return true
            case .failed:
                return entry.kind.hasSuffix(".failed") || ["failed", "refused", "timed out", "denied"].contains(where: text.contains)
            case .waiting:
                return ["waiting for you", "awaiting approval", "pending approval", "approval requested"].contains(where: text.contains)
            case .leftThisMac:
                return text.contains("left this mac")
            case .changedHere:
                return ["changed here", "local change", "on this mac"].contains(where: text.contains)
            }
        }
    }
}

public enum SinceYouLeftPresentation {
    /// True for a ledger row the owner can review: an action or a send. The
    /// conversation itself — every `message.*` row is the thread's transcript —
    /// is not work that ran while they were away. An automatic allow is not
    /// work either: a read-only default, an allow rule, or the auto policy's
    /// own answer showed no card and asked the owner nothing.
    ///
    /// A `run.finished` row is one chat turn's receipt. The turn the owner
    /// started is their own message, and its tools, skills and sends have their
    /// own rows (`tool.decision`, `skill.action`); only a scheduled or
    /// delegated run is work in itself. An older row with no `trigger` proves
    /// nothing, so it stays.
    public static func isWork(_ entry: LedgerEntry) -> Bool {
        if entry.kind.hasPrefix("message.") { return false }
        if isAutomaticAllow(entry) { return false }
        guard entry.kind == "run.finished", let payload = LedgerText.payload(entry.summary) else {
            return true
        }
        guard let trigger = payload["trigger"] as? String else { return true }
        return trigger != "owner_message"
    }

    /// True for a decision row that records an allow no one was asked about:
    /// the broker's read-only default, a matching allow rule, or the auto
    /// approver's own yes. The owner has nothing to review.
    public static func isAutomaticAllow(_ entry: LedgerEntry) -> Bool {
        switch entry.kind {
        case "approval.answered", "tool.decision":
            if let payload = LedgerText.payload(entry.summary) {
                return isAutomaticAllow(payload)
            }
            return isAutomaticPlainDecision(entry.summary)
        default:
            return false
        }
    }

    private static func isAutomaticAllow(_ payload: [String: Any]) -> Bool {
        let decision = ((payload["decision"] as? String) ?? (payload["outcome"] as? String) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard decision == "allow" || decision == "allowed" else { return false }
        if let by = (payload["by"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           !by.isEmpty {
            // "you" is the owner's answer; policy and judge answered on their own.
            return by != "you"
        }
        // An auto answer always names the tool; a row without one is the
        // owner's answer shape, which stays.
        guard (payload["tool"] as? String) != nil else { return false }
        if (payload["approved"] as? Bool) == true { return false }
        return !hasAskMarker((payload["reason"] as? String) ?? "")
    }

    /// The daemon flattens `tool.decision` to "tool allowed — reason".
    private static func isAutomaticPlainDecision(_ summary: String) -> Bool {
        guard let match = summary.range(
            of: #"^([A-Za-z][A-Za-z0-9_]*)\s+(allowed|denied|ask:approved|ask:denied)\s+—\s+(.+)$"#,
            options: .regularExpression
        ) else { return false }
        let fields = String(summary[match]).components(separatedBy: " ")
        guard fields.count >= 4, fields[1].lowercased() == "allowed" else { return false }
        let reason = fields.dropFirst(3).joined(separator: " ").lowercased()
        return !hasAskMarker(reason)
    }

    /// "ask, approved", "ask:approved", or a cut "ask, appr…" all mean a card
    /// was asked; only a reason with no "ask" word is a direct allow.
    private static func hasAskMarker(_ reason: String) -> Bool {
        reason.range(of: #"\bask\b"#, options: .regularExpression) != nil
    }

    public static func entries(_ entries: [LedgerEntry], filter: SinceYouLeftFilter = .all) -> [LedgerEntry] {
        filter.selecting(from: entries).filter {
            guard isWork($0) else { return false }
            let summary = $0.summary.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !summary.isEmpty && summary != "(empty)" else { return false }
            let line = LedgerText.what($0, language: .en).trimmingCharacters(in: .whitespacesAndNewlines)
            return !line.isEmpty && line != "No text"
        }.sorted { $0.at > $1.at }
    }

    /// The one line a "Since you left" section shows when it holds no work, or
    /// `nil` when it does. Only a loaded ledger may say there were no actions
    /// or sends: a read that failed, is still loading, or is unavailable says
    /// so, instead of claiming nothing happened.
    public static func emptyLine(_ load: Loadable<[LedgerEntry]>, language: Language) -> String? {
        switch load {
        case .loading: return L10n.ui(.loading, language)
        case .failed: return L10n.ui(.loadFailed, language)
        case .unavailable: return L10n.ui(.unavailable, language)
        case .loaded(let rows): return entries(rows).isEmpty ? L10n.ui(.ledgerEmpty, language) : nil
        }
    }

    public static func visibleEntries(_ entries: [LedgerEntry]) -> [LedgerEntry] {
        self.entries(entries)
    }

    public static func previewEntries(_ entries: [LedgerEntry]) -> [LedgerEntry] {
        self.entries(entries, filter: .all)
    }

    public static func previewLines(_ entries: [LedgerEntry], language: Language) -> [String] {
        previewEntries(entries).prefix(5).map { LedgerText.what($0, language: language) }
    }
}
public enum LedgerDetailValue: Equatable {
    case available(String)
    case unavailable
}
public struct SinceYouLeftDetail: Equatable {
    public let when: LedgerDetailValue
    public let agent: LedgerDetailValue
    public let skill: LedgerDetailValue
    public let skillVersion: LedgerDetailValue
    public let trigger: LedgerDetailValue
    public let grantUsed: LedgerDetailValue
    public let evidence: LedgerDetailValue
    public let stepOutcomes: LedgerDetailValue
    public let affectedObjects: LedgerDetailValue
    public let isFinal: Bool
    public var visibleFields: [(String, LedgerDetailValue)] {
        [
            ("When", when), ("Agent", agent), ("Skill", skill), ("Skill version", skillVersion),
            ("Trigger", trigger), ("Grant used", grantUsed), ("Evidence", evidence),
            ("Outcome per step", stepOutcomes), ("Affected objects", affectedObjects),
        ].filter { $0.1 != .unavailable }
    }
    public init(entry: LedgerEntry) {
        when = entry.at.isEmpty ? .unavailable : .available(LedgerText.localTime(entry.at))
        if let agent = entry.agent, !agent.isEmpty {
            self.agent = .available(TeamMember.displayName(agent))
        } else {
            self.agent = .unavailable
        }
        skill = entry.skill.map(LedgerDetailValue.available) ?? .unavailable
        if let hash = entry.skillHash, !hash.isEmpty {
            skillVersion = .available(hash)
        } else {
            skillVersion = .unavailable
        }
        trigger = .unavailable
        grantUsed = .unavailable
        evidence = .unavailable
        stepOutcomes = .unavailable
        affectedObjects = .unavailable
        // The ledger does not record whether an outcome is final (e.g. past a send's cancel window), so never infer it from text.
        isFinal = false
    }
}
