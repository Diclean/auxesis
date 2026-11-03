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
    public static func entries(_ entries: [LedgerEntry], filter: SinceYouLeftFilter = .all) -> [LedgerEntry] {
        filter.selecting(from: entries).filter {
            let summary = $0.summary.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !summary.isEmpty && summary != "(empty)" else { return false }
            let line = LedgerText.what($0, language: .en).trimmingCharacters(in: .whitespacesAndNewlines)
            return !line.isEmpty && line != "No text"
        }.sorted { $0.at > $1.at }
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
