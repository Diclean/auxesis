import Combine
import Foundation

/// The receipt endpoint is run-level. It cannot prove that an individual
/// provider request was sent, so unavailable request evidence stays explicit.
public enum RequestInspectorSection: Int, CaseIterable, Equatable {
    case sent, destination, agentAndSkill, trigger, replaced, coverage
    case exactRequest, restored, whatCameBack, retentionClaim
}

public enum RequestInspectorFailure: Equatable {
    case transformationFailed(reason: String)
    case recordUnavailable
}

@MainActor
public final class RequestInspectorModel: ObservableObject {
    public let receipt: Receipt?
    public let failureState: RequestInspectorFailure?
    @Published public var isRestored = false

    public var canRestore: Bool { false }
    public func notKeptDisclosure(language: Language) -> String {
        language == .fr ? "Réponse non conservée : indisponible, pas absente." : "Not kept: unavailable, not missing."
    }
    public var visibleSections: [RequestInspectorSection] {
        guard let receipt else { return [] }
        var result: [RequestInspectorSection] = []
        if receipt.started != nil { result.append(.sent) }
        if !receipt.hostsContacted.isEmpty { result.append(.destination) }
        if !receipt.agent.isEmpty || !receipt.skills.isEmpty { result.append(.agentAndSkill) }
        if ["owner_message", "schedule", "agent_delegation"].contains(receipt.trigger ?? "") { result.append(.trigger) }
        if !receipt.replacedValues.isEmpty { result.append(.replaced) }
        result.append(.coverage)
        return result
    }

    public init(receipt: Receipt) {
        self.receipt = receipt
        self.failureState = receipt.receiptError ? .recordUnavailable : nil
    }

    public init(transformationFailure reason: String) {
        receipt = nil
        failureState = .transformationFailed(reason: reason)
    }

    public func value(for section: RequestInspectorSection) -> String {
        guard let receipt else { return "unavailable" }
        switch section {
        case .sent:
            guard let started = receipt.started else { return "unavailable" }
            guard let seconds = Self.duration(receipt) else { return started }
            return "\(started) · \(seconds) s"
        case .destination:
            guard !receipt.hostsContacted.isEmpty else { return "unavailable" }
            return "Host recorded for run: \(receipt.hostsContacted.joined(separator: ", "))"
        case .agentAndSkill:
            let parts = [receipt.agent, receipt.skills.joined(separator: ", ")].filter { !$0.isEmpty }
            return parts.joined(separator: " · ")
        case .trigger:
            switch receipt.trigger {
            case "owner_message": return "Owner message"
            case "schedule": return "Schedule"
            case "agent_delegation": return "Agent delegation"
            default: return "unavailable"
            }
        case .replaced:
            guard !receipt.replacedValues.isEmpty else { return "unavailable" }
            return receipt.replacedValues.sorted { $0.key < $1.key }
                .map { "\($0.key) ×\($0.value)" }.joined(separator: ", ")
        case .coverage: return "Counts by kind only; original values are never kept in this record."
        case .exactRequest: return "unavailable"
        case .restored: return "unavailable"
        case .whatCameBack: return "Not kept: unavailable, not missing"
        case .retentionClaim: return "unavailable"
        }
    }

    private static func duration(_ receipt: Receipt) -> Int? {
        guard let start = receipt.started, let finish = receipt.finished,
              let a = timestamp(start), let b = timestamp(finish), b >= a else { return nil }
        return Int(b.timeIntervalSince(a).rounded())
    }

    private static func timestamp(_ value: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.date(from: value)
    }
}

public enum PrivacyRecordListModel {
    public static func filtered(_ receipts: [Receipt], agent: String?, day: String?) -> [Receipt] {
        receipts.filter { receipt in
            (agent == nil || receipt.agent == agent)
                && (day == nil || String((receipt.started ?? "").prefix(10)) == day)
        }
    }

    public static func agents(_ receipts: [Receipt]) -> [String] {
        Array(Set(receipts.map(\.agent))).sorted()
    }
}
