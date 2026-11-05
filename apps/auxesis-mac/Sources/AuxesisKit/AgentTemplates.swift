// "Add an agent": the starter agents from `GET /v1/agent-templates`, each
// with what it does and the grants it gets in plain words. One that already
// exists cannot be picked. The sheet's confirm button is the owner's
// approval: it sends `POST /v1/agents {"template": id}` and nothing else.
import Foundation

public protocol AgentTemplateClient: AnyObject {
    /// `GET /v1/agent-templates`.
    func agentTemplates() async throws -> [AgentTemplate]
    /// `POST /v1/agents {"template": id}`.
    func createAgent(template: String) async throws
}

public struct AgentTemplate: Decodable, Equatable, Identifiable {
    public let id: String
    public let name: String
    public let grants: AgentGrants
    /// The agent already exists on this Mac.
    public let created: Bool
}

@MainActor
public final class AgentTemplatesModel: ObservableObject, Identifiable {
    @Published public private(set) var templates: [AgentTemplate] = []
    @Published public private(set) var loaded = false
    @Published public private(set) var busy = false
    @Published public private(set) var error: String?
    @Published public var selected: String?
    public let language: Language
    private let client: AgentTemplateClient
    private let onCreated: () async -> Void

    public init(client: AgentTemplateClient, language: Language, onCreated: @escaping () async -> Void = {}) {
        (self.client, self.language, self.onCreated) = (client, language, onCreated)
    }

    public func load() async {
        do {
            templates = try await client.agentTemplates()
            error = nil
            if selected == nil { selected = templates.first { !$0.created }?.id }
        } catch {
            self.error = Self.message(error, language)
        }
        loaded = true
    }

    public var canConfirm: Bool { !busy && templates.contains { $0.id == selected && !$0.created } }

    /// Creates the picked agent, then refreshes the list. True on success.
    @discardableResult
    public func confirm() async -> Bool {
        guard canConfirm, let id = selected else { return false }
        busy = true
        defer { busy = false }
        do {
            try await client.createAgent(template: id)
            error = nil
            await onCreated()
            return true
        } catch {
            self.error = Self.message(error, language)
            return false
        }
    }

    /// `grant_exceeds_chief` in plain words; any other refusal is the
    /// daemon's own message, as the app shows it elsewhere.
    public static func message(_ error: Error, _ language: Language) -> String {
        guard let auxd = error as? AuxdError else { return L10n.t(.errorServiceRefused, language) }
        if auxd.apiErrorCode == "grant_exceeds_chief" { return L10n.ui(.addAgentExceedsChief, language) }
        if let message = auxd.apiErrorMessage?.trimmingCharacters(in: .whitespacesAndNewlines), !message.isEmpty {
            return message
        }
        return auxd.message(language)
    }

    /// One line on what the agent does.
    public static func about(_ template: AgentTemplate, _ language: Language) -> String {
        L10n.ui(TeamMember.member(template.id)?.aboutKey ?? .aboutCustom, language)
    }

    /// "Does on its own: …" and "Asks you first: …"; switched-off grants are not listed.
    public static func grantLines(_ grants: AgentGrants, _ language: Language) -> [String] {
        func words(_ level: String) -> String {
            grants.canDo.filter { $0.level == level }
                .map { skillKeys[$0.skill].map { L10n.ui($0, language) } ?? $0.skill }
                .joined(separator: ", ")
        }
        return [(UIKey.addAgentDoes, words("auto")), (.addAgentAsks, words("ask"))]
            .filter { !$0.1.isEmpty }
            .map { L10n.uf($0.0, language, $0.1) }
    }

    static let skillKeys: [String: UIKey] = [
        "mail.read": .grantMailRead, "mail.draft": .grantMailDraft, "mail.send": .grantMailSend,
        "calendar.read": .grantCalendarRead, "calendar.write": .grantCalendarWrite,
        "clients.read": .grantClientsRead, "clients.note": .grantClientsNote,
        "documents.read": .grantDocumentsRead, "documents.file": .grantDocumentsFile,
    ]
}
