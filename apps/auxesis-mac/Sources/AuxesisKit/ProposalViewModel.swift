import Foundation

public struct ProposalField: Equatable {
    public let label: String
    public let value: String

    public init(label: String, value: String) {
        self.label = label
        self.value = value
    }
}

public struct ProposalActions: Equatable {
    public let send: Bool
    public let edit: Bool
    public let notNow: Bool
    public let dontSend: Bool
}

/// A view-only projection of the approval fields the daemon currently exposes.
public struct ProposalViewModel: Equatable {
    public let title: String
    public let agent: String
    public let stateLabel: String
    public let fields: [ProposalField]
    public let body: String
    public let whatWillHappen: String
    /// The action names a tool with no explicit words: shown as unknown, raw id kept.
    public let unknownTool: Bool
    public let leftThisMac: String?
    public let stayedHere: String?
    public let boundaryLine: String
    public let grantLine: String
    public let actions: ProposalActions

    public init(approval: Approval, language: Language = .en) {
        title = PlainLabel.headline(approval.headline.isEmpty ? approval.action : approval.headline, tool: approval.scopeTool)
        agent = approval.agent
        stateLabel = Self.label(for: approval.state)
        // The daemon sends the fields as `label: value` lines and the text the
        // action carries in its own field: the card shows them as they are,
        // never re-read as a mail draft. Only the labels are put in plain words.
        var values: [String: String] = [:]
        var other: [ProposalField] = []
        for line in approval.detail {
            guard let split = line.firstIndex(of: ":") else { continue }
            let label = String(line[..<split]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: split)...]).trimmingCharacters(in: .whitespaces)
            guard !label.isEmpty, !value.isEmpty else { continue }
            if ["To", "From", "Subject"].contains(where: { $0.caseInsensitiveCompare(label) == .orderedSame }) {
                values[label.lowercased()] = value
            } else {
                other.append(ProposalField(label: PlainLabel.field(label, language: language), value: value))
            }
        }
        // A card with no mail line (an event, a file) shows no empty mail rows.
        var fields: [ProposalField] = values.isEmpty ? [] : [
            ProposalField(label: "To", value: values["to"] ?? "unavailable"),
            ProposalField(label: "From", value: values["from"] ?? "unavailable"),
            ProposalField(label: "Subject", value: values["subject"] ?? "unavailable")
        ]
        if !approval.why.isEmpty { other.append(ProposalField(label: PlainLabel.field("Why", language: language), value: approval.why)) }
        fields.append(contentsOf: other)
        self.fields = fields
        body = approval.fullPreview ?? approval.preview ?? ""
        whatWillHappen = PlainLabel.action(approval.action, language: language)
        unknownTool = PlainLabel.isUnknown(approval.action)
        leftThisMac = nil
        stayedHere = nil
        let recipient = values["to"].map { " · to \($0)" } ?? ""
        let subject = values["subject"].map { "\($0) and this text" } ?? "this content"
        boundaryLine = "This approval covers exactly: \(whatWillHappen)\(recipient) · \(subject)"
        grantLine = (approval.scopeRule.isEmpty ? "" : "Grant used: \(approval.scopeRule) ") + "Sending is never part of a grant"
        let pending = approval.state.isPending
        actions = ProposalActions(send: pending, edit: pending, notNow: pending, dontSend: pending)
    }

    private static func label(for state: ApprovalState) -> String {
        switch state {
        case .pending: "Waiting for you"
        case .allowed: "Allowed"
        case .denied: "Declined"
        case .expired: "Expired"
        case .unknown: "Unknown state"
        }
    }
}

/// Skill ids, tool names and `tool.field` run labels in the owner's words, display only. Only an id
/// listed here gets words: any other is shown as unknown with its raw id, because a friendly guess
/// ("send-email" → "Send email") could hide a different act.
public enum PlainLabel {
    private static let skills: [String: (en: String, fr: String, noun: String)] = [
        "follow-up": ("Follow-up", "Relance", "follow-up"),
        "send-invite": ("Meeting invite", "Invitation", "invite"),
        "reply-availability": ("Reply with free times", "Réponse avec disponibilités", "reply"),
        "collect-receipts": ("Collect receipts", "Collecte des reçus", "receipts"),
    ]
    private static let tools: [String: (en: String, fr: String)] = [
        "mail_send": ("Send this mail", "Envoyer ce mail"), "google_gmail_send": ("Send this mail", "Envoyer ce mail"),
        "apple_calendar_create_event": ("Create this event and send its invites", "Créer cet événement et envoyer les invitations"),
        "google_calendar_create_event": ("Create this event and send its invites", "Créer cet événement et envoyer les invitations"),
        "apple_calendar_update_event": ("Move this event", "Déplacer cet événement"),
        "calendar_update_event": ("Move this event", "Déplacer cet événement"),
    ]
    private static let groups: [String: (en: String, fr: String)] = [
        "apple_calendar_create_event": ("Event", "événement"), "google_calendar_create_event": ("Event", "événement"),
        "apple_calendar_update_event": ("Event", "événement"), "calendar_update_event": ("Event", "événement"),
    ]
    private static let keys: [String: (en: String, fr: String)] = [
        "to": ("To", "À"), "from": ("From", "De"), "subject": ("Subject", "Objet"),
        "cc": ("Cc", "Cc"), "bcc": ("Bcc", "Cci"), "attachment": ("Attachment", "Pièce jointe"),
        "why": ("Why", "Pourquoi"), "organizer": ("Organizer", "Organisateur"),
        "title": ("title", "titre"), "start": ("start", "début"), "end": ("end", "fin"),
        "time_zone": ("time zone", "fuseau horaire"), "start_utc": ("start (UTC)", "début (UTC)"),
        "end_utc": ("end (UTC)", "fin (UTC)"), "location": ("place", "lieu"), "notes": ("notes", "notes"),
        "attendee_time_zone": ("guest’s time zone", "fuseau de l’invité"), "attendee_start": ("guest’s start", "début pour l’invité"),
    ]

    /// "run skill__follow-up" → "Run “Follow-up” once, as shown".
    public static func action(_ action: String, language: Language = .en) -> String {
        guard action.hasPrefix("run ") else { return action }
        let id = String(action.dropFirst(4))
        if id.hasPrefix("skill__"), let known = skills[String(id.dropFirst(7))] {
            let name = language == .fr ? known.fr : known.en
            return language == .fr ? "Lancer « \(name) » une fois, tel qu’affiché" : "Run “\(name)” once, as shown"
        }
        if let known = tools[id] { return language == .fr ? known.fr : known.en }
        return unknown(id, language: language)
    }

    /// A skill id in the owner's words: "collect-receipts" → "Collect receipts";
    /// an id with no words here reads "Skill: <id>" (LANG-LEAKS-1).
    public static func skill(_ id: String, language: Language = .en) -> String {
        if let known = skills[id] { return language == .fr ? known.fr : known.en }
        return language == .fr ? "Compétence : \(id)" : "Skill: \(id)"
    }

    /// A skill id in the owner's words, for a step row: a known skill gets its
    /// name, an unknown one still reads as words ("Collect anything"), never as
    /// a raw id (STEP-LABELS-1). The id is trimmed first: a skill whose name
    /// starts with a dash ("skill__-foo") reads as its words, with one space
    /// between them, never a blank row (APP-P3-SWEEP-2).
    public static func skillWords(_ id: String, language: Language = .en) -> String {
        let trimmed = id.trimmingCharacters(in: .whitespacesAndNewlines)
        if let known = skills[trimmed] { return language == .fr ? known.fr : known.en }
        let words = trimmed.replacingOccurrences(of: "-", with: " ").trimmingCharacters(in: .whitespaces)
        return capitalized(words)
    }

    /// True for a `run <id>` action whose id has no explicit words here.
    public static func isUnknown(_ action: String) -> Bool {
        action.hasPrefix("run ") && Self.action(action) == unknown(String(action.dropFirst(4)))
    }

    /// An id with no explicit words: named as unknown, raw.
    public static func unknown(_ id: String, language: Language = .en) -> String {
        language == .fr ? "Outil inconnu : \(id)" : "Unknown tool: \(id)"
    }

    /// "apple_calendar_create_event.start_utc" → "Event start (UTC)".
    public static func field(_ raw: String, language: Language = .en) -> String {
        var group: String?
        var key = raw
        if let dot = raw.lastIndex(of: ".") {
            let tool = String(raw[..<dot])
            key = String(raw[raw.index(after: dot)...])
            guard let known = groups[tool] else { return raw }
            group = language == .fr ? known.fr : known.en
        }
        let word = keys[key.lowercased()].map { language == .fr ? $0.fr : $0.en } ?? key
        guard let group else { return capitalized(word) }
        return language == .fr ? "\(capitalized(word)) (\(group.lowercased()))" : "\(group) \(word)"
    }

    /// "Send send-invite to …" → "Send invite to …"; any other headline is the daemon's own.
    public static func headline(_ headline: String, tool: String) -> String {
        guard tool.hasPrefix("skill__") else { return headline }
        let id = String(tool.dropFirst(7))
        guard let noun = skills[id]?.noun else { return headline }
        for verb in ["Send ", "Create event ("] where headline.hasPrefix(verb + id) {
            return verb + noun + headline.dropFirst(verb.count + id.count)
        }
        return headline
    }

    private static func capitalized(_ text: String) -> String {
        text.prefix(1).uppercased() + text.dropFirst()
    }
}
