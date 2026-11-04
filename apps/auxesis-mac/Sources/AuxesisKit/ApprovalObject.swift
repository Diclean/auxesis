// The approval object ("one id, three places"). The daemon's
// approval is the single source; every view renders it from `Store.approvals`
// by id, so an answer given anywhere shows everywhere. This file only shapes
// one approval for display: who drafted it, with which skill, and the mail
// draft when the preview is a mail.
//
// When the approval fields (`kind`, `preview{to,subject,body}`, `trail`) are
// absent, the draft is read from the preview text: `To:` / `Subject:` /
// `Attachment:` header lines, a blank line, then the body. A preview without
// those lines is shown as plain text.
import Foundation

public struct MailDraft: Equatable {
    public var to: String?
    public var subject: String?
    public var body: String
    public var attachment: String?

    public init(to: String? = nil, subject: String? = nil, body: String, attachment: String? = nil) {
        self.to = to
        self.subject = subject
        self.body = body
        self.attachment = attachment
    }

    /// `To: …` / `Subject: …` / `Attachment: …`, blank line, body.
    public static func parse(_ text: String?) -> MailDraft? {
        guard let text, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        var to: String?
        var subject: String?
        var attachment: String?
        var lines = text.components(separatedBy: "\n")
        while let first = lines.first {
            let trimmed = first.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty {
                lines.removeFirst()
                break
            }
            if let value = header("To", trimmed) {
                to = value
            } else if let value = header("Subject", trimmed) {
                subject = value
            } else if let value = header("Attachment", trimmed) {
                attachment = value
            } else {
                break
            }
            lines.removeFirst()
        }
        let body = lines.joined(separator: "\n").trimmingCharacters(in: .newlines)
        guard to != nil || subject != nil else { return nil }
        return MailDraft(to: to, subject: subject, body: body, attachment: attachment)
    }

    /// The draft back to the preview shape, for an edited answer.
    public var text: String {
        var head: [String] = []
        if let to { head.append("To: \(to)") }
        if let subject { head.append("Subject: \(subject)") }
        if let attachment { head.append("Attachment: \(attachment)") }
        return head.isEmpty ? body : head.joined(separator: "\n") + "\n\n" + body
    }

    private static func header(_ name: String, _ line: String) -> String? {
        let prefix = name + ":"
        guard line.lowercased().hasPrefix(prefix.lowercased()) else { return nil }
        return String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
    }
}

/// Where one approval is in its life, as the card shows it.
public enum ApprovalPhase: Equatable {
    case open
    case editing
    /// The owner said yes; it leaves when the countdown ends unless undone.
    case sending(secondsLeft: Int)
    case answering
    case sent
    case notNow
    case cancelledByStop
    case declined
    case expired
    case failed

    /// True while the approval still waits for the owner's answer.
    public var isDraft: Bool {
        switch self {
        case .open, .editing: return true
        default: return false
        }
    }
}

public struct ApprovalCard: Identifiable, Equatable {
    public let approval: Approval
    public let phase: ApprovalPhase

    public var id: String { approval.id }
    public var agent: String { approval.agent }
    public var title: String { approval.headline.isEmpty ? approval.action : approval.headline }
    public var skill: String? { approval.skill }

    /// The text the card shows, read-only: what the daemon says the action
    /// will do. The edit payload never shows here.
    public var displayText: String { approval.fullPreview ?? approval.preview ?? "" }

    /// The text the owner may edit: the edit payload (the arguments as JSON),
    /// the editor's own text.
    public var editableText: String {
        approval.editPreview ?? approval.fullPreview ?? approval.preview ?? ""
    }

    /// The text the editor shows: for a skill run, only the text of its one
    /// send, never the run's payload (skill, hash, calls); empty when the run
    /// has no single text to edit. Any other ask edits its own text.
    public var editorText: String {
        RunEdit.isRun(editableText) ? (RunEdit.body(of: editableText) ?? "") : editableText
    }

    /// The detail lines a card shows below To and Subject: the sender, Cc,
    /// Bcc, an invite's organizer, attendees and event fields — every line
    /// except the ones drawn on their own.
    public var otherDetail: [String] {
        approval.detail.filter { line in
            let name = line.split(separator: ":", maxSplits: 1).first.map {
                $0.trimmingCharacters(in: .whitespaces).lowercased()
            } ?? ""
            return !["to", "subject", "attachment"].contains(name)
        }
    }

    /// True when the card has anything to show: a body or a detail line.
    public var hasPreview: Bool { !displayText.isEmpty || !approval.detail.isEmpty }

    /// One field of the card, by its label ("To", "Subject", "Attachment", …).
    public func field(_ label: String) -> String? {
        for line in approval.detail {
            guard let split = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<split]).trimmingCharacters(in: .whitespaces)
            guard name.caseInsensitiveCompare(label) == .orderedSame else { continue }
            return String(line[line.index(after: split)...]).trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    public static func make(_ approval: Approval, phase: ApprovalPhase) -> ApprovalCard {
        ApprovalCard(approval: approval, phase: phase)
    }

    /// Trail steps reached (Drafted → Approved → Sent → Delivered → Replied).
    public var trailReached: Int {
        switch phase {
        case .sending, .answering: return 2
        case .sent: return 3
        default: return 1
        }
    }
}

/// A skill run's edit payload is the daemon's run card as JSON. The owner edits
/// only the text of the run's one send; the payload is rebuilt from the version
/// the owner edited when the yes is posted, so it never shows on a card.
public enum RunEdit {
    /// True when `payload` is a skill run: a JSON object with a `skill` and `calls`.
    public static func isRun(_ payload: String) -> Bool {
        guard let run = object(payload) else { return false }
        return run["skill"] != nil && run["calls"] is [Any]
    }

    /// The text of the run's one send (`calls[i].real.body`), nil unless exactly one call has one.
    public static func body(of payload: String) -> String? {
        guard let run = object(payload), let index = sendIndex(run) else { return nil }
        return real(run, index)?["body"] as? String
    }

    /// What a yes posts: the run `base` with its send's text set to `text`, or
    /// `text` itself when `base` is not a run with one send.
    public static func posted(_ text: String, base: String) -> String {
        guard var run = object(base), let index = sendIndex(run),
              var calls = run["calls"] as? [[String: Any]], var real = real(run, index) else { return text }
        real["body"] = text
        calls[index]["real"] = real
        run["calls"] = calls
        guard let data = try? JSONSerialization.data(withJSONObject: run, options: [.withoutEscapingSlashes]),
              let json = String(data: data, encoding: .utf8) else { return text }
        return json
    }

    private static func object(_ payload: String) -> [String: Any]? {
        guard payload.hasPrefix("{"), let data = payload.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private static func real(_ run: [String: Any], _ index: Int) -> [String: Any]? {
        (run["calls"] as? [[String: Any]])?[index]["real"] as? [String: Any]
    }

    /// The one call whose `real` carries a text, nil for none or several.
    private static func sendIndex(_ run: [String: Any]) -> Int? {
        guard run["skill"] != nil, let calls = run["calls"] as? [[String: Any]] else { return nil }
        let sends = calls.indices.filter { real(run, $0)?["body"] is String }
        return sends.count == 1 ? sends[0] : nil
    }
}
