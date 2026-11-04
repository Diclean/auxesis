// LedgerText — the one readable line used wherever a ledger entry is rendered.
import Foundation

public enum LedgerText {
    public static func what(_ entry: LedgerEntry, language: Language) -> String {
        let summary = entry.summary.trimmingCharacters(in: .whitespacesAndNewlines)
        if summary.isEmpty || summary == "(empty)" { return language == .fr ? "Aucun texte" : "No text" }
        if summary.hasPrefix("[untrusted memory content") {
            return language == .fr ? "Aux a relu ses notes" : "Aux read its notes"
        }
        if entry.kind == "tool.decision", let decision = Self.plainDecision(summary, entry: entry, language: language) { return decision }
        if summary.lowercased().hasPrefix("error:"),
           summary.localizedCaseInsensitiveContains("No such file or directory") || summary.localizedCaseInsensitiveContains("os error 2") {
            let agent = TeamMember.displayName(entry.agent ?? "")
            if language == .fr { return "\(agent) \(agent == "Clients" ? "n’ont" : "n’a") pas pu ouvrir un fichier" }
            return "\(agent) could not open a file"
        }
        if let match = summary.range(of: #"^([A-Za-z][A-Za-z0-9_]*)\s+allowed\s+—\s+rule\s+\d+\s+matched:\s+allow$"#, options: .regularExpression) {
            let raw = String(summary[match]).components(separatedBy: " ").first ?? ""
            let agent = TeamMember.displayName(entry.agent ?? "")
            let action = Self.toolAction(raw, language)
            return Self.allowed(agent, action, byYou: false, language)
        }
        let payload = Self.payload(summary)
        if Self.isJSON(summary) {
            if let decision = Self.decision(entry, payload, language) { return decision }
            switch entry.kind {
            case "daemon.started":
                guard let version = payload?["version"] as? String else { break }
                return L10n.uf(.ledgerStarted, language, version)
                    .trimmingCharacters(in: CharacterSet(charactersIn: " ·"))
            case "run.finished":
                guard payload?["agent"] != nil || payload?["tokens_in"] != nil || payload?["tokens_out"] != nil else { break }
                let agent = TeamMember.displayName((payload?["agent"] as? String) ?? entry.agent ?? "")
                return Self.answered(agent, payload?["tokens_in"], payload?["tokens_out"], language)
            case "provider.created":
                guard payload?["provider"] != nil || payload?["model"] != nil else { break }
                return L10n.uf(.ledgerProviderAdded, language, (payload?["provider"] as? String) ?? "", (payload?["model"] as? String) ?? "")
            case "skill.approval":
                guard payload?["skill_name"] != nil || payload?["skill"] != nil else { break }
                return L10n.uf(.ledgerSkillAsked, language, Self.skill(entry, payload))
            case "skill.run", "skill.action":
                return Self.skillOutcome(entry, payload, language)
            default:
                break
            }
            if let line = Self.knownEvent(entry, payload, language) { return line }
            return Self.recorded((payload?["agent"] as? String) ?? entry.agent, language)
        }
        if summary.range(of: #"(?:^|\s)[A-Za-z][A-Za-z0-9_]*="#, options: .regularExpression) != nil {
            let agent = TeamMember.displayName(entry.agent ?? "")
            if let match = summary.range(of: #"unread_count\s*=\s*(\d+)"#, options: .regularExpression),
               let countRange = summary[match].range(of: #"\d+"#, options: .regularExpression) {
                let count = String(summary[countRange])
                if language == .fr { return "\(agent) a listé \(count) e-mails non lus" }
                return "\(agent) listed \(count) unread messages"
            }
            return language == .fr ? "\(agent) a terminé une étape" : "\(agent) completed a step"
        }
        switch entry.kind {
        case "daemon.started":
            return L10n.uf(.ledgerStarted, language, payload == nil ? summary : "")
                .trimmingCharacters(in: CharacterSet(charactersIn: " ·"))
        case "run.finished":
            let agent = TeamMember.displayName((payload?["agent"] as? String) ?? entry.agent ?? "")
            let tokensIn = Self.count(payload?["tokens_in"])
            let tokensOut = Self.count(payload?["tokens_out"])
            return tokensIn == "0" && tokensOut == "0" ? Self.answered(agent, 0, 0, language) : L10n.uf(.ledgerAnswered, language, agent, tokensIn, tokensOut)
        case "provider.created":
            let name = (payload?["provider"] as? String) ?? ""
            let model = (payload?["model"] as? String) ?? ""
            return L10n.uf(.ledgerProviderAdded, language, name, model)
        case "skill.approval":
            return L10n.uf(.ledgerSkillAsked, language, Self.skill(entry, payload))
        case "skill.run", "skill.action":
            return Self.cleanMarkdown(entry.summary)
        default:
            return Self.cleanMarkdown(entry.summary)
        }
    }

    /// Summarise a status string that has already passed through the activity mapper.
    /// Plain text stays as written; structured payloads never reach a view.
    public static func what(_ summary: String, agent: String?, language: Language) -> String {
        let trimmed = summary.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isJSON(trimmed) else { return Self.cleanMarkdown(trimmed) }
        return Self.recorded(agent, language)
    }

    public static func what(_ activity: ActivityEntry, language: Language) -> String {
        what(LedgerEntry(at: activity.at, kind: activity.kind, agent: activity.agent, summary: activity.summary), language: language)
    }

    private static func skillOutcome(_ entry: LedgerEntry, _ payload: [String: Any]?, _ language: Language) -> String {
        let skill = Self.skill(entry, payload)
        let outcome = (payload?["outcome"] as? String) ?? (payload?["status"] as? String)
        let readableOutcome: String?
        switch outcome?.lowercased() {
        case "success", "succeeded", "ok", "done": readableOutcome = language == .fr ? "terminé" : "completed"
        case "failed", "failure", "error": readableOutcome = language == .fr ? "échec" : "failed"
        case "uncertain": readableOutcome = language == .fr ? "peut-être envoyé" : "maybe sent"
        case "skipped": readableOutcome = language == .fr ? "ignoré" : "skipped"
        default: readableOutcome = outcome
        }
        let named = skill == "skill" ? (language == .fr ? "Compétence" : "Skill") : PlainLabel.skill(skill, language: language)
        if language == .fr {
            return "\(named) exécutée" + (readableOutcome.map { " · \($0)" } ?? "")
        }
        return "\(named) ran" + (readableOutcome.map { " · \($0)" } ?? "")
    }

    /// A JSON object or array, or one cut short by the daemon's summary limit.
    /// Bracketed plain text ("[Draft] …") and bare values ("42") stay plain.
    private static func isJSON(_ text: String) -> Bool {
        if let data = text.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) {
            return object is [String: Any] || object is [Any]
        }
        return text.hasPrefix("{\"") || text.hasPrefix("[{") || text.hasPrefix("[\"")
    }

    private static func decision(_ entry: LedgerEntry, _ payload: [String: Any]?, _ language: Language) -> String? {
        guard let payload,
              let tool = payload["tool"] as? String,
              let decision = (payload["decision"] as? String) ?? (payload["outcome"] as? String) else { return nil }
        let action = Self.toolAction(tool, language)
        let agent = TeamMember.displayName((payload["agent"] as? String) ?? entry.agent ?? "")
        let by = payload["by"] as? String
        let cannot = agent == "Clients" ? "ne peuvent pas" : "ne peut pas"
        switch decision.lowercased() {
        case "allow", "allowed":
            guard by == "policy" || by == "you" else { return nil }
            return Self.allowed(agent, action, byYou: by == "you", language)
        case "deny", "denied", "refuse", "refused":
            if by == "policy" {
                return language == .fr ? "\(agent) \(cannot) \(action) · refusé par la règle" : "\(agent) could not \(action) — denied by policy"
            }
            if by == "you" {
                return language == .fr ? "\(agent) \(cannot) \(action) · refusé" : "\(agent) could not \(action) — denied"
            }
            return nil
        default:
            return nil
        }
    }

    private static func plainDecision(_ summary: String, entry: LedgerEntry, language: Language) -> String? {
        guard let match = summary.range(of: #"^([A-Za-z][A-Za-z0-9_]*)\s+(allowed|denied|ask:approved|ask:denied)\s+—\s+(.+)$"#, options: .regularExpression) else { return nil }
        let fields = String(summary[match]).components(separatedBy: " ")
        guard fields.count >= 4 else { return nil }
        let tool = fields[0]
        let outcome = fields[1]
        let reason = fields.dropFirst(3).joined(separator: " ").lowercased()
        let agent = TeamMember.displayName(entry.agent ?? "")
        let action = Self.toolAction(tool, language)
        let cannot = agent == "Clients" ? "ne peuvent pas" : "ne peut pas"
        if outcome == "allowed" || outcome == "ask:approved" {
            let byYou = outcome == "ask:approved" || reason.contains("ask:approved") || reason.contains("ask, approved")
            return Self.allowed(agent, action, byYou: byYou, language)
        }
        if outcome == "ask:denied" || reason.contains("ask:denied") || reason.contains("ask, denied") {
            if language == .fr { return "\(agent) \(cannot) \(action) · refusé" }
            return "\(agent) could not \(action) — denied"
        }
        if language == .fr { return "\(agent) \(cannot) \(action) · refusé par la règle" }
        return "\(agent) could not \(action) — denied by policy"
    }

    private static func knownEvent(_ entry: LedgerEntry, _ payload: [String: Any]?, _ language: Language) -> String? {
        let agent = TeamMember.displayName((payload?["agent"] as? String) ?? (payload?["name"] as? String) ?? entry.agent ?? "")
        let isFrench = language == .fr
        switch entry.kind {
        case "agent.created": return isFrench ? "Agent \(agent) ajouté" : "\(agent) agent added"
        case "agent.updated": return isFrench ? "Agent \(agent) modifié" : "\(agent) agent updated"
        case "agent.deleted": return isFrench ? "Agent \(agent) supprimé" : "\(agent) agent removed"
        case "agent.paused": return isFrench ? "Agent \(agent) mis en pause" : "\(agent) agent paused"
        case "agent.resumed": return isFrench ? "Agent \(agent) repris" : "\(agent) agent resumed"
        case "agent.killed": return isFrench ? "Agent \(agent) arrêté" : "\(agent) agent stopped"
        case "approval.pending": return isFrench ? "Approbation en attente" : "Approval is waiting"
        case "approval.answered": return isFrench ? "Approbation traitée" : "Approval answered"
        case "approval.dropped": return isFrench ? "Approbation abandonnée après le redémarrage" : "Approval closed after restart"
        case "contacts.imported": return isFrench ? "Clients a importé des contacts" : "Clients imported contacts"
        case "crm.party_updated": return isFrench ? "Fiche client modifiée" : "Client record updated"
        case "daemon.stopped": return isFrench ? "Aux s’est arrêté" : "Aux stopped"
        case "daemon.stop_all": return isFrench ? "Arrêt général demandé" : "Stop all requested"
        case "provider.fallback": return isFrench ? "Un autre fournisseur a pris le relais" : "A backup provider took over"
        case "provider.created": return isFrench ? "Fournisseur ajouté" : "Provider added"
        case "provider.key_updated": return isFrench ? "Clé du fournisseur modifiée" : "Provider key updated"
        case "provider.tested": return isFrench ? "Fournisseur vérifié" : "Provider checked"
        case "brief.run": return isFrench ? "Brief du jour enregistré" : "Today’s brief recorded"
        case "skill.load_error": return isFrench ? "Compétence non chargée" : "Skill could not be loaded"
        case "agent.tool_reserved": return isFrench ? "Outil réservé à l’agent" : "Tool reserved for the agent"
        case "notify.test": return isFrench ? "Notification de test envoyée" : "Test notification sent"
        case "workspace.trust_refused": return isFrench ? "Accès à l’espace de travail refusé" : "Workspace access refused"
        case "web.fetch": return isFrench ? "Page web consultée" : "Web page checked"
        case "job.completed": return isFrench ? "Tâche terminée" : "Job completed"
        case "job.failed": return isFrench ? "Tâche échouée" : "Job failed"
        case "routine.created": return isFrench ? "Routine créée" : "Routine added"
        case "routine.updated": return isFrench ? "Routine modifiée" : "Routine updated"
        case "routine.deleted": return isFrench ? "Routine supprimée" : "Routine removed"
        case "budget.denied": return isFrench ? "Limite d’utilisation atteinte" : "Usage limit reached"
        default: return nil
        }
    }

    /// A call that already ran, said as a past fact. "Aux may read a file —
    /// allowed by policy" read as a request once a row cut it to "allow…"
    /// (ACT-FREE-REGRESS-1): no line here may sound like it waits for an OK.
    private static func allowed(_ agent: String, _ action: String, byYou: Bool, _ language: Language) -> String {
        if language == .fr {
            let was = agent == "Clients" ? "ont été autorisés" : "a été autorisé"
            return "\(agent) \(was) à \(action) · \(byYou ? "vous avez dit oui" : "sans demande")"
        }
        return "\(agent) \(agent == "Clients" ? "were" : "was") allowed to \(action) — \(byYou ? "you said yes" : "no approval needed")"
    }

    /// The tool in the base form a decision sentence needs. Known tools reuse
    /// the step cards' own words; an unknown one is humanised, never left as a
    /// raw id ("Aux was allowed to privacy record summary").
    private static func toolAction(_ tool: String, _ language: Language) -> String {
        if let action = StepLabel.action(tool, language: language) { return action }
        let words = tool
            .lowercased()
            .replacingOccurrences(of: ".", with: "_")
            .split(whereSeparator: { $0 == "_" || $0 == "-" })
            .joined(separator: " ")
        guard !words.isEmpty else { return language == .fr ? "utiliser un outil" : "use a tool" }
        return language == .fr ? "utiliser \(words)" : "use \(words)"
    }

    private static func answered(_ agent: String, _ input: Any?, _ output: Any?, _ language: Language) -> String {
        let inCount = Self.count(input), outCount = Self.count(output)
        if inCount == "0" && outCount == "0" { return language == .fr ? "\(agent) \(agent == "Clients" ? "ont" : "a") répondu" : "\(agent) answered" }
        return L10n.uf(.ledgerAnswered, language, agent, inCount, outCount)
    }

    private static func cleanMarkdown(_ text: String) -> String {
        guard text.range(of: #"(?m)^\s{0,3}(?:#{1,6}\s|[-*+]\s|\d+[.)]\s)|\*\*|__|`|(?<![\w*])\*\S"#, options: .regularExpression) != nil else { return text }
        var value = text
        let rules: [(String, String)] = [
            (#"(?m)^\s{0,3}#{1,6}\s*"#, ""), (#"(?m)^\s*[-*+]\s+"#, ""), (#"(?m)^\s*\d+[.)]\s+"#, ""),
            (#"\*\*(.+?)\*\*"#, "$1"), (#"(?<!\w)__(\S(?:.*?\S)?)__(?!\w)"#, "$1"),
            (#"(?<![\w*])\*(\S(?:.*?\S)?)\*(?![\w*])"#, "$1"), (#"`+([^`]+)`+"#, "$1"),
        ]
        for (pattern, template) in rules {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
            let range = NSRange(value.startIndex..., in: value)
            value = regex.stringByReplacingMatches(in: value, range: range, withTemplate: template)
        }
        return value.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func recorded(_ rawAgent: String?, _ language: Language) -> String {
        let agent = rawAgent.map(TeamMember.displayName).flatMap { $0.isEmpty ? nil : $0 }
        if language == .fr { return "Activité enregistrée\(agent.map { " · \($0)" } ?? "")" }
        return "Recorded\(agent.map { " \($0)" } ?? "") activity"
    }

    /// Activity API timestamps are UTC; render them in the user's local zone.
    public static func localTime(_ timestamp: String, timeZone: TimeZone = .current, locale: Locale = .current) -> String {
        let input = DateFormatter()
        input.locale = Locale(identifier: "en_US_POSIX")
        input.timeZone = TimeZone(secondsFromGMT: 0)
        input.dateFormat = "yyyy-MM-dd HH:mm:ss"
        guard let date = input.date(from: timestamp) else { return timestamp }
        let output = DateFormatter()
        output.locale = locale
        output.timeZone = timeZone
        output.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return output.string(from: date)
    }

    static func payload(_ text: String) -> [String: Any]? {
        guard text.hasPrefix("{"), let data = text.data(using: .utf8) else { return nil }
        if let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            return object
        }
        // The route cuts long summaries mid-JSON: read the complete pairs.
        guard let pattern = try? NSRegularExpression(pattern: #""([A-Za-z0-9_]+)":(?:"([^"]*)"|(-?[0-9]+))"#) else { return [:] }
        var pairs: [String: Any] = [:]
        let range = NSRange(text.startIndex..., in: text)
        for match in pattern.matches(in: text, range: range) {
            guard let key = Range(match.range(at: 1), in: text) else { continue }
            if let value = Range(match.range(at: 2), in: text) {
                pairs[String(text[key])] = String(text[value])
            } else if let value = Range(match.range(at: 3), in: text), let number = Int64(text[value]) {
                pairs[String(text[key])] = NSNumber(value: number)
            }
        }
        return pairs.isEmpty ? nil : pairs
    }

    static func skill(_ entry: LedgerEntry, _ payload: [String: Any]?) -> String {
        entry.skill ?? (payload?["skill_name"] as? String) ?? (payload?["skill"] as? String) ?? "skill"
    }

    static func count(_ value: Any?) -> String {
        let number = (value as? NSNumber)?.int64Value ?? 0
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.locale = Locale(identifier: "en_US")
        return formatter.string(from: NSNumber(value: number)) ?? "\(number)"
    }

}
