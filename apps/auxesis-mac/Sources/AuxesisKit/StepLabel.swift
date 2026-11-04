// The words one step row shows (STEP-TOOL-LABELS): the daemon sends a step as
// "running mail_read", the owner reads plain words, never a tool id.
// Display only: nothing here goes to the daemon or to a brain.
//
// Every tool the engine registers, or the skills table names, has its own
// words in both languages. Any other tool says the generic words ("Working" /
// "En cours"), never a raw or wordified id: a name without words is not
// something the owner should read. A skill id reads as its skill name. An MCP
// tool id names its tool, and an MCP id with no tool part names the service it
// used, because an installed extension is not one of the engine's tools.
//
// A delegate step names the agent it hands the work to when the caller knows
// it ("Asking the Mail agent"); with no target it still says "Asking an
// agent". The target is a closed set of known agents, never model text.
import Foundation

/// A known agent a delegate step can name. Closed on purpose: the target comes
/// from a tool argument, so only these five names may reach the label.
public enum StepAgent: String, CaseIterable {
    case aux, mail, calendar, clients, documents

    /// Case-insensitive, trimmed. Anything else is not an agent.
    public init?(_ raw: String) {
        self.init(rawValue: raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }

    /// The name the owner reads.
    public var displayName: String {
        switch self {
        case .aux: return "Aux"
        case .mail: return "Mail"
        case .calendar: return "Calendar"
        case .clients: return "Clients"
        case .documents: return "Documents"
        }
    }
}

/// The plain words of a step.
public enum StepLabel {
    /// Every tool id a step can carry, in the owner's words. Listed from the
    /// daemon's registration sites (`crates/aux-engine/src/config.rs`,
    /// `crates/auxd/src/api/turn.rs`, `crates/aux-runtime/src/tools`) and the
    /// skills table (`crates/aux-runtime/src/skills/tool_map.rs`). The checked-in
    /// fixture `Tests/AuxesisKitTests/Fixtures/step-tools.txt` is generated
    /// from those sites by `scripts/check-step-tool-ids.py`; the label test
    /// walks it, and gate-fast fails when the fixture is stale.
    private static let tools: [String: (en: String, fr: String)] = [
        // Mail
        "mail_list": ("Listing mail", "Liste des e-mails"),
        "mail_search": ("Searching mail", "Recherche dans les e-mails"),
        "mail_thread": ("Reading the thread", "Lecture du fil"),
        "mail_read": ("Reading mail", "Lecture des e-mails"),
        "mail_fetch_attachments": ("Fetching the attachments", "Récupération des pièces jointes"),
        "mail_draft": ("Drafting a mail", "Rédaction d'un brouillon"),
        "mail_send": ("Sending mail", "Envoi d'un e-mail"),
        "gmail_search": ("Searching mail", "Recherche dans les e-mails"),
        "gmail_read_message": ("Reading mail", "Lecture des e-mails"),
        "gmail_list_threads": ("Reading the thread", "Lecture du fil"),
        "google_gmail_search": ("Searching mail", "Recherche dans les e-mails"),
        "google_gmail_read_message": ("Reading mail", "Lecture des e-mails"),
        "google_gmail_create_draft": ("Drafting a mail", "Rédaction d'un e-mail"),
        "google_gmail_send": ("Sending mail", "Envoi d'un e-mail"),
        // Calendar
        "apple_calendar_list_events": ("Reading your calendar", "Lecture de votre agenda"),
        "apple_calendar_create_event": ("Creating the event", "Création de l'événement"),
        "apple_calendar_update_event": ("Changing the event", "Modification de l'événement"),
        "apple_reminders_list": ("Reading your reminders", "Lecture de vos rappels"),
        "calendar_list_events": ("Reading your calendar", "Lecture de votre agenda"),
        "calendar_get_event": ("Reading the event", "Lecture de l'événement"),
        "google_calendar_list_events": ("Reading your calendar", "Lecture de votre agenda"),
        "google_calendar_get_event": ("Reading the event", "Lecture de l'événement"),
        "google_calendar_create_event": ("Creating the event", "Création de l'événement"),
        "calendar_update_event": ("Moving an event", "Déplacement d'un événement"),
        // Clients
        "crm_list": ("Listing your clients", "Liste de vos clients"),
        "crm_search": ("Searching your clients", "Recherche parmi vos clients"),
        "crm_get": ("Reading the client card", "Lecture de la fiche client"),
        "crm_today": ("Reading today's clients", "Lecture des clients du jour"),
        "crm_create_followup": ("Adding a follow-up", "Ajout d'un suivi"),
        "crm_log_interaction": ("Writing down the meeting", "Saisie de l'échange"),
        "crm_add_note": ("Writing a note", "Écriture d'une note"),
        // Documents
        "docs_ingest": ("Collecting your documents", "Collecte de vos documents"),
        "docs_queue": ("Reading the documents queue", "Lecture de la file des documents"),
        // Memory
        "remember": ("Saving to memory", "Mémorisation"),
        "recall": ("Looking in memory", "Recherche en mémoire"),
        "forget": ("Forgetting a memory", "Oubli d'une mémoire"),
        "suggest_memory": ("Proposing a memory", "Proposition de mémoire"),
        // This Mac
        "read_file": ("Reading a file", "Lecture d'un fichier"),
        "write_file": ("Writing a file", "Écriture d'un fichier"),
        "shell": ("Running a command", "Exécution d'une commande"),
        "http_fetch": ("Reading a page", "Lecture d'une page"),
        "web_search": ("Searching the web", "Recherche sur le web"),
        "owner_profile": ("Reading your profile", "Lecture de votre profil"),
        "privacy_record_summary": ("Reading the privacy record", "Lecture du journal de confidentialité"),
        "weather_forecast": ("Reading the weather", "Lecture de la météo"),
        "weather_geocode": ("Finding the place", "Recherche du lieu"),
        "watch": ("Watching a web page", "Surveillance d'une page web"),
        // Handing work out
        "delegate": ("Asking an agent", "Demande à un agent"),
    ]

    /// The base form of the same tool, for a decision sentence: "Aux was
    /// allowed to read the privacy record". The table above is the gerund a
    /// running step shows; a sentence needs the infinitive. A tool missing
    /// here falls back to plain words in `LedgerText`, never to its id.
    private static let actions: [String: (en: String, fr: String)] = [
        // Mail
        "mail_list": ("list mail", "lister les e-mails"),
        "mail_search": ("search mail", "chercher dans les e-mails"),
        "mail_thread": ("read the thread", "lire le fil"),
        "mail_read": ("read mail", "lire les e-mails"),
        "mail_fetch_attachments": ("fetch the attachments", "récupérer les pièces jointes"),
        "mail_draft": ("draft a mail", "rédiger un brouillon"),
        "mail_send": ("send mail", "envoyer un e-mail"),
        "gmail_search": ("search mail", "chercher dans les e-mails"),
        "gmail_read_message": ("read mail", "lire les e-mails"),
        "gmail_list_threads": ("read the thread", "lire le fil"),
        "google_gmail_search": ("search mail", "chercher dans les e-mails"),
        "google_gmail_read_message": ("read mail", "lire les e-mails"),
        "google_gmail_create_draft": ("draft a mail", "rédiger un e-mail"),
        "google_gmail_send": ("send mail", "envoyer un e-mail"),
        // Calendar
        "apple_calendar_list_events": ("read your calendar", "lire votre agenda"),
        "apple_calendar_create_event": ("create the event", "créer l'événement"),
        "apple_calendar_update_event": ("change the event", "modifier l'événement"),
        "apple_reminders_list": ("read your reminders", "lire vos rappels"),
        "calendar_list_events": ("read your calendar", "lire votre agenda"),
        "calendar_get_event": ("read the event", "lire l'événement"),
        "calendar_update_event": ("move an event", "déplacer un événement"),
        "google_calendar_list_events": ("read your calendar", "lire votre agenda"),
        "google_calendar_get_event": ("read the event", "lire l'événement"),
        "google_calendar_create_event": ("create the event", "créer l'événement"),
        // Clients
        "crm_list": ("list your clients", "lister vos clients"),
        "crm_search": ("search your clients", "chercher parmi vos clients"),
        "crm_get": ("read the client card", "lire la fiche client"),
        "crm_today": ("read today's clients", "lire les clients du jour"),
        "crm_create_followup": ("add a follow-up", "ajouter un suivi"),
        "crm_log_interaction": ("write down the meeting", "saisir l'échange"),
        "crm_add_note": ("write a note", "écrire une note"),
        // Documents
        "docs_ingest": ("collect your documents", "collecter vos documents"),
        "docs_queue": ("read the documents queue", "lire la file des documents"),
        // Memory
        "remember": ("save to memory", "mémoriser"),
        "recall": ("look in memory", "chercher en mémoire"),
        "forget": ("forget a memory", "oublier une mémoire"),
        "suggest_memory": ("propose a memory", "proposer une mémoire"),
        // This Mac
        "read_file": ("read a file", "lire un fichier"),
        "write_file": ("write a file", "écrire un fichier"),
        "shell": ("run a command", "lancer une commande"),
        "http_fetch": ("read a page", "lire une page"),
        "web_search": ("search the web", "chercher sur le web"),
        "owner_profile": ("read your profile", "lire votre profil"),
        "privacy_record_summary": ("read the privacy record", "lire le journal de confidentialité"),
        "weather_forecast": ("read the weather", "lire la météo"),
        "weather_geocode": ("find the place", "chercher le lieu"),
        "watch": ("watch a web page", "surveiller une page web"),
        // Handing work out
        "delegate": ("ask an agent", "demander à un agent"),
    ]

    /// The base form of one tool id in the owner's words, or `nil` when this
    /// build has no words for it. A dot is a word break (`mail.send`).
    static func action(_ id: String, language: Language) -> String? {
        let id = id.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            .replacingOccurrences(of: ".", with: "_")
        guard let known = actions[id] else { return nil }
        return language == .fr ? known.fr : known.en
    }

    /// The words one step shows.
    /// - Parameters:
    ///   - raw: the daemon's step text ("running mail_read").
    ///   - language: the app's language.
    ///   - agent: the known target of a delegate step, when the caller has one.
    public static func text(_ raw: String, language: Language, agent: StepAgent? = nil) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return language == .fr ? "Étape" : "Step" }
        guard let step = parse(trimmed) else { return trimmed }
        if step.id.lowercased() == "delegate", let agent = agent {
            let name = agent.displayName
            let words = language == .fr ? "Demande à l'agent \(name)" : "Asking the \(name) agent"
            return framed(words, step.prefix, language: language)
        }
        guard let words = words(for: step.id, language: language) else {
            // A tool with no words in the table says its state, never its id.
            return generic(step.prefix, language: language)
        }
        return framed(words, step.prefix, language: language)
    }

    /// The words of one live tool call. A delegate call names the agent in its
    /// arguments when the frame carries them.
    public static func text(for call: ToolCall, language: Language) -> String {
        text(call.tool, language: language, agent: delegateAgent(call.args))
    }

    private static func framed(_ words: String, _ prefix: Prefix?, language: Language) -> String {
        switch prefix {
        case .running: return language == .fr ? "En cours : \(words)" : "Running: \(words)"
        case .finished: return language == .fr ? "Terminé : \(words)" : "Finished: \(words)"
        case nil: return words
        }
    }

    /// The words of one tool id: the table's own, or the words of a skill or
    /// an MCP tool. `nil` when the id names no tool the owner can read.
    private static func words(for id: String, language: Language) -> String? {
        // A tool id is read in lower case. A dot breaks a tool id into words
        // ("calendar.update_event" is "calendar_update_event"), but a skill id
        // keeps its dots: "skill__v1.2" still reads "V1.2".
        let id = id.lowercased()
        if id.hasPrefix("skill__") {
            let words = PlainLabel.skillWords(String(id.dropFirst(7)), language: language)
            // A skill id with no words ("skill__-") says nothing: the step
            // falls back to the generic words, never to a blank row.
            guard !words.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return words
        }
        // An MCP tool id ("mcp__github__search_issues") names its tool in the
        // last part: the tool is what the owner reads. An id with no tool
        // part ("mcp__github__") names the service it used ("Using github"),
        // never the raw "Mcp github".
        if id.hasPrefix("mcp__") {
            let parts = id.components(separatedBy: "__")
            let server = parts.count > 1 ? parts[1] : ""
            let tool = parts.count > 2 ? parts[2] : ""
            if !tool.isEmpty { return humanWords(tool.replacingOccurrences(of: ".", with: "_")) }
            // The name of the service is a name, not an id: an underscore is a
            // word break ("my_server" reads "my server"), never a raw id.
            let service = serviceWords(server)
            guard !service.isEmpty else { return nil }
            return language == .fr ? "Utilisation de \(service)" : "Using \(service)"
        }
        let toolId = id.replacingOccurrences(of: ".", with: "_")
        guard let known = tools[toolId] else { return nil }
        return language == .fr ? known.fr : known.en
    }

    /// An MCP tool name is not one of the engine's ids: it still reads as
    /// words (underscores become spaces, the first letter is capitalised).
    /// Runs of underscores give one space, never two. A name with nothing in
    /// it ("_") has no words at all.
    private static func humanWords(_ id: String) -> String? {
        let words = id.split(separator: "_").joined(separator: " ")
        guard words.contains(where: { $0.isLetter || $0.isNumber }) else { return nil }
        guard let first = words.first else { return nil }
        return String(first).uppercased() + words.dropFirst()
    }

    /// The name of a service, in words: an underscore is a word break, so
    /// "my_server" reads "my server" and never shows the raw name. A name
    /// with nothing in it ("_") has no words at all.
    private static func serviceWords(_ server: String) -> String {
        server.split(separator: "_").joined(separator: " ")
            .trimmingCharacters(in: .whitespaces)
    }

    /// The target of a live `delegate` call, from its JSON arguments. A frame
    /// whose arguments are absent, malformed or name an unknown agent names no
    /// agent: model text never reaches the label.
    private static func delegateAgent(_ args: String) -> StepAgent? {
        guard let data = args.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data),
              let object = json as? [String: Any],
              let raw = object["agent"] as? String
        else { return nil }
        return StepAgent(raw)
    }

    /// A step with no id to name still says something: the owner sees the
    /// step's own state, never a blank row.
    private static func generic(_ prefix: Prefix?, language: Language) -> String {
        switch prefix {
        case .finished: return language == .fr ? "Terminé" : "Finished"
        default: return language == .fr ? "En cours" : "Working"
        }
    }

    /// The step as the daemon sent it: a prefix word and a tool id, or a
    /// tool id alone. `nil` for the daemon's own sentences.
    private struct Step {
        let prefix: Prefix?
        let id: String
    }

    private enum Prefix { case running, finished }

    private static func parse(_ text: String) -> Step? {
        for (word, prefix) in [("running", Prefix.running), ("finished", Prefix.finished)] {
            guard text.hasPrefix(word + " ") else { continue }
            let rest = String(text.dropFirst(word.count + 1))
            // The prefix says the daemon is naming a step: the token after it
            // is that step's id, even one that names nothing ("running -").
            if isToken(rest) { return Step(prefix: prefix, id: rest) }
        }
        // With no prefix, the daemon may be writing its own words ("OK",
        // "Done."): only a token that looks like an id is read as one, so
        // free text stays verbatim. A token that names nothing at all
        // ("...") is not the daemon's words either: the row says its state.
        if isToken(text), looksLikeId(text) || namesNothing(text) {
            return Step(prefix: nil, id: text)
        }
        return nil
    }

    /// A token: one word of letters, digits, underscores, dashes and dots.
    /// A sentence with spaces is never a token. The check is made in lower
    /// case: an id the daemon writes in capitals is still an id.
    private static func isToken(_ text: String) -> Bool {
        guard !text.isEmpty else { return false }
        return text.lowercased().allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." }
    }

    /// A token with no letter and no digit names nothing at all ("...").
    private static func namesNothing(_ text: String) -> Bool {
        !text.contains(where: { $0.isLetter || $0.isNumber })
    }

    /// A token with no step prefix is only a tool id when it carries an
    /// underscore, or a name the table knows. Any other one-word text is the
    /// daemon's own words: it stays as it is, never capitalised and never
    /// stripped of its punctuation. An inner dot alone is not an id either: a
    /// file name ("file.txt") or a sentence ("Done...") is the daemon's text.
    private static func looksLikeId(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower.contains("_") { return true }
        return tools[lower] != nil
    }
}
