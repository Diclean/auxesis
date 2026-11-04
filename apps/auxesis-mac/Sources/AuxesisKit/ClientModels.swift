// The Clients destination: wire shapes for `/v1/clients`, the
// edit body, and the small presenter the list and the card share. The card
// carries real names and numbers: it is the owner's own data, read from this
// Mac over loopback. Decoding is tolerant like the other NEW routes: a field
// the daemon does not send reads as empty, never as a crash.
import Foundation

public struct ClientFollowup: Equatable, Decodable, Identifiable {
    public let id: Int64
    public let due: String
    public let reason: String
    public let createdBy: String

    public init(id: Int64, due: String, reason: String, createdBy: String = "owner") {
        self.id = id
        self.due = due
        self.reason = reason
        self.createdBy = createdBy
    }

    enum CodingKeys: String, CodingKey { case id, due, reason, createdBy = "created_by" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        due = (try? c.decode(String.self, forKey: .due)) ?? ""
        reason = (try? c.decode(String.self, forKey: .reason)) ?? ""
        createdBy = (try? c.decode(String.self, forKey: .createdBy)) ?? ""
    }
}

/// One row of `GET /v1/clients`.
public struct ClientSummary: Equatable, Decodable, Identifiable {
    public let id: Int64
    public let kind: String
    public let displayName: String
    public let emails: [String]
    public let phones: [String]
    public let tags: [String]
    public let nextFollowup: ClientFollowup?
    public let lastInteractionAt: String?

    public init(id: Int64, kind: String = "person", displayName: String, emails: [String] = [], phones: [String] = [],
                tags: [String] = [], nextFollowup: ClientFollowup? = nil, lastInteractionAt: String? = nil) {
        self.id = id
        self.kind = kind
        self.displayName = displayName
        self.emails = emails
        self.phones = phones
        self.tags = tags
        self.nextFollowup = nextFollowup
        self.lastInteractionAt = lastInteractionAt
    }

    enum CodingKeys: String, CodingKey {
        case id, kind, emails, phones, tags
        case displayName = "display_name"
        case nextFollowup = "next_followup"
        case lastInteractionAt = "last_interaction_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        kind = (try? c.decode(String.self, forKey: .kind)) ?? "person"
        displayName = (try? c.decode(String.self, forKey: .displayName)) ?? ""
        emails = (try? c.decode([String].self, forKey: .emails)) ?? []
        phones = (try? c.decode([String].self, forKey: .phones)) ?? []
        tags = (try? c.decode([String].self, forKey: .tags)) ?? []
        nextFollowup = try? c.decode(ClientFollowup.self, forKey: .nextFollowup)
        lastInteractionAt = try? c.decode(String.self, forKey: .lastInteractionAt)
    }
}

/// A party's identity, as the card shows and the editor changes it.
public struct ClientParty: Equatable, Decodable {
    public var id: Int64
    public var kind: String
    public var displayName: String
    public var nameVariants: [String]
    public var emails: [String]
    public var phones: [String]
    public var addresses: [String]
    public var tags: [String]
    public var notes: String
    /// The client's own IANA zone, when the daemon has one (CLIENT-TZ-FIELD).
    public var timeZone: String?
    public var origin: String

    public init(id: Int64, kind: String = "person", displayName: String, nameVariants: [String] = [], emails: [String] = [],
                phones: [String] = [], addresses: [String] = [], tags: [String] = [], notes: String = "",
                timeZone: String? = nil, origin: String = "owner") {
        self.id = id
        self.kind = kind
        self.displayName = displayName
        self.nameVariants = nameVariants
        self.emails = emails
        self.phones = phones
        self.addresses = addresses
        self.tags = tags
        self.notes = notes
        self.timeZone = timeZone
        self.origin = origin
    }

    enum CodingKeys: String, CodingKey {
        case id, kind, emails, phones, addresses, tags, notes, origin
        case displayName = "display_name"
        case nameVariants = "name_variants"
        case timeZone = "time_zone"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        kind = (try? c.decode(String.self, forKey: .kind)) ?? "person"
        displayName = (try? c.decode(String.self, forKey: .displayName)) ?? ""
        nameVariants = (try? c.decode([String].self, forKey: .nameVariants)) ?? []
        emails = (try? c.decode([String].self, forKey: .emails)) ?? []
        phones = (try? c.decode([String].self, forKey: .phones)) ?? []
        addresses = (try? c.decode([String].self, forKey: .addresses)) ?? []
        tags = (try? c.decode([String].self, forKey: .tags)) ?? []
        notes = (try? c.decode(String.self, forKey: .notes)) ?? ""
        timeZone = try? c.decode(String.self, forKey: .timeZone)
        origin = (try? c.decode(String.self, forKey: .origin)) ?? ""
    }
}

public struct ClientInteraction: Equatable, Decodable, Identifiable {
    public let id: Int64
    public let kind: String
    public let at: String
    public let summary: String
    public let provenance: String
    /// Written from outside content: the card shows the untrusted marker, never
    /// the raw summary as trusted text.
    public let tainted: Bool

    public init(id: Int64, kind: String, at: String, summary: String, provenance: String = "owner", tainted: Bool = false) {
        self.id = id
        self.kind = kind
        self.at = at
        self.summary = summary
        self.provenance = provenance
        self.tainted = tainted
    }

    enum CodingKeys: String, CodingKey { case id, kind, at, summary, provenance, tainted }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        kind = (try? c.decode(String.self, forKey: .kind)) ?? "note"
        at = (try? c.decode(String.self, forKey: .at)) ?? ""
        summary = (try? c.decode(String.self, forKey: .summary)) ?? ""
        provenance = (try? c.decode(String.self, forKey: .provenance)) ?? ""
        tainted = (try? c.decode(Bool.self, forKey: .tainted)) ?? false
    }
}

public struct ClientMemory: Equatable, Decodable, Identifiable {
    public let id: Int64
    public let title: String
    public let body: String
    public let source: String
    public let updatedAt: String?

    public init(id: Int64, title: String = "", body: String, source: String = "owner", updatedAt: String? = nil) {
        self.id = id
        self.title = title
        self.body = body
        self.source = source
        self.updatedAt = updatedAt
    }

    /// The line the card shows: the body, or the title when there is none.
    public var text: String { body.isEmpty ? title : body }

    enum CodingKeys: String, CodingKey { case id, title, body, source, updatedAt = "updated_at" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        title = (try? c.decode(String.self, forKey: .title)) ?? ""
        body = (try? c.decode(String.self, forKey: .body)) ?? ""
        source = (try? c.decode(String.self, forKey: .source)) ?? ""
        updatedAt = try? c.decode(String.self, forKey: .updatedAt)
    }
}

/// `GET /v1/clients/{id}`, and the answer to `PUT`.
public struct ClientCard: Equatable, Decodable {
    public var party: ClientParty
    /// Newest first.
    public var timeline: [ClientInteraction]
    /// Open follow-ups, earliest due first.
    public var followups: [ClientFollowup]
    public var memory: [ClientMemory]

    public init(party: ClientParty, timeline: [ClientInteraction] = [], followups: [ClientFollowup] = [], memory: [ClientMemory] = []) {
        self.party = party
        self.timeline = timeline
        self.followups = followups
        self.memory = memory
    }

    enum CodingKeys: String, CodingKey { case party, timeline, followups, memory }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        party = try c.decode(ClientParty.self, forKey: .party)
        timeline = (try? c.decode([ClientInteraction].self, forKey: .timeline)) ?? []
        followups = (try? c.decode([ClientFollowup].self, forKey: .followups)) ?? []
        memory = (try? c.decode([ClientMemory].self, forKey: .memory)) ?? []
    }
}

/// `PUT /v1/clients/{id}`. The editor works on lines of text; this trims them
/// and drops the empty ones, so a blank line never becomes a name to mask.
public struct ClientEdit: Equatable, Encodable {
    public var displayName: String
    public var nameVariants: [String]
    public var emails: [String]
    public var phones: [String]
    public var addresses: [String]
    public var tags: [String]
    public var notes: String

    public init(displayName: String, nameVariants: [String] = [], emails: [String] = [], phones: [String] = [],
                addresses: [String] = [], tags: [String] = [], notes: String = "") {
        self.displayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        self.nameVariants = Self.clean(nameVariants)
        self.emails = Self.clean(emails)
        self.phones = Self.clean(phones)
        self.addresses = Self.clean(addresses)
        self.tags = Self.clean(tags)
        self.notes = notes.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The editor's starting point: the party as it is.
    public init(_ party: ClientParty) {
        self.init(displayName: party.displayName, nameVariants: party.nameVariants, emails: party.emails,
                  phones: party.phones, addresses: party.addresses, tags: party.tags, notes: party.notes)
    }

    /// One value per line (the editor's multi-line fields).
    public static func lines(_ text: String) -> [String] {
        clean(text.components(separatedBy: .newlines))
    }

    private static func clean(_ values: [String]) -> [String] {
        values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    public var isValid: Bool { !displayName.isEmpty }

    enum CodingKeys: String, CodingKey {
        case emails, phones, addresses, tags, notes
        case displayName = "display_name"
        case nameVariants = "name_variants"
    }
}

/// The editor's text, one field per input. Lists are one value per line.
/// It lives in the shell so Save and Cancel can sit in the card's header.
public struct ClientDraft: Equatable {
    public var name: String
    public var aliases: String
    public var emails: String
    public var phones: String
    public var addresses: String
    public var tags: String
    public var notes: String

    public init(_ party: ClientParty) {
        name = party.displayName
        aliases = party.nameVariants.joined(separator: "\n")
        emails = party.emails.joined(separator: "\n")
        phones = party.phones.joined(separator: "\n")
        addresses = party.addresses.joined(separator: "\n")
        tags = party.tags.joined(separator: "\n")
        notes = party.notes
    }

    public var edit: ClientEdit {
        ClientEdit(
            displayName: name,
            nameVariants: ClientEdit.lines(aliases),
            emails: ClientEdit.lines(emails),
            phones: ClientEdit.lines(phones),
            addresses: ClientEdit.lines(addresses),
            tags: ClientEdit.lines(tags),
            notes: notes
        )
    }
}

/// The card's three tabs.
public enum ClientTab: Hashable { case overview, timeline, memory }

public enum ClientText {
    /// Two initials for the card's round mark: "Camille Exemple" → "CE".
    public static func initials(_ name: String) -> String {
        let words = name.split(whereSeparator: { $0 == " " || $0 == "-" }).filter { $0.first?.isLetter == true }
        let letters = words.prefix(2).compactMap(\.first).map { String($0).uppercased() }
        return letters.joined()
    }

    /// The name the memory lede uses: a person's first name, a company's name.
    public static func firstName(_ party: ClientParty) -> String {
        guard party.kind != "company" else { return party.displayName }
        return party.displayName.split(separator: " ").first.map(String.init) ?? party.displayName
    }

    /// An E.164 number spaced for reading. French numbers group as
    /// `+33 6 00 00 00 11`; other countries are shown as stored.
    public static func phone(_ e164: String) -> String {
        let digits = Array(e164.dropFirst())
        guard e164.hasPrefix("+33"), digits.count == 11, digits.allSatisfy(\.isNumber) else { return e164 }
        let national = digits.dropFirst(2)
        var groups = [String(national.prefix(1))]
        var rest = national.dropFirst()
        while !rest.isEmpty {
            groups.append(String(rest.prefix(2)))
            rest = rest.dropFirst(2)
        }
        return "+33 " + groups.joined(separator: " ")
    }

    /// The clients a filter keeps: name, addresses, numbers or tags contain it.
    public static func filter(_ clients: [ClientSummary], _ query: String) -> [ClientSummary] {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return clients }
        return clients.filter { client in
            ([client.displayName] + client.emails + client.phones + client.tags)
                .contains { $0.lowercased().contains(needle) }
        }
    }

    /// ↑/↓ in the list: the next shown client after `step`, clamped to the
    /// ends. With none selected, ↓ opens the first and ↑ the last.
    public static func move(from selected: Int64?, by step: Int, in shown: [ClientSummary]) -> Int64? {
        guard !shown.isEmpty else { return nil }
        guard let selected, let index = shown.firstIndex(where: { $0.id == selected }) else {
            return step >= 0 ? shown.first?.id : shown.last?.id
        }
        return shown[min(max(index + step, 0), shown.count - 1)].id
    }

    /// The list's second line: the first address, else the first number.
    public static func contactLine(_ client: ClientSummary) -> String {
        client.emails.first ?? client.phones.first ?? ""
    }

    /// The line a timeline row shows. A tainted row shows the untrusted marker,
    /// never its stored summary as trusted text.
    public static func timeline(_ item: ClientInteraction, language: Language) -> String {
        item.tainted ? L10n.ui(.clientUntrusted, language) : item.summary
    }

    /// A due date or timestamp, short: "Today", "Tue", "20 Oct".
    public static func day(_ raw: String?, now: Date, language: Language) -> String {
        guard let raw, !raw.isEmpty else { return "" }
        // Only a parsed Date is shown: a raw string (an old, model-written
        // interaction time) is never rendered as if it were a date.
        guard let date = TimeText.parse(raw) ?? dateOnly(raw) else { return "" }
        if Calendar.current.isDate(date, inSameDayAs: now) { return L10n.ui(.today, language) }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language.localeIdentifier)
        let days = Calendar.current.dateComponents([.day], from: Calendar.current.startOfDay(for: now), to: Calendar.current.startOfDay(for: date)).day ?? 0
        formatter.dateFormat = abs(days) < 7 ? "EEE d MMM" : (Calendar.current.component(.year, from: date) == Calendar.current.component(.year, from: now) ? "d MMM" : "d MMM yyyy")
        return formatter.string(from: date)
    }

    /// "Due today" / "Due 20 Oct", for a line that continues after it.
    public static func due(_ raw: String, now: Date, language: Language) -> String {
        let text = day(raw, now: now, language: language)
        if text == L10n.ui(.today, language) { return L10n.ui(.clientDueToday, language) }
        return L10n.uf(.clientDue, language, text)
    }

    /// The sentence for a refused save. A 422 names the field the daemon
    /// refused (`client_invalid`); its text is matched, never shown raw.
    public static func saveError(_ error: Error) -> UIKey {
        guard case .http(let status, let body)? = error as? AuxdError else { return .clientSaveFailed }
        if status == 404 { return .clientGone }
        guard status == 422 else { return .clientSaveFailed }
        let text = body.lowercased()
        if text.contains("phone") { return .clientInvalidPhone }
        if text.contains("e-mail") || text.contains("email") { return .clientInvalidEmail }
        if text.contains("display name") { return .clientInvalidName }
        return .clientSaveFailed
    }

    /// The `/client` command the card starts in the Clients thread.
    public static func briefCommand(_ party: ClientParty) -> String {
        "/client \(party.displayName)"
    }

    private static func dateOnly(_ raw: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.date(from: String(raw.prefix(10)))
    }
}

/// The import sheet's text helpers: the file's format, the columns
/// it read, the rows it left out, the country code the owner types. They work on
/// the daemon's counts and column names only; no contact value passes through.
public enum ContactsImportText {
    /// `vCard` or `CSV`: product-style names, the same in both languages.
    public static func format(_ raw: String?) -> String? {
        switch raw {
        case "vcard": return "vCard"
        case "csv": return "CSV"
        default: return nil
        }
    }

    public static func role(_ raw: String, _ language: Language) -> String {
        switch raw {
        case "name": return L10n.t(.importRoleName, language)
        case "given": return L10n.t(.importRoleGiven, language)
        case "family": return L10n.t(.importRoleFamily, language)
        case "nickname": return L10n.t(.importRoleNickname, language)
        case "email": return L10n.t(.importRoleEmail, language)
        case "phone": return L10n.t(.importRolePhone, language)
        default: return raw
        }
    }

    /// The reasons that left rows out, in the order the sheet lists them. Zero counts are dropped.
    public static func skippedReasons(_ skipped: ContactsImportSkipped) -> [(StringKey, Int)] {
        [
            (.importSkippedNoContact, skipped.noNameOrContact),
            (.importSkippedRepeated, skipped.repeatedInFile),
            (.importSkippedNeedsCountry, skipped.phoneNeedsCountry),
            (.importSkippedInvalidPhone, skipped.phoneInvalid),
            (.importSkippedCharset, skipped.refusedCharset),
            (.importSkippedEncoded, skipped.undecodableFields),
            (.importSkippedCap, skipped.overSizeCap),
        ].filter { $0.1 > 0 }
    }

    public static func tagLabel(_ tag: ContactsImportTag, _ language: Language) -> String {
        switch tag {
        case .client: return L10n.t(.importTagClient, language)
        case .partner: return L10n.t(.importTagPartner, language)
        case .none: return L10n.t(.importTagNone, language)
        }
    }

    /// Two ASCII letters, upper-cased (`fr` → `FR`); nil for anything else.
    public static func countryCode(_ raw: String) -> String? {
        let code = raw.trimmingCharacters(in: .whitespaces).uppercased()
        guard code.count == 2, code.allSatisfy({ $0.isASCII && $0.isLetter }) else { return nil }
        return code
    }

    /// The sentence for a refused call: the daemon's own message when it sent
    /// one (it names no one), else the plain copy. A raw body is never shown.
    public static func failure(_ error: Error, _ language: Language) -> String {
        if case .http(_, let body)? = error as? AuxdError, let message = daemonMessage(body) { return message }
        return L10n.t(.importFailed, language)
    }

    private static func daemonMessage(_ body: String) -> String? {
        struct Envelope: Decodable {
            struct Detail: Decodable { let message: String }
            let error: Detail
        }
        guard let data = body.data(using: .utf8),
              let text = (try? JSONDecoder().decode(Envelope.self, from: data))?.error.message,
              !text.isEmpty else { return nil }
        return text
    }
}
