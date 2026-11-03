// The v5 sidebar as pure rules: the status line of a row, the
// local search and the two-row privacy footer. Views read these; none words a
// status or counts a step on its own. Nothing here touches the network.
import Foundation

/// What a row's second line says, so the view can pair it with an icon.
public enum SidebarStatusKind: Equatable {
    /// "Waiting on you: <what>": amber hourglass on the right.
    case waiting
    /// "<task> · n of m": an open ring.
    case working
    /// "Idle · last: <first line>".
    case idle
    /// "Stopped: <reason>": red square and the word.
    case stopped
    /// Aux's own line (what is running, what waits).
    case plain
}

public struct SidebarStatus: Equatable {
    public let kind: SidebarStatusKind
    public let text: String
}

public enum SidebarText {
    /// The short role beside the name ("inbox, drafts"); nil for a custom agent.
    public static func role(_ member: TeamMember, _ language: Language) -> String? {
        let key: UIKey
        switch member.id {
        case TeamMember.aux.id: key = .sidebarRoleAux
        case TeamMember.mail.id: key = .sidebarRoleMail
        case TeamMember.calendar.id: key = .sidebarRoleCalendar
        case TeamMember.clients.id: key = .sidebarRoleClients
        case TeamMember.documents.id: key = .sidebarRoleDocuments
        default: return nil
        }
        return L10n.ui(key, language)
    }

    /// The second line of a row. Stopped beats waiting beats working beats
    /// idle: what needs the owner is never hidden behind a task name.
    public static func status(row: TeamRowModel, waitingWhat: String?, language: Language) -> SidebarStatus {
        if row.tone == .halt { return SidebarStatus(kind: .stopped, text: row.line) }
        if row.member.role == .chief { return SidebarStatus(kind: .plain, text: row.line) }
        if row.count > 0 {
            let what = waitingWhat?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let prefix = L10n.ui(.sidebarWaitingOn, language)
            return SidebarStatus(kind: .waiting, text: what.isEmpty ? prefix.trimmingCharacters(in: CharacterSet(charactersIn: ": ")) : prefix + what)
        }
        if row.working { return SidebarStatus(kind: .working, text: row.line) }
        // A row with no message yet falls back to the agent's role: that is not a last line.
        if row.line == L10n.ui(row.member.roleKey, language) || row.line.isEmpty {
            return SidebarStatus(kind: .idle, text: L10n.ui(.sidebarIdle, language))
        }
        return SidebarStatus(kind: .idle, text: L10n.ui(.sidebarIdleLast, language) + row.line)
    }

    /// The two footer rows. A row with nothing true to say is nil, never a claim.
    /// Requests come from the privacy record's run receipts; steps that stayed
    /// come from delegation steps whose place was recorded and whose time falls
    /// today. A step with no recorded place or time is never counted as stayed.
    public static func footer(
        read: PrivacyRecordRead,
        receipts: [Receipt],
        delegations: [Delegation],
        now: Date,
        language: Language,
        calendar: Calendar = .current
    ) -> (requests: String?, stayed: String?) {
        let state = PrivacyRecordCounter.state(read: read, receipts: receipts, now: now, calendar: calendar)
        let requests: String? = state == .loading ? nil : PrivacyRecordCounter.label(state, language)
        let stayed = delegations.flatMap(\.steps).filter { step in
            step.place == .stayed && TimeText.parse(step.at).map { calendar.isDate($0, inSameDayAs: now) } == true
        }.count
        let line: String? = stayed == 0 ? nil
            : stayed == 1 ? L10n.ui(.sidebarStayedOne, language) : L10n.uf(.sidebarStayedMany, language, stayed)
        return (requests, line)
    }
}

public enum SidebarSearch {
    /// Local filter on the row's name and last line: case and accents ignored,
    /// every word of the query must appear. An empty query keeps every row.
    public static func filter(_ entries: [SidebarEntry], query: String) -> [SidebarEntry] {
        let words = fold(query).split(whereSeparator: \.isWhitespace)
        guard !words.isEmpty else { return entries }
        return entries.filter { entry in
            let haystack = fold(entry.row.member.name + " " + entry.row.line)
            return words.allSatisfy { haystack.contains($0) }
        }
    }

    private static func fold(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
    }
}
