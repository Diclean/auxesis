// Typed result cards (UI-V5-RICH-2a): a calendar answer also shows its events and free time,
// built in the app from the `apple_calendar_list_events` row and the owner's question. Display
// only: never stored, sent to a model or part of egress. Rule: never say Free unless it knows.
import Foundation

public struct CalendarCardRow: Equatable {
    public enum Kind: Equatable { case event, free, allDay, notChecked }
    public let kind: Kind
    public let start: Date
    public let end: Date
    public let title: String  // empty on a free or not-checked row
}

public struct CalendarCardModel: Equatable {
    public let asksFree: Bool  // "what's free…": the title says so
    public let rows: [CalendarCardRow]
    public var readAt = Date.distantPast  // the tool row's time
    public var incomplete = false  // the list may be capped: events only, no Free rows

    public func title(_ language: Language) -> String { L10n.ui(asksFree ? .calCardFreeTitle : .calCardTitle, language) }

    /// The read time to show ("as of 14:05") once it is over 5 minutes old.
    public func asOf(now: Date = Date()) -> Date? { now.timeIntervalSince(readAt) > 300 ? readAt : nil }

    /// "Thu 30 Oct" / "jeu. 30 oct."
    public static func day(_ date: Date, _ language: Language, calendar: Calendar = .current) -> String {
        format("EEE d MMM", language.localeIdentifier, calendar).string(from: date)
    }

    static func format(_ pattern: String, _ locale: String, _ calendar: Calendar) -> DateFormatter {
        let formatter = DateFormatter()
        (formatter.locale, formatter.timeZone, formatter.dateFormat) = (Locale(identifier: locale), calendar.timeZone, pattern)
        return formatter
    }

    /// "14:00–15:30", or "All day".
    public static func time(_ row: CalendarCardRow, _ language: Language, calendar: Calendar = .current) -> String {
        if row.kind == .allDay { return L10n.ui(.calCardAllDay, language) }
        if row.kind == .notChecked { return "" }
        let formatter = format("HH:mm", "en_GB", calendar)
        return "\(formatter.string(from: row.start))–\(formatter.string(from: row.end))"
    }

    /// The row's words for the screen and VoiceOver: the title, or "Free".
    public static func what(_ row: CalendarCardRow, _ language: Language) -> String {
        switch row.kind {
        case .free: return L10n.ui(.calCardFreeRow, language)
        case .notChecked: return L10n.ui(.calCardNotChecked, language)
        case .event, .allDay: return row.title
        }
    }
}

public enum CalendarCard {
    struct Event: Decodable {
        let title, start, end, calendar: String, allDay: Bool?
        enum CodingKeys: String, CodingKey { case title, start, end, calendar, allDay = "all_day" }
    }

    static let (minFree, maxDays): (TimeInterval, Int) = (30 * 60, 5)  // shorter gaps get no row
    /// The tool keeps at most 100 events (`MAX_ITEMS`, apple_eventkit.rs; the app's `prefix(100)`) and the
    /// count is after de-duplication, so 50+ counts as maybe capped (lead). Backlog CAL-TRUNC-FLAG-1: a real flag.
    static let capped = 50
    /// The seven weekdays, English and French, from Sunday.
    static let weekdayNames: [[String]] = [["sunday", "dimanche"], ["monday", "lundi"], ["tuesday", "mardi"],
        ["wednesday", "mercredi"], ["thursday", "jeudi"], ["friday", "vendredi"], ["saturday", "samedi"]]
    /// The weekday of each name, to place a day.
    static let weekdayIndex: [String: Int] = {
        var map: [String: Int] = [:]
        for (index, names) in weekdayNames.enumerated() { for name in names { map[name] = index } }
        return map
    }()
    /// The parts of a day the card shows (EN + FR). "tonight" is not here: it names a day too.
    static let partOfDay: Set<String> = ["morning", "matin", "matinee", "afternoon", "aprem", "evening", "soir", "soiree"]
    /// The months (EN + FR): a month is not a day the card can place.
    static let monthNames: Set<String> = [
        "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
        "janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet", "aout", "septembre", "octobre", "novembre", "decembre"]
    /// The English abbreviations of a weekday or a month. They are not a day the card can place, and a
    /// capitalised one is not a name either: "Am I free Sat or tomorrow?" is Saturday, not a person.
    static let dayAbbreviations: Set<String> = [
        "mon", "tue", "wed", "thu", "fri", "sat", "sun",
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
    /// Date words that are never a name: a capitalised "Next" or "March" is not a person, and neither is a
    /// capitalised function word ("Except", "But"). They also stay unplaceable, so "Next Monday" and the
    /// "March meeting" never give a card (CAL-PARSE-ALLOWLIST-1).
    static let neverNames: Set<String> = monthNames.union(weekdayNames.flatMap { $0 }).union(dayAbbreviations).union([
        "next", "last", "this", "these", "that", "those", "following", "previous", "week", "weeks", "weekend", "weekends",
        "prochain", "prochaine", "prochains", "prochaines", "dernier", "derniere", "derniers", "dernieres",
        "semaine", "semaines", "mois", "month", "months", "an", "ans", "year", "years", "yesterday", "hier", "ago",
        "after", "before", "until", "till", "since", "avant", "apres", "jusqu", "jusqua", "plus", "moins", "dans",
        "days", "jours", "fortnight", "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth",
        "tenth", "eleventh", "twelfth", "thirteenth", "twentieth", "thirtieth", "premier", "premiere",
        "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve",
        "huit", "quinze", "deux", "trois", "quatre", "cinq", "sept", "neuf", "dix", "onze", "douze",
        // Function words: a capitalised one is not a name (CAL-PARSE-ALLOWLIST-1).
        "except", "but", "not", "no", "without", "instead", "only", "other", "besides", "apart",
        "sans", "sauf", "pas", "ni", "hors", "excepte", "every", "each", "any", "all", "tous", "toutes",
        "chaque", "either", "neither", "or", "and", "ou", "et", "between", "entre", "from", "des",
        "depuis", "past", "suivant", "suivante", "precedent", "ce", "cette",
        // Range words: a range of days is not a day, so they are never a name either.
        "to", "au", "aux", "through", "thru"])
    /// The marks that join the two ends of a range of days: "Monday-Friday", "Monday/Friday",
    /// "Monday – Friday", "Monday — Friday", "Monday ~ Friday" and every other dash Unicode
    /// writes — "Monday‐Friday" (U+2010), "Monday‑Friday" (U+2011), "Monday‒Friday" (U+2012),
    /// "Monday―Friday" (U+2015), "Monday－Friday" (U+FF0D) or "lundi〜vendredi" (U+301C). A range is
    /// not a day and we do not expand it, so a range of days means no card (CAL-PARSE-RANGE-2,
    /// CAL-PARSE-RANGE-3).
    static func isRangeMark(_ character: Character) -> Bool {
        if character == "/" || character == "~" || character == "\u{223C}" { return true }
        // Dash punctuation (Pd): the hyphen and every typographic dash. The wave dash (U+301C) and
        // the fullwidth hyphen (U+FF0D) are dashes too.
        return character.unicodeScalars.contains { $0.properties.generalCategory == .dashPunctuation }
    }
    /// The French elisions written with a hyphen, folded: "qu'est-ce", "est-ce", "est-il", "a-t-il",
    /// "ai-je", "suis-je", "dois-je", "puis-je". The words around the hyphen are one phrase, so the
    /// hyphen is not a range mark (CAL-PARSE-RANGE-3).
    static let elisionPhrases: [String] = [
        "qu'est-ce", "est-ce", "est-il", "a-t-il", "ai-je", "suis-je", "dois-je", "puis-je"]
    /// The words that join the two ends of a range of days, folded ("à" is "a"): "lundi à vendredi",
    /// "de lundi à vendredi", "Monday to Friday" (CAL-PARSE-RANGE-2).
    static let rangeWords: Set<String> = ["a", "to", "au", "through", "thru", "till", "until", "jusqu"]
    /// The words a calendar question may use around the day (EN + FR): a closed, small list. A word that is
    /// not here, and is not a name, means the card does not show (CAL-PARSE-ALLOWLIST-1). A range word
    /// ("Monday to Friday", "du lundi au vendredi") is not here: a range is not a day.
    static let questionWords: Set<String> = [
        // EN
        "a", "am", "an", "and", "any", "anything", "are", "at", "available", "busy", "calendar", "call", "calls",
        "check", "coffee", "day", "demo", "dinner", "do", "does", "event", "events", "everything", "for", "free",
        "got", "have", "i", "in", "interview", "is", "it", "list", "lunch", "me", "meeting", "meetings", "my",
        "nothing", "of", "off", "on", "or", "party", "plan", "planned", "plans", "remind", "review", "s",
        "schedule", "session", "show", "slot", "standup", "tell", "the", "thing", "what", "whats", "when",
        "who", "with", "workshop",
        // FR
        "agenda", "ai", "as", "avec", "calendrier", "chose", "creneau", "de", "dejeuner",
        "diner", "dispo", "disponible", "du", "est", "et", "il", "j", "je", "le", "la", "les", "libre", "libres",
        "liste", "ma", "mes", "moi", "montre", "n", "occupe", "occupes", "planning", "prevu",
        "qu", "que", "quel", "quelle", "quelque", "quand", "quoi", "pour", "rdv", "rendez", "reunion", "reunions",
        "rien", "sur", "suis", "un", "une", "vous", "y"]
    /// The words a French question uses and an English one does not. One of them means the question is
    /// French, so "mon" may be read as "my" and not as "Mon" (Monday): an English "Mon" is a day the
    /// card cannot place. A word both languages use ("agenda", "planning", "diner") is not here: an
    /// English question that says "Mon" must not be read as French. Neither is a word that is also a
    /// common English word or a name ("ai", "la", "de", "le", "du", "des", "a", "est", "ma", "me",
    /// "on", "ou", "plus", "sans", "pas"): they would call an English question French, and a mixed
    /// question must never read "mon" as "my" (CAL-PARSE-RANGE-2).
    static let frenchMarkers: Set<String> = [
        "demain", "aujourd", "hier", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche",
        "matin", "matinee", "soir", "soiree", "aprem", "apres", "avant", "calendrier", "creneau", "dejeuner",
        "dispo", "disponible", "libre", "libres", "prevu", "occupe", "occupes", "ce", "cette", "j", "je",
        "suis", "quoi", "qu", "quel", "quelle", "quelque", "quand", "rendez",
        "moi", "avec", "pour", "rien", "vous", "mes", "une"]
    /// The question words that are an English day abbreviation at the same time: "mon" is "my" in French
    /// and "Mon" is Monday in English. A French question that writes the word in lower case may use it;
    /// any other use is a day the card cannot place, so the card does not show (CAL-PARSE-ALLOWLIST-1,
    /// CAL-PARSE-RANGE-2).
    static let frenchDayWords: Set<String> = ["mon"]

    /// The words that are names: capitalised in the original question, not the first word of it and not a
    /// date word ("the Dupont meeting").
    static func names(original: [String], folded: [String]) -> Set<Int> {
        guard original.count == folded.count else { return [] }
        var found: Set<Int> = []
        for (index, word) in original.enumerated() where index > 0 {
            guard let first = word.first, first.isUppercase, !neverNames.contains(folded[index]) else { continue }
            found.insert(index)
        }
        return found
    }

    /// Is the word at this index written in lower case in the question as it was written? The first
    /// word of a question is capitalised because the sentence starts there ("Mon agenda"), but a
    /// capitalised word is not a lower case word: "Mon" may be "my" only when it is written in lower
    /// case, and a shouted word ("MON") is not one either (CAL-PARSE-RANGE-2).
    static func isLowerCase(_ original: [String], _ index: Int) -> Bool {
        guard index < original.count else { return false }
        return original[index] == original[index].lowercased()
    }

    /// The events of a calendar tool row; nil for "access not granted", a stale copy with its note, or `[]`.
    static func events(_ toolText: String) -> [(title: String, start: Date, end: Date, allDay: Bool)]? {
        let text = toolText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix("["), let data = text.data(using: .utf8),
              let list = try? JSONDecoder().decode([Event].self, from: data), !list.isEmpty else { return nil }
        let parsed = list.compactMap { event -> (title: String, start: Date, end: Date, allDay: Bool)? in
            guard let start = TimeText.parse(event.start), let end = TimeText.parse(event.end), end >= start else { return nil }
            return (event.title, start, end, event.allDay ?? false)
        }
        return parsed.count == list.count ? parsed : nil
    }

    /// Days and hours asked (EN, FR): only today, tomorrow, the day after, a bare weekday; else nil, never a wrong day.
    /// CAL-PARSE-ALLOWLIST-1: every word of the question must be one the card understands — a word that
    /// places a day (today, tomorrow, the day after, a weekday), a part of a day, a question word, or a
    /// name. A word we do not know means no card: a wrong day is worse than no card, and no card still
    /// shows the chat answer as text.
    /// CAL-PARSE-RANGE-2: a range of days ("Monday-Friday", "lundi à vendredi") is not a day and we do
    /// not expand it: no card. And "mon" is the French "my" only when it is written in lower case in a
    /// question that holds a lower case French word: a mixed question gives no card either.
    /// CAL-PARSE-RANGE-3: every dash Unicode writes joins two days ("Monday‐Friday", U+2010), and the
    /// hyphen of a French elision ("est-ce", "y a-t-il") is not a range: the words around it are one
    /// phrase.
    static func window(_ question: String, now: Date, calendar: Calendar) -> (days: [Date], from: Int, to: Int)? {
        let q = question.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
            .replacingOccurrences(of: "’", with: "'")
        guard q.rangeOfCharacter(from: .decimalDigits) == nil else { return nil }  // a number: a day we cannot place
        let words = q.components(separatedBy: CharacterSet.letters.inverted).filter { !$0.isEmpty }
        let original = question.components(separatedBy: CharacterSet.letters.inverted).filter { !$0.isEmpty }
        let named = names(original: original, folded: words)
        let aligned = original.count == words.count  // the written words and the folded ones line up
        // The question is written in French when it holds a French-only word written in lower case:
        // "AI", "La", "De", "Le" and "Du" are English too, and a shouted word is not a marker
        // (CAL-PARSE-RANGE-2).
        let french = aligned && words.indices.contains { index in
            frenchMarkers.contains(words[index]) && isLowerCase(original, index)
        }
        // A mark or a word that joins two days may hide the days between them ("Monday-Friday" hides
        // Tuesday, Wednesday and Thursday). We do not expand a range: a range of days means no card
        // (CAL-PARSE-RANGE-2).
        // The hyphens of "après-demain" and "après-midi" are one day, not a range, and neither is the
        // hyphen of a French elision ("est-ce", "y a-t-il", "ai-je"): the words around it are one
        // phrase (CAL-PARSE-RANGE-3).
        let markless = elisionPhrases.reduce(q) { text, phrase in
            text.replacingOccurrences(of: phrase, with: phrase.replacingOccurrences(of: "-", with: " "))
        }
        let rangeMarked = markless.replacingOccurrences(of: "apres-demain", with: "apres demain")
            .replacingOccurrences(of: "apres-midi", with: "apres midi").contains(where: isRangeMark)
        let rangeWorded = words.contains { rangeWords.contains($0) }
        var offsets: Set<Int> = []  // 0 today, 1 tomorrow, 2 the day after
        var weekdays: [Int] = []
        var morning = false, afternoon = false, evening = false
        var index = 0
        while index < words.count {
            let word = words[index]
            let next = index + 1 < words.count ? words[index + 1] : ""
            // The phrases the card understands: "day after tomorrow", "après-demain", "après-midi".
            if word == "day", next == "after", index + 2 < words.count, words[index + 2] == "tomorrow" {
                offsets.insert(2); index += 3; continue
            }
            // "y a-t-il" and "a-t-il": one elided phrase, and its hyphen is not a range
            // (CAL-PARSE-RANGE-3).
            if word == "a", next == "t", index + 2 < words.count, words[index + 2] == "il" { index += 3; continue }
            if word == "apres", next == "demain" { offsets.insert(2); index += 2; continue }
            if word == "apres", next == "midi" { afternoon = true; index += 2; continue }
            if word == "this" || word == "cette" {
                // Only before a weekday or a part of a day: "this Friday", "cette semaine" is not a day.
                guard weekdayIndex[next] != nil || partOfDay.contains(next) else { return nil }
                if partOfDay.contains(next) { offsets.insert(0) }
                index += 1; continue
            }
            switch word {
            case "today": offsets.insert(0)
            case "tonight": offsets.insert(0); evening = true
            case "tomorrow": offsets.insert(1)
            case "demain": offsets.insert(1)
            case "aujourd", "hui": offsets.insert(0)
            case "morning", "matin", "matinee": morning = true
            case "afternoon", "aprem": afternoon = true
            case "evening", "soir", "soiree": evening = true
            case "ce": if partOfDay.contains(next) { offsets.insert(0) }  // "ce soir" is today
            default:
                if let weekday = weekdayIndex[word] { weekdays.append(weekday) }
                else if dayAbbreviations.contains(word) {
                    // "Mon" is Monday in English and "my" in French, and "Sat" is a day the card cannot
                    // place. Only a French question that writes the word in lower case may use one
                    // (CAL-PARSE-ALLOWLIST-1, CAL-PARSE-RANGE-2).
                    guard frenchDayWords.contains(word), french, aligned, isLowerCase(original, index) else { return nil }
                }
                else if !questionWords.contains(word) && !named.contains(index) { return nil }
            }
            index += 1
        }
        let today = calendar.startOfDay(for: now)
        func plus(_ days: Int) -> Date { calendar.date(byAdding: .day, value: days, to: today) ?? today }
        let todayWeekday = calendar.component(.weekday, from: today)
        var days: [Date] = []
        if offsets.contains(0) { days.append(today) }
        if offsets.contains(1) { days.append(plus(1)) }
        if offsets.contains(2) { days.append(plus(2)) }
        for weekday in weekdays { days.append(plus((weekday + 1 - todayWeekday + 7) % 7)) }
        let unique = Array(Set(days)).sorted().prefix(maxDays)
        guard !unique.isEmpty else { return nil }
        // Any two days joined by a range ("today-Monday", "demain à lundi") may hide the days between.
        if unique.count > 1, rangeMarked || rangeWorded { return nil }
        if morning { return (Array(unique), 8, 12) }
        if afternoon { return (Array(unique), 12, 18) }
        if evening { return (Array(unique), 18, 22) }
        return (Array(unique), 9, 18)
    }

    /// The card for one tool row (read at `readAt`) and its question. The row has no window: the app reads 8 days
    /// from the capture day's start (`boundedAndCleaned`) and auxd never serves a copy over `STALE_AFTER_HOURS`
    /// (2 h, apple_eventkit.rs) old, so the days known read end at the start of (readAt − 2 h)'s day + 8.
    public static func make(toolText: String, question: String, now: Date, readAt: Date, calendar: Calendar = .current) -> CalendarCardModel? {
        guard let events = events(toolText), let window = window(question, now: now, calendar: calendar) else { return nil }
        let readFrom = calendar.startOfDay(for: readAt)
        let readTo = calendar.date(byAdding: .day, value: 8, to: calendar.startOfDay(for: readAt.addingTimeInterval(-2 * 3600))) ?? readFrom
        let incomplete = events.count >= capped
        let q = question.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
        let asksFree = ["free", "available", "availab", "slot", "libre", "dispo", "creneau"].contains { q.contains($0) }
        var rows: [CalendarCardRow] = []
        for day in window.days {
            guard let from = calendar.date(bySettingHour: window.from, minute: 0, second: 0, of: day),
                  let to = calendar.date(bySettingHour: window.to, minute: 0, second: 0, of: day),
                  let nextDay = calendar.date(byAdding: .day, value: 1, to: day) else { continue }
            guard day >= readFrom, nextDay <= readTo else { rows.append(CalendarCardRow(kind: .notChecked, start: day, end: nextDay, title: "")); continue }
            let allDay = events.filter { $0.allDay && $0.start < nextDay && $0.end > day }
            rows += allDay.map { CalendarCardRow(kind: .allDay, start: day, end: nextDay, title: $0.title) }
            let timed = events.filter { !$0.allDay && $0.start < to && $0.end > from }.sorted { $0.start < $1.start }
            // No Free row on a day an all-day event blocks, or from a capped list.
            let free = allDay.isEmpty && !incomplete
            var cursor = max(from, now)  // free time starts no earlier than the question
            for event in timed {
                if free, event.start.timeIntervalSince(cursor) >= minFree { rows.append(CalendarCardRow(kind: .free, start: cursor, end: event.start, title: "")) }
                rows.append(CalendarCardRow(kind: .event, start: event.start, end: event.end, title: event.title))
                cursor = max(cursor, event.end)
            }
            if free, to.timeIntervalSince(cursor) >= minFree { rows.append(CalendarCardRow(kind: .free, start: cursor, end: to, title: "")) }
        }
        guard rows.contains(where: { $0.kind != .notChecked }) else { return nil }
        return CalendarCardModel(asksFree: asksFree, rows: rows, readAt: readAt, incomplete: incomplete)
    }

    /// Puts each card on the agent reply that follows a calendar tool row, using
    /// the owner's last message before it as the question. Display only.
    public static func attach(_ messages: [ChatMessage], calendar: Calendar = .current) -> [ChatMessage] {
        var out = messages
        var question: ChatMessage?
        var toolRow: ChatMessage?
        for index in out.indices {
            switch out[index].author {
            case .you: question = out[index]; toolRow = nil
            // Only this tool's row makes a card, never other JSON of the same shape.
            case .tool: if out[index].toolName == "apple_calendar_list_events", events(out[index].text) != nil { toolRow = out[index] }
            case .agent:
                if let toolRow, let question {
                    let now = question.ts > 0 ? Date(timeIntervalSince1970: TimeInterval(question.ts) / 1000) : Date()
                    let readAt = toolRow.ts > 0 ? Date(timeIntervalSince1970: TimeInterval(toolRow.ts) / 1000) : now
                    out[index].calendarCard = make(toolText: toolRow.text, question: question.text, now: now, readAt: readAt, calendar: calendar)
                }
                toolRow = nil
            case .system: break
            }  // a system line between the tool row and the reply keeps the pair
        }
        return out
    }
}
