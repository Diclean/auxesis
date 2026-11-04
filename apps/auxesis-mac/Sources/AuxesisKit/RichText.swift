// Agent replies as blocks, tables and chips. Pure text in,
// values out. Nothing here fetches, opens or evaluates anything: a link is
// only text with a host, an image is only text, HTML stays literal.
import Foundation

public struct MarkdownTable: Equatable {
    public enum Align: Equatable { case leading, center, trailing }
    /// Rows kept for display; a longer table keeps this many and counts the rest in `hiddenRows`.
    public static let maxRows = 2_000
    public var header: [String]
    public var aligns: [Align]
    public var rows: [[String]]
    public var hiddenRows = 0
    /// The author's alignment, or right for a column whose every cell is a number or an amount. Computed once.
    public private(set) var columns: [Align]

    public init(header: [String], aligns: [Align], rows: [[String]], hiddenRows: Int = 0) {
        (self.header, self.aligns, self.rows, self.hiddenRows) = (header, aligns, rows, hiddenRows)
        columns = aligns.indices.map { column in
            if aligns[column] != .leading { return aligns[column] }
            var seen = false
            for row in rows {
                let cell = row[column].trimmingCharacters(in: .whitespaces)
                if cell.isEmpty { continue }
                if !Self.isNumeric(cell) { return .leading }
                seen = true
            }
            return seen ? .trailing : .leading
        }
    }

    public func alignment(of column: Int) -> Align { columns[column] }

    static func isNumeric(_ cell: String) -> Bool {
        var digits = 0
        for ch in cell {
            if ch.isNumber { digits += 1 } else if !"€$£¥%+-−.,:'’ \u{A0}\u{202F}".contains(ch) { return false }
        }
        return digits > 0
    }
}

public struct ListItem: Equatable {
    public var text: String
    public var children: [String]
}

public enum MarkdownBlock: Equatable {
    case paragraph(String)
    case heading(String)
    case list(ordered: Bool, items: [ListItem])
    case quote(String)
    case code(String)
    case rule
    case table(MarkdownTable)
}

public enum MarkdownParser {
    public static func parse(_ source: String) -> [MarkdownBlock] {
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map { $0.hasSuffix("\r") ? $0.dropLast() : $0 }
        var blocks: [MarkdownBlock] = []
        var paragraph: [Substring] = []
        func flush() {
            if !paragraph.isEmpty { blocks.append(.paragraph(paragraph.joined(separator: "\n"))) }
            paragraph = []
        }
        var i = 0
        while i < lines.count {
            let line = lines[i]
            let trimmed = line.drop { $0 == " " }
            if trimmed.hasPrefix("```") || trimmed.hasPrefix("~~~") {
                flush()
                let fence = trimmed.prefix(3)
                var body: [Substring] = []
                i += 1
                while i < lines.count, !lines[i].drop(while: { $0 == " " }).hasPrefix(fence) { body.append(lines[i]); i += 1 }
                blocks.append(.code(body.joined(separator: "\n")))   // an unterminated fence runs to the end
                i += 1
            } else if trimmed.allSatisfy({ $0 == " " }) {
                flush(); i += 1
            } else if let heading = headingText(trimmed) {
                flush(); blocks.append(.heading(heading)); i += 1
            } else if isRule(trimmed) {
                flush(); blocks.append(.rule); i += 1
            } else if trimmed.hasPrefix(">") {
                flush()
                var quoted: [String] = []
                while i < lines.count, lines[i].drop(while: { $0 == " " }).hasPrefix(">") {
                    var text = lines[i].drop { $0 == " " }.dropFirst()
                    if text.first == " " { text = text.dropFirst() }
                    quoted.append(String(text)); i += 1
                }
                blocks.append(.quote(quoted.joined(separator: "\n")))
            } else if marker(line) != nil {
                flush()
                var items: [ListItem] = []
                let ordered = marker(line)!.ordered
                while i < lines.count, let m = marker(lines[i]) {
                    if m.indent >= 2, !items.isEmpty { items[items.count - 1].children.append(m.text) }
                    else { items.append(ListItem(text: m.text, children: [])) }
                    i += 1
                }
                blocks.append(.list(ordered: ordered, items: items))
            } else if i + 1 < lines.count, line.contains("|"), let table = table(lines, from: i) {
                flush(); blocks.append(.table(table.0)); i = table.1
            } else {
                paragraph.append(line); i += 1
            }
        }
        flush()
        return blocks
    }

    private static func headingText(_ line: Substring) -> String? {
        let hashes = line.prefix { $0 == "#" }
        guard (1...6).contains(hashes.count), line.dropFirst(hashes.count).first == " " else { return nil }
        return line.dropFirst(hashes.count).trimmingCharacters(in: .whitespaces)
    }

    private static func isRule(_ line: Substring) -> Bool {
        let body = line.filter { $0 != " " }
        guard body.count >= 3, let first = body.first, "-*_".contains(first) else { return false }
        return body.allSatisfy { $0 == first }
    }

    private static func marker(_ line: Substring) -> (indent: Int, ordered: Bool, text: String)? {
        let indent = line.prefix { $0 == " " }.count
        let rest = line.dropFirst(indent)
        if let first = rest.first, "-*+".contains(first), rest.dropFirst().first == " ", !isRule(rest) {
            return (indent, false, rest.dropFirst(2).trimmingCharacters(in: .whitespaces))
        }
        let digits = rest.prefix { $0.isASCII && $0.isNumber }
        let after = rest.dropFirst(digits.count)
        if !digits.isEmpty, digits.count <= 9, let p = after.first, ".)".contains(p), after.dropFirst().first == " " {
            return (indent, true, after.dropFirst(2).trimmingCharacters(in: .whitespaces))
        }
        return nil
    }

    private static func cells(_ line: Substring) -> [String] {
        var parts = line.split(separator: "|", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.first == "" { parts.removeFirst() }
        if parts.last == "" { parts.removeLast() }
        return parts
    }

    /// A header row, a `---` row of the same width, then body rows. Anything else is not a table.
    private static func table(_ lines: [Substring], from start: Int) -> (MarkdownTable, Int)? {
        let header = cells(lines[start])
        let rule = cells(lines[start + 1])
        guard header.count >= 2, rule.count == header.count else { return nil }
        var aligns: [MarkdownTable.Align] = []
        for cell in rule {
            let core = cell.trimmingCharacters(in: CharacterSet(charactersIn: ":"))
            guard !core.isEmpty, core.allSatisfy({ $0 == "-" }) else { return nil }
            aligns.append(cell.hasSuffix(":") ? (cell.hasPrefix(":") ? .center : .trailing) : .leading)
        }
        var rows: [[String]] = []
        var hidden = 0
        var i = start + 2
        while i < lines.count, lines[i].contains("|"), !lines[i].allSatisfy({ $0 == " " }) {
            if rows.count < MarkdownTable.maxRows {
                var row = cells(lines[i])
                row = Array((row + Array(repeating: "", count: header.count)).prefix(header.count))
                rows.append(row)
            } else { hidden += 1 }
            i += 1
        }
        return (MarkdownTable(header: header, aligns: aligns, rows: rows, hiddenRows: hidden), i)
    }
}

/// One styled stretch of a line.
public struct InlineRun: Equatable {
    public var text: String
    public var bold = false
    public var italic = false
    public var code = false
    /// The link target, shown as text only; the app never opens it.
    public var link: String?
    /// A value the daemon replaced.
    public var chip = false
}

/// The placeholders the daemon puts where it hid a value (crates/auxd/src/api/display.rs,
/// the kernel's `crates/kernel-privacy/src/safetext.rs`, crates/aux-engine/src/{prompt,trust}.rs and
/// engine/privacy.rs): `[hidden]`, `[name hidden]`, `[nom masqué]`, `[<class> removed]`
/// (class: iban, card, health, address, id, secret, MRN … , optionally with digits),
/// `[auxesis: withheld]`, `[message withheld for privacy]` and its French twin,
/// `[redacted]`, `[redacted:KIND]`, `⟦KIND_HEX⟧`, and the design label `‹email›`.
/// Ordinary brackets (`[1]`, `<tag>`, `[link](url)`, `[Invoice removed]`) are not chips.
public enum TokenChip {
    static let fixed: Set<String> = [
        "hidden", "name hidden", "nom masqué", "auxesis: withheld", "redacted",
        "message withheld for privacy", "message retiré pour confidentialité",
    ]
    static let classes: Set<String> = [
        "iban", "card", "health", "address", "id", "secret", "mrn", "date", "phone", "email", "name", "passport", "tax", "vat", "ssn",
    ]

    /// Whether the text between `[` and `]` is a daemon placeholder.
    static func isBracket(_ inner: ArraySlice<Character>) -> Bool {
        let text = String(inner)
        if fixed.contains(text) { return true }
        if text.hasPrefix("redacted:") {
            let kind = text.dropFirst(9)
            return !kind.isEmpty && kind.count <= 40 && kind.allSatisfy { $0.isASCII && ($0.isUppercase || $0 == "_") }
        }
        guard text.hasSuffix(" removed") else { return false }
        let words = text.dropLast(8).split(separator: " ", omittingEmptySubsequences: false)
        return (1...4).contains(words.count) && classes.contains(words[0].lowercased())
            && words.allSatisfy { !$0.isEmpty && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) } }
    }

    /// Length in characters of the chip starting at `chars[i]`, given the index of the next closer.
    static func length(_ chars: [Character], at i: Int, close: Int?) -> Int? {
        guard let close, close - i <= 80, close > i + 1 else { return nil }
        let inner = chars[(i + 1)..<close]
        guard !inner.contains(chars[i]) else { return nil }   // an opener inside: not this closer's partner
        switch chars[i] {
        case "[": return isBracket(inner) ? close - i + 1 : nil
        case "⟦": return inner.reduce(0) { $0 + String($1).utf8.count } <= 64 ? close - i + 1 : nil
        default: return inner.count <= 24 ? close - i + 1 : nil   // ‹email›
        }
    }
}

/// The kernel's removal marker (`removal_text` in
/// the kernel's `crates/kernel-privacy/src/safetext.rs`) is one stable English text: the
/// model sees it and the daemon stores it. Only the chip shown to the owner
/// follows the reply's language; the stored and copied text never changes.
public enum RemovalMarker {
    private static let french: [String: String] = [
        "[iban removed]": "[IBAN retiré]",
        "[card removed]": "[carte retirée]",
        "[health removed]": "[santé retirée]",
        "[address removed]": "[adresse retirée]",
        "[date of birth removed]": "[date de naissance retirée]",
        "[id removed]": "[pièce d’identité retirée]",
        "[secret removed]": "[secret retiré]",
    ]

    /// The chip's text for a reply in `language`: a known marker in French,
    /// anything else as the daemon wrote it.
    public static func display(_ chip: String, language: Language) -> String {
        language == .fr ? french[chip] ?? chip : chip
    }

    private static let frenchWords: Set<String> = [
        "le", "la", "les", "de", "des", "du", "un", "une", "et", "est", "je", "tu", "ton", "ta", "tes",
        "mon", "ma", "mes", "pas", "que", "qui", "pour", "dans", "sur", "avec", "ce", "cette", "il",
        "elle", "nous", "vous", "au", "aux", "ne", "ai", "j", "l", "d", "c", "qu", "n", "sont", "mais",
    ]
    private static let englishWords: Set<String> = [
        "the", "a", "an", "and", "is", "are", "i", "you", "your", "my", "not", "that", "to", "of",
        "in", "on", "with", "it", "this", "for", "be", "was", "have", "will", "there", "but",
    ]

    /// The language a reply is written in: French when its common French words
    /// outnumber its common English ones, English otherwise (the base language).
    public static func language(of reply: String) -> Language {
        var french = 0, english = 0
        for word in reply.lowercased().split(whereSeparator: { !$0.isLetter }) {
            if frenchWords.contains(String(word)) { french += 1 }
            if englishWords.contains(String(word)) { english += 1 }
        }
        return french > english ? .fr : .en
    }
}

/// One piece of a line: plain words, or a protected value the daemon replaced
/// (drawn as a lock chip).
public enum TokenPart: Equatable {
    case text(String)
    case token(String)

    /// The characters of the part, the chip's own spelling included: the text
    /// the owner reads, whatever the daemon hid.
    public var text: String {
        switch self {
        case .text(let text): return text
        case .token(let token): return token
        }
    }

    /// The part as an inline run: words, or a chip for a protected value.
    public var run: InlineRun {
        switch self {
        case .text(let text): return InlineRun(text: text)
        case .token(let token): return InlineRun(text: token, chip: true)
        }
    }
}

/// Splits a line into words and protected values, and nothing else. A markdown
/// link keeps its brackets and its URL, a `*` and a backtick stay characters:
/// only the daemon's own placeholders become chips. The approval the owner
/// sends is read exactly as it was written.
public enum TokenParser {
    /// The parts of a line.
    public static func parts(_ line: String) -> [TokenPart] {
        let chars = Array(line)
        var parts: [TokenPart] = []
        var plain = ""
        var index = 0
        while index < chars.count {
            let char = chars[index]
            let closer: Character? = char == "[" ? "]" : char == "⟦" ? "⟧" : char == "‹" ? "›" : nil
            if let closer, let length = TokenChip.length(chars, at: index, close: find(chars, closer, from: index + 1)) {
                if !plain.isEmpty { parts.append(.text(plain)); plain = "" }
                parts.append(.token(String(chars[index..<(index + length)])))
                index += length
                continue
            }
            plain.append(char)
            index += 1
        }
        if !plain.isEmpty { parts.append(.text(plain)) }
        return parts
    }

    /// The first words of a line, cut at a word boundary. A token is never
    /// split: it is kept whole, or left out.
    public static func short(_ parts: [TokenPart], limit: Int = 48) -> [TokenPart] {
        var out: [TokenPart] = []
        var used = 0
        for part in parts {
            switch part {
            case .text(let text):
                guard used + text.count > limit else {
                    out.append(.text(text)); used += text.count; continue
                }
                let head = String(text.prefix(max(limit - used, 0)))
                let cut = head.split(separator: " ").dropLast().joined(separator: " ")
                if !cut.isEmpty { out.append(.text(cut + "…")) }
                return out
            case .token(let token):
                out.append(.token(token))
            }
        }
        return out
    }

    /// What a screen reader says: a chip is "hidden value", never its spelling.
    public static func spoken(_ parts: [TokenPart]) -> String {
        var out = ""
        for part in parts {
            switch part {
            case .text(let text):
                out += text
            case .token:
                if out.last.map({ !$0.isWhitespace }) == true { out += " " }
                out += "hidden value"
            }
        }
        return out
    }

    /// The next closer, at most 80 characters away (a chip is never longer).
    private static func find(_ chars: [Character], _ closer: Character, from start: Int) -> Int? {
        let end = min(chars.count, start + 80)
        var index = start
        while index < end {
            if chars[index] == closer { return index }
            index += 1
        }
        return nil
    }
}

public enum InlineParser {
    /// Position of the next occurrence of each pattern, filled in one backward pass
    /// the first time it is asked for, so a line of unclosed brackets stays linear.
    private final class Finder {
        let chars: [Character]
        var next: [String: [Int]] = [:]
        init(_ chars: [Character]) { self.chars = chars }

        func find(_ pattern: String, from i: Int) -> Int? {
            let key = Array(pattern)
            if next[pattern] == nil {
                var table = [Int](repeating: -1, count: chars.count + 1)
                var k = chars.count - key.count
                var last = -1
                while k >= 0 {
                    if chars[k] == key[0], key.count == 1 || chars[k + 1] == key[1] { last = k }
                    table[k] = last; k -= 1
                }
                for j in max(0, chars.count - key.count + 1)..<chars.count { table[j] = -1 }
                next[pattern] = table
            }
            guard i < chars.count, let hit = next[pattern]?[i], hit >= 0 else { return nil }
            return hit
        }
    }

    public static func parse(_ line: String) -> [InlineRun] {
        let chars = Array(line)
        return scan(chars, from: 0, to: chars.count, Finder(chars), bold: false, italic: false)
    }

    /// The runs of one line of a reply written in `replyLanguage`: a removal
    /// marker chip reads in that language (display only).
    public static func parse(_ line: String, replyLanguage: Language) -> [InlineRun] {
        parse(line).map { run in
            guard run.chip else { return run }
            var shown = run
            shown.text = RemovalMarker.display(run.text, language: replyLanguage)
            return shown
        }
    }

    private static func scan(_ chars: [Character], from start: Int, to end: Int, _ finder: Finder, bold: Bool, italic: Bool) -> [InlineRun] {
        var runs: [InlineRun] = []
        var plain = ""
        func flush() { if !plain.isEmpty { runs.append(InlineRun(text: plain, bold: bold, italic: italic)); plain = "" } }
        func text(_ a: Int, _ b: Int) -> String { String(chars[a..<b]) }
        var i = start
        var previous: Character = " "
        while i < end {
            let ch = chars[i]
            let closer: String? = ch == "[" ? "]" : ch == "⟦" ? "⟧" : ch == "‹" ? "›" : nil
            if let closer, let n = TokenChip.length(chars, at: i, close: finder.find(closer, from: i + 1).flatMap { $0 < end ? $0 : nil }) {
                flush(); runs.append(InlineRun(text: text(i, i + n), bold: bold, italic: italic, chip: true))
                i += n; previous = "]"; continue
            }
            if ch == "`", let close = finder.find("`", from: i + 1), close < end {
                flush(); runs.append(InlineRun(text: text(i + 1, close), code: true))
                i = close + 1; previous = "`"; continue
            }
            if ch == "[", let mid = finder.find("](", from: i + 1), mid < end, mid - i <= 200,
               !chars[(i + 1)..<mid].contains("["), let close = finder.find(")", from: mid + 2), close < end, close - mid <= 2_048 {
                flush()
                runs.append(InlineRun(text: text(i + 1, mid), bold: bold, italic: italic, link: text(mid + 2, close)))
                i = close + 1; previous = ")"; continue
            }
            if ch == "*" || ch == "_", let (inner, next) = emphasis(chars, at: i, to: end, finder, previous: previous, bold: bold, italic: italic) {
                flush(); runs += inner; i = next; previous = "*"; continue
            }
            plain.append(ch); previous = ch; i += 1
        }
        flush()
        return runs
    }

    /// `**bold**`, `__bold__`, `*italic*`, `_italic_` (an underscore inside a word stays text).
    private static func emphasis(_ chars: [Character], at i: Int, to end: Int, _ finder: Finder, previous: Character, bold: Bool, italic: Bool) -> ([InlineRun], Int)? {
        let ch = chars[i]
        let double = i + 1 < end && chars[i + 1] == ch
        let delimiter = String(repeating: ch, count: double ? 2 : 1)
        let from = i + delimiter.count
        if ch == "_", previous.isLetter || previous.isNumber { return nil }
        guard from < end, chars[from] != " ", let close = finder.find(delimiter, from: from), close < end,
              close > from, chars[close - 1] != " " else { return nil }
        return (scan(chars, from: from, to: close, finder, bold: bold || double, italic: italic || !double), close + delimiter.count)
    }

    /// What a screen reader says: chips are "hidden value", never their spelling.
    public static func spoken(_ runs: [InlineRun]) -> String {
        runs.map { $0.chip ? "hidden value" : $0.text }.joined()
    }
}
