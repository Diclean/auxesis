// Server text is hostile input. Every string the approval card shows (and the
// endpoint-rejection notice) comes from the daemon or the environment, so it is
// sanitised at render time:
//
//   * one rule decides what may never be shown raw — the Unicode general
//     category. Control (Cc) and format (Cf) scalars can hide or reorder a
//     scope; line/paragraph separators (Zl/Zp) and non-ASCII spaces (Zs) can
//     forge an extra card row or pad a label; private-use (Co) and unassigned
//     (Cn) scalars have no dependable glyph. ASCII space U+0020 is the single
//     exception. A category rule is used instead of a hand-kept list because a
//     closed list always misses a code point (U+206A, U+2028, …).
//   * `clean` removes the invisible ones (Cf/Co/Cn) and folds the row-breaking
//     ones (Cc/Zl/Zp/Zs) into one space, so a crafted `why` can never fabricate
//     extra card rows;
//   * `quoted` and the unknown-id rendering escape every such scalar as a
//     visible `\u{XXXX}` instead of dropping it, so two ids that differ only in
//     invisible or separator bytes stay tellable apart;
//   * a tool **identifier** is never passed to `quoted` raw: it goes through
//     `quotedIdentifier`, whose strict escape also spells out the quote
//     delimiters (guillemets, ❝❞, the ASCII quotes). `quoted` demotes those to
//     keep a free-text block unambiguous, and demotion would make two distinct
//     ids — `x«y`, `x‹y`, `x❝y` — render as one and the same label;
//   * output is capped with a visible truncation marker (`…`), so a 1 MB
//     headline cannot build a 1 MB `Text`.
//
// `quoted()` is the only shape the card renders server text in: the sanitised
// body sits between fixed local guillemets, and any guillemets inside the body
// are demoted to their single forms, so untrusted text can never close the
// block or pass for a card label (Why / Checks / Provenance / Scope).
import Foundation

public enum ServerText {
    /// The truncation marker appended when text is capped.
    public static let truncationMarker = "…"

    /// Per-field caps. Generous enough for real asks, small enough that a
    /// hostile frame cannot build an unbounded `Text`.
    public enum Limits {
        public static let agentName = 60
        public static let action = 80
        public static let headline = 200
        public static let preview = 280
        public static let fullPreview = 12000
        public static let detailLine = 240
        public static let why = 400
        public static let taint = 120
        public static let cleanNote = 240
        public static let scopeTool = 80
        /// Unknown tool ids are spelled out so two distinct ids cannot render
        /// identically; this only bounds a hostile 1 MB id, it is far above any
        /// real identifier (see `ReceiptDetailCopy.friendlyTool`).
        public static let unknownTool = 200
        public static let scopeRule = 240
        public static let scopeResource = 160
        public static let verifierModel = 80
        public static let verifierRationale = 400
        public static let checkLabel = 80
        public static let checkGate = 40
        public static let unknownState = 60
        public static let hostNotice = 80
    }

    /// The one rule for scalars the card must never show raw. `generalCategory`
    /// decides, never a hand-kept list: a closed list always misses a code point
    /// (`U+206A`, `U+2028`, …). ASCII space U+0020 is the sole exception.
    static func isEscaped(_ scalar: Unicode.Scalar) -> Bool {
        if scalar == " " { return false }
        switch scalar.properties.generalCategory {
        case .control, .format,
             .lineSeparator, .paragraphSeparator, .spaceSeparator,
             .privateUse, .unassigned:
            return true
        default:
            return false
        }
    }

    /// True for the scalars `clean` drops outright: no dependable glyph to show
    /// and nothing to space out.
    public static func isStripped(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .format, .privateUse, .unassigned: return true
        default: return false
        }
    }

    /// True for the scalars that act as a break or a space: `clean` folds each
    /// into one ASCII space so it can never start a new card row.
    static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .control, .lineSeparator, .paragraphSeparator, .spaceSeparator: return true
        default: return false
        }
    }

    /// Renders one scalar as a literal `\u{XXXX}` escape. Used where an id must
    /// stay tellable apart on screen: an invisible or control character is shown
    /// as an escape, never silently dropped.
    static func escapedScalar(_ scalar: Unicode.Scalar) -> String {
        String(format: "\\u{%04X}", scalar.value)
    }

    /// The stricter rule reserved for **unknown tool ids**: every scalar outside
    /// printable ASCII (`!`…`~`, U+0021…U+007E) is escaped, ASCII space U+0020
    /// included, and so are the ASCII quotes U+0022/U+0027. The category rule is
    /// not enough there — a combining mark (category Mn, e.g. U+034F) carries no
    /// advance width, so `mystery` and `mystery\u{034F}` render identically while
    /// "Allow once" stays available; and the quote delimiters (U+00AB «, U+00BB »,
    /// U+2039 ‹, U+203A ›, U+275D ❝, U+275E ❞, U+201C/U+201D/U+2018/U+2019, the
    /// ASCII `"` and `'`) must never be shown raw, or `quoted` would demote them
    /// and two distinct ids would share one label. Escaping every non-ASCII scalar
    /// keeps them visibly distinct; escaping the space too keeps an id made only of
    /// spaces from rendering as a blank block that another all-space id could
    /// imitate (`\u{0020}` vs `\u{00A0}`).
    /// Known labels never go through this rule.
    static func isEscapedStrict(_ scalar: Unicode.Scalar) -> Bool {
        if scalar == "\"" || scalar == "'" { return true }
        return scalar.value <= 0x20 || scalar.value > 0x7E
    }

    /// The card-safe rendering of an id that must remain distinguishable: every
    /// scalar the category rule flags becomes a visible `\u{XXXX}` escape. At
    /// most `maxLength` **Unicode scalars** are kept (the bound counts scalars,
    /// never grapheme clusters), and the caller adds any truncation marker: the
    /// raw scalar count stays available through `unicodeScalars.count` on the
    /// input.
    public static func escaped(_ raw: String, maxLength: Int) -> String {
        escaped(raw, maxLength: maxLength, escaping: isEscaped)
    }

    /// `escaped` under the unknown-id rule above: every scalar outside printable
    /// ASCII (`!`…`~`) is spelled out — ASCII space and NBSP included — so two
    /// ids that differ only by a space, a combining mark, an accent or any other
    /// width-less/invisible scalar stay distinct. The ASCII backslash itself is
    /// doubled (`\\`), because the escape spelling uses a backslash: without
    /// this, a literal `\u{200B}` and a real U+200B would render identically.
    /// Same scalar bound and count semantics as `escaped`.
    public static func escapedStrict(_ raw: String, maxLength: Int) -> String {
        escaped(
            raw,
            maxLength: maxLength,
            escaping: isEscapedStrict,
            escapingBackslash: true
        )
    }

    private static func escaped(
        _ raw: String,
        maxLength: Int,
        escaping: (Unicode.Scalar) -> Bool,
        escapingBackslash: Bool = false
    ) -> String {
        let limit = max(0, maxLength)
        var out = ""
        var written = 0
        for scalar in raw.unicodeScalars {
            if written >= limit { break }
            written += 1
            if escaping(scalar) {
                out += escapedScalar(scalar)
            } else if escapingBackslash, scalar == "\\" {
                out += "\\\\"
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    /// Strips the invisible format/private scalars, collapses the row-breaking
    /// ones (controls, line/paragraph separators, exotic spaces) to one ASCII
    /// space and caps the result with `…`. The cap counts **Unicode scalars**,
    /// not grapheme clusters, so an id of 10 000 combining marks is still
    /// bounded. Never returns more than `maxLength + 1` scalars.
    public static func clean(_ raw: String, maxLength: Int) -> String {
        let limit = max(0, maxLength)
        var scalars = String.UnicodeScalarView()
        var pendingSpace = false // a space/control seen, not yet flushed
        var hasContent = false
        for scalar in raw.unicodeScalars {
            if scalar == " " || isControl(scalar) {
                if hasContent { pendingSpace = true }
                continue
            }
            if isStripped(scalar) { continue }
            if pendingSpace {
                scalars.append(" ")
                pendingSpace = false
            }
            scalars.append(scalar)
            hasContent = true
        }
        let cleaned = String(scalars)
        guard limit > 0, cleaned.unicodeScalars.count > limit else { return cleaned }
        var head = String.UnicodeScalarView()
        head.append(contentsOf: cleaned.unicodeScalars.prefix(limit))
        return String(head) + truncationMarker
    }

    /// The card's rendering of free server text: `« sanitised body »`, with
    /// delimiter lookalikes inside the body demoted so the block boundary stays
    /// unambiguous. Every scalar the category rule flags is spelled out as a
    /// `\u{XXXX}` escape, so a server field can never inject a real line break
    /// (`U+2028`, `U+2029`, `U+0085`) or an invisible format it smuggled in.
    /// A tool **identifier** must not go through this raw (the demotion would
    /// merge two distinct ids): use `quotedIdentifier`.
    public static func quoted(_ raw: String, maxLength: Int) -> String {
        let limit = max(0, maxLength)
        var scalars = String.UnicodeScalarView()
        var written = 0
        for scalar in raw.unicodeScalars {
            if written >= limit { break }
            written += 1
            if isEscaped(scalar) {
                scalars.append(contentsOf: escapedScalar(scalar).unicodeScalars)
            } else {
                scalars.append(scalar)
            }
        }
        var body = String(scalars)
        if raw.unicodeScalars.count > limit {
            body += truncationMarker
        }
        body = body
            .replacingOccurrences(of: "«", with: "‹")
            .replacingOccurrences(of: "»", with: "›")
            .replacingOccurrences(of: "❝", with: "‹")
            .replacingOccurrences(of: "❞", with: "›")
        return "« \(body) »"
    }

    /// The card's quote block for a tool **identifier**. Unlike free text, an id
    /// must stay tellable apart from every other id, so the body is put through
    /// the strict unknown-id rule first: every quote delimiter smuggled into the
    /// id is spelled out (`\u{00AB}`, `\u{2039}`, `\u{275D}`, `\u{0022}`, …)
    /// instead of being demoted by `quoted`, which would let `x«y`, `x‹y` and
    /// `x❝y` render as one and the same label. Known ids are made of kept ASCII
    /// scalars, so their rendering is unchanged; a literal backslash is doubled,
    /// so `\u{200B}` never imitates a real U+200B. The bound counts Unicode
    /// scalars and the `…` marker is added when the raw id is capped.
    public static func quotedIdentifier(_ raw: String, maxLength: Int) -> String {
        let limit = max(0, maxLength)
        var body = escapedStrict(raw, maxLength: limit)
        if raw.unicodeScalars.count > limit {
            body += truncationMarker
        }
        // The body is already escaped and bounded above, so `quoted` only adds
        // the local delimiters.
        return quoted(body, maxLength: Int.max)
    }
}
