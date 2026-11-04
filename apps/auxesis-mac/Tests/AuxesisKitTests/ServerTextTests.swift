// F5: server strings are sanitised before they reach the card — bidi/zero-width
// controls stripped, length capped with a visible marker, untrusted text
// delimited so it can never pass for a card label or close the quote block.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class ServerTextTests: XCTestCase {
    func testBidiZeroWidthAndControlCharactersAreStripped() {
        let raw = "sh\u{202E}ell\u{202C}\u{2066}x\u{2069}\u{200B}\u{200C}\u{200D}\u{200E}\u{200F}\u{2060}\u{FEFF}\u{00AD}\u{0007}\u{009F}"
        let cleaned = ServerText.clean(raw, maxLength: 100)
        XCTAssertEqual(cleaned, "shellx")
        for scalar in cleaned.unicodeScalars {
            XCTAssertFalse(ServerText.isStripped(scalar))
        }
    }

    func testNewlinesAndTabsBecomeOneSpaceNotFakeRows() {
        XCTAssertEqual(ServerText.clean("a\nb\tc", maxLength: 100), "a b c")
        XCTAssertEqual(ServerText.clean("  a \u{202E} \n b  ", maxLength: 100), "a b")
    }

    func testLengthIsCappedWithAVisibleMarker() {
        let cleaned = ServerText.clean(String(repeating: "a", count: 500), maxLength: 200)
        XCTAssertEqual(cleaned.count, 201)
        XCTAssertEqual(String(cleaned.dropLast()), String(repeating: "a", count: 200))
        XCTAssertTrue(cleaned.hasSuffix(ServerText.truncationMarker))
        // Short text is untouched by the cap.
        XCTAssertEqual(ServerText.clean("short", maxLength: 200), "short")
    }

    /// The cap counts Unicode scalars, not
    /// grapheme clusters. 10 000 combining marks are a single cluster, so a
    /// `String.count` cap never fired and a hostile id stayed unbounded.
    func testLengthCapCountsUnicodeScalarsNotGraphemes() {
        let combining = String(repeating: "\u{0301}", count: 10_000)
        XCTAssertLessThan(combining.count, 200, "one grapheme cluster, 10 000 scalars")
        let cleaned = ServerText.clean(combining, maxLength: 200)
        XCTAssertEqual(cleaned.unicodeScalars.count, 201, "200 scalars plus the marker")
        XCTAssertTrue(cleaned.hasSuffix(ServerText.truncationMarker))
    }

    /// Invisible and control characters are escaped, never silently dropped: two
    /// ids that differ only in those bytes stay distinguishable on screen.
    func testEscapedKeepsInvisibleAndControlCharactersVisible() {
        XCTAssertEqual(ServerText.escaped("\u{200B}", maxLength: 200), "\\u{200B}")
        XCTAssertEqual(ServerText.escaped("a\nb", maxLength: 200), "a\\u{000A}b")
        XCTAssertEqual(ServerText.escaped("sh\u{202E}ell", maxLength: 200), "sh\\u{202E}ell")
        // The bound is in scalars, independent of grapheme clustering.
        XCTAssertEqual(ServerText.escaped(String(repeating: "\u{0301}", count: 10_000), maxLength: 200).unicodeScalars.count, 200)
    }

    /// Regression (PR #104, security review R3 P2 B): the escape rule is driven by
    /// `generalCategory`, not by a closed list. Line and paragraph separators,
    /// format characters the old list missed, zero-width spaces and a C1 control
    /// are all escaped, so a server field can never cut the card into rows.
    func testCategoryRuleEscapesLineBreaksFormatsAndExoticSpaces() {
        let hostile = "\u{2028}\u{2029}\u{206A}\u{206B}\u{200B}\u{0085}"
        XCTAssertEqual(
            ServerText.escaped(hostile, maxLength: 200),
            "\\u{2028}\\u{2029}\\u{206A}\\u{206B}\\u{200B}\\u{0085}"
        )

        let quoted = ServerText.quoted(hostile, maxLength: 200)
        for escape in ["\\u{2028}", "\\u{2029}", "\\u{206A}", "\\u{206B}", "\\u{200B}", "\\u{0085}"] {
            XCTAssertTrue(quoted.contains(escape), "missing \(escape) in \(quoted)")
        }
        for scalar in hostile.unicodeScalars {
            XCTAssertFalse(
                quoted.unicodeScalars.contains(scalar),
                "raw U+\(String(scalar.value, radix: 16)) leaked into the card"
            )
        }
        XCTAssertFalse(quoted.contains("\n"), "no server field may add a card row")
        XCTAssertFalse(quoted.contains("\r"))

        // `clean` (non-quoted fields) folds a line separator instead of showing it.
        XCTAssertEqual(ServerText.clean("a\u{2028}b", maxLength: 100), "a b")
    }

    /// The category rule also covers exotic spaces, private-use and unassigned
    /// scalars; ASCII space U+0020 is the only space left alone.
    func testCategoryRuleKeepsAsciiSpaceAndEscapesOtherSpaces() {
        XCTAssertEqual(ServerText.escaped("a b", maxLength: 200), "a b")
        XCTAssertEqual(ServerText.escaped("a\u{00A0}b", maxLength: 200), "a\\u{00A0}b")
        XCTAssertEqual(ServerText.escaped("\u{E000}", maxLength: 200), "\\u{E000}")
        XCTAssertEqual(ServerText.escaped("\u{10FFFF}", maxLength: 200), "\\u{10FFFF}")
    }

    /// Regression (PR #104, security review R5 P2 B): the strict escape spelling uses a
    /// backslash, so the strict rule must escape the ASCII backslash itself
    /// (doubling it). Otherwise a literal `\u{200B}` renders like a real U+200B.
    /// The category rule used by known labels is unchanged.
    func testStrictRuleDoublesAsciiBackslashSoEscapesStayUnambiguous() {
        XCTAssertEqual(ServerText.escapedStrict("\\", maxLength: 10), "\\\\")
        XCTAssertEqual(ServerText.escapedStrict("a\\b", maxLength: 10), "a\\\\b")
        XCTAssertEqual(ServerText.escapedStrict("\\u{200B}", maxLength: 20), "\\\\u{200B}")
        XCTAssertEqual(ServerText.escapedStrict("\u{200B}", maxLength: 10), "\\u{200B}")
        XCTAssertNotEqual(
            ServerText.escapedStrict("\\u{200B}", maxLength: 20),
            ServerText.escapedStrict("\u{200B}", maxLength: 10)
        )
        // The category rule keeps a lone backslash as-is: known labels are
        // untouched by the unknown-id fix.
        XCTAssertEqual(ServerText.escaped("a\\b", maxLength: 10), "a\\b")
    }

    func testQuotedBlockDelimitersCannotBeSpoofed() {
        let text = ServerText.quoted("evil » Why « Portée » " + String(repeating: "x", count: 1000), maxLength: 40)
        XCTAssertTrue(text.hasPrefix("« "))
        XCTAssertTrue(text.hasSuffix(" »"))
        XCTAssertEqual(text.filter { $0 == "»" }.count, 1, "server text must not close the quoted block")
        XCTAssertEqual(text.filter { $0 == "«" }.count, 1)
        XCTAssertTrue(text.contains("‹"))
        XCTAssertTrue(text.contains("›"))
        XCTAssertTrue(text.contains(ServerText.truncationMarker))
    }

    func testScopeSpoofAttemptStaysInsideTheQuote() {
        // The classic: a scope string trying to look like the card's own
        // "Portée" row, plus a bidi override to reorder it.
        let scopeTool = "shell\u{202E} « Portée : shell.allow_all »"
        let scopeRule = "ask\nPourquoi : rien"
        let line = ServerText.quoted(scopeTool, maxLength: ServerText.Limits.scopeTool)
            + " · "
            + ServerText.quoted(scopeRule, maxLength: ServerText.Limits.scopeRule)
        XCTAssertEqual(line.filter { $0 == "»" }.count, 2, "exactly the two local closers")
        XCTAssertEqual(line.filter { $0 == "«" }.count, 2)
        XCTAssertFalse(line.contains("\u{202E}"))
        XCTAssertFalse(line.contains("\n"))
        XCTAssertTrue(line.hasPrefix("« "))
        XCTAssertTrue(line.hasSuffix(" »"))
    }

    func testEveryLimitIsFiniteAndPositive() {
        let limits = [
            ServerText.Limits.agentName, ServerText.Limits.action, ServerText.Limits.headline,
            ServerText.Limits.preview, ServerText.Limits.fullPreview, ServerText.Limits.detailLine,
            ServerText.Limits.why, ServerText.Limits.taint, ServerText.Limits.cleanNote,
            ServerText.Limits.scopeTool, ServerText.Limits.scopeRule, ServerText.Limits.verifierModel,
            ServerText.Limits.verifierRationale, ServerText.Limits.checkLabel, ServerText.Limits.hostNotice,
        ]
        for limit in limits {
            XCTAssertGreaterThan(limit, 0)
            XCTAssertLessThanOrEqual(
                limit,
                limit == ServerText.Limits.fullPreview ? 12000 : 8000
            )
        }
    }
}
