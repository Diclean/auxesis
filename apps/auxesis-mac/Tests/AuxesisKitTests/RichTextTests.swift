// The reply parser and the token chips.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class RichTextTests: XCTestCase {
    private func blocks(_ text: String) -> [MarkdownBlock] { MarkdownParser.parse(text) }

    func testEachBlockType() {
        let parsed = blocks("# Title\nSome *text*.\n\n- one\n- two\n\n1. a\n2) b\n\n> quoted\n> more\n\n---\n```swift\nlet x = 1\n```")
        XCTAssertEqual(parsed, [
            .heading("Title"), .paragraph("Some *text*."),
            .list(ordered: false, items: [ListItem(text: "one", children: []), ListItem(text: "two", children: [])]),
            .list(ordered: true, items: [ListItem(text: "a", children: []), ListItem(text: "b", children: [])]),
            .quote("quoted\nmore"), .rule, .code("let x = 1"),
        ])
    }

    func testTableKeepsAlignmentAndRightAlignsNumbers() {
        let parsed = blocks("| Invoice | Client | Amount |\n|:--|:-:|--:|\n| INV-1 | Acme | €1,204.00 |\n| INV-2 | Beta | €36 |")
        guard case .table(let table) = parsed.first else { return XCTFail("no table: \(parsed)") }
        XCTAssertEqual(table.header, ["Invoice", "Client", "Amount"])
        XCTAssertEqual(table.aligns, [.leading, .center, .trailing])
        XCTAssertEqual(table.rows.count, 2)
        XCTAssertEqual(table.alignment(of: 2), .trailing)
        let plain = blocks("| a | b |\n|---|---|\n| x | 12 |\n| y | 3,5 % |")
        guard case .table(let numeric) = plain.first else { return XCTFail("no table") }
        XCTAssertEqual([numeric.alignment(of: 0), numeric.alignment(of: 1)], [.leading, .trailing])
    }

    func testNestedListOneLevel() {
        XCTAssertEqual(blocks("- a\n  - a1\n  - a2\n- b"), [
            .list(ordered: false, items: [ListItem(text: "a", children: ["a1", "a2"]), ListItem(text: "b", children: [])]),
        ])
    }

    func testMalformedTableFallsBackToText() {
        XCTAssertEqual(blocks("| a | b |\n| x | y |"), [.paragraph("| a | b |\n| x | y |")])
        XCTAssertEqual(blocks("a | b\n--|--|--"), [.paragraph("a | b\n--|--|--")])
    }

    func testUnterminatedFenceRunsToTheEnd() {
        XCTAssertEqual(blocks("before\n```\nlet a = 1\nlet b = 2"), [.paragraph("before"), .code("let a = 1\nlet b = 2")])
    }

    /// Best of three, so one busy CI moment does not fail a sound parser.
    private func fastest(_ body: () -> Void) -> TimeInterval {
        (0..<3).map { _ in let t = Date(); body(); return Date().timeIntervalSince(t) }.min()!
    }

    func testFiveThousandLinesParseQuickly() {
        var text = ""
        for i in 0..<1_000 {
            text += "## Part \(i)\nA paragraph with **bold** and `code`.\n\n- item \(i)\n- next\n\n| a | b |\n|---|--:|\n| x | \(i) |\n"
        }
        var parsed: [MarkdownBlock] = []
        XCTAssertLessThan(fastest { parsed = blocks(text) }, 0.2)
        XCTAssertEqual(parsed.count, 4_000)
    }

    func testHostileInlineLinesParseInLinearTime() {
        let unit = ["[", "*", "`", "‹", "⟦", "[a](", "_x ", "[a b c removed", "**a "]
        for piece in unit {
            let line = String(repeating: piece, count: 100_000 / piece.count)
            XCTAssertLessThan(fastest { _ = InlineParser.parse(line) }, 0.2, piece)
        }
        let mixed = String(repeating: "[*`‹⟦](_", count: 12_500)
        XCTAssertLessThan(fastest { _ = InlineParser.parse(mixed) }, 0.2)
    }

    func testBigTableKeepsTwoThousandRowsAndAlignsOnce() {
        let rows = (0..<5_000).map { "| r\($0) | \($0) |" }.joined(separator: "\n")
        var parsed: [MarkdownBlock] = []
        XCTAssertLessThan(fastest { parsed = blocks("| a | b |\n|---|---|\n" + rows) }, 0.2)
        guard case .table(let table) = parsed.first else { return XCTFail("no table") }
        XCTAssertEqual(table.rows.count, MarkdownTable.maxRows)
        XCTAssertEqual(table.hiddenRows, 3_000)
        XCTAssertEqual([table.alignment(of: 0), table.alignment(of: 1)], [.leading, .trailing])
    }

    func testInlineSpans() {
        let runs = InlineParser.parse("A **bold** and *it* and `x_y` and [site](https://example.com/a) and snake_case")
        XCTAssertEqual(runs.filter(\.bold).map(\.text), ["bold"])
        XCTAssertEqual(runs.filter(\.italic).map(\.text), ["it"])
        XCTAssertEqual(runs.filter(\.code).map(\.text), ["x_y"])
        XCTAssertEqual(runs.compactMap(\.link), ["https://example.com/a"])
        XCTAssertTrue(runs.last!.text.hasSuffix("snake_case"))
    }

    func testTokenChipsForEveryPlaceholderTheDaemonEmits() {
        for text in ["[hidden]", "[name hidden]", "[nom masqué]", "[iban removed]", "[date of birth removed]", "[health 4412 removed]", "[auxesis: withheld]", "[message withheld for privacy]", "[message retiré pour confidentialité]", "[redacted]", "[redacted:EMAIL]", "[redacted:SEXUAL_ORIENTATION]", "⟦EMAIL_0123456789AB⟧", "‹email›"] {
            let runs = InlineParser.parse("Write to \(text) today")
            XCTAssertEqual(runs.filter(\.chip).map(\.text), [text], text)
            XCTAssertEqual(InlineParser.spoken(runs), "Write to hidden value today")
        }
    }

    func testNormalBracketsAreNotChips() {
        for text in ["see [1] and [note]", "a <tag> and </div>", "[link](https://example.com)", "[hidden stuff]", "[removed]", "[Invoice removed]", "[redacted:email]", "[a b c d e removed]", "⟦⟧", "‹›", "[ unclosed", "x [1]: y"] {
            XCTAssertTrue(InlineParser.parse(text).allSatisfy { !$0.chip }, text)
        }
        XCTAssertEqual(InlineParser.parse("[a](https://e.com/?q=[hidden])").filter(\.chip).count, 0)
    }
}
