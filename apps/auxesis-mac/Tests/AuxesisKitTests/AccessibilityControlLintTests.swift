import Foundation
import XCTest

/// Static guard for accessibility metadata on SwiftUI controls in the Mac app.
/// It parses each control expression and only inspects that expression's own
/// postfix modifier chain, stopping before the next sibling statement.
@objcMembers @MainActor final class AccessibilityControlLintTests: XCTestCase {
    private struct Token {
        let text: String
        let line: Int
    }

    private struct Control {
        let name: String
        let line: Int
        let hasLabel: Bool
        let hasIdentifier: Bool
    }

    private let controlNames: Set<String> = [
        "Button", "Toggle", "Picker", "Menu", "TextField", "TextEditor", "SecureField", "DatePicker"
    ]

    func testEveryMacControlDeclaresAccessibilityLabelAndIdentifier() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceRoot = packageRoot.appendingPathComponent("Sources/AuxesisMac", isDirectory: true)
        guard let enumerator = FileManager.default.enumerator(at: sourceRoot, includingPropertiesForKeys: nil) else {
            XCTFail("Could not scan Mac sources at \(sourceRoot.path)")
            return
        }
        var files: [URL] = []
        while let item = enumerator.nextObject() as? URL {
            if item.pathExtension == "swift" { files.append(item) }
        }
        files.sort { $0.path < $1.path }
        let missing = files.flatMap { file -> [String] in
            guard let source = try? String(contentsOf: file, encoding: .utf8) else {
                return ["Could not read \(file.lastPathComponent)"]
            }
            return missingMetadata(in: source, sourceName: file.lastPathComponent)
        }
        XCTAssertTrue(missing.isEmpty, "Missing control accessibility metadata:\n\(missing.joined(separator: "\n"))")
    }

    func testRemovingEitherModifierFailsForInlineFixtures() {
        let fixtures: [(source: String, label: String, identifier: String, control: String)] = [
            (
                """
                Button("Send") {
                    Text("Nested").accessibilityLabel("Nested child").accessibilityIdentifier("nested-child")
                }
                .accessibilityLabel("Send")
                .accessibilityIdentifier("send-button")
                """,
                ".accessibilityLabel(\"Send\")", ".accessibilityIdentifier(\"send-button\")", "Button"
            ),
            (
                """
                Menu {
                    Button("Save") {}
                        .accessibilityLabel("Save")
                        .accessibilityIdentifier("save-button")
                } label: { Text("Actions") }
                .accessibilityLabel("Actions")
                .accessibilityIdentifier("actions-menu")
                """,
                ".accessibilityLabel(\"Actions\")", ".accessibilityIdentifier(\"actions-menu\")", "Menu"
            ),
            (
                """
                Toggle("Enabled", isOn: $enabled).toggleStyle(.switch)
                    .accessibilityLabel("Enabled")
                    .accessibilityIdentifier("enabled-toggle")
                """,
                ".accessibilityLabel(\"Enabled\")", ".accessibilityIdentifier(\"enabled-toggle\")", "Toggle"
            ),
            (
                """
                TextField("Search", text: $search)
                    .accessibilityLabel("Search")
                    .accessibilityIdentifier("search-field")
                """,
                ".accessibilityLabel(\"Search\")", ".accessibilityIdentifier(\"search-field\")", "TextField"
            )
        ]

        for fixture in fixtures {
            XCTAssertTrue(missingMetadata(in: fixture.source).isEmpty, "Valid \(fixture.control) fixture should pass")
            let withoutLabel = fixture.source.replacingOccurrences(of: fixture.label, with: "")
            let labelIssue = missingMetadata(in: withoutLabel).first { $0.contains(" \(fixture.control) ") }
            XCTAssertNotNil(labelIssue, "Removing the label must fail for \(fixture.control)")
            XCTAssertTrue(labelIssue?.contains("accessibilityLabel") == true)
            XCTAssertFalse(labelIssue?.contains("accessibilityIdentifier") == true)

            let withoutIdentifier = fixture.source.replacingOccurrences(of: fixture.identifier, with: "")
            let identifierIssue = missingMetadata(in: withoutIdentifier).first { $0.contains(" \(fixture.control) ") }
            XCTAssertNotNil(identifierIssue, "Removing the identifier must fail for \(fixture.control)")
            XCTAssertTrue(identifierIssue?.contains("accessibilityIdentifier") == true)
            XCTAssertFalse(identifierIssue?.contains("accessibilityLabel") == true)
        }

        let siblings = """
        Button("First") {}
        TextField("Second", text: $second)
            .accessibilityLabel("Second")
            .accessibilityIdentifier("second-field")
        """
        XCTAssertEqual(missingMetadata(in: siblings).count, 1, "A sibling's modifiers must not satisfy the first control")
    }

    private func missingMetadata(in source: String, sourceName: String = "fixture") -> [String] {
        scan(source).compactMap { control in
            var missing: [String] = []
            if !control.hasLabel { missing.append("accessibilityLabel") }
            if !control.hasIdentifier { missing.append("accessibilityIdentifier") }
            return missing.isEmpty ? nil : "\(sourceName):\(control.line) \(control.name) missing \(missing.joined(separator: " and "))"
        }
    }

    private func scan(_ source: String) -> [Control] {
        let tokens = lex(source)
        return tokens.indices.compactMap { index in
            guard controlNames.contains(tokens[index].text), index + 1 < tokens.count,
                  ["(", "{"].contains(tokens[index + 1].text),
                  let end = controlExpressionEnd(tokens, opening: index + 1) else { return nil }
            let (label, identifier) = accessibilityModifiers(tokens, after: end)
            return Control(name: tokens[index].text, line: tokens[index].line, hasLabel: label, hasIdentifier: identifier)
        }
    }

    private func controlExpressionEnd(_ tokens: [Token], opening: Int) -> Int? {
        guard let close = matchingDelimiter(tokens, opening: opening) else { return nil }
        var cursor = close + 1
        while cursor < tokens.count {
            if tokens[cursor].text == "{" {
                guard let end = matchingDelimiter(tokens, opening: cursor) else { return nil }
                cursor = end + 1
            } else if cursor + 2 < tokens.count, isIdentifier(tokens[cursor].text),
                      tokens[cursor + 1].text == ":", tokens[cursor + 2].text == "{" {
                guard let end = matchingDelimiter(tokens, opening: cursor + 2) else { return nil }
                cursor = end + 1
            } else {
                break
            }
        }
        return cursor
    }

    private func accessibilityModifiers(_ tokens: [Token], after start: Int) -> (Bool, Bool) {
        var cursor = start
        var hasLabel = false
        var hasIdentifier = false
        while cursor + 1 < tokens.count, tokens[cursor].text == ".", isIdentifier(tokens[cursor + 1].text) {
            let name = tokens[cursor + 1].text
            cursor += 2
            var isCall = false
            if cursor < tokens.count, tokens[cursor].text == "(" {
                guard let end = matchingDelimiter(tokens, opening: cursor) else { break }
                cursor = end + 1
                isCall = true
            }
            if isCall && name == "accessibilityLabel" { hasLabel = true }
            if isCall && name == "accessibilityIdentifier" { hasIdentifier = true }
            while cursor < tokens.count {
                if tokens[cursor].text == "{" {
                    guard let end = matchingDelimiter(tokens, opening: cursor) else { return (hasLabel, hasIdentifier) }
                    cursor = end + 1
                } else if cursor + 2 < tokens.count, isIdentifier(tokens[cursor].text),
                          tokens[cursor + 1].text == ":", tokens[cursor + 2].text == "{" {
                    guard let end = matchingDelimiter(tokens, opening: cursor + 2) else { return (hasLabel, hasIdentifier) }
                    cursor = end + 1
                } else {
                    break
                }
            }
        }
        return (hasLabel, hasIdentifier)
    }

    private func matchingDelimiter(_ tokens: [Token], opening: Int) -> Int? {
        let pairs = ["(": ")", "[": "]", "{": "}"]
        guard let first = pairs[tokens[opening].text] else { return nil }
        var stack = [first]
        for index in (opening + 1)..<tokens.count {
            if let close = pairs[tokens[index].text] {
                stack.append(close)
            } else if [")", "]", "}"].contains(tokens[index].text) {
                guard stack.popLast() == tokens[index].text else { return nil }
                if stack.isEmpty { return index }
            }
        }
        return nil
    }

    private func isIdentifier(_ text: String) -> Bool {
        guard let first = text.first else { return false }
        return first == "_" || first.isLetter
    }

    private func lex(_ source: String) -> [Token] {
        let characters = Array(source)
        var tokens: [Token] = []
        var index = 0
        var line = 1
        while index < characters.count {
            let character = characters[index]
            if character.isWhitespace {
                if character == "\n" { line += 1 }
                index += 1
            } else if let end = commentEnd(characters, at: index, line: &line) {
                index = end
            } else if stringOpening(characters, at: index) != nil {
                index = skipString(characters, at: index, line: &line)
            } else if character == "_" || character.isLetter {
                let start = index
                index += 1
                while index < characters.count, characters[index] == "_" || characters[index].isLetter || characters[index].isNumber {
                    index += 1
                }
                tokens.append(Token(text: String(characters[start..<index]), line: line))
            } else {
                tokens.append(Token(text: String(character), line: line))
                index += 1
            }
        }
        return tokens
    }

    private func stringOpening(_ characters: [Character], at start: Int) -> (quote: Int, hashes: Int, width: Int)? {
        var quote = start
        while quote < characters.count, characters[quote] == "#" { quote += 1 }
        guard quote < characters.count, characters[quote] == "\"" else { return nil }
        let triple = quote + 2 < characters.count && characters[quote + 1] == "\"" && characters[quote + 2] == "\""
        return (quote, quote - start, triple ? 3 : 1)
    }

    private func skipString(_ characters: [Character], at start: Int, line: inout Int) -> Int {
        guard let opening = stringOpening(characters, at: start) else { return start + 1 }
        var index = opening.quote + opening.width
        while index < characters.count {
            if characters[index] == "\\" {
                var afterEscape = index + 1
                var hashes = 0
                while afterEscape < characters.count, characters[afterEscape] == "#" { hashes += 1; afterEscape += 1 }
                if hashes == opening.hashes, afterEscape < characters.count {
                    if characters[afterEscape] == "(" {
                        index = skipInterpolation(characters, opening: afterEscape, line: &line)
                    } else {
                        if characters[afterEscape] == "\n" { line += 1 }
                        index = afterEscape + 1
                    }
                    continue
                }
            }
            if characters[index] == "\"", hasClosingDelimiter(characters, at: index, opening: opening) {
                return index + opening.width + opening.hashes
            }
            if characters[index] == "\n" { line += 1 }
            index += 1
        }
        return characters.count
    }

    private func skipInterpolation(_ characters: [Character], opening: Int, line: inout Int) -> Int {
        var index = opening
        var depth = 0
        while index < characters.count {
            if let end = commentEnd(characters, at: index, line: &line) {
                index = end
            } else if stringOpening(characters, at: index) != nil {
                index = skipString(characters, at: index, line: &line)
            } else {
                if characters[index] == "(" { depth += 1 }
                if characters[index] == ")" {
                    depth -= 1
                    if depth == 0 { return index + 1 }
                }
                if characters[index] == "\n" { line += 1 }
                index += 1
            }
        }
        return characters.count
    }

    private func hasClosingDelimiter(_ characters: [Character], at index: Int, opening: (quote: Int, hashes: Int, width: Int)) -> Bool {
        guard index + opening.width <= characters.count,
              characters[index..<(index + opening.width)].allSatisfy({ $0 == "\"" }) else { return false }
        let suffix = index + opening.width
        guard suffix + opening.hashes <= characters.count else { return false }
        return characters[suffix..<(suffix + opening.hashes)].allSatisfy({ $0 == "#" })
    }

    private func commentEnd(_ characters: [Character], at start: Int, line: inout Int) -> Int? {
        guard start + 1 < characters.count, characters[start] == "/" else { return nil }
        if characters[start + 1] == "/" {
            var index = start + 2
            while index < characters.count, characters[index] != "\n" { index += 1 }
            return index
        }
        guard characters[start + 1] == "*" else { return nil }
        var index = start + 2
        var depth = 1
        while index + 1 < characters.count, depth > 0 {
            if characters[index] == "/", characters[index + 1] == "*" { depth += 1; index += 2 }
            else if characters[index] == "*", characters[index + 1] == "/" { depth -= 1; index += 2 }
            else {
                if characters[index] == "\n" { line += 1 }
                index += 1
            }
        }
        return index
    }
}
