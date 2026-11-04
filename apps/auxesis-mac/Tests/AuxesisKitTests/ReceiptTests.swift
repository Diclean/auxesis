// Run receipts: golden decoding for every status, unknown-field tolerance,
// the plain-French copy (no banned words), the cost label rules, the one-line
// summary, the client path, and the Store's live insertion ordering.
//
// Support helpers live in a file-private enum (not methods on the
// `@objcMembers` test class), so no helper method is ObjC-exposed.
import Foundation
import Testing
@testable import AuxesisKit

private enum ReceiptFixtures {
    @MainActor
    static func startedStore(_ transport: FakeTransport) -> Store {
        let store = Store(transport: transport, language: .fr)
        store.start()
        XCTAssertTrue(waitUntil { store.phase == .live })
        return store
    }

    static func receipt(_ receipts: [Receipt], _ id: String) throws -> Receipt {
        try XCTUnwrapOptional(receipts.first { $0.runId == id })
    }
}

@objcMembers @MainActor final class ReceiptTests: XCTestCase {
    // MARK: Golden decoding

    func testGoldenReceiptsDecodeAllStatuses() throws {
        let receipts = try Fixtures.receipts()
        XCTAssertEqual(receipts.count, 6)
        XCTAssertEqual(receipts[0].status, .done)
        XCTAssertEqual(receipts[1].status, .doneUnverified)
        XCTAssertEqual(receipts[2].status, .pausedNeedsYou)
        XCTAssertEqual(receipts[3].status, .stoppedBudget)
        XCTAssertEqual(receipts[4].status, .failed)
        XCTAssertTrue(receipts[5].receiptError, "the fallback row's flag decodes")

        let scout = receipts[0]
        XCTAssertEqual(scout.agent, "scout")
        XCTAssertEqual(scout.started, "2026-10-07 09:00:00")
        XCTAssertEqual(scout.finished, "2026-10-07 09:00:12")
        XCTAssertEqual(scout.tokensIn, 1200)
        XCTAssertEqual(scout.tokensOut, 340)
        XCTAssertEqual(scout.costCents, 1)
        XCTAssertEqual(scout.tools["read_file"], 3)
        XCTAssertEqual(scout.tools["web_search"], 1)
        XCTAssertEqual(scout.filesTouched, ["notes.md", "plan.md", "todo.md"])
        XCTAssertEqual(scout.hostsContacted, ["example.com"])
        XCTAssertFalse(scout.tainted)

        let mail = receipts[1]
        XCTAssertEqual(mail.couldNotVerify.count, 1)
        XCTAssertEqual(mail.approvalsAsked, ["mail.send"])
        XCTAssertEqual(mail.approvalsAnswered, ["allow_once"])
        XCTAssertEqual(mail.messagesSent, ["billing@acme-studio.test"])
    }

    func testUnknownFieldsAndWrongTypesAreTolerated() throws {
        // Brand-new fields are ignored; a wrong-typed known field falls back
        // (never throws), and an unknown status is preserved, not fatal.
        let json = #"{"run_id":"r1","agent":"a","status":"needs_a_nap","brand_new":[1,2],"tokens_in":"oops","tainted":"maybe"}"#
        let receipt = try JSONDecoder().decode(Receipt.self, from: Data(json.utf8))
        XCTAssertEqual(receipt.status, .unknown("needs_a_nap"))
        XCTAssertEqual(receipt.tokensIn, 0)
        XCTAssertEqual(receipt.costCents, 0)
        XCTAssertFalse(receipt.tainted)
        XCTAssertFalse(receipt.receiptError)

        let bare = try JSONDecoder().decode(Receipt.self, from: Data(#"{"status":"done"}"#.utf8))
        XCTAssertEqual(bare.status, .done)
        XCTAssertEqual(bare.runId, "")
    }

    func testReceiptFramesDecodeFromTheJournal() throws {
        let frames = try Fixtures.receiptFrames()
        XCTAssertEqual(frames.count, 2)
        guard case .runFinished(let first) = frames[0] else { return XCTFail("expected run.finished") }
        XCTAssertEqual(first.runId, "turn-7-1")
        XCTAssertEqual(first.agent, "scout")
        guard case .runFinished(let second) = frames[1] else { return XCTFail("expected run.finished") }
        XCTAssertEqual(second.status, .doneUnverified)

        // A run.finished frame without the typed receipt stays honest `.other`.
        let bare = Data(#"{"type":"run.finished","at":"2026-10-07 09:00:12","agent":"scout"}"#.utf8)
        guard case .other(let kind) = try WireEventDecoder.decode(bare) else {
            return XCTFail("a receipt-less frame must be .other")
        }
        XCTAssertEqual(kind, "run.finished")
    }

    // MARK: French copy

    func testFrenchStatusWordsMatchTheCharter() {
        XCTAssertEqual(ReceiptStatusCopy.label(.done, .fr), "terminé")
        XCTAssertEqual(ReceiptStatusCopy.label(.doneUnverified, .fr), "terminé")
        XCTAssertEqual(ReceiptStatusCopy.label(.pausedNeedsYou, .fr), "en pause : a besoin de toi")
        XCTAssertEqual(ReceiptStatusCopy.label(.stoppedBudget, .fr), "interrompu")
        XCTAssertEqual(ReceiptStatusCopy.label(.failed, .fr), "échoué")
        XCTAssertEqual(ReceiptStatusCopy.label(.unknown("future"), .fr), "état inconnu")
    }

    func testNoBannedWordInAnyReceiptCopy() throws {
        let banned = ["agent", "daemon", "taint", "mcp", "provider", "prompt", "token", "sandbox", "auxd"]
        let statuses: [ReceiptStatus] = [.done, .doneUnverified, .pausedNeedsYou, .stoppedBudget, .failed, .unknown("future")]
        var corpus: [String] = []
        for status in statuses {
            corpus.append(ReceiptStatusCopy.label(status, .fr))
            corpus.append(ReceiptStatusCopy.label(status, .en))
        }
        let costStates: [ReceiptCostState] = [.known(cents: 1), .unknown, .unverified, .incomplete]
        for state in costStates {
            corpus.append(ReceiptCostCopy.label(state, .fr))
            corpus.append(ReceiptCostCopy.label(state, .en))
        }
        for receipt in try Fixtures.receipts() {
            corpus.append(ReceiptSummary.line(receipt, .fr))
            corpus.append(ReceiptSummary.line(receipt, .en))
            let fr = ReceiptDetailCopy.detail(for: receipt, .fr)
            let en = ReceiptDetailCopy.detail(for: receipt, .en)
            corpus += fr.effects + fr.cost + fr.proof + fr.decisions
            corpus += en.effects + en.cost + en.proof + en.decisions
        }
        for text in corpus {
            let lower = text.lowercased()
            for word in banned {
                XCTAssertFalse(lower.contains(word), "banned word '\(word)' in: \(text)")
            }
        }
    }

    func testKnownToolIdsNeverReachTheScreen() throws {
        for raw in ["read_file", "shell.exec", "mail.send"] {
            let friendly = ReceiptDetailCopy.friendlyTool(raw, .fr)
            XCTAssertFalse(friendly.lowercased().contains("_"), "raw id leaked: \(friendly)")
            XCTAssertNotEqual(friendly, raw)
        }
    }

    func testFetchAndOpenUrlHaveDistinctLabels() {
        let fetchFr = ReceiptDetailCopy.friendlyTool("fetch", .fr)
        let openUrlFr = ReceiptDetailCopy.friendlyTool("open_url", .fr)
        XCTAssertEqual(fetchFr, "lire une page web")
        XCTAssertEqual(openUrlFr, "ouvrir un lien")
        XCTAssertNotEqual(fetchFr, openUrlFr, "fetch and open_url must not share a label")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("fetch", .en), "read a web page")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("open_url", .en), "open a link")
    }

    func testUnknownToolKeepsPlainWordAndSpellsOutTheId() {
        let unknownFr = ReceiptDetailCopy.friendlyTool("totally_new_tool_9000", .fr)
        let unknownEn = ReceiptDetailCopy.friendlyTool("totally_new_tool_9000", .en)
        XCTAssertEqual(unknownFr, "un outil « totally_new_tool_9000 »")
        XCTAssertEqual(unknownEn, "a tool « totally_new_tool_9000 »")
    }

    /// An id made only of invisible
    /// characters must not disappear behind the generic phrase, and the id must
    /// sit inside the card's quote. Two invisible-only ids stay distinct because
    /// the characters are escaped, never dropped.
    func testInvisibleOnlyToolIdsStayDistinctAndQuoted() {
        let zeroWidthSpace = "\u{200B}"
        let zeroWidthNonJoiner = "\u{200C}"
        // Both sanitise to nothing: that is exactly why they used to collide.
        XCTAssertEqual(ServerText.clean(zeroWidthSpace, maxLength: ServerText.Limits.unknownTool), "")
        XCTAssertEqual(ServerText.clean(zeroWidthNonJoiner, maxLength: ServerText.Limits.unknownTool), "")

        let labelA = ReceiptDetailCopy.friendlyTool(zeroWidthSpace, .fr)
        let labelB = ReceiptDetailCopy.friendlyTool(zeroWidthNonJoiner, .fr)
        XCTAssertEqual(labelA, "un outil « \\u{200B} »")
        XCTAssertEqual(labelB, "un outil « \\u{200C} »")
        XCTAssertNotEqual(labelA, labelB, "two invisible-only ids must not share one label")
    }

    /// A combining mark (category Mn) carries
    /// no width of its own, so `mystery` and `mystery\u{034F}` used to render
    /// identically while "Allow once" stayed available. For an unknown id every
    /// scalar outside printable ASCII is now escaped, so the pair is visibly
    /// distinct; a plain ASCII id stays readable and known ids keep their words.
    func testUnknownIdsEscapeEveryNonPrintableASCIIScalar() {
        let plain = "mystery"
        let combining = "mystery\u{034F}"
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool(plain, .fr), "un outil « mystery »")
        XCTAssertEqual(
            ReceiptDetailCopy.friendlyTool(combining, .fr),
            "un outil « mystery\\u{034F} »"
        )
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool(plain, .fr),
            ReceiptDetailCopy.friendlyTool(combining, .fr),
            "an invisible combining mark must not hide the difference"
        )

        // Accented letters are outside printable ASCII too: escaped, not shown.
        XCTAssertEqual(
            ReceiptDetailCopy.friendlyTool("myst\u{00E9}r", .en),
            "a tool « myst\\u{00E9}r »"
        )

        // Known ids keep their plain label and behaviour.
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("read_file", .fr), "lire un fichier")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("mail.send", .en), "send an email")
    }

    /// Regression (PR #104, GLM r3 P3): for an unknown id, `escapedStrict`
    /// escapes every scalar outside printable ASCII — the line/paragraph
    /// separators (U+2028, U+2029), the Arabic letter mark (U+061C), the
    /// invisible operators (U+2061–U+2065), the interlinear annotation controls
    /// (U+FFF9–U+FFFB) and the variation selectors (U+FE00–U+FE0F) included.
    /// Each must reach the screen as a visible `\u{XXXX}`, never raw or dropped.
    func testUnknownIdEscapesSeparatorsInvisibleOperatorsAndVariationSelectors() {
        let values: [UInt32] = [
            0x2028, 0x2029, 0x061C,
            0x2061, 0x2062, 0x2063, 0x2064, 0x2065,
            0xFFF9, 0xFFFA, 0xFFFB,
            0xFE00, 0xFE01, 0xFE02, 0xFE03, 0xFE04, 0xFE05, 0xFE06, 0xFE07,
            0xFE08, 0xFE09, 0xFE0A, 0xFE0B, 0xFE0C, 0xFE0D, 0xFE0E, 0xFE0F,
        ]
        for value in values {
            guard let scalar = Unicode.Scalar(value) else {
                XCTFail("U+\(String(value, radix: 16)) is not a scalar")
                continue
            }
            let escape = String(format: "\\u{%04X}", value)
            XCTAssertEqual(
                ServerText.escapedStrict(String(scalar), maxLength: 10),
                escape,
                "U+\(String(value, radix: 16)) must go through escapedStrict"
            )
            let label = ReceiptDetailCopy.friendlyTool("mystery\(scalar)tool", .fr)
            XCTAssertTrue(
                label.contains(escape),
                "U+\(String(value, radix: 16)) missing from \(label)"
            )
            XCTAssertFalse(
                label.unicodeScalars.contains(scalar),
                "raw U+\(String(value, radix: 16)) leaked into the label"
            )
        }
    }

    /// Regression (PR #104, GLM r3 P3): an unknown id made only of spaces used to
    /// render as a blank quote block, and two all-space ids looked identical. For
    /// an unknown id, space U+0020 and NBSP U+00A0 are now escaped like the rest
    /// of the strict set, so all-space ids stay tellable apart.
    func testSpaceOnlyUnknownIdsStayDistinctAndEscaped() {
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool(" ", .fr), "un outil « \\u{0020} »")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("\u{00A0}", .fr), "un outil « \\u{00A0} »")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("  ", .fr), "un outil « \\u{0020}\\u{0020} »")
        XCTAssertEqual(
            ReceiptDetailCopy.friendlyTool("my tool", .en),
            "a tool « my\\u{0020}tool »"
        )
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool(" ", .fr),
            ReceiptDetailCopy.friendlyTool("\u{00A0}", .fr),
            "a plain space must not look like an NBSP"
        )
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool(" ", .fr),
            ReceiptDetailCopy.friendlyTool("  ", .fr),
            "one space and two spaces must not share a blank rendering"
        )
    }

    /// Regression (PR #104, security review FAIL P2 d): the unknown id is rendered through
    /// `ServerText.quoted`, so it can never close the quote block or pass for a
    /// card label. The stricter unknown-id escape now spells out the smuggled
    /// closer instead of demoting it; the block boundary is still unambiguous.
    func testUnknownToolIdIsRenderedInsideTheCardQuote() {
        let label = ReceiptDetailCopy.friendlyTool("mystery»tool", .fr)
        XCTAssertEqual(label.filter { $0 == "«" }.count, 1)
        XCTAssertEqual(label.filter { $0 == "»" }.count, 1, "server text must not close the quote")
        XCTAssertTrue(label.contains("\\u{00BB}"), "the smuggled closer is escaped: \(label)")
    }

    /// Regression (PR #104, security review R5 P2 B): the strict escape spelling uses a
    /// backslash (`\u{200B}`), but a literal ASCII backslash was not escaped, so
    /// an unknown id spelled `probe\u{200B}` (literal backslash) rendered exactly
    /// like `probe` + U+200B and the two were confusable. The ASCII backslash is
    /// now doubled for an unknown id; known labels are untouched.
    func testUnknownIdLiteralBackslashCannotImitateAnEscape() {
        let invisible = "probe\u{200B}"
        let literal = "probe\\u{200B}"
        XCTAssertNotEqual(invisible, literal, "the two ids are genuinely different")

        let invisibleLabel = ReceiptDetailCopy.friendlyTool(invisible, .fr)
        let literalLabel = ReceiptDetailCopy.friendlyTool(literal, .fr)
        XCTAssertEqual(invisibleLabel, "un outil « probe\\u{200B} »")
        XCTAssertEqual(literalLabel, "un outil « probe\\\\u{200B} »")
        XCTAssertNotEqual(
            invisibleLabel,
            literalLabel,
            "a literal backslash must not render like the escape it spells"
        )

        // Ids differing only by a trailing literal backslash stay apart too.
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool("tool\\", .fr),
            ReceiptDetailCopy.friendlyTool("tool", .fr)
        )

        // Known labels never go through the strict rule and are unchanged.
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("read_file", .fr), "lire un fichier")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("mail.send", .fr), "envoyer un email")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("fetch", .fr), "lire une page web")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("open_url", .fr), "ouvrir un lien")
    }

    /// Regression (PR #104, GLM r4 P2): a quote delimiter smuggled into an
    /// unknown id was demoted by `quoted` — `x«y`, `x‹y` and `x❝y` all rendered
    /// `« x‹y »` — so two distinct unknown ids shared one visible label and
    /// "Allow once" stayed available. An unknown id now spells out every quote
    /// delimiter (guillemets, ❝❞, the ASCII quotes), and the card's scope line
    /// goes through `quotedIdentifier`, which never demotes. Known labels are
    /// unchanged.
    func testUnknownIdsWithQuoteDelimitersStayDistinct() {
        let cases: [(id: String, escape: String)] = [
            ("x\u{00AB}y", "\\u{00AB}"), // «
            ("x\u{00BB}y", "\\u{00BB}"), // »
            ("x\u{2039}y", "\\u{2039}"), // ‹
            ("x\u{203A}y", "\\u{203A}"), // ›
            ("x\u{275D}y", "\\u{275D}"), // ❝
            ("x\u{275E}y", "\\u{275E}"), // ❞
            ("x\u{201C}y", "\\u{201C}"),
            ("x\u{201D}y", "\\u{201D}"),
            ("x\u{2018}y", "\\u{2018}"),
            ("x\u{2019}y", "\\u{2019}"),
            ("x\"y", "\\u{0022}"),
            ("x'y", "\\u{0027}"),
        ]

        var labels: Set<String> = []
        var scopeLines: Set<String> = []
        for (id, escape) in cases {
            let label = ReceiptDetailCopy.friendlyTool(id, .fr)
            XCTAssertTrue(label.contains(escape), "\(escape) missing from \(label)")
            labels.insert(label)

            let scope = ServerText.quotedIdentifier(id, maxLength: ServerText.Limits.scopeTool)
            XCTAssertTrue(scope.contains(escape), "\(escape) missing from \(scope)")
            XCTAssertEqual(scope.filter { $0 == "«" }.count, 1, "block boundary: \(scope)")
            XCTAssertEqual(scope.filter { $0 == "»" }.count, 1, "block boundary: \(scope)")
            scopeLines.insert(scope)
        }
        XCTAssertEqual(labels.count, cases.count, "distinct ids must not share a label")
        XCTAssertEqual(scopeLines.count, cases.count, "distinct ids must not share a scope line")

        // The two ids named in the finding, side by side.
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool("x\u{00AB}y", .fr),
            ReceiptDetailCopy.friendlyTool("x\u{2039}y", .fr)
        )
        XCTAssertNotEqual(
            ServerText.quotedIdentifier("x\u{00AB}y", maxLength: ServerText.Limits.scopeTool),
            ServerText.quotedIdentifier("x\u{2039}y", maxLength: ServerText.Limits.scopeTool)
        )

        // Known ids keep their plain label and their unchanged scope rendering.
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("read_file", .fr), "lire un fichier")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("mail.send", .en), "send an email")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("open_url", .fr), "ouvrir un lien")
        XCTAssertEqual(
            ServerText.quotedIdentifier("read_file", maxLength: ServerText.Limits.scopeTool),
            "« read_file »"
        )
        XCTAssertEqual(
            ServerText.quotedIdentifier("mail.send", maxLength: ServerText.Limits.scopeTool),
            "« mail.send »"
        )
    }

    /// Regression (PR #104, security review R5 P2 A): the command aliases the card labels
    /// "lancer une commande" are one class for the "Always" gate. The shared
    /// predicate is driven by the label, not by the raw `shell` prefix, and known
    /// non-command tools keep their plain label and behaviour.
    func testCommandAliasesShareTheCommandLabel() {
        for raw in ["shell", "shell.exec", "run_command", "run", "bash", "exec", "BASH", "Exec"] {
            XCTAssertTrue(ReceiptDetailCopy.isCommandTool(raw), "\(raw) is a command")
            XCTAssertEqual(ReceiptDetailCopy.friendlyTool(raw, .en), "run a command")
        }
        XCTAssertFalse(ReceiptDetailCopy.isCommandTool("read_file"))
        XCTAssertFalse(ReceiptDetailCopy.isCommandTool("mail.send"))
        XCTAssertFalse(ReceiptDetailCopy.isCommandTool("fetch"))
        XCTAssertFalse(ReceiptDetailCopy.isCommandTool("open_url"))
        XCTAssertFalse(ReceiptDetailCopy.isCommandTool("totally_new_tool_9000"))
    }

    /// Regression (PR #104, security review FAIL P2 c): the bound counts Unicode scalars, not
    /// grapheme clusters. 10 000 combining marks are one cluster, so the label must
    /// still be capped and say how many scalars it hid.
    func testUnknownToolBoundCountsUnicodeScalars() {
        let combining = String(repeating: "\u{0301}", count: 10_000)
        XCTAssertLessThan(combining.count, 200, "grapheme clusters hide the 10 000 scalars")

        let label = ReceiptDetailCopy.friendlyTool(combining, .fr)
        XCTAssertTrue(label.hasSuffix("… (10000 caractères) »"), label)
        XCTAssertEqual(
            ServerText.escaped(combining, maxLength: ServerText.Limits.unknownTool).unicodeScalars.count,
            ServerText.Limits.unknownTool
        )
    }

    /// Regression (PR #104, security review FAIL P2): two unknown ids sharing their first
    /// 80 characters used to render identically — the card showed the generic
    /// "un outil" plus a scope line truncated at 80. They must be tellable
    /// apart now, and a known id must keep its plain label.
    func testUnknownToolsRenderDistinctlyBeyondTheScopeCap() {
        let head = String(repeating: "x", count: 80)
        let alpha = head + "_tool_alpha"
        let beta = head + "_tool_beta"
        XCTAssertEqual(alpha.prefix(80), beta.prefix(80), "the pair differs only after the scope cap")

        let labelAlpha = ReceiptDetailCopy.friendlyTool(alpha, .fr)
        let labelBeta = ReceiptDetailCopy.friendlyTool(beta, .fr)
        XCTAssertNotEqual(labelAlpha, labelBeta, "two distinct unknown ids must not share a label")
        XCTAssertTrue(labelAlpha.contains("_tool_alpha"), labelAlpha)
        XCTAssertTrue(labelBeta.contains("_tool_beta"), labelBeta)
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool(alpha, .en),
            ReceiptDetailCopy.friendlyTool(beta, .en)
        )

        // Ids that differ only in characters `clean` strips must stay apart too.
        let strippedA = "future\u{200B}tool"
        let strippedB = "future\u{200C}tool"
        XCTAssertEqual(
            ServerText.clean(strippedA, maxLength: ServerText.Limits.unknownTool),
            ServerText.clean(strippedB, maxLength: ServerText.Limits.unknownTool)
        )
        XCTAssertNotEqual(
            ReceiptDetailCopy.friendlyTool(strippedA, .fr),
            ReceiptDetailCopy.friendlyTool(strippedB, .fr)
        )

        // Known ids keep their plain label.
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("read_file", .fr), "lire un fichier")
        XCTAssertEqual(ReceiptDetailCopy.friendlyTool("mail.send", .en), "send an email")
    }

    // MARK: Cost rules

    func testKnownCostShowsCentsAndTonService() {
        let label = ReceiptCostCopy.label(.known(cents: 1), .fr)
        XCTAssertTrue(label.contains("1 ¢"), label)
        XCTAssertTrue(label.contains("(ton service d'IA)"), label)
        XCTAssertTrue(ReceiptCostCopy.showsCents(.known(cents: 1)))
    }

    func testUnknownCostNeverShowsCents() {
        for state in [ReceiptCostState.unknown, .unverified, .incomplete] {
            let label = ReceiptCostCopy.label(state, .fr)
            XCTAssertFalse(label.contains("¢"), "no cents when unknown: \(label)")
            XCTAssertFalse(ReceiptCostCopy.showsCents(state))
        }
        XCTAssertTrue(ReceiptCostCopy.label(.unverified, .fr).contains("Coût non vérifié"))
        XCTAssertTrue(ReceiptCostCopy.label(.unknown, .fr).contains("Coût inconnu"))
        XCTAssertEqual(ReceiptCostCopy.label(.incomplete, .fr), "Reçu incomplet")
        XCTAssertTrue(ReceiptCostCopy.label(.unverified, .fr).contains("(ton service d'IA)"))
        XCTAssertTrue(ReceiptCostCopy.label(.unknown, .fr).contains("(ton service d'IA)"))
    }

    func testCostStateDerivesFromReceiptFlags() throws {
        let receipts = try Fixtures.receipts()
        XCTAssertEqual(ReceiptCostState.of(try ReceiptFixtures.receipt(receipts, "turn-7-1")), .known(cents: 1))
        XCTAssertEqual(ReceiptCostState.of(try ReceiptFixtures.receipt(receipts, "turn-5-2")), .unverified)
        XCTAssertEqual(ReceiptCostState.of(try ReceiptFixtures.receipt(receipts, "turn-3-9")), .known(cents: 0))
        XCTAssertEqual(ReceiptCostState.of(try ReceiptFixtures.receipt(receipts, "turn-6-3")), .unknown)
        XCTAssertEqual(ReceiptCostState.of(try ReceiptFixtures.receipt(receipts, "turn-7-4")), .incomplete)
    }

    // MARK: One-line summary

    func testOneLineSummaryUsesRealFields() throws {
        let receipts = try Fixtures.receipts()
        XCTAssertEqual(
            ReceiptSummary.line(try ReceiptFixtures.receipt(receipts, "turn-7-1"), .fr),
            "12 s · 3 fichiers lus · 1 site consulté · 1 ¢ (ton service d'IA)"
        )
        XCTAssertEqual(
            ReceiptSummary.line(try ReceiptFixtures.receipt(receipts, "turn-5-2"), .fr),
            "4 s · 1 message envoyé · Coût non vérifié (ton service d'IA)"
        )
        XCTAssertEqual(
            ReceiptSummary.line(try ReceiptFixtures.receipt(receipts, "turn-3-9"), .fr),
            "en pause : a besoin de toi · 20 s · 1 fichier lu · 0 ¢ (ton service d'IA)"
        )
        XCTAssertEqual(
            ReceiptSummary.line(try ReceiptFixtures.receipt(receipts, "turn-6-3"), .fr),
            "échoué · 2 s · Coût inconnu (ton service d'IA)"
        )
        XCTAssertEqual(
            ReceiptSummary.line(try ReceiptFixtures.receipt(receipts, "turn-7-4"), .fr),
            "5 s · Reçu incomplet"
        )
    }

    func testDurationIsOmittedWhenStampsAreMissing() {
        let receipt = Receipt(runId: "r", agent: "a", started: nil, finished: nil, costCents: 1)
        XCTAssertNil(ReceiptSummary.durationSeconds(receipt))
        XCTAssertEqual(ReceiptSummary.line(receipt, .fr), "1 ¢ (ton service d'IA)")
    }

    // MARK: When

    func testReceiptWhenShowsTheRunDateAndTime() throws {
        let receipts = try Fixtures.receipts()
        let scout = try ReceiptFixtures.receipt(receipts, "turn-7-1")
        XCTAssertEqual(ReceiptTime.label(scout, .fr), "7 oct. 2026 à 09:00")
        XCTAssertEqual(ReceiptTime.label(scout, .en), "Oct 7, 2026 at 09:00")

        // A missing start falls back to the finish; no stamp shows nothing.
        let finishedOnly = Receipt(runId: "r", agent: "a", started: nil, finished: "2026-01-02 03:04:05")
        XCTAssertEqual(ReceiptTime.label(finishedOnly, .fr), "2 janv. 2026 à 03:04")
        let unparseable = Receipt(runId: "r2", agent: "a", started: "not a date", finished: nil)
        XCTAssertEqual(ReceiptTime.label(unparseable, .fr), "")
        XCTAssertEqual(ReceiptTime.label(Receipt(runId: "r3", agent: "a"), .fr), "")
    }

    // MARK: Client

    func testClientReceiptsPath() {
        XCTAssertEqual(
            AuxdClient.receiptsPath(agent: "scout", limit: 5),
            "/v1/receipts?limit=5&agent=scout"
        )
        XCTAssertEqual(
            AuxdClient.receiptsPath(agent: nil, limit: 10),
            "/v1/receipts?limit=10"
        )
        XCTAssertEqual(
            AuxdClient.receiptsPath(agent: "a b&c=d", limit: 1),
            "/v1/receipts?limit=1&agent=a%20b%26c%3Dd"
        )
    }

    // MARK: Store — snapshot and live frames

    func testSnapshotLoadsReceiptsInOrder() throws {
        let transport = FakeTransport()
        let golden = try Fixtures.receipts()
        transport.receiptsResult = .success(golden)
        let store = ReceiptFixtures.startedStore(transport)
        XCTAssertTrue(waitUntil { store.receiptLog.receipts.count == golden.count })
        XCTAssertEqual(store.receiptLog.receipts.map(\.runId), golden.map(\.runId))
        XCTAssertTrue(transport.receiptsCalls.contains { $0.agent == nil }, "the snapshot reads every agent")
        store.stop()
    }

    func testLiveFrameInsertionOrderingAndDedupe() {
        let transport = FakeTransport()
        let store = ReceiptFixtures.startedStore(transport)
        XCTAssertTrue(store.receiptLog.receipts.isEmpty)

        transport.emit(.runFinished(Receipt(runId: "run-1", agent: "scout", costCents: 1)))
        transport.emit(.runFinished(Receipt(runId: "run-2", agent: "scout", costCents: 2)))
        transport.emit(.runFinished(Receipt(runId: "run-3", agent: "mail", costCents: 3)))
        XCTAssertTrue(waitUntil { store.receiptLog.receipts.count == 3 })
        XCTAssertEqual(store.receiptLog.receipts.map(\.runId), ["run-3", "run-2", "run-1"], "newest first")

        // A replayed frame replaces in place: no duplicate, no reorder.
        transport.emit(.runFinished(Receipt(runId: "run-2", agent: "scout", costCents: 9)))
        XCTAssertTrue(waitUntil { store.receiptLog.receipts.first { $0.runId == "run-2" }?.costCents == 9 })
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        XCTAssertEqual(store.receiptLog.receipts.map(\.runId), ["run-3", "run-2", "run-1"])
        XCTAssertEqual(store.receiptLog.receipts.count, 3)

        XCTAssertEqual(store.receiptLog.receipts(for: "scout").map(\.runId), ["run-2", "run-1"])
        XCTAssertEqual(store.receiptLog.receipts(for: "mail").map(\.runId), ["run-3"])
        store.stop()
    }

    func testSelectingAnAgentRefreshesItsReceipts() throws {
        let transport = FakeTransport()
        transport.receiptsResult = .success([])
        let store = ReceiptFixtures.startedStore(transport)
        XCTAssertTrue(store.receiptLog.receipts.isEmpty)

        let golden = try Fixtures.receipts()
        transport.receiptsResult = .success(golden)
        store.selectAgent("mail")
        XCTAssertTrue(waitUntil { transport.receiptsCalls.contains { $0.agent == "mail" } && store.receiptLog.receipts.count == golden.count })
        store.stop()
    }
}
