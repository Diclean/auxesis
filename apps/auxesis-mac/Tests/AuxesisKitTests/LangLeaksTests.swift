// A French day showed English and raw ids. The kernel's
// removal marker stays one English text for the model; only the chip the owner
// reads follows the reply's language. Skill ids and brain ids read as names.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class LangLeaksTests: XCTestCase {
    private func chips(_ reply: String) -> [String] {
        InlineParser.parse(reply, replyLanguage: RemovalMarker.language(of: reply)).filter(\.chip).map(\.text)
    }

    func testAFrenchReplyShowsTheIbanMarkerInFrenchAndEnglishStaysAsIs() {
        let french = "Je l’ai vu apparaître sous la forme [iban removed], donc je n’ai jamais eu la valeur."
        XCTAssertEqual(RemovalMarker.language(of: french), .fr)
        XCTAssertEqual(chips(french), ["[IBAN retiré]"])
        let english = "I saw it as [iban removed], so I never had the value."
        XCTAssertEqual(RemovalMarker.language(of: english), .en)
        XCTAssertEqual(chips(english), ["[iban removed]"])
    }

    func testEveryKernelMarkerHasAFrenchChipAndOthersAreUntouched() {
        let markers = ["[iban removed]", "[card removed]", "[health removed]", "[address removed]",
                       "[date of birth removed]", "[id removed]", "[secret removed]"]
        for marker in markers {
            let shown = RemovalMarker.display(marker, language: .fr)
            XCTAssertNotEqual(shown, marker, marker)
            XCTAssertTrue(shown.hasPrefix("[") && shown.hasSuffix("]"), marker)
            XCTAssertEqual(RemovalMarker.display(marker, language: .en), marker)
        }
        for other in ["[hidden]", "[nom masqué]", "[health 4412 removed]", "⟦EMAIL_0123456789AB⟧"] {
            XCTAssertEqual(RemovalMarker.display(other, language: .fr), other)
        }
    }

    func testTheStoredTextIsNeverRewritten() {
        let line = "Ton IBAN est [iban removed] et je ne l’ai pas."
        XCTAssertEqual(InlineParser.parse(line).map(\.text).joined(), line)
        XCTAssertEqual(InlineParser.spoken(InlineParser.parse(line, replyLanguage: .fr)), "Ton IBAN est hidden value et je ne l’ai pas.")
    }

    func testSkillIdsReadAsNamesAndUnknownOnesAreNamedRaw() {
        XCTAssertEqual(PlainLabel.skill("collect-receipts"), "Collect receipts")
        XCTAssertEqual(PlainLabel.skill("collect-receipts", language: .fr), "Collecte des reçus")
        XCTAssertEqual(PlainLabel.skill("collect-anything"), "Skill: collect-anything")
        XCTAssertEqual(PlainLabel.skill("collect-anything", language: .fr), "Compétence : collect-anything")
        let entry = LedgerEntry(at: "", kind: "skill.run", agent: "documents", summary: #"{"skill_name":"collect-receipts","outcome":"done"}"#)
        XCTAssertEqual(LedgerText.what(entry, language: .en), "Collect receipts ran · completed")
        XCTAssertEqual(LedgerText.what(entry, language: .fr), "Collecte des reçus exécutée · terminé")
    }

    func testBrainIdsShowTheirDisplayName() {
        XCTAssertEqual(BrainName.display("deepseek-flash"), "DeepSeek Flash")
        XCTAssertEqual(BrainName.display("gpt-4o-mini"), "GPT 4o Mini")
        XCTAssertEqual(BrainName.display("DeepSeek V3.2"), "DeepSeek V3.2")
        XCTAssertEqual(BrainName.display("qwen3:8b"), "qwen3:8b")
        XCTAssertEqual(BrainName.display("llama3"), "llama3")
    }

    func testStepsWithNoPlaceSayItPlainly() {
        let steps = StepsCardModel(steps: [DelegationStep(text: "a", state: .done, place: nil)])
        XCTAssertTrue(steps.summary(.en).hasSuffix("1 not recorded where they ran"))
        XCTAssertTrue(steps.summary(.fr).hasSuffix("1 sans lieu d’exécution enregistré"))
    }
}
