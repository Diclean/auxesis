// The brand guard the SVG badges had, restored for the
// agents the owner reads. The names of the old brand sheet are that brand's,
// and another company's product is another company's: no built-in agent,
// mascot or tint carries one. The check is a word check, and it is never
// vacuous: a planted brand name is caught, a word that only looks like one
// is left alone.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class AgentBrandNameTests: XCTestCase {
    /// The names of the old brand sheet: they are the brand's, not the app's.
    private let oldBrand = ["iris", "horai", "philia", "archeion", "phylax"]

    /// Another company's product: the app's agents are not theirs.
    private let thirdParty = ["claude", "chatgpt", "openai", "copilot", "gemini", "grok", "mistral", "llama",
                              "perplexity", "siri", "alexa", "jarvis", "slack", "notion", "trello", "asana",
                              "hubspot", "salesforce", "discord", "whatsapp", "zoom", "telegram"]

    /// The owner reads Aux, Mail, Calendar, Clients and Documents. None of
    /// them carries a brand name.
    func testNoBuiltInAgentIsNamedAfterABrand() {
        // The catalogue of brand definitions; an install may have only some.
        for member in TeamMember.all + [.main] {
            let shown = TeamMember.displayName(member.id)
            XCTAssertEqual(shown, member.name, "\(member.id) shows its own name")
            for brand in oldBrand + thirdParty {
                XCTAssertFalse(says(shown, brand), "\(member.id) is named \(brand)")
            }
        }
    }

    /// The mascots and the tints are the app's own: they carry no brand.
    func testNoMascotOrTintIsNamedAfterABrand() {
        var lines: [(String, String)] = []
        for variant in MascotVariant.allCases { lines.append(("mascot.\(variant.rawValue)", variant.name)) }
        for tint in MascotTint.allCases { lines.append(("tint.\(tint.rawValue)", tint.name)) }
        XCTAssertGreaterThan(lines.count, 10, "the mascots and the tints are read")
        for (key, text) in lines {
            for brand in oldBrand + thirdParty {
                XCTAssertFalse(says(text, brand), "\(key) says the brand name \(brand)")
            }
        }
    }

    /// The guard is not vacuous: it catches a brand name, and a word that
    /// only looks like one stays alone.
    func testTheBrandCheckCatchesANameAndLeavesAnotherWordAlone() {
        XCTAssertTrue(says("Claude", "claude"))
        XCTAssertTrue(says("OpenAI", "openai"))
        XCTAssertTrue(says("Iris", "iris"))
        XCTAssertFalse(says("Horaires", "horai"), "a word that only looks like one is not a brand")
        XCTAssertFalse(says("Mail", "mal"), "a brand is a whole word")
    }

    /// True when the text says the name as a word: "Horaires" is not "Horai".
    private func says(_ text: String, _ name: String) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: "\\b\(name)\\b", options: [.caseInsensitive]) else { return false }
        return regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }
}
