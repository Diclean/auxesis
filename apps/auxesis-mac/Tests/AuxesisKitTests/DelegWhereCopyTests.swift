// The copy for a step the daemon marks `where: local`.
//
// A `local` brain is reached over a loopback address, and the Mac cannot see
// through it: the owner may have aliased a cloud model (`ollama cp
// gpt-oss:120b-cloud mybrain`) or forwarded the port elsewhere. So the copy
// names who handled the step, and never says the data stayed here.
import Foundation
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class DelegWhereCopyTests: XCTestCase {
    /// The label the step line, the stop report and the privacy record read.
    func testTheLongFormNamesTheBrainAndNotTheData() {
        XCTAssertEqual(L10n.ui(.stayedOnMac, .en), "Handled by a brain on this Mac")
        XCTAssertEqual(L10n.ui(.stayedOnMac, .fr), "Traité par un modèle sur ce Mac")
    }

    /// The counts are compact: the same fact, in the short form.
    func testTheShortFormIsTheCompactNameOfTheSameThing() {
        XCTAssertEqual(L10n.uf(.stepsStayed, .en, 5), "5 handled by a local brain")
        XCTAssertEqual(L10n.uf(.stepsStayed, .fr, 5), "5 traitées par un modèle sur ce Mac")
        XCTAssertEqual(L10n.ui(.sidebarStayedOne, .en), "1 step handled by a local brain today")
        XCTAssertEqual(L10n.ui(.sidebarStayedOne, .fr), "1 étape traitée par un modèle sur ce Mac aujourd’hui")
    }

    /// Every string a user reads for a `local` step, in both languages.
    private func localStrings(_ language: Language) -> [String] {
        [
            L10n.ui(.stayedOnMac, language),
            L10n.uf(.stepsStayed, language, 5),
            L10n.ui(.sidebarStayedOne, language),
            L10n.uf(.sidebarStayedMany, language, 12),
        ]
    }

    func testNoLocalStringSaysTheDataStayedOnThisMac() {
        let banned = ["stayed", "resté", "reste", "never left", "jamais", "tokenis", "leak-free", "anonym"]
        for language in Language.allCases {
            for text in localStrings(language) {
                let lower = text.lowercased()
                for word in banned {
                    XCTAssertFalse(lower.contains(word), "\(language.rawValue) says \(word): \(text)")
                }
            }
        }
    }

    /// The other two places a step can land keep their own words, and they
    /// claim no more than the record proves.
    func testTheCloudAndUnknownStringsStayWhereTheyAre() {
        XCTAssertEqual(L10n.ui(.whereLeft, .en), "Left this Mac")
        XCTAssertEqual(L10n.ui(.whereLeft, .fr), "Sorti de ce Mac")
        XCTAssertEqual(L10n.ui(.whereUnavailable, .en), "Not known where it ran")
        XCTAssertEqual(L10n.ui(.whereUnavailable, .fr), "Lieu inconnu")
        for language in Language.allCases {
            for text in [L10n.ui(.whereLeft, language), L10n.ui(.whereUnavailable, language)] {
                let lower = text.lowercased()
                for word in ["stayed", "resté", "never left", "jamais", "tokenis"] {
                    XCTAssertFalse(lower.contains(word), "\(language.rawValue) says \(word): \(text)")
                }
            }
        }
    }
}
