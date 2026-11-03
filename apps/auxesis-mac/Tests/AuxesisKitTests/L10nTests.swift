// Copy rules: the system language by default, every key in both languages, and
// plain words — "agent" not "agent", "source not trusted" not "taint",
// "service" not "daemon".
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class L10nTests: XCTestCase {
    /// A stub locale source: the test controls what the system "prefers".
    private struct StubLocale: LocaleLanguageProviding {
        let preferredLanguages: [String]
    }

    func testSystemLanguageIsFrenchOnlyForAFrenchPreference() {
        XCTAssertEqual(
            Language.preferred(using: StubLocale(preferredLanguages: ["fr-FR", "en-US"])), .fr)
        XCTAssertEqual(Language.preferred(using: StubLocale(preferredLanguages: ["fr"])), .fr)
        XCTAssertEqual(Language.preferred(using: StubLocale(preferredLanguages: ["en-US"])), .en)
        XCTAssertEqual(Language.preferred(using: StubLocale(preferredLanguages: ["de-DE"])), .en)
        XCTAssertEqual(Language.preferred(using: StubLocale(preferredLanguages: [])), .en)
        XCTAssertEqual(Language.allCases, [.fr, .en])
    }

    /// A language the owner chose by hand (`auxesis.language`) always wins.
    func testAHandChosenLanguageWinsOverTheSystem() {
        let suite = "auxesis.l10n.tests.chosen"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Language.fr.rawValue, forKey: Store.languageKey)

        let store = Store(
            transport: FakeTransport(),
            localeProvider: StubLocale(preferredLanguages: ["en-US"]),
            defaults: defaults
        )
        XCTAssertEqual(store.language, .fr, "the explicit choice must win over the system")
    }

    /// With no explicit choice, a fresh install follows the system.
    func testSystemLanguageIsTheDefaultWithoutAnExplicitChoice() {
        let suite = "auxesis.l10n.tests.system"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }

        let store = Store(
            transport: FakeTransport(),
            localeProvider: StubLocale(preferredLanguages: ["en-GB"]),
            defaults: defaults
        )
        XCTAssertEqual(store.language, .en)
    }

    func testEveryKeyIsTranslatedInBothLanguages() {
        for key in StringKey.allCases {
            let translations = L10n.table[key]
            XCTAssertNotNil(translations, "missing table entry: \(key.rawValue)")
            for language in Language.allCases {
                let value = translations?[language] ?? ""
                XCTAssertFalse(value.isEmpty, "\(key.rawValue) missing \(language.rawValue)")
                XCTAssertNotEqual(value, key.rawValue, "\(key.rawValue) must not fall back to its key")
            }
        }
    }

    func testNoJargonInUserVisibleCopy() {
        let banned = ["\\bdot(s)?\\b", "\\btaint(ed)?\\b", "\\bdaemon\\b"]
        for key in StringKey.allCases {
            guard let translations = L10n.table[key] else { continue }
            for (language, value) in translations {
                for pattern in banned {
                    let range = value.range(of: pattern, options: [.regularExpression, .caseInsensitive])
                    XCTAssertNil(
                        range,
                        "\(key.rawValue) [\(language.rawValue)] contains jargon /\(pattern)/: \(value)"
                    )
                }
            }
        }
    }

    /// The copy audit's jargon must never creep back into user-visible copy:
    /// the internal access key (*jeton*), the AI-service word
    /// (*fournisseur*/*provider*), and the *scope*, *audit*, *sandbox* and
    /// third-party-hub internals. Case-insensitive, in the French and English
    /// tables.
    func testForbiddenWordsNeverReappearInUserVisibleCopy() {
        let banned = [
            "jeton",
            "fournisseur",
            "\\bprovider(s)?\\b",
            "\\bscope\\b",
            "\\baudit\\b",
            "\\bsandbox\\b",
            "\\bmcp\\b",
            "\\bconnecteur(s)?\\b",
        ]
        for key in StringKey.allCases {
            guard let translations = L10n.table[key] else { continue }
            for (language, value) in translations {
                for pattern in banned {
                    let range = value.range(of: pattern, options: [.regularExpression, .caseInsensitive])
                    XCTAssertNil(
                        range,
                        "\(key.rawValue) [\(language.rawValue)] contains forbidden /\(pattern)/: \(value)"
                    )
                }
            }
        }
    }

    func testPlainAgentWordingExists() {
        XCTAssertEqual(L10n.t(.sectionAgents, .fr), "TES AGENTS")
        XCTAssertEqual(L10n.t(.sectionAgents, .en), "YOUR AGENTS")
        XCTAssertEqual(L10n.t(.stateNeedsYou, .fr), "attend ta réponse")
        XCTAssertEqual(L10n.t(.stateNeedsYou, .en), "waiting for you")
        XCTAssertFalse(L10n.t(.approvalTrust, .fr).lowercased().contains("taint"))
        XCTAssertFalse(L10n.t(.approvalTrust, .en).lowercased().contains("taint"))
        XCTAssertTrue(L10n.t(.approvalTaintValue, .fr).contains("source non fiable"))
        XCTAssertTrue(L10n.t(.approvalTaintValue, .en).contains("untrusted source"))
    }

    /// The owner's word for the personality is "personnalité", never the
    /// internal "soul" or "système prompt": the editor must never leak jargon.
    func testPersonalityCopyNeverSaysSoulOrPromptSystem() {
        XCTAssertEqual(L10n.t(.personalityTitle, .fr), "Personnalité")
        XCTAssertEqual(L10n.t(.personalityIntro, .fr), "Comment cet agent doit se comporter")
        let keys: [StringKey] = [
            .personalityTitle,
            .personalityIntro,
            .personalityHint,
            .personalityDefault,
            .personalitySave,
            .personalitySaved,
            .personalityTooLong,
        ]
        for key in keys {
            for language in Language.allCases {
                let value = L10n.t(key, language).lowercased()
                XCTAssertFalse(value.contains("soul"), "\(key.rawValue) [\(language.rawValue)]: \(value)")
                XCTAssertFalse(value.contains("prompt"), "\(key.rawValue) [\(language.rawValue)]: \(value)")
            }
        }
    }

    func testStarterPromptsMatchTheCharter() {
        XCTAssertEqual(L10n.starterPrompts, [.starterPrepareDay, .starterDraftMessage, .starterExplain])
        XCTAssertEqual(L10n.t(.starterPrepareDay, .fr), "Aide-moi à préparer ma journée")
        XCTAssertEqual(L10n.t(.starterDraftMessage, .fr), "Rédige un brouillon de message")
        XCTAssertEqual(L10n.t(.starterExplain, .fr), "Explique-moi ce que tu peux faire")
        for key in L10n.starterPrompts {
            for language in Language.allCases {
                let prompt = L10n.t(key, language)
                XCTAssertFalse(prompt.isEmpty)
                XCTAssertNotEqual(prompt, key.rawValue)
            }
        }
        XCTAssertFalse(L10n.t(.starterHint, .fr).isEmpty)
        XCTAssertFalse(L10n.t(.starterHint, .en).isEmpty)
    }

    func testFormatting() {
        let text = L10n.f(.threadPlaceholder, .fr, "Scout")
        XCTAssertEqual(text, "Écris à Scout…")
        let label = L10n.f(.approvalPending, .en, 4809)
        XCTAssertEqual(label, "pending · #4809")
    }

    func testAThreadBusyRefusalAsksToAnswerTheCard() {
        let busy = AuxdError.http(status: 409, body: #"{"error":{"code":"thread_busy","message":"x"}}"#)
        XCTAssertEqual(busy.message(.en), L10n.t(.errorThreadBusy, .en))
        XCTAssertEqual(busy.message(.fr), L10n.t(.errorThreadBusy, .fr))
        XCTAssertEqual(AuxdError.http(status: 409, body: "{}").message(.en), L10n.t(.errorServiceRefused, .en))
    }
}
