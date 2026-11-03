// The offline view-model: which pane wins (never a blank shell) and the exact
// words/commands the window shows when the service or the token file is
// missing. Pure, so `swift test` covers it without a window.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class OfflinePresentationTests: XCTestCase {
    func testOfflineWinsBeforeAnythingEverLoaded() {
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: false,
                firstRun: false,
                connection: .offline("connection refused"),
                hasLoadedContent: false
            ),
            .offline
        )
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: false,
                firstRun: false,
                connection: .connecting,
                hasLoadedContent: false
            ),
            .offline
        )
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: false,
                firstRun: false,
                connection: .unauthorized,
                hasLoadedContent: false
            ),
            .offline
        )
    }

    func testMainShellStaysWhenContentIsAlreadyOnScreen() {
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: true,
                firstRun: false,
                connection: .offline("socket dropped"),
                hasLoadedContent: true
            ),
            .main
        )
        // Offline with nothing loaded yet: explain, don't show an empty shell.
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: true,
                firstRun: false,
                connection: .offline("socket dropped"),
                hasLoadedContent: false
            ),
            .offline
        )
    }

    func testFirstRunScreenWinsWhileSetupIsPending() {
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: true,
                firstRun: true,
                connection: .online(version: "0.1.0"),
                hasLoadedContent: false
            ),
            .firstRun
        )
        // The first-run screen shows the live status + "check again" itself,
        // so it stays even if the service drops mid-setup.
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: true,
                firstRun: true,
                connection: .offline("socket dropped"),
                hasLoadedContent: false
            ),
            .firstRun
        )
    }

    func testOnlineWithoutFirstRunShowsTheMainShell() {
        XCTAssertEqual(
            ShellPresentation.screen(
                firstRunKnown: true,
                firstRun: false,
                connection: .online(version: "0.1.0"),
                hasLoadedContent: true
            ),
            .main
        )
    }

    // MARK: Calm offline surface — one sentence, one button, details folded

    /// The visible offline screen is one plain sentence and one restart button;
    /// the Terminal commands and the technical reason live under the details
    /// disclosure. The sentence says what happened, that nothing was sent, and
    /// what to do next.
    func testOfflineScreenShowsOneSentenceAndOneRestartButton() {
        XCTAssertEqual(
            OfflinePresentation.offlineSentence(.fr),
            "Le service s'est arrêté. Rien n'a été envoyé. Relance Auxesis, puis réessaie."
        )
        XCTAssertEqual(
            OfflinePresentation.offlineSentence(.en),
            "The service stopped. Nothing was sent. Restart Auxesis, then try again."
        )
        XCTAssertEqual(OfflinePresentation.detailsTitle(.fr), "Voir les détails")
        XCTAssertEqual(OfflinePresentation.detailsTitle(.en), "Show details")
        XCTAssertEqual(OfflinePresentation.restartLabel(.fr), "Relancer Auxesis")
        XCTAssertEqual(OfflinePresentation.restartLabel(.en), "Restart Auxesis")

        // Every failure cause shows the sentence and the restart button, and
        // keeps the technical block under the same details title.
        let causes: [OfflineCause] = [.tokenMissing, .tokenUnsafe, .keyRefused, .unreachable("connection refused")]
        for cause in causes {
            for language in Language.allCases {
                let guidance = OfflinePresentation.guidance(cause: cause, language: language)
                XCTAssertEqual(guidance.sentence, OfflinePresentation.offlineSentence(language), "\(cause) \(language)")
                XCTAssertEqual(guidance.detailsTitle, OfflinePresentation.detailsTitle(language), "\(cause) \(language)")
                XCTAssertEqual(guidance.retry, OfflinePresentation.restartLabel(language), "\(cause) \(language)")
            }
        }
    }

    /// Nothing user-visible on the offline surface (sentence, disclosure title,
    /// button, details or commands) may use the internal words the copy audit
    /// banned.
    func testOfflineVisibleCopyHasNoForbiddenWords() {
        let banned = [
            "jeton", "fournisseur", "provider", "\\bscope\\b", "\\baudit\\b",
            "\\bsandbox\\b", "daemon", "\\bmcp\\b", "connecteur",
        ]
        let causes: [OfflineCause?] = [nil, .tokenMissing, .tokenUnsafe, .keyRefused, .unreachable("connection refused")]
        for cause in causes {
            for language in Language.allCases {
                let guidance = OfflinePresentation.guidance(cause: cause, language: language)
                let surfaces = [
                    guidance.sentence, guidance.detailsTitle, guidance.retry,
                    guidance.title, guidance.detail, guidance.hint,
                    guidance.terminalLabel, guidance.notice ?? "",
                    guidance.commands.joined(separator: "\n"),
                ]
                for surface in surfaces {
                    for pattern in banned {
                        XCTAssertNil(
                            surface.range(of: pattern, options: [.regularExpression, .caseInsensitive]),
                            "\(String(describing: cause)) \(language): forbidden /\(pattern)/ in: \(surface)"
                        )
                    }
                }
            }
        }
    }

    func testTokenMissingGuidanceNamesTheAccessKeyAndTheCommand() {
        for language in Language.allCases {
            let guidance = OfflinePresentation.guidance(cause: .tokenMissing, language: language)
            XCTAssertTrue(
                guidance.detail.localizedCaseInsensitiveContains("clé d'accès")
                    || guidance.detail.localizedCaseInsensitiveContains("access key"),
                "\(language): \(guidance.detail)"
            )
            XCTAssertFalse(guidance.detail.contains("api.token"), "\(language): path must stay out of the prose")
            // A DMG install has nothing on PATH: the copyable command field must
            // name the binary inside the app bundle, not a bare `auxd`/`aux install`.
            XCTAssertTrue(guidance.commands.contains(L10n.embeddedServicePath), "\(language)")
            XCTAssertFalse(
                guidance.hint.contains(L10n.embeddedServicePath),
                "\(language): the binary path belongs only in the command field"
            )
            XCTAssertFalse(guidance.hint.contains("aux install"), "\(language)")
            XCTAssertEqual(guidance.commands, [OfflinePresentation.startServiceCommand])
            XCTAssertEqual(guidance.retry, language == .fr ? "Relancer Auxesis" : "Restart Auxesis")
            XCTAssertFalse(guidance.terminalLabel.isEmpty)
        }
    }

    func testEveryCauseHasFriendlyCopyAndACommand() {
        let causes: [OfflineCause] = [
            .tokenMissing,
            .tokenUnsafe,
            .keyRefused,
            .unreachable("connection refused"),
        ]
        for cause in causes {
            for language in Language.allCases {
                let guidance = OfflinePresentation.guidance(cause: cause, language: language)
                XCTAssertFalse(guidance.title.isEmpty, "\(cause) \(language)")
                XCTAssertFalse(guidance.detail.isEmpty, "\(cause) \(language)")
                XCTAssertFalse(guidance.hint.isEmpty, "\(cause) \(language)")
                XCTAssertFalse(guidance.commands.isEmpty, "\(cause) \(language)")
                XCTAssertEqual(guidance.retry, language == .fr ? "Relancer Auxesis" : "Restart Auxesis")
            }
        }
    }

    func testConnectingGuidanceSaysConnectingNotBroken() {
        let guidance = OfflinePresentation.guidance(cause: nil, language: .fr)
        XCTAssertEqual(guidance.title, L10n.t(.connectingTitle, .fr))
        XCTAssertEqual(guidance.detail, L10n.t(.connConnecting, .fr))
        XCTAssertEqual(guidance.commands, [OfflinePresentation.startServiceCommand])
    }

    func testUnreachableDetailKeepsTheRealReason() {
        let guidance = OfflinePresentation.guidance(
            cause: .unreachable("connection refused"),
            language: .en
        )
        XCTAssertTrue(guidance.detail.contains("connection refused"))
        XCTAssertFalse(guidance.hint.contains(L10n.embeddedServicePath))
        XCTAssertTrue(guidance.commands.contains(L10n.embeddedServicePath))
    }

    /// The binary path belongs only in the copyable command field. Every hint
    /// stays in plain words and the command block always names the embedded
    /// path, so the guidance is paste-ready after a DMG install.
    func testEveryGuidanceKeepsTheBinaryPathOutOfProseAndInsideTheCommandBlock() {
        let causes: [OfflineCause?] = [nil, .tokenMissing, .tokenUnsafe, .keyRefused, .unreachable("connection refused")]
        for cause in causes {
            for language in Language.allCases {
                let guidance = OfflinePresentation.guidance(cause: cause, language: language)
                let label = "\(String(describing: cause)) \(language)"
                XCTAssertFalse(
                    guidance.hint.contains(L10n.embeddedServicePath),
                    "\(label): the binary path belongs only in the copyable command: \(guidance.hint)"
                )
                XCTAssertFalse(guidance.hint.contains("« auxd »"), "\(label)")
                XCTAssertFalse(guidance.hint.contains("“auxd”"), "\(label)")
                XCTAssertFalse(guidance.hint.contains("aux install"), "\(label)")
                XCTAssertTrue(
                    guidance.commands.contains { $0.contains(L10n.embeddedServicePath) },
                    "\(label): copy block must name the embedded path: \(guidance.commands)"
                )
            }
        }
    }

    /// The whole offline surface — every state, both languages — must be
    /// paste-ready on a DMG install: the only `auxd` it may name is the full
    /// embedded path, and the `aux install` shorthand (dev/Homebrew only) is
    /// gone. This is the P2-F2 net over *all* states at once, copy block
    /// included.
    func testNoOfflineStateEverShowsABareAuxdOrAuxInstall() {
        let causes: [OfflineCause?] = [
            nil, .tokenMissing, .tokenUnsafe, .keyRefused, .unreachable("connection refused"),
        ]
        for cause in causes {
            for language in Language.allCases {
                let guidance = OfflinePresentation.guidance(cause: cause, language: language)
                let label = "\(String(describing: cause)) \(language)"
                // The copy block must name the real binary, not nothing.
                XCTAssertTrue(
                    guidance.commands.contains { $0.contains(L10n.embeddedServicePath) },
                    "\(label): copy block never names the embedded path: \(guidance.commands)"
                )
                let surfaces = [guidance.title, guidance.detail, guidance.hint,
                                guidance.terminalLabel, guidance.commands.joined(separator: "\n")]
                for surface in surfaces {
                    // Erase the one legitimate spelling, then look for leftovers.
                    // (Only the path is erased; `startServiceCommand` is not,
                    // so a wrong helper cannot hide itself here — the positive
                    // assertion above pins it.)
                    let stripped = surface
                        .replacingOccurrences(of: L10n.embeddedServicePath, with: " ")
                        .lowercased()
                    let words = stripped.split { !($0.isLetter || $0.isNumber) }.map(String.init)
                    XCTAssertFalse(
                        words.contains("auxd"),
                        "\(label): bare `auxd` outside the embedded path: \(surface)"
                    )
                    XCTAssertFalse(
                        stripped.contains("aux install"),
                        "\(label): `aux install` is not on a DMG install: \(surface)"
                    )
                }
            }
        }
    }

    /// The embedded path is already one safe shell word, so it is pasted
    /// unquoted; a bundle copied somewhere with a space gets quoted instead of
    /// silently becoming two arguments.
    func testEmbeddedServiceCommandIsQuotedOnlyWhenThePathNeedsIt() {
        XCTAssertEqual(OfflinePresentation.startServiceCommand, L10n.embeddedServicePath)
        XCTAssertEqual(OfflinePresentation.shellQuoted("/Applications/Auxesis.app/Contents/Resources/bin/auxd"),
                       L10n.embeddedServicePath)
        XCTAssertEqual(OfflinePresentation.shellQuoted("/Users/me/My Apps/Auxesis.app/bin/auxd"),
                       "'/Users/me/My Apps/Auxesis.app/bin/auxd'")
    }

    // MARK: F1 — a refused override is surfaced, host only

    func testRefusedOverrideIsSurfacedWithTheHostAndTheFallbackOnly() {
        let rejection = EndpointOverrideRejection(source: "AUXESIS_API_BASE", host: "evil.work")
        for language in Language.allCases {
            let guidance = OfflinePresentation.guidance(
                cause: .unreachable("connection refused"),
                language: language,
                overrideRejection: rejection
            )
            let notice = guidance.notice ?? ""
            XCTAssertTrue(notice.contains("evil.work"), "\(language)")
            XCTAssertTrue(notice.contains("127.0.0.1:2893"), "\(language)")
            XCTAssertTrue(notice.contains("AUXESIS_API_BASE"), "\(language)")
            XCTAssertFalse(notice.contains("@"), "\(language)")
            XCTAssertFalse(notice.contains("http://127.0.0.1@"),
                           "never echo the full rejected value (\(language))")
        }
    }

    func testNoRefusedOverrideMeansNoNotice() {
        XCTAssertNil(OfflinePresentation.guidance(cause: .tokenMissing, language: .fr).notice)
        let noHost = EndpointOverrideRejection(source: "AUXESIS_API", host: nil)
        let notice = OfflinePresentation.overrideNotice(noHost, language: .en)
        XCTAssertTrue(notice.contains("AUXESIS_API"))
        XCTAssertTrue(notice.contains("127.0.0.1:2893"))
    }
}
