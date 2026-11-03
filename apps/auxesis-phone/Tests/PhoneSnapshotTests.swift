import XCTest
import SwiftUI
@testable import AuxesisPhone

private struct SnapshotAuth: DraftAuthenticating {
    func authenticate(reason: String) async -> Bool { true }
}

@MainActor
final class PhoneSnapshotTests: XCTestCase {
    func testBoardScreensInBothAppearancesAndFrench() async throws {
        for scheme in [ColorScheme.light, .dark] {
            for screen in Screen.allCases {
                try await capture(screen, scheme: scheme, locale: "en", suffix: "\(screen.rawValue)-\(scheme == .light ? "light" : "dark")-en")
            }
        }
        try await capture(.review, scheme: .light, locale: "fr", suffix: "review-light-fr")
        for screen in [Screen.chats, .chat, .waiting, .review] {
            try await capture(screen, scheme: .light, locale: "en", suffix: "\(screen.rawValue)-light-en-xxl", typeSize: .xxLarge)
        }
    }
    private func capture(_ screen: Screen, scheme: ColorScheme, locale: String, suffix: String, typeSize: DynamicTypeSize = .large) async throws {
        let model = PhoneModel(authenticator: SnapshotAuth(), autoConfirm: false)
        if screen == .waiting {
            model.openDraft(.jonas)
            await model.send(reason: "Sample")
            model.macConfirmed(.jonas)
        }
        model.screen = screen
        let content = PhoneRoot(model: model)
            .environment(\.snapshotRendering, true)
            .environment(\.locale, Locale(identifier: locale))
            .environment(\.colorScheme, scheme)
            .environment(\.dynamicTypeSize, typeSize)
            .frame(width: 393, height: 852)
        let renderer = ImageRenderer(content: content)
        renderer.scale = 2
        let image = try XCTUnwrap(renderer.uiImage, "SwiftUI image for \(suffix)")
        let attachment = XCTAttachment(image: image)
        attachment.name = suffix
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
