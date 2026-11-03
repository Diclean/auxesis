// Contract v3 palette values and text contrast are executable tokens.
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class PaletteContrastTests: XCTestCase {
    func testEveryContractHexIsExactInBothAppearances() {
        let light = Palette.light
        XCTAssertEqual([
            light.blue, light.blueSoft, light.amber, light.amberSoft,
            light.green, light.greenSoft, light.red, light.redSoft,
            light.out, light.outSoft, light.work, light.list, light.hover,
            light.raise, light.line, light.line2, light.ink, light.ink2, light.ink3,
            light.onBlue,
        ].map(\.hexString), [
            "#1C1C1E", "#ECECEE", "#955300", "#FBF0E0",
            "#2F7A3A", "#E5F2E6", "#B0251C", "#FBE8E6",
            "#4B4FC4", "#E8E9FA", "#FFFFFF", "#F2F2F3", "#F5F5F6",
            "#FFFFFF", "#E3E3E6", "#C9C9CE", "#1C1C1E", "#4C4C50", "#5C5C61",
            "#FFFFFF",
        ])
        XCTAssertEqual([
            Palette.dark.blue, Palette.dark.blueSoft, Palette.dark.amber, Palette.dark.amberSoft,
            Palette.dark.green, Palette.dark.greenSoft, Palette.dark.red, Palette.dark.redSoft,
            Palette.dark.out, Palette.dark.outSoft, Palette.dark.work, Palette.dark.list, Palette.dark.hover,
            Palette.dark.raise, Palette.dark.line, Palette.dark.line2, Palette.dark.ink, Palette.dark.ink2,
            Palette.dark.ink3, Palette.dark.onBlue,
        ].map(\.hexString), [
            "#F2F2F4", "#2C2C2E", "#E8A94F", "#33281C",
            "#7BCB84", "#1A2F1E", "#F27A6F", "#3A1F1F",
            "#9A9DF5", "#23254A", "#161618", "#1B1B1D", "#111113",
            "#1F1F22", "#2A2A2D", "#3C3C40", "#ECECEE", "#AEAEB2", "#96969B",
            "#1C1C1E",
        ])
    }

    func testInk3MeetsAAOnSidebarAndContentBackgrounds() {
        for palette in [Palette.light, .dark] {
            XCTAssertGreaterThanOrEqual(Contrast.ratio(palette.ink3, palette.list), 4.5)
            XCTAssertGreaterThanOrEqual(Contrast.ratio(palette.ink3, palette.work), 4.5)
        }
    }

    func testEveryMeaningColourMeetsAAOnItsSoftFill() {
        for palette in [Palette.light, .dark] {
            for (foreground, background, role) in [
                (palette.blue, palette.blueSoft, "accent"),
                (palette.amber, palette.amberSoft, "wait"),
                (palette.green, palette.greenSoft, "local"),
                (palette.red, palette.redSoft, "bad"),
                (palette.out, palette.outSoft, "out"),
            ] {
                XCTAssertGreaterThanOrEqual(Contrast.ratio(foreground, background), 4.5, role)
            }
        }
    }

    func testCompletionAndBubbleSurfacesAreNeutral() {
        XCTAssertEqual(Palette.light.ownerBubble.hexString, "#E9E9EC")
        XCTAssertEqual(Palette.light.agentBubble.hexString, "#FFFFFF")
        XCTAssertEqual(Palette.dark.ownerBubble.hexString, "#ECECEE")
        XCTAssertEqual(Palette.dark.agentBubble.hexString, "#111113")
        for palette in [Palette.light, .dark] {
            XCTAssertGreaterThanOrEqual(Contrast.ratio(palette.ownerInk, palette.ownerBubble), 4.5)
            XCTAssertGreaterThanOrEqual(Contrast.ratio(palette.ink, palette.agentBubble), 4.5)
        }
    }

    // UI-V4-3: the accent is neutral ink; the four meaning hues did not move.
    func testAccentIsNeutralInkAndMeaningHuesAreUntouched() {
        XCTAssertEqual(
            [Palette.light.blue, Palette.light.blueSoft, Palette.light.onBlue].map(\.hexString),
            ["#1C1C1E", "#ECECEE", "#FFFFFF"])
        XCTAssertEqual(
            [Palette.dark.blue, Palette.dark.blueSoft, Palette.dark.onBlue].map(\.hexString),
            ["#F2F2F4", "#2C2C2E", "#1C1C1E"])
        XCTAssertEqual(
            [Palette.light.amber, Palette.light.green, Palette.light.red, Palette.light.out].map(\.hexString),
            ["#955300", "#2F7A3A", "#B0251C", "#4B4FC4"])
        XCTAssertEqual(
            [Palette.dark.amber, Palette.dark.green, Palette.dark.red, Palette.dark.out].map(\.hexString),
            ["#E8A94F", "#7BCB84", "#F27A6F", "#9A9DF5"])
        for palette in [Palette.light, .dark] {
            for colour in [palette.blue, palette.blueSoft, palette.selection, palette.onBlue, palette.hover] {
                // No teal left: red, green and blue channels stay within a few steps.
                XCTAssertLessThan(max(colour.red, colour.green, colour.blue) - min(colour.red, colour.green, colour.blue), 0.03)
            }
        }
    }

    // SOBER-1 (owner 2026-10-30, "trop vert"): every surface, line and ink
    // is a neutral grey; only the four meaning hues carry a colour.
    func testSurfacesLinesAndInksCarryNoHue() {
        for palette in [Palette.light, .dark] {
            for colour in [palette.work, palette.list, palette.raise, palette.hover, palette.selection,
                           palette.ink, palette.ink2, palette.ink3, palette.muted, palette.faint,
                           palette.line, palette.line2, palette.ownerBubble, palette.ownerInk, palette.agentBubble] {
                XCTAssertLessThan(max(colour.red, colour.green, colour.blue) - min(colour.red, colour.green, colour.blue),
                                  0.03, colour.hexString)
            }
        }
    }

    func testInkAccentPairsMeetAAInBothAppearances() {
        for palette in [Palette.light, .dark] {
            let pairs: [(RGBA, RGBA, String)] = [
                (palette.onBlue, palette.blue, "primary button"),
                (palette.blue, palette.work, "link on work"),
                (palette.blue, palette.list, "link on sidebar"),
                (palette.blue, palette.blueSoft, "accent on soft"),
                (palette.ink, palette.selection, "ink on selected row"),
                (palette.ink2, palette.selection, "ink2 on selected row"),
                (palette.ink3, palette.selection, "ink3 on selected row"),
                (palette.amber, palette.selection, "wait on selected row"),
                (palette.red, palette.selection, "bad on selected row"),
                (palette.out, palette.selection, "out on selected row"),
            ]
            // No sidebar row prints green text (the local line sits on the sidebar fill).
            for (foreground, background, label) in pairs {
                XCTAssertGreaterThanOrEqual(Contrast.ratio(foreground, background), 4.5, label)
            }
        }
    }

    // Ink links cannot rely on colour: they are underlined at rest and on hover.
    func testLinksAreUnderlinedAtRestAndOnHover() {
        XCTAssertTrue(LinkStyle.underlined(hovering: false))
        XCTAssertTrue(LinkStyle.underlined(hovering: true))
    }

    func testFocusRingAndSelectionShowAgainstTheirSurface() {
        for palette in [Palette.light, .dark] {
            let ring = palette.blue.opacity(0.55).over(palette.work)
            XCTAssertGreaterThanOrEqual(Contrast.ratio(ring, palette.work), 3)
            XCTAssertGreaterThanOrEqual(Contrast.ratio(palette.selection, palette.list), 1.1, "the selected row shows on the sidebar")
        }
    }
}
