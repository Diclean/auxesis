// Theme — v4 contract tokens. Legacy property names remain at call sites:
// blue=accent (neutral ink since UI-V4-3), green=local, red=bad, amber=wait.
// Completion is neutral.
import CoreGraphics
import Foundation

/// Straight sRGB components; the app maps these to `Color`.
public struct RGBA: Equatable {
    public let red: Double
    public let green: Double
    public let blue: Double
    public let alpha: Double

    public init(red: Double, green: Double, blue: Double, alpha: Double = 1) {
        self.red = red
        self.green = green
        self.blue = blue
        self.alpha = alpha
    }

    public init(hex: UInt32, alpha: Double = 1) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            alpha: alpha
        )
    }

    /// `#RRGGBB`, for tests and diagnostics.
    public var hexString: String {
        String(
            format: "#%02X%02X%02X",
            Int((red * 255).rounded()),
            Int((green * 255).rounded()),
            Int((blue * 255).rounded())
        )
    }

    /// The same colour at another opacity.
    public func opacity(_ alpha: Double) -> RGBA {
        RGBA(red: red, green: green, blue: blue, alpha: alpha)
    }

    /// Opaque result of drawing `self` (with its alpha) over `background`.
    public func over(_ background: RGBA) -> RGBA {
        RGBA(
            red: red * alpha + background.red * (1 - alpha),
            green: green * alpha + background.green * (1 - alpha),
            blue: blue * alpha + background.blue * (1 - alpha)
        )
    }
}

/// Stable per-name index kept for `Mapper` (the old rail's hues). The new UI
/// never colour-codes agents: identity is a glyph, not a colour.
public enum AgentHues {
    public static let count = 12

    /// Stable index for an agent name (FNV-1a).
    public static func index(for name: String) -> Int {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325
        for byte in name.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        return Int(hash % UInt64(count))
    }
}

/// Semantic colour roles, one instance per appearance (contract table).
public struct Palette: Equatable {
    /// The conversation and every view.
    public let work: RGBA
    /// The team sidebar, a notch dimmer.
    public let list: RGBA
    /// Raised wells: pinned bar, "what the model saw" panel, disabled composer.
    public let raise: RGBA
    public let hover: RGBA
    /// Selected row: soft ink, a notch deeper than `blueSoft` in light so it
    /// shows on the sidebar.
    public let selection: RGBA
    public let ink: RGBA
    public let ink2: RGBA
    public let ink3: RGBA
    public let muted: RGBA
    /// Disabled and not-yet text; decorative.
    public let faint: RGBA
    /// Decorative hairline.
    public let line: RGBA
    /// Control outline and stronger hairline.
    public let line2: RGBA
    /// The `accent` role: neutral ink for actions you can press, links, focus.
    public let blue: RGBA
    /// Inverse text on a solid accent (ink) control.
    public let onBlue: RGBA
    public let blueSoft: RGBA
    /// The owner's bubble.
    public let ownerBubble: RGBA
    /// Text on the owner's bubble (v4: the same dark ink in both appearances).
    public let ownerInk: RGBA
    /// The agent's bubble.
    public let agentBubble: RGBA
    /// Handled by a brain on this Mac. Nothing else.
    public let green: RGBA
    public let greenSoft: RGBA
    /// Stop, stopped, errors.
    public let red: RGBA
    public let redSoft: RGBA
    /// A difference to explain.
    public let amber: RGBA
    public let amberSoft: RGBA
    /// Left this Mac (egress).
    public let out: RGBA
    public let outSoft: RGBA

    public static let light = Palette(
        work: RGBA(hex: 0xFFFFFF),
        list: RGBA(hex: 0xF2F2F3),
        raise: RGBA(hex: 0xFFFFFF),
        hover: RGBA(hex: 0xF5F5F6),
        selection: RGBA(hex: 0xE2E2E6),
        ink: RGBA(hex: 0x1C1C1E),
        ink2: RGBA(hex: 0x4C4C50),
        ink3: RGBA(hex: 0x5C5C61),
        muted: RGBA(hex: 0x4C4C50),
        faint: RGBA(hex: 0x5C5C61),
        line: RGBA(hex: 0xE3E3E6),
        line2: RGBA(hex: 0xC9C9CE),
        blue: RGBA(hex: 0x1C1C1E),
        onBlue: RGBA(hex: 0xFFFFFF),
        blueSoft: RGBA(hex: 0xECECEE),
        ownerBubble: RGBA(hex: 0xE9E9EC),
        ownerInk: RGBA(hex: 0x1C1C1E),
        agentBubble: RGBA(hex: 0xFFFFFF),
        green: RGBA(hex: 0x2F7A3A),
        greenSoft: RGBA(hex: 0xE5F2E6),
        red: RGBA(hex: 0xB0251C),
        redSoft: RGBA(hex: 0xFBE8E6),
        amber: RGBA(hex: 0x955300),
        amberSoft: RGBA(hex: 0xFBF0E0),
        out: RGBA(hex: 0x4B4FC4),
        outSoft: RGBA(hex: 0xE8E9FA)
    )

    public static let dark = Palette(
        work: RGBA(hex: 0x161618),
        list: RGBA(hex: 0x1B1B1D),
        raise: RGBA(hex: 0x1F1F22),
        hover: RGBA(hex: 0x111113),
        selection: RGBA(hex: 0x2A2A2D),
        ink: RGBA(hex: 0xECECEE),
        ink2: RGBA(hex: 0xAEAEB2),
        ink3: RGBA(hex: 0x96969B),
        muted: RGBA(hex: 0xAEAEB2),
        faint: RGBA(hex: 0x96969B),
        line: RGBA(hex: 0x2A2A2D),
        line2: RGBA(hex: 0x3C3C40),
        blue: RGBA(hex: 0xF2F2F4),
        onBlue: RGBA(hex: 0x1C1C1E),
        blueSoft: RGBA(hex: 0x2C2C2E),
        ownerBubble: RGBA(hex: 0xECECEE),
        ownerInk: RGBA(hex: 0x1C1C1E),
        agentBubble: RGBA(hex: 0x111113),
        green: RGBA(hex: 0x7BCB84),
        greenSoft: RGBA(hex: 0x1A2F1E),
        red: RGBA(hex: 0xF27A6F),
        redSoft: RGBA(hex: 0x3A1F1F),
        amber: RGBA(hex: 0xE8A94F),
        amberSoft: RGBA(hex: 0x33281C),
        out: RGBA(hex: 0x9A9DF5),
        outSoft: RGBA(hex: 0x23254A)
    )
}

/// Type scale and visual constants, in points.
public enum Theme {
    public enum Text {
        public static let caption: CGFloat = 11
        public static let meta: CGFloat = 12
        public static let ui: CGFloat = 13
        public static let body: CGFloat = 14
        public static let title: CGFloat = 17
        public static let heading: CGFloat = 24
        public static let secondary: CGFloat = 12.5
        public static let lead: CGFloat = 16
        public static let detailTitleTracking: CGFloat = -0.3
        public static let leadLineHeight: CGFloat = 1.5
    }

    /// Legacy numeric values map to Regular, Medium and Semibold.
    public enum Weight {
        public static let regular: CGFloat = 400
        public static let medium: CGFloat = 500
        public static let semibold: CGFloat = 600
        public static let strong: CGFloat = 600
        public static let bold: CGFloat = 600
    }

    public static let sidebarWidth: CGFloat = 288
    public static let inspectorWidth: CGFloat = 360
    public static let barHeight: CGFloat = 52
    /// The conversation column and its composer (prototype `.col`).
    public static let columnWidth: CGFloat = 640
    public static let composerWidth: CGFloat = 640
    public static let viewWidth: CGFloat = 900
    public static let bubbleRadius: CGFloat = 18
    public static let bubbleTightRadius: CGFloat = 6
    public static let hairline: CGFloat = 1
    public static let controlRadius: CGFloat = 6
    public static let popoverRadius: CGFloat = 8
    public static let proposalRadius: CGFloat = 10
    public static let rowVerticalPadding: CGFloat = 10
    public static let rowHorizontalPadding: CGFloat = 18
    public static let detailTopPadding: CGFloat = 28
    public static let detailSidePadding: CGFloat = 36
    public static let sectionGap: CGFloat = 26
    public static let labelValueGap: CGFloat = 7
    public static let shadowY: CGFloat = 12
    public static let shadowBlur: CGFloat = 32
    public static let shadowLightOpacity: CGFloat = 0.22
    public static let shadowDarkOpacity: CGFloat = 0.60
}

/// WCAG 2.x relative-luminance contrast (opaque colours).
public enum Contrast {
    public static func luminance(_ color: RGBA) -> Double {
        func channel(_ value: Double) -> Double {
            value <= 0.04045 ? value / 12.92 : pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * channel(color.red) + 0.7152 * channel(color.green) + 0.0722 * channel(color.blue)
    }

    public static func ratio(_ a: RGBA, _ b: RGBA) -> Double {
        let la = luminance(a)
        let lb = luminance(b)
        return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
    }
}

/// A link is ink, so colour cannot tell it from body text: it is always
/// underlined, and the hover state only adds emphasis.
public enum LinkStyle {
    public static func underlined(hovering: Bool) -> Bool { true }
}

/// Pure decisions the views consult, so Reduce Motion is testable.
public enum Motion {
    /// The tile outline breathes only while the agent works, and never when
    /// the owner asked for reduced motion or Stop all is engaged.
    public static func tileBreathes(working: Bool, stopped: Bool, reduceMotion: Bool) -> Bool {
        working && !stopped && !reduceMotion
    }
}
