// Style — the contract's type, colour and controls, translated to SwiftUI.
import AppKit
import AuxesisKit
import SwiftUI

// MARK: - Fonts

enum Fonts {
    /// System SF Pro with tabular digits.
    static func nsFont(_ size: CGFloat, _ weight: CGFloat) -> NSFont {
        let systemWeight: NSFont.Weight
        switch weight {
        case ..<450: systemWeight = .regular
        case ..<550: systemWeight = .medium
        default: systemWeight = .semibold
        }
        let features: [[NSFontDescriptor.FeatureKey: Int]] = [
            [.typeIdentifier: kNumberSpacingType, .selectorIdentifier: kMonospacedNumbersSelector],
        ]
        let system = NSFont.systemFont(ofSize: size, weight: systemWeight)
        return NSFont(descriptor: system.fontDescriptor.addingAttributes([.featureSettings: features]), size: size) ?? system
    }
}

extension Font {
    /// SF Pro at a contract size and weight.
    static func hk(_ size: CGFloat, _ weight: CGFloat = Theme.Weight.regular) -> Font {
        Font(Fonts.nsFont(size, weight))
    }

    static var caption: Font { .hk(Theme.Text.caption) }
    static var meta: Font { .hk(Theme.Text.meta) }
    static var ui: Font { .hk(Theme.Text.ui) }
    static var body15: Font { .hk(Theme.Text.body) }
}

// MARK: - Colour

extension RGBA {
    var color: Color {
        Color(.sRGB, red: red, green: green, blue: blue, opacity: alpha)
    }
}

private struct PaletteKey: EnvironmentKey {
    static let defaultValue = Palette.light
}

private struct LanguageKey: EnvironmentKey {
    static let defaultValue = Language.en
}

/// The language of the reply a `RichMessage` draws (its chips follow it).
private struct ReplyLanguageKey: EnvironmentKey {
    static let defaultValue = Language.en
}

/// Snapshots only: open threads at their top instead of their latest message.
private struct ThreadStartsAtTopKey: EnvironmentKey {
    static let defaultValue = false
}

extension EnvironmentValues {
    var threadStartsAtTop: Bool {
        get { self[ThreadStartsAtTopKey.self] }
        set { self[ThreadStartsAtTopKey.self] = newValue }
    }

    var palette: Palette {
        get { self[PaletteKey.self] }
        set { self[PaletteKey.self] = newValue }
    }

    var language: Language {
        get { self[LanguageKey.self] }
        set { self[LanguageKey.self] = newValue }
    }

    var replyLanguage: Language {
        get { self[ReplyLanguageKey.self] }
        set { self[ReplyLanguageKey.self] = newValue }
    }
}

/// Sets the palette from the appearance; every view below reads `\.palette`.
struct Themed: ViewModifier {
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        content.environment(\.palette, scheme == .dark ? .dark : .light)
    }
}

extension View {
    func themed() -> some View { modifier(Themed()) }
}

/// Copy lookup bound to the environment language.
struct Copy {
    let language: Language
    func callAsFunction(_ key: UIKey) -> String { L10n.ui(key, language) }
    func f(_ key: UIKey, _ arguments: CVarArg...) -> String {
        String(format: L10n.ui(key, language), arguments: arguments)
    }
}

// MARK: - Icons and tiles

struct IconShape: Shape {
    let icon: Icon

    func path(in rect: CGRect) -> Path {
        let scale = min(rect.width, rect.height) / 16
        var transform = CGAffineTransform(translationX: rect.minX, y: rect.minY).scaledBy(x: scale, y: scale)
        return Path(icon.path.copy(using: &transform) ?? icon.path)
    }
}

/// A drawn icon: 16-unit grid, 1.5 stroke, round caps (prototype `svg.i`).
struct IconView: View {
    let icon: Icon
    var size: CGFloat = 16
    var weight: CGFloat = 1.5

    var body: some View {
        IconShape(icon: icon)
            .stroke(style: StrokeStyle(lineWidth: weight * size / 16, lineCap: .round, lineJoin: .round))
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// The agent's mascot at one of the tile sizes (MASCOT-1). Every agent wears
/// one: an agent the owner added starts as Sprout.
struct AgentTile: View {
    enum Size {
        case xs, sm, header, row, large

        var side: CGFloat {
            switch self {
            case .xs: return 20
            case .sm: return 28
            case .header: return 30
            case .row: return 40
            case .large: return 46
            }
        }
    }

    let member: TeamMember
    var size: Size = .row
    var working = false
    var stopped = false

    var body: some View {
        AgentMascot(agentId: member.id, size: size.side, working: working, stopped: stopped, label: member.name)
    }
}

// MARK: - Controls

/// A label whose words and glyph take two inks. SOBER-1: where data went is
/// said in `ink2` words with a small `ink3` glyph, never in a hue.
struct TwoToneLabelStyle: LabelStyle {
    let titleColor: Color
    let iconColor: Color

    func makeBody(configuration: Configuration) -> some View {
        Label {
            configuration.title.foregroundStyle(titleColor)
        } icon: {
            configuration.icon.foregroundStyle(iconColor)
        }
    }
}

/// `.btn`: hairline outlined button; `.pri`: filled blue; `.stop`: red outline.
struct AuxButtonStyle: ButtonStyle {
    enum Kind { case normal, primary, stop, stopFilled, link, plain }
    var kind: Kind = .normal
    var height: CGFloat = 28
    @Environment(\.palette) private var palette
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        StyledButton(configuration: configuration, kind: kind, height: height, palette: palette, enabled: enabled)
    }

    private struct StyledButton: View {
        let configuration: ButtonStyle.Configuration
        let kind: Kind
        let height: CGFloat
        let palette: Palette
        let enabled: Bool
        @State private var hovering = false

        var body: some View {
            let shape = RoundedRectangle(cornerRadius: kind == .link ? 4 : 7, style: .continuous)
            configuration.label
                .font(.hk(Theme.Text.ui, kind == .plain ? Theme.Weight.regular : Theme.Weight.semibold))
                .lineLimit(1)
                .padding(.horizontal, kind == .link ? 2 : 12)
                .frame(height: kind == .link ? nil : height)
                .foregroundStyle(foreground)
                .background(shape.fill(background))
                .underline(kind == .link && LinkStyle.underlined(hovering: hovering))
                .overlay(shape.strokeBorder(border, lineWidth: 1))
                .opacity(enabled ? 1 : 0.45)
                .scaleEffect(configuration.isPressed ? 0.98 : 1)
                .contentShape(shape)
                .onHover { hovering = $0 }
        }

        private var foreground: Color {
            switch kind {
            case .normal: return palette.ink.color
            case .primary: return palette.onBlue.color
            case .stop: return palette.red.color
            case .stopFilled: return .white
            case .link: return palette.blue.color
            case .plain: return palette.ink2.color
            }
        }

        private var background: Color {
            switch kind {
            case .normal, .plain: return hovering ? palette.hover.color : (kind == .plain ? .clear : palette.work.color)
            case .primary: return palette.blue.color.opacity(hovering ? 0.92 : 1)
            case .stop: return hovering ? palette.redSoft.color : .clear
            case .stopFilled: return palette.red.color
            case .link: return .clear
            }
        }

        private var border: Color {
            switch kind {
            case .normal: return palette.line2.color
            case .primary, .stopFilled: return .clear
            case .stop: return palette.red.color.opacity(0.4)
            case .link, .plain: return .clear
            }
        }
    }
}

/// The inline keyboard under a message (`.k`): blue text, hairline inset.
struct KeyButtonStyle: ButtonStyle {
    var primary = false
    @Environment(\.palette) private var palette
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        configuration.label
            .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
            .lineLimit(1)
            .padding(.horizontal, 13)
            .frame(height: 32)
            .foregroundStyle(primary ? palette.onBlue.color : palette.blue.color)
            .background(shape.fill(primary ? palette.blue.color : palette.work.color))
            .overlay(shape.strokeBorder(primary ? Color.clear : palette.line2.color, lineWidth: 1))
            .opacity(enabled ? 1 : 0.45)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .contentShape(shape)
    }
}

/// A hairline, the contract's separator of choice.
struct Hairline: View {
    var strong = false
    @Environment(\.palette) private var palette

    var body: some View {
        Rectangle().fill((strong ? palette.line2 : palette.line).color).frame(height: 1)
    }
}

/// Toolbar icon button (`.tb`), 28×28.
struct ToolbarIconButton: View {
    let icon: Icon
    let help: String
    let identifier: String
    var pressed = false
    let action: () -> Void
    @Environment(\.palette) private var palette
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            IconView(icon: icon)
                .foregroundStyle(hovering || pressed ? palette.ink.color : palette.muted.color)
                .frame(width: 28, height: 28)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(pressed ? palette.selection.color : hovering ? palette.hover.color : .clear)
                )
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
        .accessibilityIdentifier(identifier)
        .onHover { hovering = $0 }
    }
}

extension Store.Connection {
    var isOnline: Bool {
        if case .online = self { return true }
        return false
    }
}
