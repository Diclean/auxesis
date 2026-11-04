import SwiftUI
import AuxesisShared

struct PhonePalette {
    let bg, raise, line, ink, ink2, ink3, soft, wait, waitBG, local, out, bad, badBG, clay, onInk: Color
    init(_ scheme: ColorScheme) {
        let dark = scheme == .dark
        func color(_ light: UInt32, _ darkValue: UInt32) -> Color {
            let rgba = RGBA(hex: dark ? darkValue : light)
            return Color(red: rgba.red, green: rgba.green, blue: rgba.blue)
        }
        bg = color(0xF4F2EE, 0x0F0F10); raise = color(0xECE9E3, 0x1A1A1C)
        line = color(0xDEDAD2, 0x2A2A2D); ink = color(0x2A2826, 0xF2F2F4)
        ink2 = color(0x4F4B46, 0xB4B4BA); ink3 = color(0x6B665F, 0x8E8E95)
        soft = color(0xE7E3DC, 0x2C2C2E); wait = color(0x8A5200, 0xE8A94F)
        waitBG = color(0xFDF1DE, 0x33281C); local = color(0x2E7D3A, 0x7BCB84)
        out = color(0x4B4FC4, 0x9A9DF5); bad = color(0xB8322A, 0xF27A6F)
        badBG = color(0xFBE9E7, 0x3A1F1C); clay = color(0xC95F3B, 0xD9714D)
        onInk = color(0xF4F2EE, 0x1C1C1E)
    }
}

enum MascotKind { case loop, glance, hook, twin, specs, sprout }

/// The board's 232-unit SVG, including the open 330° elliptical loop.
struct MascotLine: Shape {
    let kind: MascotKind
    func path(in rect: CGRect) -> Path {
        let rx: CGFloat = kind == .hook ? 66 : 72
        let ry: CGFloat = 70
        let scale = min(rect.width, rect.height) / 232
        func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.midX + x * scale, y: rect.minY + (y + 130) * scale)
        }
        var path = Path()
        for index in 0...110 {
            let angle = (30.0 + Double(index) * 330.0 / 110.0) * .pi / 180
            let p = point(rx * cos(angle), ry * sin(angle))
            if index == 0 { path.move(to: p) } else { path.addLine(to: p) }
        }
        path.move(to: point(rx, 46)); path.addLine(to: point(rx, -100))
        if kind == .hook {
            path.move(to: point(rx, -100))
            path.addQuadCurve(to: point(rx - 18, -118), control: point(rx, -118))
        }
        return path
    }
}

struct MascotEyes: Shape {
    let kind: MascotKind
    func path(in rect: CGRect) -> Path {
        let s = min(rect.width, rect.height) / 232
        func ellipse(_ x: CGFloat, _ y: CGFloat, _ r: CGFloat) -> CGRect {
            CGRect(x: rect.midX + (x-r)*s, y: rect.minY + (y+130-r)*s, width: 2*r*s, height: 2*r*s)
        }
        var p = Path()
        switch kind {
        case .glance: p.addEllipse(in: ellipse(-8, -12, 12)); p.addEllipse(in: ellipse(34, -12, 12))
        case .twin: p.addEllipse(in: ellipse(-30, -6, 10)); p.addEllipse(in: ellipse(-6, -6, 10))
        case .hook: p.addEllipse(in: ellipse(-22, -4, 12)); p.addEllipse(in: ellipse(16, -4, 12))
        case .specs:
            // The glasses are rings, with the bridge from the board.
            p.addEllipse(in: ellipse(-24, -6, 17)); p.addEllipse(in: ellipse(22, -6, 17))
            p.addRect(CGRect(x: rect.midX - 7*s, y: rect.minY + 119*s, width: 12*s, height: 10*s))
        default: p.addEllipse(in: ellipse(-24, -6, 12)); p.addEllipse(in: ellipse(18, -6, 12))
        }
        return p
    }
}

struct Mascot: View {
    let kind: MascotKind
    let size: CGFloat
    let palette: PhonePalette
    var body: some View {
        ZStack {
            MascotLine(kind: kind).stroke(palette.ink, style: StrokeStyle(lineWidth: size * 18 / 232, lineCap: .round, lineJoin: .round))
            if kind == .specs {
                MascotEyes(kind: kind).stroke(palette.ink, lineWidth: size * 10 / 232)
            } else { MascotEyes(kind: kind).fill(palette.ink) }
            Circle().fill(palette.clay).frame(width: size * 32 / 232, height: size * 32 / 232)
                .offset(x: size * (kind == .hook ? 66 : 72) / 232, y: size * (-100 + 130 - 116) / 232)
        }
        .frame(width: size, height: size).accessibilityHidden(true)
    }
}

struct Card<Content: View>: View {
    let palette: PhonePalette
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 7) { content }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(palette.raise, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(palette.line, lineWidth: 1))
    }
}

struct Fact: View {
    let icon: String
    let text: String
    let palette: PhonePalette
    var glyph: Color? = nil
    var body: some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: icon).font(.caption).foregroundStyle(glyph ?? palette.ink2).frame(width: 16).accessibilityHidden(true)
            Text(text).font(.caption).foregroundStyle(palette.ink2).fixedSize(horizontal: false, vertical: true)
        }.accessibilityElement(children: .combine)
    }
}

struct ActionButton: View {
    let title: String
    let palette: PhonePalette
    var primary = false
    var icon: String? = nil
    var fullWidth = false
    var action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if let icon { Image(systemName: icon).accessibilityHidden(true) }
                Text(title).fontWeight(.semibold)
            }
            .font(.subheadline).padding(.horizontal, 13).padding(.vertical, 9)
            .frame(maxWidth: fullWidth ? .infinity : nil, minHeight: 44)
            .foregroundStyle(primary ? palette.onInk : palette.ink)
            .background(primary ? palette.ink : palette.bg, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(primary ? palette.ink : palette.line))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }
}

struct NeedsBadge: View {
    let text: String
    let palette: PhonePalette
    var body: some View {
        Label(text, systemImage: "hourglass")
            .font(.caption2.weight(.semibold)).padding(.horizontal, 8).padding(.vertical, 4)
            .foregroundStyle(palette.wait).background(palette.waitBG, in: Capsule())
            .accessibilityElement(children: .combine)
    }
}

struct SectionLabel: View {
    let title: String
    let palette: PhonePalette
    var body: some View {
        Text(title.uppercased()).font(.caption2.weight(.semibold)).tracking(0.6).foregroundStyle(palette.ink3)
            .accessibilityAddTraits(.isHeader)
    }
}

private struct SnapshotRenderingKey: EnvironmentKey { static let defaultValue = false }
extension EnvironmentValues {
    var snapshotRendering: Bool {
        get { self[SnapshotRenderingKey.self] }
        set { self[SnapshotRenderingKey.self] = newValue }
    }
}

/// ImageRenderer cannot flatten UIKit-backed text controls. The snapshot uses
/// the same text and styling without creating a native input view.
struct FixtureTextField: View {
    let placeholder: String
    @Binding var text: String
    var multiline = false
    @Environment(\.snapshotRendering) private var snapshotRendering
    var body: some View {
        if snapshotRendering {
            Text(text.isEmpty ? placeholder : text).frame(maxWidth: .infinity, alignment: .leading)
        } else if multiline {
            TextField(placeholder, text: $text, axis: .vertical).lineLimit(3...6)
        } else {
            TextField(placeholder, text: $text)
        }
    }
}

/// ImageRenderer also omits UIKit-backed scroll views. Render their initial
/// viewport directly for the snapshot; the app keeps native scrolling.
struct FixtureScroll<Content: View>: View {
    var axes: Axis.Set = .vertical
    var showsIndicators = true
    @ViewBuilder var content: Content
    @Environment(\.snapshotRendering) private var snapshotRendering
    var body: some View {
        if snapshotRendering {
            if axes == .horizontal {
                content.fixedSize(horizontal: true, vertical: false).frame(maxWidth: .infinity, alignment: .leading).clipped()
            } else {
                content.fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top).clipped()
            }
        } else {
            ScrollView(axes, showsIndicators: showsIndicators) { content }
        }
    }
}
