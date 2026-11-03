// Agent mascots (MASCOT-1, direction A "line"): pure
// SwiftUI Shapes on a 232-unit grid, no bitmap. The tint draws the body, the
// clay dot is the one accent and never changes. 28 pt in the sidebar, 20 pt
// on the chat author line, 16 pt (all ink3) on handoff lines.
import AuxesisKit
import SwiftUI

/// The parts of one mascot on its grid (−116…116, y down), as fill paths:
/// strokes are outlined and merged, so one fill draws them without seams.
struct MascotGeometry {
    static let grid: CGFloat = 232

    let ink: Path
    let accent: Path
    let bounds: CGRect

    /// At 20 pt and under the small optical size keeps 16 pt readable.
    static func of(_ variant: MascotVariant, small: Bool) -> MascotGeometry {
        cache["\(variant.rawValue)-\(small)"]!
    }

    private static let cache: [String: MascotGeometry] = Dictionary(uniqueKeysWithValues:
        MascotVariant.allCases.flatMap { variant in
            [false, true].map { ("\(variant.rawValue)-\($0)", MascotGeometry(variant, small: $0)) }
        })

    private init(_ variant: MascotVariant, small: Bool) {
        // Secondary lines (Specs rings, Visor bar) grow with the main line.
        let grow: CGFloat = small ? 26.0 / 22.0 : 1
        let line: CGFloat = small ? 26 : 22
        let eye: CGFloat = small ? 14 : 12
        let dot: CGFloat = small ? 18 : 16
        let (rx, ry): (CGFloat, CGFloat) = variant == .tall ? (58, 82) : variant == .wide ? (88, 56) : (72, 70)
        let style = StrokeStyle(lineWidth: line, lineCap: .round, lineJoin: .round)

        // Body: the open loop, from 30° below the right side, clockwise round to 0°.
        var body = Path()
        body.addArc(center: .zero, radius: 1, startAngle: .degrees(30), endAngle: .degrees(360), clockwise: false,
                    transform: CGAffineTransform(scaleX: rx, y: ry))

        // Stem: the antenna at x = rx, ending where the dot (or leaf) sits.
        var stem = Path()
        stem.move(to: CGPoint(x: rx, y: 0.66 * ry))
        var tip = CGPoint(x: rx, y: variant == .sprout ? -ry - 6 : -ry - 30)
        if variant == .hook {
            stem.addLine(to: CGPoint(x: rx, y: -ry))
            tip = CGPoint(x: rx + 28, y: -ry - 24)
            stem.addQuadCurve(to: tip, control: CGPoint(x: rx, y: -ry - 24))
        } else {
            stem.addLine(to: tip)
        }
        if variant == .twin {
            // A second, dotless stem on the left, rising from the loop.
            stem.move(to: CGPoint(x: -0.7 * rx, y: -0.71 * ry))
            stem.addLine(to: CGPoint(x: -0.7 * rx, y: -ry - 18))
        }
        var ink = body.strokedPath(style).union(stem.strokedPath(style))

        // Eyes only, never a mouth.
        let shift: CGSize = variant == .glance ? CGSize(width: 16, height: -6) : .zero
        let eyes = [CGPoint(x: -24 + shift.width, y: -6 + shift.height), CGPoint(x: 18 + shift.width, y: -6 + shift.height)]
        func circle(_ centre: CGPoint, _ r: CGFloat) -> CGRect { CGRect(x: centre.x - r, y: centre.y - r, width: r * 2, height: r * 2) }
        var face = Path()
        switch variant {
        case .specs:
            var rings = Path()
            for centre in eyes { rings.addEllipse(in: circle(centre, 17)) }
            if !small {
                rings.move(to: CGPoint(x: eyes[0].x + 17, y: -6))
                rings.addLine(to: CGPoint(x: eyes[1].x - 17, y: -6))
            }
            face = rings.strokedPath(StrokeStyle(lineWidth: 10 * grow, lineCap: .round))
        case .visor:
            var bar = Path()
            bar.move(to: CGPoint(x: -38, y: -6))
            bar.addLine(to: CGPoint(x: 32, y: -6))
            face = bar.strokedPath(StrokeStyle(lineWidth: 20 * grow, lineCap: .round))
        case .calm:
            var arcs = Path()
            for centre in eyes {
                // Move to each arc's start first: addArc would join the two eyes with a line.
                arcs.move(to: CGPoint(x: centre.x + 10 * cos(.pi / 9), y: centre.y + 10 * sin(.pi / 9)))
                arcs.addArc(center: centre, radius: 10, startAngle: .degrees(20), endAngle: .degrees(160), clockwise: false)
            }
            face = arcs.strokedPath(StrokeStyle(lineWidth: small ? 17 : 11, lineCap: .round))
        default:
            for centre in eyes { face.addEllipse(in: circle(centre, eye)) }
        }
        ink = ink.union(face)

        // The clay accent: the dot on the antenna, or Sprout's leaf.
        var accent = Path()
        if variant == .sprout {
            let k = dot / 16
            func at(_ dx: CGFloat, _ dy: CGFloat) -> CGPoint { CGPoint(x: tip.x + dx * k, y: tip.y + dy * k) }
            accent.move(to: tip)
            accent.addCurve(to: at(20, -46), control1: at(-18, -14), control2: at(-6, -42))
            accent.addCurve(to: tip, control1: at(36, -32), control2: at(26, -6))
            accent.closeSubpath()
        } else {
            accent.addEllipse(in: circle(tip, dot))
        }

        self.ink = ink
        self.accent = accent
        self.bounds = ink.boundingRect.union(accent.boundingRect)
    }
}

/// One layer of a mascot, centred on its bounding box and scaled so the
/// 232 grid fills the frame.
struct MascotShape: Shape {
    let geometry: MascotGeometry
    let accent: Bool

    func path(in rect: CGRect) -> Path {
        let box = geometry.bounds
        let scale = min(rect.width, rect.height) / max(MascotGeometry.grid, box.width, box.height)
        let transform = CGAffineTransform(translationX: rect.midX, y: rect.midY)
            .scaledBy(x: scale, y: scale)
            .translatedBy(x: -box.midX, y: -box.midY)
        return (accent ? geometry.accent : geometry.ink).applying(transform)
    }
}

struct MascotView: View {
    let look: MascotLook
    var size: CGFloat = 28
    /// Handoff lines: every part, the dot included, in ink3.
    var mono = false
    var working = false
    /// Stopped: the mascot drops to 45 %; the row keeps the red square and word.
    var stopped = false
    /// Read by VoiceOver only when the mascot stands alone; beside a visible
    /// name it is hidden.
    var label: String?
    @Environment(\.palette) private var palette
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var fade = false

    var body: some View {
        let geometry = MascotGeometry.of(look.variant, small: size <= 20)
        ZStack {
            MascotShape(geometry: geometry, accent: false)
                .fill((mono ? palette.ink3 : look.tint.value(dark: scheme == .dark)).color)
            MascotShape(geometry: geometry, accent: true)
                .fill((mono ? palette.ink3 : MascotLook.clay).color)
                .opacity(fade ? 0.35 : 1)
        }
        .frame(width: size, height: size)
        .compositingGroup()
        .opacity(stopped ? 0.45 : 1)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label ?? "")
        .accessibilityHidden(label == nil)
        .onAppear { animate() }
        .onChange(of: working) { _, _ in animate() }
        .onChange(of: stopped) { _, _ in animate() }
    }

    /// Working: the dot fades 100 → 35 % on a 1.6 s loop; still under Reduce Motion.
    private func animate() {
        guard Motion.tileBreathes(working: working, stopped: stopped, reduceMotion: reduceMotion) else {
            fade = false
            return
        }
        withAnimation(.easeInOut(duration: 0.8).repeatForever(autoreverses: true)) { fade = true }
    }
}

/// An agent's mascot as the owner picked it (or its default). It redraws
/// the moment `AgentLooks` saves a new look, wherever it is on screen.
struct AgentMascot: View {
    let agentId: String
    var size: CGFloat = 28
    var mono = false
    var working = false
    var stopped = false
    var label: String?
    @State private var revision = 0

    var body: some View {
        let _ = revision
        MascotView(look: AgentLooks().look(for: agentId), size: size, mono: mono, working: working, stopped: stopped, label: label)
            .onReceive(NotificationCenter.default.publisher(for: AgentLooks.didChange)) { note in
                if note.object as? String == agentId { revision += 1 }
            }
    }
}
