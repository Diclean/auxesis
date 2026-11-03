// The menu-bar extra: the state line, Waiting for you (N), Stop all (red) or
// Resume, Open Auxesis, Quit. Stop calls `POST /v1/stop-all`; Resume
// `POST /v1/resume`. Offline: the mark is drawn outlined and the panel offers Start.
import AppKit
import AuxesisKit
import SwiftUI

struct MenuBarLabel: View {
    @ObservedObject var shell: ShellModel

    var body: some View {
        let icon: Icon = shell.stopped ? .stop : .mark
        Image(nsImage: MenuBarGlyph.image(icon, dimmed: !shell.store.connection.isOnline))
            .accessibilityLabel(L10n.ui(.appName, shell.language))
    }
}

/// Template images for the status item, drawn from the same 16-unit icons.
enum MenuBarGlyph {
    private static var cache: [String: NSImage] = [:]

    static func image(_ icon: Icon, dimmed: Bool) -> NSImage {
        let key = "\(icon.rawValue)-\(dimmed)"
        if let image = cache[key] { return image }
        let side: CGFloat = 18
        let image = NSImage(size: NSSize(width: side, height: side), flipped: true) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            let scale = rect.width / 16
            var transform = CGAffineTransform(scaleX: scale, y: scale)
            guard let path = icon.path.copy(using: &transform) else { return false }
            context.addPath(path)
            context.setLineWidth(dimmed ? 1.1 : 1.6)
            context.setLineCap(.round)
            context.setLineJoin(.round)
            context.setStrokeColor(NSColor.black.withAlphaComponent(dimmed ? 0.5 : 1).cgColor)
            context.strokePath()
            return true
        }
        image.isTemplate = true
        cache[key] = image
        return image
    }
}

struct MenuBarPanel: View {
    let onOpen: () -> Void
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let online = shell.store.connection.isOnline
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                Circle().fill(dot(online)).frame(width: 7, height: 7)
                Text(stateLine(copy, online: online))
                    .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                    .foregroundStyle(palette.ink.color)
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            Hairline().padding(.horizontal, 4).padding(.vertical, 3)
            if online {
                MenuItem(title: copy.f(.menuWaiting, shell.waitingCount()), icon: .inbox, identifier: "menu-bar-waiting") {
                    shell.go(.waiting)
                    onOpen()
                }
                if shell.stopped {
                    MenuItem(title: copy(.resume), icon: .play, identifier: "menu-bar-resume", shortcut: "⌘.") { shell.resumeAll() }
                        .disabled(shell.stopInFlight)
                } else {
                    MenuItem(title: copy(.stopAll), icon: .stop, identifier: "menu-bar-stop-all", shortcut: "⌘.", destructive: true) { shell.stopAll() }
                        .disabled(shell.stopInFlight)
                }
            } else {
                MenuItem(title: copy(.menuOffline), icon: .play, identifier: "menu-bar-start") { shell.store.restart() }
            }
            Hairline().padding(.horizontal, 4).padding(.vertical, 3)
            MenuItem(title: copy(.menuOpen), icon: .mark, identifier: "menu-bar-open", action: onOpen)
            MenuItem(title: copy(.menuQuit), icon: .x, identifier: "menu-bar-quit") { NSApp.terminate(nil) }
        }
        .padding(5)
        .frame(width: 260)
        .background(palette.work.color)
    }

    private func dot(_ online: Bool) -> Color {
        if !online { return palette.faint.color }
        return shell.stopped ? palette.red.color : palette.ink2.color
    }

    private func stateLine(_ copy: Copy, online: Bool) -> String {
        guard online else { return copy(.stateOffline) }
        if shell.stopped { return copy(.stateStopped) }
        let working = shell.workingAgents.count
        if working == 0 { return copy(.menuIdle) }
        return working == 1 ? copy(.menuWorkingOne) : copy.f(.menuWorkingMany, working)
    }
}

/// `.mi`: a menu row; hover fills blue, Stop all is red.
private struct MenuItem: View {
    let title: String
    let icon: Icon
    let identifier: String
    var shortcut: String?
    var destructive = false
    let action: () -> Void
    @Environment(\.palette) private var palette
    @Environment(\.isEnabled) private var enabled
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                IconView(icon: icon, size: 15)
                Text(title).frame(maxWidth: .infinity, alignment: .leading)
                if let shortcut {
                    Text(shortcut).font(.meta).opacity(0.7)
                }
            }
            .font(.ui)
            .foregroundStyle(foreground)
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(background))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .opacity(enabled ? 1 : 0.45)
        .accessibilityLabel(title).accessibilityIdentifier(identifier)
    }

    private var foreground: Color {
        if hovering { return destructive ? .white : palette.onBlue.color }
        return destructive ? palette.red.color : palette.ink.color
    }

    private var background: Color {
        guard hovering else { return .clear }
        return destructive ? palette.red.color : palette.blue.color
    }
}
