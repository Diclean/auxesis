// Where the main window should sit: never zero-sized, never parked off-screen.
//
// AppKit screen coordinates (origin bottom-left), so `NSScreen.visibleFrame`
// can be passed straight through. Pure math — `swift test` covers it without a
// window, and the app target only applies the returned frame to `NSWindow`.
import CoreGraphics

public enum WindowGeometry {
    /// The size the window opens with when it has none (SwiftUI's `.defaultSize`).
    public static let defaultSize = CGSize(width: 1280, height: 820)
    /// Never smaller than this; a window below it is resized to the default.
    public static let minimumSize = CGSize(width: 900, height: 600)

    /// The frame to apply to the main window on `screen` (its `visibleFrame`):
    /// keeps a sane on-screen size and position, centres a fresh/off-screen
    /// window, and clamps the origin so a usable slice always stays visible.
    public static func fit(current: CGRect, screen: CGRect) -> CGRect {
        let size = size(fitting: current.size, screen: screen.size)
        var origin = current.origin
        if !isUsable(current, on: screen) {
            origin = CGPoint(x: screen.midX - size.width / 2, y: screen.midY - size.height / 2)
        }
        if size.width <= screen.width {
            origin.x = min(max(origin.x, screen.minX), screen.maxX - size.width)
        } else {
            origin.x = screen.minX
        }
        if size.height <= screen.height {
            origin.y = min(max(origin.y, screen.minY), screen.maxY - size.height)
        } else {
            origin.y = screen.minY
        }
        return CGRect(origin: origin, size: size)
    }

    /// A window smaller than the minimum opens at the default size; a window
    /// wider/taller than the screen is clamped to the screen (or the minimum,
    /// whichever is smaller — real Macs are never below it).
    static func size(fitting current: CGSize, screen: CGSize) -> CGSize {
        var width = current.width
        var height = current.height
        if width < minimumSize.width { width = defaultSize.width }
        if height < minimumSize.height { height = defaultSize.height }
        let maxWidth = max(screen.width, minimumSize.width)
        let maxHeight = max(screen.height, minimumSize.height)
        width = min(width, maxWidth)
        height = min(height, maxHeight)
        return CGSize(width: width, height: height)
    }

    /// A frame is usable when a decent slice (title bar + some content) is on
    /// the target screen.
    static func isUsable(_ frame: CGRect, on screen: CGRect) -> Bool {
        let visible = frame.intersection(screen)
        return !visible.isNull && visible.width >= 200 && visible.height >= 80
    }
}
