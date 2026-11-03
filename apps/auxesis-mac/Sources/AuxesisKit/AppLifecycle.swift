// Window lifecycle for the macOS app shell, kept as a pure decision so the
// "always on" promise can be asserted with `swift test` — no AppKit, no window.
import Foundation

public enum AppLifecycle {
    /// Closing the main window must not quit Auxesis: the menu-bar item stays
    /// alive and the window reopens from that icon or the Dock. Only an
    /// explicit "Quitter Auxesis" ends the process, so this is always `false`.
    ///
    /// Mirrors `applicationShouldTerminateAfterLastWindowClosed` in the app
    /// shell, where it used to be `true` and silently killed the menu-bar item.
    public static func shouldTerminateAfterLastWindowClosed() -> Bool {
        false
    }
}
