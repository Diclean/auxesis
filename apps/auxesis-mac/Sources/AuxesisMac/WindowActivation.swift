// Bringing a bare SwiftPM executable to the front is not something AppKit does
// for free: with no bundle, an early `activate` can be ignored while the first
// window is created, so the app opens behind everything. These helpers retry
// for ~2 s after the first window exists, and fit the window so a zero size or
// a stale position can never park it off-screen.
import AppKit
import AuxesisKit
import SwiftUI

enum AppActivation {
    /// Retry schedule after the first window appears; sums to ≈ 2 s.
    static let retryDelays: [TimeInterval] = [0.1, 0.3, 0.6, 1.0, 1.5, 2.0]

    static func bringToFront(_ window: NSWindow) {
        // A sandbox instance never activates itself: it would take the focus
        // away from the owner (LaunchPolicy).
        guard LaunchPolicy.shouldActivate() else { return }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Up to ~2 s of retries: enough for a launched-from-Terminal binary,
    /// harmless when the app is already frontmost (then it stops early).
    static func scheduleBringToFront(_ window: NSWindow) {
        for delay in retryDelays {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak window] in
                guard let window, !window.isMiniaturized else { return }
                guard !(NSApp.isActive && window.isKeyWindow) else { return }
                // A window that never became key may still be zero-sized or
                // off-screen; re-fit while the user can't have moved it yet.
                if !window.isKeyWindow { fit(window, screen: window.screen) }
                bringToFront(window)
            }
        }
    }

    /// 1280x820 centred when the window is tiny/absent, min 900x600, clamped so
    /// it is never fully off-screen.
    static func fit(_ window: NSWindow, screen: NSScreen?) {
        window.minSize = WindowGeometry.minimumSize
        guard let visible = (screen ?? window.screen ?? NSScreen.main)?.visibleFrame else { return }
        let target = WindowGeometry.fit(current: window.frame, screen: visible)
        if target != window.frame {
            window.setFrame(target, display: true)
        }
    }
}

/// No field takes the keyboard when the window opens: AppKit hands it to the
/// first text field (the header's "Ask Aux…") unless the window is told to
/// start with no first responder. Cleared once, when the window first appears
/// and when it first becomes key (a window shown later from a hidden launch).
struct NoInitialFocus: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { Probe() }
    func updateNSView(_ view: NSView, context: Context) {}

    final class Probe: NSView {
        private var observer: NSObjectProtocol?

        override func viewDidMoveToWindow() {
            guard let window, observer == nil else { return }
            DispatchQueue.main.async { [weak window] in window?.makeFirstResponder(nil) }
            observer = NotificationCenter.default.addObserver(
                forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main
            ) { [weak self, weak window] _ in
                DispatchQueue.main.async { window?.makeFirstResponder(nil) }
                if let observer = self?.observer { NotificationCenter.default.removeObserver(observer) }
            }
        }

        deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    }
}
