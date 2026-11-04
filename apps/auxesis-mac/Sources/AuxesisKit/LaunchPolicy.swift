// Whether the app may pull the focus to itself.
//
// The owner's own app comes to the front: that is what an app is for. A
// sandbox instance is a different thing: it runs on the owner's Mac while the
// owner works (a UI driver can drive it with the Accessibility API), and
// it must never take the focus away from whatever the owner is doing. So in
// a sandbox the app opens its window and works, without ever activating
// itself; the owner's own sandbox dev script brings the app forward itself.
//
// The owner's deploy launches the app with `open -g -j`: in the background and
// hidden, so a deploy never pulls the owner out of what they are doing. That
// launch must not activate the app either. It is told apart by
// the launch itself, not by the environment (Finder and `open` pass none):
// LaunchServices hides the app for `-j` and leaves it inactive for `-g`, and
// `--background` says it outright.
// Only the launch is held back: a click on the Dock icon is a person asking.
import Foundation

public enum LaunchPolicy {
    /// The explicit "stay in the background" switch, for a run that wants it
    /// outside a sandbox.
    public static let backgroundKey = "AUXESIS_MAC_BACKGROUND"

    /// The explicit "stay in the background" argument (`open -g -j app --args --background`).
    public static let backgroundArgument = "--background"

    /// Whether this launch was asked to stay in the background. Measured on a
    /// sandbox bundle: `open -g -j` starts hidden and inactive, `open -g` visible
    /// and inactive, a plain open or a double click visible and active. A bare
    /// binary (not in a bundle) is never active at start, so it does not count.
    public static func launchedInBackground(isHidden: Bool, isActive: Bool, inBundle: Bool) -> Bool {
        isHidden || (inBundle && !isActive)
    }

    /// True when the app may activate itself at launch: it may when it may at
    /// all and this launch was not asked to stay in the background.
    public static func shouldActivateAtLaunch(
        env: [String: String] = ProcessInfo.processInfo.environment,
        arguments: [String] = CommandLine.arguments,
        inBackground: Bool
    ) -> Bool {
        shouldActivate(env: env) && !inBackground && !arguments.contains(backgroundArgument)
    }

    /// True when the app may activate itself (come to the front).
    public static func shouldActivate(env: [String: String] = ProcessInfo.processInfo.environment) -> Bool {
        env[backgroundKey] != "1" && env["AUXESIS_SANDBOX"] != "1"
    }
}
