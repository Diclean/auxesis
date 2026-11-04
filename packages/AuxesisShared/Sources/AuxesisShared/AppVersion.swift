// The app's own version, with a safe fallback for the bare SwiftPM binary.
// The build number (CFBundleVersion) is an integer: scripts/package-mac.sh
// writes the commit count, or the number given with --build, so the updater
// can compare it with the build of a release manifest.
import Foundation

public enum AppVersion {
    /// The dotted version (`CFBundleShortVersionString`), e.g. "0.1.0".
    public static var short: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0.1.0"
    }

    /// The build number (`CFBundleVersion`), an integer.
    public static var build: Int {
        build(in: Bundle.main.infoDictionary)
    }

    /// Reads the build number out of an Info.plist dictionary: an integer as
    /// is, a numeric string as a number, anything else (a dotted version, a
    /// missing key) falls back to 1.
    public static func build(in info: [String: Any]?) -> Int {
        if let value = info?["CFBundleVersion"] as? Int { return value }
        if let text = info?["CFBundleVersion"] as? String, let value = Int(text) {
            return value
        }
        return 1
    }
}
