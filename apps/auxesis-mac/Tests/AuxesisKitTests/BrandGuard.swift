// The brand guard shared by the mascot tests: the
// names of the old brand sheet are the brand's, not the app's. No source
// file, no agent, mascot, tint or copy string says one.
import Foundation

enum BrandGuard {
    /// The names of the old brand sheet.
    static let names = ["iris", "horai", "philia", "archeion", "phylax"]

    /// True when the text says the name as a word: "Horaires" is not "Horai".
    static func says(_ text: String, _ name: String) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: "\\b\(name)\\b", options: [.caseInsensitive]) else { return false }
        return regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }

    /// Every `.swift` file under the app's two source folders, as
    /// (path, source), sorted by path. The package root comes from this
    /// file's own path, never from the working directory.
    static func sources() throws -> [(path: String, source: String)] {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        var found: [URL] = []
        for folder in ["Sources/AuxesisKit", "Sources/AuxesisMac"] {
            let root = packageRoot.appendingPathComponent(folder, isDirectory: true)
            guard let walk = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else {
                throw BrandGuardScanError(path: root.path)
            }
            while let file = walk.nextObject() as? URL {
                if file.pathExtension == "swift" { found.append(file) }
            }
        }
        found.sort { $0.path < $1.path }
        let prefix = packageRoot.path + "/"
        return try found.map { file in
            let source = try String(contentsOf: file, encoding: .utf8)
            let path = file.path.hasPrefix(prefix) ? String(file.path.dropFirst(prefix.count)) : file.path
            return (path: path, source: source)
        }
    }
}

struct BrandGuardScanError: Error, CustomStringConvertible {
    let path: String
    var description: String { "could not scan \(path)" }
}
