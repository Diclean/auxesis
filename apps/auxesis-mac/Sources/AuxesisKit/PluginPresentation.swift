// M6-4: what the Plugins tab says about a catalog entry, a server and a preview.
// Words first, a monochrome glyph second; amber only on "Needs you", red on an error.
import Foundation

public enum PluginState: Equatable {
    case on, off, needsYou, error
    public init(_ server: McpServerView) {
        switch server.state {
        case "ready": self = .on
        case "needs_approval", "needs_confirmation": self = .needsYou
        case "disabled": self = .off
        case "quarantined", "failed", "error": self = .error
        default: self = server.enabled ? .error : .off
        }
    }
    public var key: UIKey { [.on: .pluginOn, .off: .pluginOff, .needsYou: .pluginNeedsYou, .error: .pluginError][self]! }
    public var icon: Icon { [.on: .check, .off: .ban, .needsYou: .clock, .error: .alert][self]! }
    /// Amber is kept for the one state the owner must act on.
    public var isAmber: Bool { self == .needsYou }
}

public enum PluginAccess: Equatable {
    case read, readWrite, unknown
    /// Catalog `access` ("read-only"/"read-write") or preview tool `access` ("read"/"write").
    public init(_ access: String) {
        self = ["read-only": .read, "read": .read, "read-write": .readWrite, "write": .readWrite][access] ?? .unknown
    }
    public var key: UIKey { [.read: .pluginRead, .readWrite: .pluginReadWrite, .unknown: .pluginNotChecked][self]! }
    public var icon: Icon { [.read: .eye, .readWrite: .tool, .unknown: .alert][self]! }
}

public enum PluginText {
    public static func host(_ endpoint: String?) -> String? {
        guard let endpoint, let url = URL(string: endpoint), ["https", "http"].contains(url.scheme ?? "") else { return nil }
        return url.host
    }
    /// Where a catalog entry connects, read from the catalog only: no request.
    public static func connects(_ entry: McpCatalogEntry, _ language: Language) -> String {
        host(entry.endpoint) ?? L10n.ui(entry.transport == "stdio" ? .pluginOnThisMac : .pluginNotChecked, language)
    }
    /// One line of purpose: the first sentence of the catalog note.
    public static func purpose(_ entry: McpCatalogEntry) -> String {
        guard let notes = entry.notes, let first = notes.split(separator: ".", maxSplits: 1).first else { return entry.category }
        return first + "."
    }
    public static func auth(_ auth: String, _ language: Language) -> String { L10n.ui(auth == "none" ? .pluginNone : .pluginAuthKey, language) }
    public static func dataClass(_ value: String, _ language: Language) -> String { L10n.ui(value == "public" ? .pluginDataPublic : .pluginDataPrivate, language) }
    public static func network(_ preview: McpApprovalPreview, _ language: Language) -> String {
        host(preview.endpoint) ?? L10n.ui(preview.network ? .pluginNetworkAny : .pluginNoNetwork, language)
    }
    /// The endpoint, or the exact program line for a program on this Mac.
    public static func runs(_ preview: McpApprovalPreview) -> String {
        preview.endpoint ?? ([preview.command ?? "?"] + preview.args).joined(separator: " ")
    }
    public static func tools(_ tools: [(name: String, access: PluginAccess)], _ language: Language) -> String {
        tools.isEmpty ? L10n.ui(.pluginNone, language) : tools.map { "\($0.name) · \(L10n.ui($0.access.key, language))" }.joined(separator: "\n")
    }
}
