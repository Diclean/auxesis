// Agent mascots (MASCOT-1): one family drawn from the Open Alpha "a" — the
// open loop is the body, the stem the antenna, the clay dot the one accent.
// The look of each agent (mascot + tint) is app-only presentation: it lives
// in UserDefaults under `agentLook.<id>` and never goes to the daemon.
import Foundation

/// The ten mascots. The names are names: they are not translated.
public enum MascotVariant: String, CaseIterable, Codable, Sendable {
    case loop, glance, specs, visor, calm, tall, wide, sprout, twin, hook

    public var name: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }
}

/// The five tints: low-chroma, none of them a meaning hue (amber, green, red
/// or indigo). Each has a light and a dark value, both at least 3:1 against
/// their background.
public enum MascotTint: String, CaseIterable, Codable, Sendable {
    case ink, graphite, slate, bark, plum

    public var name: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }

    /// Light and dark values (sRGB hex).
    private var hex: (light: UInt32, dark: UInt32) {
        switch self {
        case .ink: return (0x1C1C1E, 0xF2F2F4)
        case .graphite: return (0x686870, 0xA6A6AE)
        case .slate: return (0x44586A, 0x9FB2C3)
        case .bark: return (0x6E523C, 0xC6A98F)
        case .plum: return (0x614866, 0xC4A7C9)
        }
    }

    public var light: RGBA { RGBA(hex: hex.light) }
    public var dark: RGBA { RGBA(hex: hex.dark) }
    public func value(dark isDark: Bool) -> RGBA { isDark ? dark : light }
}

/// The look of one agent: which mascot it wears, in which tint.
public struct MascotLook: Codable, Equatable, Hashable, Sendable {
    public var variant: MascotVariant
    public var tint: MascotTint

    public init(_ variant: MascotVariant, _ tint: MascotTint = .ink) {
        self.variant = variant
        self.tint = tint
    }

    /// The clay of the antenna dot and of Sprout's leaf. The only accent: it
    /// never takes the tint.
    public static let clay = RGBA(hex: 0xC75B3A)

    /// The look an agent wears until the owner picks another. Any agent the
    /// owner added starts as Sprout. All start in Ink.
    public static func `default`(for agentId: String) -> MascotLook {
        switch agentId {
        case TeamMember.aux.id: return MascotLook(.loop)
        case TeamMember.mail.id: return MascotLook(.glance)
        case TeamMember.calendar.id: return MascotLook(.hook)
        case TeamMember.clients.id: return MascotLook(.twin)
        case TeamMember.documents.id: return MascotLook(.specs)
        default: return MascotLook(.sprout)
        }
    }

    /// The stored form, "glance:slate".
    public var stored: String { "\(variant.rawValue):\(tint.rawValue)" }

    /// The look a stored value names; nil when it names nothing we know.
    public init?(stored: String) {
        let parts = stored.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let variant = MascotVariant(rawValue: String(parts[0])),
              let tint = MascotTint(rawValue: String(parts[1])) else { return nil }
        self.init(variant, tint)
    }
}

/// Where the owner's picks live: UserDefaults, one key per agent id. A value
/// that is missing or broken gives the default look.
public struct AgentLooks {
    public static let keyPrefix = "agentLook."
    /// Posted on every save or reset (object: the agent id), so each mascot
    /// on screen redraws with the new look at once.
    public static let didChange = Notification.Name("AgentLooks.didChange")
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func look(for agentId: String) -> MascotLook {
        defaults.string(forKey: Self.keyPrefix + agentId).flatMap(MascotLook.init(stored:))
            ?? .default(for: agentId)
    }

    /// Saves a pick. Picking the default clears the key, so a later change
    /// of default reaches the agent.
    public func set(_ look: MascotLook, for agentId: String) {
        if look == .default(for: agentId) {
            defaults.removeObject(forKey: Self.keyPrefix + agentId)
        } else {
            defaults.set(look.stored, forKey: Self.keyPrefix + agentId)
        }
        NotificationCenter.default.post(name: Self.didChange, object: agentId)
    }

    public func reset(_ agentId: String) {
        defaults.removeObject(forKey: Self.keyPrefix + agentId)
        NotificationCenter.default.post(name: Self.didChange, object: agentId)
    }
}

/// The "<Agent>'s mascot" sheet (MASCOT-2): the pick lives here until Done
/// saves it; Cancel just drops it.
public struct MascotPicker {
    public static let columns = 5

    public let agentId: String
    public var look: MascotLook

    public init(agentId: String, looks: AgentLooks) {
        self.agentId = agentId
        self.look = looks.look(for: agentId)
    }

    public var defaultLook: MascotLook { .default(for: agentId) }
    public var isDefault: Bool { look == defaultLook }

    public mutating func reset() { look = defaultLook }

    /// Done: the pick is saved. The sheet's Done button calls this, then closes.
    public func save(to looks: AgentLooks) { looks.set(look, for: agentId) }

    /// Cancel: the pick is dropped and the saved look stands. The sheet's
    /// Cancel button calls this, then closes. Nothing is written here: the
    /// rule lives in the model, so a test drives the same path the button
    /// takes.
    public mutating func cancel(_ looks: AgentLooks) {
        look = looks.look(for: agentId)
    }

    /// The first other agent that already wears the picked look, if any. Two
    /// agents may look the same: the sheet says so and never blocks.
    public func twin(among agentIds: [String], looks: AgentLooks) -> String? {
        agentIds.first { $0 != agentId && looks.look(for: $0) == look }
    }

    /// An arrow key in the 5 × 2 grid; the edges hold.
    public static func move(_ variant: MascotVariant, dx: Int, dy: Int) -> MascotVariant {
        let all = MascotVariant.allCases
        // No index, no move: the pick stays where it is.
        guard let index = all.firstIndex(of: variant) else { return variant }
        let rows = (all.count + columns - 1) / columns
        let column = min(max(index % columns + dx, 0), columns - 1)
        let row = min(max(index / columns + dy, 0), rows - 1)
        return all[min(row * columns + column, all.count - 1)]
    }
}
