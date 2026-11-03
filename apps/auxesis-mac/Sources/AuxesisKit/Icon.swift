// Glyphs — the drawn icons of the frozen prototype (`agents.html` <symbol>s),
// as data. Each icon is a list of SVG primitives on a 16×16 grid, stroked at
// 1.5 with round caps and joins. `IconPath` turns SVG path data into a
// `CGPath`, so the app draws exactly the prototype's shapes: no icon font, no
// remote asset. Generated from the prototype; edit both together.
import CoreGraphics
import Foundation

public enum Icon: String, CaseIterable, Sendable {
    case mark, sun, side, insp, new, search, people, doc, ledger, gear, stop, play, x, down, up, arrowUp, arrowDown, mail, receipt, clip, mic, shield, eye, check, check2, reply, clock, copy, pin, bellOff, archive, alert, retry, cpu, gauge, sliders, bolt, link, memory, tool, chat, cal, back, fwd, inbox, moon, lock, ban, hand

    /// Agent glyphs (contract: leaf, envelope, calendar, people, receipt).
    public static let leaf = Icon.mark
    public static let envelope = Icon.mail
    public static let calendar = Icon.cal

    public var primitives: [IconPrimitive] {
        switch self {
        case .mark: return [.path("M8 14V7.5"), .path("M8 9.5C8 6.5 6 4.75 3 4.75c0 3 2 4.75 5 4.75z"), .path("M8 7.5c0-2.6 1.75-4.25 4.75-4.25 0 2.6-1.75 4.25-4.75 4.25z")]
        case .sun: return [.circle(8, 8, 2.75), .path("M8 1.75v1.5M8 12.75v1.5M1.75 8h1.5M12.75 8h1.5M3.6 3.6l1.05 1.05M11.35 11.35l1.05 1.05M3.6 12.4l1.05-1.05M11.35 4.65l1.05-1.05")]
        case .side: return [.rect(1.75, 2.75, 12.5, 10.5, 2), .path("M6 2.75v10.5")]
        case .insp: return [.rect(1.75, 2.75, 12.5, 10.5, 2), .path("M10 2.75v10.5")]
        case .new: return [.path("M13.25 8.75v3.5a1.5 1.5 0 0 1-1.5 1.5h-8a1.5 1.5 0 0 1-1.5-1.5v-8a1.5 1.5 0 0 1 1.5-1.5h3.5"), .path("M11.6 2.4a1.27 1.27 0 0 1 1.8 1.8L8.2 9.4l-2.45.65.65-2.45z")]
        case .search: return [.circle(7, 7, 4.25), .path("m10.25 10.25 3.5 3.5")]
        case .people: return [.circle(6, 5.75, 2.4), .path("M1.75 13.25c.5-2.1 2.15-3.25 4.25-3.25s3.75 1.150 4.25 3.25"), .path("M10.5 3.6a2.4 2.4 0 0 1 0 4.4M12 10.2c1.1.45 1.9 1.4 2.25 3.05")]
        case .doc: return [.path("M4.25 1.75h5l3 3v8a1.5 1.5 0 0 1-1.5 1.5h-6.5a1.5 1.5 0 0 1-1.5-1.5v-9.5a1.5 1.5 0 0 1 1.5-1.5z"), .path("M9.25 1.75v3h3M5.5 8.25h5M5.5 10.75h3.5")]
        case .ledger: return [.path("M3 2.75h10M3 6.25h10M3 9.75h6M3 13.25h4"), .path("m10.5 12 1.5 1.5 2.5-3")]
        case .gear: return [.circle(8, 8, 2.25), .path("M8 1.75v1.6M8 12.65v1.6M14.25 8h-1.6M3.35 8h-1.6M12.42 3.58l-1.13 1.13M4.71 11.29l-1.13 1.13M12.42 12.42l-1.13-1.13M4.71 4.71 3.58 3.58"), .circle(8, 8, 4.6)]
        case .stop: return [.circle(8, 8, 6.25), .rect(5.6, 5.6, 4.8, 4.8, 0.8)]
        case .play: return [.circle(8, 8, 6.25), .path("M6.75 5.6v4.8L10.4 8z")]
        case .x: return [.path("m4 4 8 8M12 4l-8 8")]
        case .down: return [.path("m4.5 6.25 3.5 3.5 3.5-3.5")]
        case .up: return [.path("m4.5 9.75 3.5-3.5 3.5 3.5")]
        case .arrowUp: return [.path("M8 13V3.5M4 7.25 8 3.25l4 4")]
        case .arrowDown: return [.path("M8 3v9.5M4 8.75l4 4 4-4")]
        case .mail: return [.rect(1.75, 3.25, 12.5, 9.5, 1.5), .path("m2.25 4 5.75 4.5L13.75 4")]
        case .receipt: return [.path("M3.25 1.75h9.5v12.5l-1.6-1-1.6 1-1.55-1-1.6 1-1.6-1-1.55 1z"), .path("M5.5 5.25h5M5.5 7.75h5M5.5 10.25h3")]
        case .clip: return [.path("m13.2 7.6-5.3 5.3a3.1 3.1 0 0 1-4.4-4.4l5.7-5.7a2.05 2.05 0 0 1 2.9 2.9l-5.6 5.6a1 1 0 0 1-1.45-1.45L10.2 4.7")]
        case .mic: return [.rect(5.75, 1.75, 4.5, 8, 2.25), .path("M3.5 7.75a4.5 4.5 0 0 0 9 0M8 12.25v2")]
        case .shield: return [.path("M8 1.75 13.25 3.5v4.1c0 3.1-2.15 5.45-5.25 6.65C4.9 13.05 2.75 10.7 2.75 7.6V3.5z"), .path("m5.75 8 1.6 1.6 2.9-3.1")]
        case .eye: return [.path("M1.5 8S3.9 3.25 8 3.25 14.5 8 14.5 8 12.1 12.75 8 12.75 1.5 8 1.5 8z"), .circle(8, 8, 2)]
        case .check: return [.path("m3.25 8.5 3 3 6.5-7")]
        case .check2: return [.path("m1.25 8.75 2.75 2.75 5.5-6"), .path("m7.25 11.25.25.25 5.5-6")]
        case .reply: return [.path("M6.5 3.5 2.75 7.25 6.5 11"), .path("M2.75 7.25h6.5a4 4 0 0 1 4 4v1.25")]
        case .clock: return [.circle(8, 8, 6.25), .path("M8 4.5V8l2.5 1.5")]
        case .copy: return [.rect(5.25, 5.25, 8.5, 8.5, 1.5), .path("M10.75 5.25V3.75a1.5 1.5 0 0 0-1.5-1.5h-5.5a1.5 1.5 0 0 0-1.5 1.5v5.5a1.5 1.5 0 0 0 1.5 1.5h1.5")]
        case .pin: return [.path("M9.6 1.9 14.1 6.4l-1.6.6-2.4 2.4-.3 2.9-1.3 1.3-2.6-2.6-3.4 3.4M4.5 9.8 2 7.3l1.3-1.3 2.9-.3 2.4-2.4z")]
        case .bellOff: return [.path("M4.5 6.5a3.5 3.5 0 0 1 6.3-2.1M11.5 7v2.5l1.25 2H5.5M3.25 11.5h.5M6.5 13.25a1.6 1.6 0 0 0 3 0M2 2l12 12")]
        case .archive: return [.rect(1.75, 2.75, 12.5, 3, 1), .path("M2.75 5.75v6.5a1.5 1.5 0 0 0 1.5 1.5h7.5a1.5 1.5 0 0 0 1.5-1.5v-6.5M6.25 8.5h3.5")]
        case .alert: return [.path("M7.1 2.6a1 1 0 0 1 1.8 0l5.4 9.9a1 1 0 0 1-.9 1.5H2.6a1 1 0 0 1-.9-1.5z"), .path("M8 6.25v3M8 11.6v.1")]
        case .retry: return [.path("M13.25 8A5.25 5.25 0 1 1 11.6 4.2"), .path("M12 1.75v2.9H9.1")]
        case .cpu: return [.rect(3.75, 3.75, 8.5, 8.5, 1.5), .path("M6 1.75v2M10 1.75v2M6 12.25v2M10 12.25v2M1.75 6h2M1.75 10h2M12.25 6h2M12.25 10h2")]
        case .gauge: return [.path("M2.5 11.5a5.75 5.75 0 1 1 11 0"), .path("m8 9.5 2.6-3.6")]
        case .sliders: return [.path("M2.5 4.5h6M11.5 4.5h2M2.5 11.5h2M7.5 11.5h6"), .circle(10, 4.5, 1.5), .circle(6, 11.5, 1.5)]
        case .bolt: return [.path("M9 1.75 3.5 9h4l-1 5.25L12.5 7h-4z")]
        case .link: return [.path("M6.6 9.4a2.6 2.6 0 0 0 3.7 0l2.3-2.3a2.6 2.6 0 0 0-3.7-3.7l-.8.8"), .path("M9.4 6.6a2.6 2.6 0 0 0-3.7 0L3.4 8.9a2.6 2.6 0 0 0 3.7 3.7l.8-.8")]
        case .memory: return [.path("M3.25 2.75h7.5l2 2v8.5h-9.5z"), .path("M5.75 6.25h4.5M5.75 8.75h4.5M5.75 11.25h2.5")]
        case .tool: return [.path("M10.2 2.2a3.25 3.25 0 0 0-3.9 4.2L2.2 10.5a1.4 1.4 0 0 0 2 2l4.1-4.1a3.25 3.25 0 0 0 4.2-3.9l-2 2-1.9-.4-.4-1.9z")]
        case .chat: return [.path("M2.75 4.25a1.5 1.5 0 0 1 1.5-1.5h7.5a1.5 1.5 0 0 1 1.5 1.5v5.5a1.5 1.5 0 0 1-1.5 1.5H7l-3 2.25v-2.25a1.25 1.25 0 0 1-1.25-1.25z")]
        case .cal: return [.rect(2.25, 3, 11.5, 10.75, 1.75), .path("M2.25 6.5h11.5M5.5 1.75V4M10.5 1.75V4"), .path("M5 9.25h1.5M7.25 9.25h1.5M9.5 9.25h1.5M5 11.5h1.5M7.25 11.5h1.5")]
        case .back: return [.path("M10 3.5 5.5 8l4.5 4.5")]
        case .fwd: return [.path("M6 3.5 10.5 8 6 12.5")]
        case .inbox: return [.path("M2.25 9.25 4 3.5a1 1 0 0 1 0.95-.75h6.1a1 1 0 0 1 0.95.75l1.75 5.75v3a1.5 1.5 0 0 1-1.5 1.5h-8.5a1.5 1.5 0 0 1-1.5-1.5z"), .path("M2.25 9.25h3l1 1.75h3.5l1-1.75h3")]
        case .moon: return [.path("M13.25 9.6A5.5 5.5 0 0 1 6.4 2.75a5.5 5.5 0 1 0 6.85 6.85z")]
        case .lock: return [.rect(3.25, 7, 9.5, 6.75, 1.5), .path("M5.5 7V5.25a2.5 2.5 0 0 1 5 0V7")]
        case .ban: return [.circle(8, 8, 6), .path("m3.75 12.25 8.5-8.5")]
        case .hand: return [.path("M2.75 8h9M8.5 4.5 12 8l-3.5 3.5"), .path("M14 3v10")]

        }
    }

    /// The whole icon on its 16×16 grid.
    public var path: CGPath {
        let path = CGMutablePath()
        for primitive in primitives {
            primitive.append(to: path)
        }
        return path
    }
}
