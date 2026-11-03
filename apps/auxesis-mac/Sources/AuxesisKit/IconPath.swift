// IconPath — a small SVG path-data reader for the prototype's icons
// (M L H V C S Q Z A, absolute and relative, implicit repeats). Arcs become
// cubic Béziers. Malformed data stops at the first bad token instead of
// crashing; `IconTests` parses every icon.
import CoreGraphics
import Foundation

public enum IconPrimitive: Equatable {
    case path(String)
    case circle(CGFloat, CGFloat, CGFloat)
    case rect(CGFloat, CGFloat, CGFloat, CGFloat, CGFloat)

    func append(to path: CGMutablePath) {
        switch self {
        case .path(let data):
            path.addPath(IconPath.parse(data))
        case .circle(let cx, let cy, let r):
            path.addEllipse(in: CGRect(x: cx - r, y: cy - r, width: r * 2, height: r * 2))
        case .rect(let x, let y, let width, let height, let radius):
            let rect = CGRect(x: x, y: y, width: width, height: height)
            if radius > 0 {
                path.addRoundedRect(in: rect, cornerWidth: radius, cornerHeight: radius)
            } else {
                path.addRect(rect)
            }
        }
    }
}

public enum IconPath {
    enum Token: Equatable {
        case command(Character)
        case number(CGFloat)
    }

    static func tokenize(_ data: String) -> [Token] {
        var tokens: [Token] = []
        let chars = Array(data)
        var index = 0
        while index < chars.count {
            let char = chars[index]
            if "MmLlHhVvCcSsQqZzAa".contains(char) {
                tokens.append(.command(char))
                index += 1
            } else if char.isNumber || char == "." || char == "-" || char == "+" {
                var text = String(char)
                var seenDot = char == "."
                var seenExponent = false
                index += 1
                while index < chars.count {
                    let next = chars[index]
                    if next.isNumber {
                        text.append(next)
                    } else if next == ".", !seenDot, !seenExponent {
                        seenDot = true
                        text.append(next)
                    } else if next == "e" || next == "E", !seenExponent {
                        seenExponent = true
                        text.append(next)
                    } else if (next == "-" || next == "+"), text.last == "e" || text.last == "E" {
                        text.append(next)
                    } else {
                        break
                    }
                    index += 1
                }
                guard let value = Double(text) else { return tokens }
                tokens.append(.number(CGFloat(value)))
            } else {
                index += 1
            }
        }
        return tokens
    }

    /// Arc flags may be written without separators (`a1 1 0 0110 10`); the
    /// prototype never does, so flags are read as ordinary numbers.
    public static func parse(_ data: String) -> CGPath {
        let path = CGMutablePath()
        let tokens = tokenize(data)
        var index = 0
        var command: Character = "M"
        var current = CGPoint.zero
        var start = CGPoint.zero
        var lastControl: CGPoint?

        func number() -> CGFloat? {
            guard index < tokens.count, case .number(let value) = tokens[index] else { return nil }
            index += 1
            return value
        }
        func numbers(_ count: Int) -> [CGFloat]? {
            var values: [CGFloat] = []
            for _ in 0..<count {
                guard let value = number() else { return nil }
                values.append(value)
            }
            return values
        }

        while index < tokens.count {
            if case .command(let next) = tokens[index] {
                command = next
                index += 1
            }
            let relative = command.isLowercase
            let origin = relative ? current : .zero
            switch command {
            case "M", "m":
                guard let v = numbers(2) else { return path }
                current = CGPoint(x: origin.x + v[0], y: origin.y + v[1])
                start = current
                path.move(to: current)
                command = relative ? "l" : "L"
                lastControl = nil
            case "L", "l":
                guard let v = numbers(2) else { return path }
                current = CGPoint(x: origin.x + v[0], y: origin.y + v[1])
                path.addLine(to: current)
                lastControl = nil
            case "H", "h":
                guard let x = number() else { return path }
                current = CGPoint(x: (relative ? current.x : 0) + x, y: current.y)
                path.addLine(to: current)
                lastControl = nil
            case "V", "v":
                guard let y = number() else { return path }
                current = CGPoint(x: current.x, y: (relative ? current.y : 0) + y)
                path.addLine(to: current)
                lastControl = nil
            case "C", "c":
                guard let v = numbers(6) else { return path }
                let c1 = CGPoint(x: origin.x + v[0], y: origin.y + v[1])
                let c2 = CGPoint(x: origin.x + v[2], y: origin.y + v[3])
                current = CGPoint(x: origin.x + v[4], y: origin.y + v[5])
                path.addCurve(to: current, control1: c1, control2: c2)
                lastControl = c2
            case "S", "s":
                guard let v = numbers(4) else { return path }
                let c1 = lastControl.map { CGPoint(x: 2 * current.x - $0.x, y: 2 * current.y - $0.y) } ?? current
                let c2 = CGPoint(x: origin.x + v[0], y: origin.y + v[1])
                current = CGPoint(x: origin.x + v[2], y: origin.y + v[3])
                path.addCurve(to: current, control1: c1, control2: c2)
                lastControl = c2
            case "Q", "q":
                guard let v = numbers(4) else { return path }
                let control = CGPoint(x: origin.x + v[0], y: origin.y + v[1])
                current = CGPoint(x: origin.x + v[2], y: origin.y + v[3])
                path.addQuadCurve(to: current, control: control)
                lastControl = nil
            case "A", "a":
                guard let v = numbers(7) else { return path }
                let end = CGPoint(x: origin.x + v[5], y: origin.y + v[6])
                addArc(to: path, from: current, to: end, rx: v[0], ry: v[1], rotation: v[2], large: v[3] != 0, sweep: v[4] != 0)
                current = end
                lastControl = nil
            case "Z", "z":
                path.closeSubpath()
                current = start
                lastControl = nil
                // A number after Z without a command is malformed; stop.
                if index < tokens.count, case .number = tokens[index] { return path }
            default:
                return path
            }
        }
        return path
    }

    /// SVG endpoint arc → cubic Béziers (SVG 1.1 implementation notes F.6).
    static func addArc(
        to path: CGMutablePath, from p0: CGPoint, to p1: CGPoint,
        rx rxIn: CGFloat, ry ryIn: CGFloat, rotation: CGFloat, large: Bool, sweep: Bool
    ) {
        var rx = abs(rxIn)
        var ry = abs(ryIn)
        guard rx > 0, ry > 0, p0 != p1 else {
            path.addLine(to: p1)
            return
        }
        let phi = rotation * .pi / 180
        let cosPhi = cos(phi)
        let sinPhi = sin(phi)
        let dx = (p0.x - p1.x) / 2
        let dy = (p0.y - p1.y) / 2
        let x1 = cosPhi * dx + sinPhi * dy
        let y1 = -sinPhi * dx + cosPhi * dy
        let lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry)
        if lambda > 1 {
            rx *= sqrt(lambda)
            ry *= sqrt(lambda)
        }
        let numerator = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1
        let denominator = rx * rx * y1 * y1 + ry * ry * x1 * x1
        var factor = sqrt(max(0, numerator / denominator))
        if large == sweep { factor = -factor }
        let cxp = factor * rx * y1 / ry
        let cyp = -factor * ry * x1 / rx
        let cx = cosPhi * cxp - sinPhi * cyp + (p0.x + p1.x) / 2
        let cy = sinPhi * cxp + cosPhi * cyp + (p0.y + p1.y) / 2

        func angle(_ ux: CGFloat, _ uy: CGFloat, _ vx: CGFloat, _ vy: CGFloat) -> CGFloat {
            let sign: CGFloat = ux * vy - uy * vx < 0 ? -1 : 1
            let dot = ux * vx + uy * vy
            let length = sqrt(ux * ux + uy * uy) * sqrt(vx * vx + vy * vy)
            return sign * acos(min(1, max(-1, dot / length)))
        }
        let theta1 = angle(1, 0, (x1 - cxp) / rx, (y1 - cyp) / ry)
        var delta = angle((x1 - cxp) / rx, (y1 - cyp) / ry, (-x1 - cxp) / rx, (-y1 - cyp) / ry)
        if !sweep, delta > 0 { delta -= 2 * .pi }
        if sweep, delta < 0 { delta += 2 * .pi }

        let segments = max(1, Int(ceil(abs(delta) / (.pi / 2))))
        let step = delta / CGFloat(segments)
        let k = 4.0 / 3.0 * tan(step / 4)
        var theta = theta1
        func point(_ t: CGFloat) -> CGPoint {
            CGPoint(
                x: cx + rx * cos(t) * cosPhi - ry * sin(t) * sinPhi,
                y: cy + rx * cos(t) * sinPhi + ry * sin(t) * cosPhi
            )
        }
        func derivative(_ t: CGFloat) -> CGPoint {
            CGPoint(
                x: -rx * sin(t) * cosPhi - ry * cos(t) * sinPhi,
                y: -rx * sin(t) * sinPhi + ry * cos(t) * cosPhi
            )
        }
        for _ in 0..<segments {
            let next = theta + step
            let a = point(theta)
            let b = point(next)
            let da = derivative(theta)
            let db = derivative(next)
            path.addCurve(
                to: b,
                control1: CGPoint(x: a.x + k * da.x, y: a.y + k * da.y),
                control2: CGPoint(x: b.x - k * db.x, y: b.y - k * db.y)
            )
            theta = next
        }
    }
}
