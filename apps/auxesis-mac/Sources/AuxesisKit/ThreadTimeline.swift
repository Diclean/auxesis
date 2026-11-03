// ThreadTimeline — one thread as the messaging layout draws it: date chips,
// then groups of consecutive entries from one voice. Three voices in a domain
// thread (contract): the owner (right, blue), this agent (left, grey) and Aux
// handing over work (left, outlined, Aux's tile). In Aux's thread, the team's
// delegations sit inside Aux's group as one hairline list, and approvals born
// in a domain thread are mirrored there.
import Foundation

public enum ThreadVoice: Equatable {
    case owner
    case agent(String)
    /// Aux handing work to a domain agent, inside that agent's thread.
    case handoff
    case system
}

public enum ThreadEntry: Identifiable, Equatable {
    case message(ChatMessage)
    /// Consecutive delegations, one hairline list (Aux's thread).
    case delegations([Delegation])
    /// Aux's ask, outlined (domain thread).
    case handoff(Delegation)
    /// The delegation row "Work for Aux", open by default (domain thread).
    case work(Delegation)
    /// The approval object; `mirrored` in Aux's thread.
    case approval(Approval, mirrored: Bool)

    public var id: String {
        switch self {
        case .message(let message): return "m-\(message.id)"
        case .delegations(let list): return "dl-" + list.map(\.id).joined(separator: ",")
        case .handoff(let delegation): return "ho-\(delegation.id)"
        case .work(let delegation): return "wk-\(delegation.id)"
        case .approval(let approval, _): return "ap-\(approval.id)"
        }
    }
}

public struct ThreadGroup: Identifiable, Equatable {
    public let voice: ThreadVoice
    public var entries: [ThreadEntry]
    public let first: Date
    public var last: Date

    public var id: String { entries.first?.id ?? "empty" }
}

public enum ThreadItem: Identifiable, Equatable {
    case day(Date)
    case group(ThreadGroup)

    public var id: String {
        switch self {
        case .day(let date): return "day-\(Int(date.timeIntervalSince1970))"
        case .group(let group): return "g-\(group.id)"
        }
    }
}

public enum ThreadTimeline {
    struct Stamped {
        let at: Date
        let voice: ThreadVoice
        let entry: ThreadEntry
    }

    public static func build(
        agent: String,
        messages: [ChatMessage],
        delegations: [Delegation],
        approvals: [Approval],
        threadStartedAt: Date? = nil,
        calendar: Calendar = .current
    ) -> [ThreadItem] {
        let isChief = agent == TeamMember.aux.id
        let scopedDelegations = delegations.filter { delegation in
            guard let threadStartedAt, let at = TimeText.parse(delegation.at) else { return true }
            return at >= threadStartedAt
        }
        var stamped: [Stamped] = []
        // A message without a time (a send still in flight, a provisional id)
        // keeps its arrival order: just after the message before it.
        var previous: Date?
        let messages = CalendarCard.attach(foldPreambles(messages), calendar: calendar)
        // In a domain thread, Aux's ask is stored as a `user` row when the
        // agent's turn starts. The row says who wrote it: a row with the
        // source `delegation` is the grey delegation event line, never an
        // owner's bubble. A row with no source is the owner's own words; for
        // a delegation no source-bearing row claimed, the old text match
        // still claims one of them (rows stored before the field existed).
        var askRows = Set<String>()
        func trimmed(_ text: String) -> String { text.trimmingCharacters(in: .whitespacesAndNewlines) }
        let delegations = isChief ? [] : scopedDelegations.filter({ $0.agent == agent })
        // The rows that name their source: a delegated ask, in every thread.
        for message in messages where message.source == "delegation" {
            askRows.insert(message.id)
        }
        // The delegation each of them belongs to: the last one that started
        // before the row, since the row is written when that turn starts. It
        // needs no text match any more.
        var claimed = Set<String>()
        let byTime = delegations.sorted {
            (TimeText.parse($0.at) ?? .distantPast) < (TimeText.parse($1.at) ?? .distantPast)
        }
        for message in messages where message.source == "delegation" && message.ts > 0 {
            let at = date(ms: message.ts)
            if let owner = byTime.last(where: {
                (TimeText.parse($0.at)?.addingTimeInterval(-2) ?? .distantPast) <= at
            }) {
                claimed.insert(owner.id)
            }
        }
        // The old text match, for the rows stored before the field existed.
        for delegation in delegations where !claimed.contains(delegation.id) {
            let start = TimeText.parse(delegation.at)?.addingTimeInterval(-2) ?? .distantPast
            let row = messages.first {
                $0.author == .you && $0.ts > 0 && !askRows.contains($0.id) && $0.source == nil
                    && date(ms: $0.ts) >= start && trimmed($0.text) == trimmed(delegation.ask)
            }
            if let row { askRows.insert(row.id) }
        }
        for (index, message) in messages.enumerated() {
            let voice: ThreadVoice
            switch message.author {
            case .you:
                if askRows.contains(message.id) { continue }
                voice = .owner
            case .agent(let name): voice = .agent(name)
            case .tool: continue
            case .system: voice = .system
            }
            let next = messages[(index + 1)...].first { $0.ts > 0 }.map { date(ms: $0.ts).addingTimeInterval(-0.001) }
            let at = message.ts > 0 ? date(ms: message.ts) : (previous?.addingTimeInterval(0.001) ?? next ?? Date())
            previous = at
            stamped.append(Stamped(at: at, voice: voice, entry: .message(message)))
        }
        if isChief {
            for delegation in scopedDelegations {
                let at = TimeText.parse(delegation.at) ?? .distantPast
                stamped.append(Stamped(at: at, voice: .agent(agent), entry: .delegations([delegation])))
            }
        } else {
            for delegation in scopedDelegations where delegation.agent == agent {
                let at = TimeText.parse(delegation.at) ?? .distantPast
                stamped.append(Stamped(at: at, voice: .handoff, entry: .handoff(delegation)))
                stamped.append(Stamped(at: at.addingTimeInterval(0.001), voice: .agent(agent), entry: .work(delegation)))
            }
        }
        for approval in approvals where isChief || approval.agent == agent {
            stamped.append(Stamped(at: date(ms: approval.ts), voice: .agent(agent), entry: .approval(approval, mirrored: isChief && approval.agent != agent)))
        }
        // Stable: equal times keep insertion order (message, then delegation).
        let ordered = stamped.enumerated().sorted { lhs, rhs in
            lhs.element.at == rhs.element.at ? lhs.offset < rhs.offset : lhs.element.at < rhs.element.at
        }.map(\.element)

        var items: [ThreadItem] = []
        var current: ThreadGroup?
        var lastDay: Date?
        func flush() {
            if let group = current { items.append(.group(group)) }
            current = nil
        }
        for item in ordered {
            let day = calendar.startOfDay(for: item.at)
            if item.at != .distantPast, lastDay != day {
                flush()
                items.append(.day(day))
                lastDay = day
            }
            if var group = current, group.voice == item.voice, item.at.timeIntervalSince(group.last) < 600 {
                // Consecutive delegations merge into one list.
                if case .delegations(let more) = item.entry, case .delegations(let list)? = group.entries.last {
                    group.entries[group.entries.count - 1] = .delegations(list + more)
                } else {
                    group.entries.append(item.entry)
                }
                group.last = item.at
                current = group
            } else {
                flush()
                current = ThreadGroup(voice: item.voice, entries: [item.entry], first: item.at, last: item.at)
            }
        }
        flush()
        return items
    }

    /// One turn, one bubble: an agent's reply that called a tool folds into
    /// the reply after the tool rows, as its status line. The owner's words,
    /// a reply without a tool between them, or a reply of another run (a job,
    /// an iMessage turn; live rows only) keep their own bubbles.
    static func foldPreambles(_ messages: [ChatMessage]) -> [ChatMessage] {
        var out: [ChatMessage] = []
        for message in messages {
            var message = message
            if case .agent = message.author,
               let lastNonTool = out.lastIndex(where: { $0.author != .tool }),
               lastNonTool < out.count - 1,
               out[lastNonTool].author == message.author,
               out[lastNonTool].runId == message.runId {
                let earlier = out.remove(at: lastNonTool)
                message.preamble = earlier.preamble + [earlier]
            }
            out.append(message)
        }
        return out
    }

    static func date(ms: Int64) -> Date {
        ms > 0 ? Date(timeIntervalSince1970: TimeInterval(ms) / 1000) : Date()
    }
}
