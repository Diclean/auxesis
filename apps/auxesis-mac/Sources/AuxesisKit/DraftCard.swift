// The v5 draft card and the next-step links under an
// agent reply. Both are decisions, not drawings: the views only draw what these
// two say, and the tests can prove them without a window.
//
// One approval = one exact act. The card shows what the agent drafted and the
// owner's answers are the ones the app already has (Send, Edit, Not now). A
// finished approval has no draft card. A next-step link acts inside the app
// only: it opens a draft, opens a steps card, or fills the composer. It never
// sends, never pays and never opens a URL.
import Foundation

/// The draft card of one approval that still waits for an answer.
public struct DraftCard: Equatable {
    /// What the owner can do with the draft: send it (the ten-second cancel
    /// window stays), send the edited text, edit it, show or hide it, leave it
    /// for later, or leave the editor.
    public enum Action: Equatable, CaseIterable {
        case send, sendEdited, edit, showDraft, notNow, cancel
    }

    public let approvalId: String
    /// What will happen: the words, and the protected values the daemon
    /// replaced (each one a chip, never the raw token).
    public let title: [TokenPart]
    /// The draft card always shows its text, in Aux's mirror too, so
    /// Send is offered on a pending draft only with its text in view. Kept for
    /// "Show draft" on a card that is ever folded again.
    public let folded: Bool
    public let phase: ApprovalPhase

    /// The card exists while the approval waits for an answer, and only then.
    public init?(card: ApprovalCard, mirrored: Bool, language: Language) {
        guard card.phase.isDraft else { return nil }
        approvalId = card.approval.id
        title = DraftCard.title(for: card, language: language)
        folded = false
        phase = card.phase
    }

    /// The buttons, in order. A folded mirror shows "Show draft", not "Edit".
    public var actions: [Action] {
        switch phase {
        case .editing: return [.sendEdited, .cancel]
        case .open: return folded ? [.send, .showDraft, .notNow] : [.send, .edit, .notNow]
        default: return []
        }
    }

    /// What will happen. The daemon's headline; without one, "Reply to <name>".
    /// A name the daemon hid stays a chip, never the raw token.
    public static func title(for card: ApprovalCard, language: Language) -> [TokenPart] {
        let headline = card.approval.headline.trimmingCharacters(in: .whitespacesAndNewlines)
        if !headline.isEmpty { return TokenParser.parts(headline) }
        guard let to = card.field("To"), !to.isEmpty else {
            return [.text(card.approval.action)]
        }
        // The name before the address.
        let raw = to.split(separator: "<", maxSplits: 1).first.map { String($0) } ?? to
        let parts = TokenParser.parts(raw)
        let name = parts.compactMap { part -> String? in
            if case .text(let text) = part { return text } else { return nil }
        }.joined().trimmingCharacters(in: .whitespaces)
        guard name.isEmpty else {
            return [.text(L10n.uf(.draftReplyTo, language, name))]
        }
        // The name itself is a protected value: "Reply" and the chip.
        return [.text(L10n.ui(.draftReply, language))] + parts.filter { part in
            if case .token = part { return true } else { return false }
        }
    }
}

/// A small link under an agent reply.
public struct NextStepItem: Equatable, Identifiable {
    /// Open a draft card, open a steps card, or put a question in the
    /// composer. It is never sent from here.
    public enum Action: Equatable {
        case openApproval(String)
        case openSteps(String)
        case fillComposer(String)
    }

    public let id: String
    /// The words of the link, and the protected values the daemon replaced.
    public let label: [TokenPart]
    public let action: Action

    public init(id: String, label: [TokenPart], action: Action) {
        self.id = id
        self.label = label
        self.action = action
    }

    /// What the thread scrolls to when a link opens a draft or a steps card.
    public static func draftTarget(_ id: String) -> String { "draft-\(id)" }
    public static func stepsTarget(_ id: String) -> String { "steps-\(id)" }
}

/// The links under one agent turn: at most two (the contract's cap), and only
/// from what the turn already holds. No data, no links.
public enum NextSteps {
    public static let limit = 2

    /// The links for one turn, from the entries it holds.
    public static func links(entries: [ThreadEntry], language: Language) -> [NextStepItem] {
        var links: [NextStepItem] = []
        // A folded draft (Aux's mirror): open it.
        for case .approval(let approval, let mirrored) in entries where mirrored {
            guard approval.state.isPending else { continue }
            links.append(NextStepItem(id: "draft-\(approval.id)", label: [.text(L10n.ui(.nextOpenDraft, language))],
                                      action: .openApproval(approval.id)))
            break
        }
        // A steps card the owner has not opened yet (Aux's rows).
        for case .delegations(let list) in entries {
            if let delegation = list.last(where: { !$0.steps.isEmpty }) {
                links.append(NextStepItem(id: "steps-\(delegation.id)", label: [.text(L10n.ui(.nextSeeSteps, language))],
                                          action: .openSteps(delegation.id)))
            }
            break
        }
        // A question the owner can ask next: it fills the composer, it never
        // sends by itself.
        for case .work(let delegation) in entries where !delegation.ask.isEmpty {
            let ask = delegation.ask.trimmingCharacters(in: .whitespacesAndNewlines)
            links.append(NextStepItem(
                id: "ask-\(delegation.id)",
                label: TokenParser.short(TokenParser.parts(ask)),
                action: .fillComposer(ask)
            ))
            break
        }
        return Array(links.prefix(limit))
    }
}
