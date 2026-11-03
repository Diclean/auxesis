// The v5 draft card: the draft and the owner's
// answers. Protected values stay the neutral lock chips of the rich reply.
import AuxesisKit
import SwiftUI

/// One line drawn as it was written: the words stay, and only a protected
/// value the daemon replaced becomes a lock chip. A markdown link keeps its
/// brackets and its URL, a `*` and a backtick stay characters: the approval
/// the owner sends is read exactly as it was written.
struct VerbatimLine: View {
    let parts: [TokenPart]
    var size: CGFloat = 14.5
    var bold = false
    var color: Color?
    @Environment(\.palette) private var palette

    var body: some View {
        RichInline.compose(parts.map(\.run), bold: bold, palette: palette, color: color ?? palette.ink.color, size: size)
            .lineSpacing(3.5)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityLabel(TokenParser.spoken(parts))
    }
}

/// The reason the daemon refused an edited card, on the card that stays open.
///
/// The daemon's words are plain text: never markdown, never a link, never a
/// button. The card stays editable so the owner can fix the draft.
struct RefusalNote: View {
    let message: String
    @Environment(\.palette) private var palette

    var body: some View {
        Label {
            Text(verbatim: message)
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle")
                .accessibilityHidden(true)
        }
        .font(.meta)
        .foregroundStyle(palette.red.color)
        .textSelection(.enabled)
    }
}

/// The act's fields and its text, as the daemon wrote them. A mirror keeps
/// the draft folded until "Show draft"; the editor takes its place while the
/// owner rewrites it.
struct DraftContent: View {
    let card: ApprovalCard
    let draft: DraftCard
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let unfolded = !draft.folded || shell.isDraftUnfolded(card.approval.id)
        VStack(alignment: .leading, spacing: 0) {
            if !fields.isEmpty, !shell.shownDraft(for: card.approval).edited {
                VerbatimLine(parts: TokenParser.parts(fields), size: Theme.Text.ui, color: palette.ink2.color)
            }
            ForEach(Array(card.otherDetail.enumerated()), id: \.offset) { _, detail in
                VerbatimLine(parts: TokenParser.parts(detail), size: Theme.Text.ui, color: palette.ink3.color)
            }
            if let attachment = card.field("Attachment") {
                HStack(spacing: 6) {
                    IconView(icon: .clip, size: 14)
                    VerbatimLine(parts: TokenParser.parts(attachment), size: Theme.Text.ui, color: palette.ink3.color)
                }
            }
            if card.phase == .editing {
                TextEditor(text: Binding(
                    get: { shell.editDrafts[card.id] ?? card.editorText },
                    set: { shell.editDrafts[card.id] = $0 }
                ))
                .font(.body15)
                .scrollContentBackground(.hidden)
                .background(palette.raise.color)
                .frame(minHeight: 120, maxHeight: 260)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .accessibilityLabel(language == .fr ? "Message" : "Body")
                .accessibilityIdentifier("draft-body-\(card.id)")
            } else if unfolded {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(paragraphs.enumerated()), id: \.offset) { _, paragraph in
                        VerbatimLine(parts: TokenParser.parts(paragraph))
                    }
                }
                .padding(.top, 6)
                .accessibilityIdentifier("draft-body-\(card.id)")
            }
        }
        .padding(.top, 5)
    }

    private var fields: String {
        var parts: [String] = []
        if let to = card.field("To") { parts.append("To \(to)") }
        if let subject = card.field("Subject") { parts.append("Subject: \(subject)") }
        return parts.joined(separator: " · ")
    }

    private var paragraphs: [String] {
        shell.shownDraft(for: card.approval).text.components(separatedBy: "\n\n")
            .map { $0.trimmingCharacters(in: .newlines) }
            .filter { !$0.isEmpty }
    }
}

/// The owner's answers: they call the answers the app already has, and a
/// folded draft is never approved unseen.
struct DraftControls: View {
    let card: ApprovalCard
    let approval: Approval
    let draft: DraftCard
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.language) private var language

    var body: some View {
        HStack(spacing: 6) {
            ForEach(draft.actions, id: \.self) { action in
                button(action)
            }
        }
        .padding(.top, 8)
    }

    private func button(_ action: DraftCard.Action) -> some View {
        let copy = Copy(language: language)
        let unfolded = !draft.folded || shell.isDraftUnfolded(approval.id)
        let label: String
        let primary: Bool
        let disabled: Bool
        let run: () -> Void
        switch action {
        case .send:
            label = copy(.apSend); primary = true
            disabled = shell.stopped || !unfolded; run = { shell.answer(.send, for: approval) }
        case .sendEdited:
            label = copy(.apSendEdited); primary = true
            disabled = shell.stopped; run = { shell.answer(.sendEdited, for: approval) }
        case .edit:
            label = copy(.apEdit); primary = false
            disabled = shell.stopped || card.editorText.isEmpty; run = { shell.answer(.edit, for: approval) }
        case .showDraft:
            label = unfolded ? copy(.apHideDraft) : copy(.apShowDraft); primary = false
            disabled = false; run = { shell.toggleDraft(approval.id) }
        case .notNow:
            label = copy(.apNotNow); primary = false
            disabled = false; run = { shell.answer(.notNow, for: approval) }
        case .cancel:
            label = copy(.apCancel); primary = false
            disabled = false; run = { shell.answer(.cancel, for: approval) }
        }
        return Button(label, action: run)
            .buttonStyle(KeyButtonStyle(primary: primary))
            .disabled(disabled)
            .accessibilityLabel(label)
            .accessibilityIdentifier("team-proposal-\(action)-\(approval.id)")
    }
}
