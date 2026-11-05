// The approval object, which appears in more than one place (the agent's
// thread, Aux's mirror, Waiting for you). Each reads the same state by id from
// ShellModel, so answering anywhere answers everywhere. Delegations are drawn
// by the v5 Steps card (StepsCardView.swift).
import AuxesisKit
import SwiftUI

// MARK: - Approval object

/// The approval inside a thread: the v5 draft card while it waits for an
/// answer, then one quiet line (the trail, or why it did not go). In Aux's
/// thread it is a mirror with "Open in Mail".
struct ApprovalCardView: View {
    let approval: Approval
    var mirrored = false
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let card = shell.card(for: approval)
        let draft = DraftCard(card: card, mirrored: mirrored, language: language)
        if let draft {
            draftCard(card, draft)
        } else {
            // Answered: no card, only the line that says what happened.
            ApprovalBody(card: card)
                .padding(.leading, 4)
        }
    }

    private func draftCard(_ card: ApprovalCard, _ draft: DraftCard) -> some View {
        let copy = Copy(language: language)
        let member = TeamMember.member(approval.agent) ?? .mail
        return VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 7) {
                AgentTile(member: member, size: .xs)
                (Text(member.name).font(.hk(Theme.Text.meta, Theme.Weight.strong)).foregroundColor(palette.ink.color)
                    + Text(" " + copy(.apDraftedReply)).font(.meta).foregroundColor(palette.muted.color))
                Spacer(minLength: 8)
                if draft != nil {
                    // The words carry the meaning, the amber only repeats it.
                    Label(copy(.apNeedsYou), systemImage: "hourglass")
                        .font(.hk(Theme.Text.caption, Theme.Weight.semibold))
                        .foregroundStyle(palette.amber.color)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(palette.amberSoft.color))
                        .fixedSize()
                }
            }
            .padding(.bottom, 6)
            VerbatimLine(parts: draft.title, size: Theme.Text.body, bold: true)
            DraftContent(card: card, draft: draft)
            DraftControls(card: card, approval: approval, draft: draft)
            // A refused edited card keeps its reason here: the card stays open
            // and editable, and the daemon's words are plain text.
            if let refusal = shell.store.refusalReason(for: approval) {
                RefusalNote(message: refusal)
                    .padding(.top, 8)
                    .accessibilityIdentifier("team-proposal-refusal-\(approval.id)")
            }
            if mirrored || card.skill != nil {
                HStack(spacing: 4) {
                    if let skill = card.skill {
                        Text(copy.f(.apSkill, skill))
                    }
                    if mirrored {
                        if card.skill != nil { Text("·") }
                        Text(copy.f(.apAskedBy, member.name, TimeText.clock(Date(timeIntervalSince1970: TimeInterval(approval.ts) / 1000))))
                        Text("·")
                        Button(copy.f(.apOpenIn, member.name)) { shell.go(.agent(member.id)) }
                            .buttonStyle(AuxButtonStyle(kind: .link))
                            .accessibilityLabel(copy.f(.apOpenIn, member.name)).accessibilityIdentifier("approval-open-agent-\(approval.id)")
                    }
                }
                .font(.meta)
                .foregroundStyle(palette.muted.color)
                .padding(.top, 7)
            }
        }
        .padding(.horizontal, 13)
        .padding(.top, 9)
        .padding(.bottom, 10)
        .frame(maxWidth: 600, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Theme.bubbleRadius, style: .continuous).fill(palette.raise.color))
        .overlay(RoundedRectangle(cornerRadius: Theme.bubbleRadius, style: .continuous).strokeBorder(palette.line.color, lineWidth: Theme.hairline))
        .id(NextStepItem.draftTarget(approval.id))
        .accessibilityElement(children: .contain)
    }
}

/// What is left of an approval's life once it no longer waits for an answer:
/// the trail, the countdown, or the reason it did not go. One quiet line, never
/// a card; the draft card owns the phases that wait.
struct ApprovalBody: View {
    let card: ApprovalCard
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        controls
    }

    @ViewBuilder private var controls: some View {
        let copy = Copy(language: language)
        let approval = card.approval
        switch card.phase {
        case .sending(let left):
            // The countdown shows what will go, as a yes posts it.
            VerbatimLine(parts: TokenParser.parts(shell.shownDraft(for: approval).text), size: Theme.Text.ui, color: palette.ink2.color)
                .padding(.top, 6)
                .accessibilityIdentifier("team-proposal-sending-body-\(approval.id)")
            HStack(spacing: 10) {
                CountdownRing(left: left, total: ShellModel.undoSeconds)
                Text(copy.f(.apSendingIn, left)).foregroundStyle(palette.ink2.color)
                Button(copy(.apUndo)) { shell.undo(approval) }
                    .buttonStyle(KeyButtonStyle())
                    .accessibilityLabel(copy(.apUndo)).accessibilityIdentifier("team-proposal-undo-send-\(approval.id)")
            }
            .font(.ui)
            .padding(.top, 8)
            Trail(reached: 2)
        case .answering:
            Trail(reached: 2)
        case .sent:
            Trail(reached: 3)
        case .notNow:
            note(copy(.apNotNowNote), color: palette.muted.color, reopen: true)
        case .cancelledByStop:
            note(copy(.apCancelledByStop), color: palette.red.color, reopen: !shell.stopped)
        case .failed:
            note(shell.store.approvalErrors[approval.id] ?? copy(.apError), color: palette.red.color, reopen: true, icon: "exclamationmark.triangle")
        case .declined:
            note(copy(.apDeclined), color: palette.muted.color, reopen: false)
        case .expired:
            note(copy(.apExpired), color: palette.muted.color, reopen: false)
        case .open, .editing:
            EmptyView()
        }
    }

    private func note(_ text: String, color: Color, reopen: Bool, icon: String? = nil) -> some View {
        let copy = Copy(language: language)
        return HStack(spacing: 10) {
            if let icon {
                Image(systemName: icon).font(.meta).foregroundStyle(color).accessibilityHidden(true)
            }
            Text(text).font(.meta).foregroundStyle(color)
            if reopen {
                Button(copy(.apReopen)) { shell.reopen(card.approval) }
                    .buttonStyle(AuxButtonStyle(kind: .link))
                    .font(.meta)
                    .accessibilityLabel(copy(.apReopen)).accessibilityIdentifier("team-proposal-reopen-\(card.id)")
            }
        }
        .padding(.top, 8)
    }
}

struct ApprovalProposalView: View {
    let approval: Approval
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var confirmDontSend = false

    var body: some View {
        let copy = Copy(language: language)
        let proposal = shell.proposal(for: approval)
        let card = shell.card(for: approval)
        let activePhase: Bool = [.open, .notNow, .editing, .cancelledByStop].contains(card.phase)
        let active = proposal.actions.send && activePhase && shell.store.canAct(approval) && !shell.stopped
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 5) {
                        Label(stateLabel(proposal), systemImage: stateIcon)
                            .font(.meta).foregroundStyle(stateColor(approval))
                        // An edit may change the recipient or subject: the headline then names the edit, never the old draft.
                        Text(shell.shownDraft(for: approval).edited
                             ? (language == .fr ? "Brouillon modifié, envoyé tel qu’affiché ci-dessous" : "Edited draft, sent as shown below")
                             : proposal.title)
                            .font(.hk(Theme.Text.title, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
                        Text(TeamMember.displayName(proposal.agent)).font(.meta).foregroundStyle(palette.muted.color)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    HStack(spacing: 8) {
                        Image(systemName: "circle.dashed").foregroundStyle(palette.muted.color)
                        Text("Prepared").foregroundStyle(palette.muted.color)
                        Image(systemName: "chevron.right").foregroundStyle(palette.muted.color)
                        Label(stateLabel(proposal), systemImage: stateIcon).foregroundStyle(stateColor(approval))
                    }
                    .font(.meta)
                    if !proposal.fields.isEmpty, !shell.shownDraft(for: approval).edited {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(language == .fr ? "Champs" : "Fields").font(.meta).foregroundStyle(palette.muted.color)
                            ForEach(Array(proposal.fields.enumerated()), id: \.offset) { _, field in
                                HStack(alignment: .firstTextBaseline, spacing: 14) {
                                    Text(fieldLabel(field.label)).font(.meta).foregroundStyle(palette.muted.color).frame(width: 86, alignment: .leading)
                                    Text(field.value == "unavailable" ? (language == .fr ? "Non disponible" : "Unavailable") : field.value)
                                        .font(.ui).foregroundStyle(field.value == "unavailable" ? palette.muted.color : palette.ink.color)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text(language == .fr ? "Message" : "Body").font(.meta).foregroundStyle(palette.muted.color)
                        if card.phase == .editing {
                            TextEditor(text: Binding(
                                get: { shell.editDrafts[approval.id] ?? card.editorText },
                                set: { shell.editDrafts[approval.id] = $0 }
                            ))
                            .font(.ui).frame(minHeight: 120).scrollContentBackground(.hidden)
                            .padding(8).background(palette.work.color, in: RoundedRectangle(cornerRadius: 8))
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(palette.line.color))
                            .accessibilityLabel(language == .fr ? "Message" : "Body").accessibilityIdentifier("inbox-proposal-body-\(approval.id)")
                        } else {
                            // A queued edit shows as it will go, never the text it replaced.
                            let shown = shell.shownDraft(for: approval)
                            let body = shown.edited ? shown.text : proposal.body
                            Text(body.isEmpty ? copy(.unavailable) : body)
                                .font(.ui).foregroundStyle(palette.ink.color).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    VStack(alignment: .leading, spacing: 10) {
                        Text(language == .fr ? "Ce qui va se passer" : "What will happen").font(.meta).foregroundStyle(palette.muted.color)
                        Label(proposal.whatWillHappen.isEmpty ? copy(.unavailable) : proposal.whatWillHappen,
                              systemImage: proposal.unknownTool ? "exclamationmark.triangle" : "checkmark.circle")
                            .fontWeight(proposal.unknownTool ? .semibold : .regular)
                            .foregroundStyle(proposal.unknownTool ? palette.ink.color : palette.ink2.color)
                            .accessibilityIdentifier("inbox-proposal-what-\(approval.id)")
                        if let left = proposal.leftThisMac {
                            Label(left, systemImage: "arrow.up.right")
                                .labelStyle(TwoToneLabelStyle(titleColor: palette.ink2.color, iconColor: palette.ink3.color))
                        }
                        if let stayed = proposal.stayedHere {
                            Label(stayed, systemImage: "house")
                                .labelStyle(TwoToneLabelStyle(titleColor: palette.ink2.color, iconColor: palette.ink3.color))
                        }
                    }
                    .font(.ui)
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                VStack(alignment: .leading, spacing: 9) {
                    // A refused edited card keeps its reason here too: the
                    // daemon's words are plain text, and the draft stays
                    // editable below.
                    if let refusal = shell.store.refusalReason(for: approval) {
                        RefusalNote(message: refusal)
                            .accessibilityIdentifier("inbox-proposal-refusal-\(approval.id)")
                    }
                    Text(shell.shownDraft(for: approval).edited
                         ? (language == .fr ? "Cette approbation couvre exactement la version modifiée ci-dessus, et rien d’autre."
                                            : "This approval covers exactly the edited version above, and nothing else.")
                         : proposal.boundaryLine)
                        .font(.meta).foregroundStyle(palette.ink.color).textSelection(.enabled)
                    Text(proposal.grantLine).font(.meta).foregroundStyle(palette.muted.color)
                    HStack(spacing: 8) {
                        if case .sending(let secondsLeft) = card.phase {
                            Text(language == .fr ? "Envoi dans \(secondsLeft) s" : "Sending in \(secondsLeft) s")
                                .font(.meta.monospacedDigit()).foregroundStyle(palette.ink2.color)
                            Button(language == .fr ? "Annuler l’envoi" : "Cancel send") { shell.undo(approval) }
                                .buttonStyle(AuxButtonStyle()).viewShortcut(.cancelSend)
                                .disabled(!shell.store.canAct(approval) || shell.stopped)
                                .accessibilityLabel(language == .fr ? "Annuler l’envoi" : "Cancel send").accessibilityIdentifier("inbox-proposal-cancel-send-\(approval.id)")
                        } else {
                            Button(copy(.apSend)) { shell.sendProposal(approval) }
                            .buttonStyle(AuxButtonStyle(kind: .primary))
                            .viewShortcut(.sendProposal)
                            .disabled(!active || !shell.canSendProposal(approval))
                            .accessibilityLabel(copy(.apSend)).accessibilityIdentifier("inbox-proposal-send-\(approval.id)")
                            Button(copy(.apEdit)) { shell.beginEdit(approval) }
                                .buttonStyle(AuxButtonStyle())
                                .disabled(!active || card.phase == .editing || card.editorText.isEmpty || AppTextFocus.isFocused)
                                .accessibilityLabel(copy(.apEdit)).accessibilityIdentifier("inbox-proposal-edit-\(approval.id)")
                            Button(copy(.apNotNow)) { shell.notNow(approval) }
                                .buttonStyle(AuxButtonStyle()).disabled(!active)
                                .accessibilityLabel(copy(.apNotNow)).accessibilityIdentifier("inbox-proposal-not-now-\(approval.id)")
                            Spacer()
                            Button(language == .fr ? "Ne pas envoyer" : "Don’t send", role: .destructive) { confirmDontSend = true }
                                .buttonStyle(AuxButtonStyle()).foregroundStyle(palette.red.color)
                                .disabled(!active)
                                .accessibilityLabel(language == .fr ? "Ne pas envoyer" : "Don’t send").accessibilityIdentifier("inbox-proposal-dont-send-\(approval.id)")
                        }
                    }
                }
                .padding(.horizontal, 20).padding(.vertical, 13)
                .background(palette.work.color)
                .overlay(alignment: .top) { Rectangle().fill(palette.line.color).frame(height: 1) }
            }
        }
        .background(palette.work.color)
        .onKeyPress(.escape) {
            guard shell.editing == approval.id else { return .ignored }
            shell.cancelEdit()
            return .handled
        }
        .onKeyPress("e") {
            guard ApprovalKeyboardPolicy.shouldHandle(
                .editProposal,
                focus: .approvalProposal,
                textFieldFocused: AppTextFocus.isFocused,
                editingThisProposal: shell.editing == approval.id
            ), active, card.phase != .editing, !card.editorText.isEmpty else { return .ignored }
            shell.beginEdit(approval)
            return .handled
        }
        .confirmationDialog(language == .fr ? "Retirer cette proposition ?" : "Withdraw this proposal?",
                            isPresented: $confirmDontSend, titleVisibility: .visible) {
            Button(language == .fr ? "Ne pas envoyer" : "Don’t send", role: .destructive) {
                shell.store.resolve(approval, decision: .deny)
            }
            .accessibilityLabel(language == .fr ? "Ne pas envoyer" : "Don’t send").accessibilityIdentifier("inbox-proposal-confirm-dont-send-\(approval.id)")
            Button(copy(.apCancel), role: .cancel) {}
                .accessibilityLabel(copy(.apCancel)).accessibilityIdentifier("inbox-proposal-confirm-cancel-\(approval.id)")
        } message: {
            Text(language == .fr ? "Cette proposition sera retirée. Rien ne sera envoyé." : "This proposal will be withdrawn. Nothing will be sent.")
        }
    }

    private func stateLabel(_ proposal: ProposalViewModel) -> String {
        guard language == .fr else { return proposal.stateLabel }
        switch approval.state {
        case .pending: return "Vous attend"
        case .allowed: return "Autorisée"
        case .denied: return "Refusée"
        case .expired: return "Expirée"
        case .unknown: return "État inconnu"
        }
    }

    private func fieldLabel(_ label: String) -> String {
        PlainLabel.field(label, language: language)
    }

    /// One icon per state, next to its label: never the waiting clock on an answered card.
    private var stateIcon: String {
        switch approval.state {
        case .pending: "clock"
        case .allowed: "checkmark.circle"
        case .denied: "xmark.circle"
        case .expired, .unknown: "minus.circle"
        }
    }

    private func stateColor(_ approval: Approval) -> Color {
        switch approval.state {
        case .pending: return palette.amber.color
        case .allowed: return palette.muted.color
        case .denied: return palette.red.color
        case .expired, .unknown: return palette.muted.color
        }
    }
}

/// Drafted → Approved → Sent → Delivered → Replied (WhatsApp ticks).
private struct Trail: View {
    let reached: Int
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let steps: [UIKey] = [.apTrailDrafted, .apTrailApproved, .apTrailSent, .apTrailDelivered, .apTrailReplied]
        HStack(spacing: 8) {
            ForEach(Array(steps.enumerated()), id: \.offset) { index, key in
                if index > 0 {
                    Rectangle().fill(palette.line2.color).frame(width: 10, height: 1)
                }
                let on = index < reached
                let current = index == reached - 1
                HStack(spacing: 4) {
                    if on { IconView(icon: .check, size: 14).foregroundStyle(palette.blue.color) }
                    Text(copy(key))
                        .fontWeight(current ? .semibold : .regular)
                        .foregroundStyle(current ? palette.ink.color : on ? palette.muted.color : palette.faint.color)
                }
            }
        }
        .font(.meta)
        .padding(.top, 8)
        .padding(.horizontal, 2)
    }
}

private struct CountdownRing: View {
    let left: Int
    let total: Int
    @Environment(\.palette) private var palette

    var body: some View {
        ZStack {
            Circle().stroke(palette.line2.color, lineWidth: 2.2)
            Circle()
                .trim(from: 0, to: CGFloat(left) / CGFloat(max(total, 1)))
                .stroke(palette.blue.color, style: StrokeStyle(lineWidth: 2.2, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: left)
        }
        .frame(width: 18, height: 18)
    }
}
