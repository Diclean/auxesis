// The v5 Steps card: "Steps · n done" and "m handled on this Mac · k left",
// collapsed by default; a click lists every step with its mark, the place its
// data went and its source. It replaces the boxed delegation rows: the task's
// Open, Stop and Resume live in the open card. Rules live in `StepsCardModel`.
import AuxesisKit
import SwiftUI

struct StepsCardView: View {
    let delegations: [Delegation]
    /// In an agent's own thread the card opens on that agent's work for Aux.
    var inAgentThread = false
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    private var open: Bool { delegations.contains { shell.expanded.contains($0.id) } }

    var body: some View {
        let copy = Copy(language: language)
        let rows = StepsCardModel.rows(delegations, stopped: shell.stopped, language: language)
        let card = StepsCardModel(steps: rows.map(\.step))
        let title = card.title(language, halted: rows.filter(\.halted).count)
        VStack(alignment: .leading, spacing: 0) {
            // "See steps" and "‹ Aux" scroll to any of these tasks.
            ForEach(delegations) { Color.clear.frame(height: 0).id(NextStepItem.stepsTarget($0.id)) }
            Button(action: toggle) {
                HStack(spacing: 10) {
                    Text(title).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                    Spacer(minLength: 8)
                    Text(card.placeSummary(language)).font(.meta).foregroundStyle(palette.ink3.color).lineLimit(1)
                    IconView(icon: .down, size: 13).foregroundStyle(palette.ink3.color)
                        .rotationEffect(.degrees(open ? 180 : 0))
                }
                .padding(.horizontal, 14).padding(.vertical, 11)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(title + ". " + card.placeSummary(language))
            .accessibilityHint(copy(open ? .stepsHide : .stepsShow))
            .accessibilityIdentifier("steps-card-toggle-\(delegations.first?.id ?? "")")
            .accessibilityAddTraits(open ? [.isSelected] : [])
            if open {
                ForEach(delegations) { delegation in
                    ForEach(Array(StepsCardModel.rows([delegation], stopped: shell.stopped, language: language).enumerated()), id: \.offset) { _, row in
                        Hairline()
                        StepLine(row: row)
                    }
                    TaskActions(delegation: delegation, inAgentThread: inAgentThread)
                }
            }
        }
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(delegations.contains { shell.flashDelegation == $0.id } ? palette.blueSoft.color : palette.raise.color))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(palette.line.color, lineWidth: 1))
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 2)
    }

    private func toggle() {
        withAnimation(.easeOut(duration: 0.15)) {
            if open { shell.expanded.subtract(delegations.map(\.id)) } else { shell.expanded.formUnion(delegations.map(\.id)) }
        }
    }
}

/// One step: mark · what happened · where its data went · source (84 pt).
private struct StepLine: View {
    let row: StepsCardRow
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let step = row.step
        let place = StepsCardModel.placeLabel(step, language)
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            mark.frame(width: 16)
            Text(step.text)
                .font(.hk(Theme.Text.ui, Theme.Weight.regular))
                .foregroundStyle(step.state == .todo ? palette.ink3.color : palette.ink.color)
                .frame(maxWidth: .infinity, alignment: .leading)
            Label(place, systemImage: icon).font(.meta).lineLimit(2)
                .labelStyle(TwoToneLabelStyle(titleColor: palette.ink2.color, iconColor: palette.ink3.color))
            Text(row.source).font(.meta).foregroundStyle(palette.ink3.color)
                .frame(width: 84, alignment: .trailing).lineLimit(1)
        }
        .padding(.horizontal, 14).padding(.vertical, 7)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel([stateWord, step.text, place, L10n.uf(.stepSource, language, row.source)].joined(separator: ". "))
    }

    private var stateWord: String {
        if row.halted { return L10n.ui(.stepMarkHalted, language) }
        return L10n.ui(row.step.state == .done ? .stepMarkDone : .stepMarkRunning, language)
    }

    /// ✓ done (no hue) · open ring running · red ✕ stopped or failed.
    @ViewBuilder private var mark: some View {
        if row.halted {
            Image(systemName: "xmark").font(.system(size: 10, weight: .bold)).foregroundStyle(palette.red.color)
        } else if row.step.state == .done {
            IconView(icon: .check, size: 13).foregroundStyle(palette.ink2.color)
        } else {
            Circle().trim(from: 0, to: 0.75).stroke(palette.ink2.color, lineWidth: 1.5).frame(width: 9, height: 9)
        }
    }

    private var icon: String {
        switch row.step.place {
        case .stayed: return "lock.shield"
        case .left: return "arrow.up.right"
        case nil: return "questionmark.circle"
        }
    }
}

/// Under a task's steps: what came back, then Open in <agent> · Stop · Resume.
private struct TaskActions: View {
    let delegation: Delegation
    let inAgentThread: Bool
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let member = TeamMember.member(delegation.agent) ?? .custom(delegation.agent)
        let halted = delegation.state == .stopped || (shell.stopped && delegation.state.isOpen)
        // A task that ran nothing kept no partial work: the row
        // says "Stopped", never "couldn't finish" and never "partial work".
        let nothingRan = delegation.attemptedNothing
        VStack(alignment: .leading, spacing: 6) {
            if halted {
                result(copy(.delegStopped), nothingRan ? nil : copy(.delegKeptPartial), halt: true)
            } else if delegation.state == .failed {
                result(copy.f(.delegCouldntFinish, member.name), delegation.result, halt: true)
            } else if delegation.state == .done, let text = delegation.result {
                result(inAgentThread ? copy(.delegSentBackToAux) : copy.f(.delegSentBack, member.name), text, halt: false)
            }
            HStack(spacing: 14) {
                if !inAgentThread {
                    Button(copy.f(.delegOpenIn, member.name)) { shell.open(agent: member.id, fromDelegation: delegation.id) }
                        .buttonStyle(AuxButtonStyle(kind: .link))
                        .accessibilityLabel(copy.f(.delegOpenIn, member.name)).accessibilityIdentifier("delegation-open-agent-\(delegation.id)")
                }
                if delegation.state.isOpen, !shell.stopped {
                    Button(copy(.delegStopTask)) { shell.stopDelegation(delegation) }
                        .buttonStyle(.plain).foregroundStyle(palette.red.color)
                        .accessibilityLabel(copy(.delegStopTask)).accessibilityIdentifier("delegation-stop-\(delegation.id)")
                }
                if delegation.state == .stopped, !shell.stopped {
                    Button(copy(.delegResume)) { shell.resumeDelegation(delegation) }
                        .buttonStyle(AuxButtonStyle(kind: .link))
                        .accessibilityLabel(copy(.delegResume)).accessibilityIdentifier("delegation-resume-\(delegation.id)")
                }
                if let brain = delegation.brain { Text(BrainName.display(brain)).foregroundStyle(palette.ink3.color) }
            }
            .font(.meta)
            if delegation.state == .stopped, let note = shell.delegationResumeNote, note.id == delegation.id {
                Text(note.text).font(.meta).foregroundStyle(palette.red.color)
                    .accessibilityIdentifier("delegation-resume-note-\(delegation.id)")
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .top) { Hairline() }
    }

    private func result(_ head: String, _ text: String?, halt: Bool) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(head).font(.hk(Theme.Text.meta, Theme.Weight.semibold))
                .foregroundStyle(halt ? palette.red.color : palette.ink2.color)
            if let text { Text(text).font(.ui).foregroundStyle(palette.ink.color).lineSpacing(2) }
        }
    }
}

/// A handoff or system event, centred and grey between two hairlines.
struct EventLine: View {
    let text: String
    /// Each agent named on the line gets its 16-pt mascot, in ink3.
    var agents: [String] = []
    /// The mascot sheet's preview shows one agent in its unsaved look.
    var preview: (agent: String, look: MascotLook)?
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: 8) {
            Rectangle().fill(palette.line.color).frame(width: 60, height: 1)
            HStack(spacing: 0) {
                ForEach(Array(HandoffLine.pieces(text, agents: agents).enumerated()), id: \.offset) { _, piece in
                    if let agent = piece.agent {
                        Group {
                            if let preview, preview.agent == agent {
                                MascotView(look: preview.look, size: 16, mono: true)
                            } else {
                                AgentMascot(agentId: agent, size: 16, mono: true)
                            }
                        }
                        .padding(.trailing, 3)
                    }
                    Text(piece.text).font(.meta).foregroundStyle(palette.ink3.color).lineLimit(1).fixedSize()
                }
            }
            Rectangle().fill(palette.line.color).frame(width: 60, height: 1)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(text)
    }
}
