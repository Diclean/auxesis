// One agent's thread: date chips, voice groups (owner right and blue, agent
// left and grey, Aux's hand-off outlined), Aux's delegation list, the approval
// object inline, "What X sent to its brain" under each agent group, the typing
// and tool line, and the composer. One centred 640-pt column.
import AuxesisKit
import SwiftUI

struct ConversationView: View {
    let agent: String
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @Environment(\.threadStartsAtTop) private var startsAtTop

    private var member: TeamMember { TeamMember.member(agent) ?? .custom(agent) }

    var body: some View {
        let copy = Copy(language: language)
        let items = ThreadTimeline.build(
            agent: agent,
            messages: shell.store.conversation,
            delegations: shell.delegations,
            approvals: shell.approvals(inThreadOf: agent),
            threadStartedAt: shell.store.threadStartedAt(for: agent)
        )
        // v5: what waits shows on the sidebar badge, the draft card and the
        // Work tab, not in a bar over the thread.
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        Color.clear.frame(height: 1).id("top")
                        if items.isEmpty {
                            EmptyThread(member: member)
                        }
                        ForEach(items) { item in
                            switch item {
                            case .day(let date):
                                DayChip(date: date)
                            case .group(let group):
                                GroupView(agent: agent, group: group) { link in
                                    nextStep(link, proxy: proxy)
                                }
                            }
                        }
                        if shell.store.isSendingMessage {
                            TypingLine(member: member, tool: shell.store.liveTool)
                        }
                        if let error = shell.store.lastMessageError {
                            Text(error)
                                .font(.meta)
                                .foregroundStyle(palette.red.color)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                                .padding(.top, 4)
                        }
                        Color.clear.frame(height: 1).id("bottom")
                    }
                    .frame(maxWidth: Theme.columnWidth)
                    .padding(.horizontal, 28)
                    .padding(.top, 18)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity)
                }
                .onAppear { if !startsAtTop { proxy.scrollTo("bottom", anchor: .bottom) } }
                .onChange(of: items.count) { _, _ in
                    guard !startsAtTop else { return }
                    withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo("bottom", anchor: .bottom) }
                }
            }
            Composer(member: member)
        }
        .background(palette.work.color.contentShape(Rectangle()).onTapGesture { shell.requestComposerFocus() })
        .accessibilityLabel(copy.f(.composerPlaceholder, member.name))
    }

    /// A next-step link acts inside the app only: it never sends a URL.
    private func nextStep(_ link: NextStepItem, proxy: ScrollViewProxy) {
        guard let target = shell.act(on: link) else { return }
        withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(target, anchor: .center) }
    }
}

// MARK: - Day, empty

struct DayChip: View {
    let date: Date
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let calendar = Calendar.current
        let text: String = {
            if calendar.isDateInToday(date) { return copy(.today) }
            if calendar.isDateInYesterday(date) { return copy(.yesterday) }
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: language.localeIdentifier)
            formatter.dateFormat = "EEEE d MMMM"
            return formatter.string(from: date)
        }()
        Text(text)
            .font(.hk(Theme.Text.caption, Theme.Weight.strong))
            .foregroundStyle(palette.muted.color)
            .padding(.horizontal, 10)
            .padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 10).fill(palette.work.color))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(palette.line.color, lineWidth: 1))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
    }
}

struct EmptyThread: View {
    let member: TeamMember
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        VStack(spacing: 0) {
            AgentTile(member: member, size: .large)
                .padding(.bottom, 14)
            if shell.hasBrain {
                Text(member.name)
                    .font(.hk(Theme.Text.heading, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                    .padding(.bottom, 6)
                Text(member.role == .chief ? copy(.emptyChief) : copy.f(.emptyAgent, member.name))
                    .font(.body15)
                    .foregroundStyle(palette.muted.color)
                    .lineSpacing(4)
            } else {
                Text(copy(.noBrainTitle))
                    .font(.hk(Theme.Text.heading, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                    .padding(.bottom, 6)
                Text(copy(.noBrainBody))
                    .font(.body15)
                    .foregroundStyle(palette.muted.color)
                    .padding(.bottom, 14)
                Button(copy(.openSettings)) { shell.settingsTab = .providers }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .accessibilityLabel(copy(.openSettings)).accessibilityIdentifier("conversation-open-settings")
            }
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity)
        .padding(.top, 110)
    }
}

// MARK: - Groups

struct GroupView: View {
    let agent: String
    let group: ThreadGroup
    /// A next-step link under the answer acts inside the app only.
    var onNextStep: (NextStepItem) -> Void = { _ in }
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        switch group.voice {
        case .owner:
            VStack(alignment: .trailing, spacing: 3) {
                ForEach(Array(group.entries.enumerated()), id: \.element.id) { index, entry in
                    if case .message(let message) = entry {
                        Bubble(text: message.text, owner: true, position: position(index), pending: message.pending || message.delivery != nil)
                        if let delivery = message.delivery {
                            DeliveryLine(delivery: delivery)
                        }
                    }
                }
                MetaLine(time: group.last, alignTrailing: true)
            }
            .frame(maxWidth: .infinity, alignment: .trailing)
            .padding(.bottom, 14)
        case .system:
            ForEach(group.entries) { entry in
                if case .message(let message) = entry {
                    Text(message.text)
                        .font(.meta)
                        .foregroundStyle(palette.muted.color)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 520)
                        .frame(maxWidth: .infinity)
                        .padding(.top, 10)
                        .padding(.bottom, 14)
                }
            }
        case .handoff:
            ForEach(group.entries) { entry in
                if case .handoff(let delegation) = entry {
                    HandoffBubble(delegation: delegation)
                }
            }
        case .agent(let name):
            agentGroup(name: name)
        }
    }

    private func agentGroup(name: String) -> some View {
        let member = TeamMember.member(name) ?? TeamMember.member(agent) ?? .aux
        let swapped = shell.swapped.contains(group.id)
        let record = swapped ? shell.modelSaw(agent: member.id, group: group) : nil
        return HStack(alignment: .bottom, spacing: 8) {
            AgentMascot(agentId: member.id, size: 20, label: member.name)
                .padding(.bottom, 22)
            VStack(alignment: .leading, spacing: 3) {
                if swapped {
                    ModelSawPanel(member: member, record: record)
                }
                ForEach(Array(group.entries.enumerated()), id: \.element.id) { index, entry in
                    switch entry {
                    case .message(let message):
                        Bubble(
                            text: swapped ? (record?.tokenised[message.id] ?? message.text) : message.text,
                            owner: false,
                            position: position(index),
                            pending: message.streaming,
                            tokenised: swapped,
                            status: message.statusLines(tokenised: record?.tokenised)
                        )
                        if !swapped, let card = message.calendarCard { CalendarCardView(card: card) }
                    case .delegations(let list):
                        // Centred on the whole column, not on the reply beside the mascot (20 + 8).
                        EventLine(text: HandoffLine.text(agents: list.map(\.agent), at: TimeText.parse(list.first?.at), language: language),
                                  agents: [TeamMember.aux.id] + list.map(\.agent))
                            .offset(x: -14)
                        StepsCardView(delegations: list)
                    case .work(let delegation):
                        StepsCardView(delegations: [delegation], inAgentThread: true)
                    case .approval(let approval, let mirrored):
                        ApprovalCardView(approval: approval, mirrored: mirrored)
                    case .handoff:
                        EmptyView()
                    }
                }
                // The next steps under this answer: only from what the turn
                // holds, and only under a reply.
                let links = hasText ? NextSteps.links(entries: group.entries, language: language) : []
                if !links.isEmpty {
                    NextStepItemsView(links: links, onTap: onNextStep)
                        .padding(.bottom, 4)
                }
                MetaLine(time: group.last, swapMember: hasText ? member : nil, swapped: swapped) {
                    withAnimation(.easeOut(duration: 0.2)) {
                        if swapped { shell.swapped.remove(group.id) } else { shell.swapped.insert(group.id) }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.bottom, 14)
    }

    private var hasText: Bool {
        group.entries.contains { if case .message = $0 { return true } else { return false } }
    }

    private func position(_ index: Int) -> Bubble.Position {
        let count = group.entries.count
        if count == 1 { return .single }
        if index == 0 { return .first }
        if index == count - 1 { return .last }
        return .middle
    }
}

/// Under an owner bubble the app holds back: a fact with an icon, never a hue
/// alone. Queued waits its turn; Not sent was cancelled by Stop.
struct DeliveryLine: View {
    let delivery: ChatMessage.Delivery
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let queued = delivery == .queued
        HStack(spacing: 4) {
            IconView(icon: queued ? .clock : .stop, size: 11)
            Text(copy(queued ? .sendQueued : .sendNotSent)).font(.meta)
        }
        .foregroundStyle(queued ? palette.muted.color : palette.red.color)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(queued ? "send-queued" : "send-not-sent")
    }
}

struct Bubble: View {
    enum Position { case single, first, middle, last }

    let text: String
    let owner: Bool
    var position: Position = .single
    var pending = false
    var tokenised = false
    /// Earlier lines of the same turn ("I'll check your calendar…"), quiet,
    /// above the answer inside the one bubble.
    var status: [String] = []
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(status.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.meta)
                    .foregroundStyle(palette.muted.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if owner || tokenised {
                // The owner's words and the "what the model saw" view stay plain text.
                Text(tokenised ? highlighted : AttributedString(text))
                    .font(.body15)
                    .lineSpacing(3)
                    .foregroundStyle(owner ? palette.ownerInk.color : palette.ink.color)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                RichMessage(text: text)
            }
        }
        // Agent text has no bubble; only the owner's does.
        .padding(.horizontal, owner ? 13 : 0)
        .padding(.top, 8)
        .padding(.bottom, 9)
        .background { if owner { shape.fill(palette.ownerBubble.color) } }
        .opacity(pending && owner ? 0.6 : 1)
        .frame(maxWidth: owner ? 520 : 640, alignment: owner ? .trailing : .leading)
    }

    /// Tokens stay neutral; v3 does not assign them a hue.
    private var highlighted: AttributedString {
        var result = AttributedString(text)
        var searchStart = result.startIndex
        while let open = result[searchStart...].range(of: "[") {
            guard let close = result[open.upperBound...].range(of: "]") else { break }
            let range = open.lowerBound..<close.upperBound
            result[range].foregroundColor = palette.ink.color
            result[range].backgroundColor = palette.hover.color
            result[range].font = .hk(Theme.Text.body * 0.92, Theme.Weight.semibold)
            searchStart = close.upperBound
        }
        return result
    }

    private var shape: UnevenRoundedRectangle {
        let big = Theme.bubbleRadius
        let tight = Theme.bubbleTightRadius
        let topTight = position == .middle || position == .last
        let bottomTight = position == .first || position == .middle
        if owner {
            // Radius 16, bottom-trailing corner 6.
            return UnevenRoundedRectangle(
                topLeadingRadius: 16, bottomLeadingRadius: 16,
                bottomTrailingRadius: 6, topTrailingRadius: topTight ? tight : 16,
                style: .continuous
            )
        }
        return UnevenRoundedRectangle(
            topLeadingRadius: topTight ? tight : big, bottomLeadingRadius: bottomTight ? tight : big,
            bottomTrailingRadius: big, topTrailingRadius: big,
            style: .continuous
        )
    }
}

/// Aux handing work to this agent: a centred grey line, then the ask
/// in Aux's words, never a bubble.
struct HandoffBubble: View {
    let delegation: Delegation
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        VStack(spacing: 4) {
            EventLine(text: HandoffLine.text(agents: [delegation.agent], at: TimeText.parse(delegation.at), language: language),
                      agents: [TeamMember.aux.id, delegation.agent])
            Text(delegation.ask)
                .font(.ui)
                .foregroundStyle(palette.ink2.color)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
        }
        .frame(maxWidth: .infinity)
        .padding(.bottom, 10)
    }
}

/// `.meta`: time, then "What X sent to its brain" (green while open).
struct MetaLine: View {
    let time: Date
    var alignTrailing = false
    var swapMember: TeamMember?
    var swapped = false
    var onSwap: () -> Void = {}
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        HStack(spacing: 6) {
            Text(TimeText.clock(time))
            if let member = swapMember {
                Text("·")
                Button(action: onSwap) {
                    HStack(spacing: 4) {
                        IconView(icon: .shield, size: 13)
                        Text(swapped ? copy(.modelSawHide) : copy.f(.modelSawLink, member.name))
                    }
                    .foregroundStyle(palette.muted.color)
                    .padding(.horizontal, 3)
                    .padding(.vertical, 1)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(swapped ? copy(.modelSawHide) : copy.f(.modelSawLink, member.name)).accessibilityIdentifier("conversation-model-visibility-\(member.id)")
                .accessibilityAddTraits(swapped ? [.isSelected] : [])
            }
        }
        .font(.caption)
        .foregroundStyle(palette.muted.color)
        .padding(.horizontal, 4)
        .padding(.top, 5)
        .frame(maxWidth: .infinity, alignment: alignTrailing ? .trailing : .leading)
    }
}

/// `.sent`: who sent what, to which brain, and what left this Mac.
struct ModelSawPanel: View {
    let member: TeamMember
    let record: ModelSawRecord?
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 6) {
            if let record {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 3) {
                    GridRow {
                        Text(copy(.sentBy)).foregroundStyle(palette.muted.color).frame(width: 120, alignment: .leading)
                        Text(member.name)
                    }
                    GridRow {
                        Text(copy(.sentTo)).foregroundStyle(palette.muted.color)
                        Text(record.sentSummary).foregroundStyle(palette.ink.color)
                    }
                    if let at = record.at {
                        GridRow {
                            Text(copy(.sentWhen)).foregroundStyle(palette.muted.color)
                            Text(TimeText.clock(at))
                        }
                    }
                    if !record.kept.isEmpty {
                        GridRow {
                            Label(copy(.leftMac), systemImage: "arrow.up.right")
                                .labelStyle(TwoToneLabelStyle(titleColor: palette.muted.color, iconColor: palette.ink3.color))
                            Text(record.kept.joined(separator: ", "))
                                .foregroundStyle(palette.ink.color)
                                .fontWeight(.semibold)
                        }
                    }
                }
                if member.role == .chief {
                    Text(copy(.modelSawAux))
                }
                if record.tokenised.isEmpty {
                    Text(copy(.modelSawNoTokens)).foregroundStyle(palette.muted.color)
                }
            } else {
                Text(copy(.modelSawGone)).foregroundStyle(palette.muted.color)
            }
            Button(copy(.openLedger)) { shell.go(.ledger) }
                .buttonStyle(AuxButtonStyle(kind: .link))
                .font(.meta)
                .accessibilityLabel(copy(.openLedger)).accessibilityIdentifier("conversation-open-ledger")
        }
        .font(.ui)
        .foregroundStyle(palette.ink2.color)
        .lineSpacing(3)
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: 600, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(palette.raise.color))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(palette.line.color, lineWidth: 1))
        .padding(.bottom, 8)
        .transition(.opacity)
    }
}

/// "Working" with a static open ring, then the tool line. No dots.
struct TypingLine: View {
    let member: TeamMember
    let tool: ToolCall?
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        HStack(alignment: .center, spacing: 8) {
            AgentMascot(agentId: member.id, size: 20, working: true)
            Circle().strokeBorder(palette.ink3.color, lineWidth: 1.25).frame(width: 8, height: 8)
            Text(tool.map { StepLabel.text(for: $0, language: language) } ?? copy(.agentWorking))
                .font(.meta)
                .foregroundStyle(palette.muted.color)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(copy.f(.typing, member.name))
        .padding(.bottom, 14)
    }
}

// MARK: - Next steps

/// Up to two small links under an answer: ink, underlined.
struct NextStepItemsView: View {
    let links: [NextStepItem]
    let onTap: (NextStepItem) -> Void
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: 14) {
            ForEach(links) { link in
                Button { onTap(link) } label: {
                    VerbatimLine(parts: link.label, size: Theme.Text.ui)
                        .underline()
                }
                .buttonStyle(.plain)
                .foregroundStyle(palette.ink.color)
                .accessibilityLabel(TokenParser.spoken(link.label))
                .accessibilityIdentifier("next-step-\(link.id)")
            }
            Spacer(minLength: 0)
        }
        .padding(.top, 2)
    }
}

// MARK: - Composer

struct Composer: View {
    let member: TeamMember
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @FocusState private var focused: Bool

    var body: some View {
        let copy = Copy(language: language)
        let offline = !shell.store.connection.isOnline
        let disabled = shell.stopped || offline
        // A send while a turn runs is queued, never refused.
        let canSend = !disabled
            && !shell.store.composerText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        VStack(spacing: 6) {
            HStack(alignment: .bottom, spacing: 6) {
                TextField(
                    shell.stopped ? copy(.composerStopped) : offline ? copy(.composerOffline) : copy.f(.composerPlaceholder, member.name),
                    text: Binding(get: { shell.store.composerText }, set: { shell.store.composerText = $0 }),
                    axis: .vertical
                )
                .textFieldStyle(.plain)
                .font(.body15)
                .foregroundStyle(palette.ink.color)
                .lineLimit(1...7)
                .padding(.vertical, 4)
                .focused($focused)
                .disabled(disabled)
                .onSubmit { if canSend { shell.store.sendMessage() } }
                .accessibilityLabel(copy.f(.composerPlaceholder, member.name))
                .accessibilityIdentifier("composer")
                Button { shell.store.sendMessage() } label: {
                    IconView(icon: .arrowUp, size: 16, weight: 1.9)
                        .foregroundStyle(canSend ? palette.onBlue.color : palette.faint.color)
                        .frame(width: 30, height: 30)
                        .background(Circle().fill(canSend ? palette.blue.color : palette.selection.color))
                }
                .buttonStyle(.plain)
                .disabled(!canSend)
                .viewShortcut(.sendMessage)
                .accessibilityLabel(copy(.send))
                .accessibilityIdentifier("send")
            }
            .padding(.leading, 14)
            .padding([.trailing, .vertical], 8)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(disabled ? palette.raise.color : palette.work.color))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(focused ? palette.blue.color.opacity(0.55) : palette.line2.color, lineWidth: 1)
            )
            .background(
                RoundedRectangle(cornerRadius: 17, style: .continuous)
                    .fill(focused ? palette.blueSoft.color : .clear)
                    .padding(-3)
            )
            HStack(spacing: 6) {
                IconView(icon: .shield, size: 12).foregroundStyle(palette.ink3.color)
                // The hint; the full list of what is replaced stays one hover away.
                Text(hint(copy)).font(.caption).foregroundStyle(palette.muted.color)
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    .help(detail(copy))
                Spacer()
                Button(copy(.newChat)) { shell.store.startNewChat() }
                    .buttonStyle(.plain)
                    .font(.caption)
                    .foregroundStyle(palette.muted.color)
                    .disabled(disabled || shell.store.isSendingMessage)
                    .accessibilityLabel(copy(.newChat))
                    .accessibilityIdentifier("new-chat")
            }
            .padding(.horizontal, 14)
        }
        .frame(maxWidth: Theme.composerWidth)
        .padding(.horizontal, 28)
        .padding(.bottom, 16)
        .frame(maxWidth: .infinity)
        // Nothing takes the keyboard when the conversation opens; a click on it does.
        // ⌘K: also when this composer appeared only after the move to Aux.
        .task(id: shell.askFocusRequest) { if shell.consumeAskFocus() { focused = true } }
        .onChange(of: shell.composerFocusRequest) { _, _ in focused = true }
    }

    private func hint(_ copy: Copy) -> String {
        let mode = copy(shell.privacyMode(of: member.id).composerKey)
        if member.role != .chief, let brain = shell.brain(of: member.id) {
            return copy.f(.composerHintAgent, brain, mode)
        }
        return copy.f(.composerHintChief, mode)
    }

    private func detail(_ copy: Copy) -> String {
        if let modeDetail = shell.privacyMode(of: member.id).detailKey { return copy(modeDetail) }
        if member.role == .chief { return copy(.hintChief) }
        if let brain = shell.brainLabel(of: member.id) { return copy.f(.hintAgent, member.name, brain) }
        return copy(.hintAgentNoBrain)
    }
}
