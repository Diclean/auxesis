// The agent profile (⌥⌘I, 360 on the right): identity, brain, Can see, Can do,
// Never, the green "stays on this Mac" line, Works with, Memory, Skills,
// Workshop and Pause. Grants and memory are NEW routes (E0): when the daemon
// does not serve them yet the panel says so, in one quiet line.
import AuxesisKit
import SwiftUI

struct ProfileInspector: View {
    let member: TeamMember
    /// Inside the right panel's Work tab the panel owns the header.
    var embedded = false
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var mascotOpen = false

    var body: some View {
        let copy = Copy(language: language)
        VStack(spacing: 0) {
            HStack {
                Text(copy(.profile))
                    .font(.hk(Theme.Text.ui, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                Spacer()
                ToolbarIconButton(icon: .x, help: copy(.close), identifier: "inspector-close") {
                    withAnimation(.easeOut(duration: 0.24)) { shell.setRightPanel(false) }
                }
            }
            .padding(.horizontal, 16)
            .frame(height: embedded ? 0 : Theme.barHeight)
            .clipped()
            .accessibilityHidden(embedded)
            if !embedded { Hairline() }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    identity(copy)
                    ForEach(AgentProfileSection.contractOrder, id: \.self) { section in
                        switch section {
                        case .grants: grantsSection(copy)
                        case .brain: brainRow(copy)
                        case .lastUse: lastUseRow(copy)
                        }
                    }
                    heading(copy(.worksWith))
                    paragraph(member.role == .chief ? copy(.worksWithTeam) : copy(.worksWithAux))
                    memorySection(copy)
                    heading(copy(.skills))
                    paragraph(skillsLine(copy))
                    heading(copy(.workshop))
                    paragraph(copy(.workshopEmpty))
                    pauseRow(copy)
                }
                .padding(.horizontal, 20)
                .padding(.top, 18)
                .padding(.bottom, 28)
            }
        }
        .background(palette.work.color)
        .onAppear { shell.loadProfile(member.id) }
        .onChange(of: member.id) { _, id in shell.loadProfile(id) }
    }

    private func identity(_ copy: Copy) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                AgentTile(member: member, size: .large)
                VStack(alignment: .leading, spacing: 1) {
                    Text(member.name)
                        .font(.hk(Theme.Text.title, Theme.Weight.bold))
                        .foregroundStyle(palette.ink.color)
                    Text(member.role == .chief ? copy(.chief) : copy(.domainAgent))
                        .font(.ui)
                        .foregroundStyle(palette.muted.color)
                }
                Spacer()
                // MASCOT-2: the agent's look, in its own sheet.
                Button(copy(.mascotMenu)) { mascotOpen = true }
                    .buttonStyle(AuxButtonStyle())
                    .accessibilityLabel(copy(.mascotMenu)).accessibilityIdentifier("agent-profile-mascot")
            }
            .padding(.bottom, 14)
            .sheet(isPresented: $mascotOpen) {
                MascotPickerSheet(member: member, team: TeamMap.members(agents: shell.store.agents),
                                  status: shell.sidebarEntries().first { $0.row.member.id == member.id }?.status.text)
                    .environment(\.language, shell.language)
                    .themed()
            }
            paragraph(copy(member.aboutKey))
        }
    }

    private func brainRow(_ copy: Copy) -> some View {
        HStack(spacing: 10) {
            IconView(icon: .cpu).foregroundStyle(palette.ink2.color)
            VStack(alignment: .leading, spacing: 1) {
                Text(shell.brainLabel(of: member.id) ?? copy(.todayUnavailable)).foregroundStyle(palette.ink.color)
                Text(copy(.brain) + " · " + copy(.privateMode)).font(.meta).foregroundStyle(palette.muted.color)
            }
            Spacer()
            Button(copy(.changeBrain)) {}
                .disabled(true)
                .help(copy(.notAvailableYet))
                .buttonStyle(AuxButtonStyle())
                .accessibilityLabel(copy(.changeBrain)).accessibilityIdentifier("agent-profile-change-brain")
            Text(copy(.notAvailableYet)).font(.meta).foregroundStyle(palette.muted.color)
        }
        .font(.ui)
        .padding(.vertical, 8)
    }

    private func lastUseRow(_ copy: Copy) -> some View {
        let agent = shell.store.agents.first { $0.name == member.id }
        let lastUse = agent?.lastActive.map { TimeText.short(Date(timeIntervalSince1970: Double($0) / 1000), now: Date(), language: language) } ?? copy(.todayUnavailable)
        return HStack {
            Text(copy(.lastUse)).foregroundStyle(palette.ink2.color)
            Spacer()
            Text(lastUse).foregroundStyle(palette.ink.color)
        }
        .font(.ui)
        .padding(.vertical, 8)
        .overlay(alignment: .top) { Hairline() }
    }

    @ViewBuilder private func grantsSection(_ copy: Copy) -> some View {
        switch shell.grants[member.id] ?? .loading {
        case .loaded(let grants):
            heading(copy(.canSee))
            GrantList {
                ForEach(Array(grants.see.enumerated()), id: \.offset) { _, see in
                    GrantRow(icon: .eye, title: see.scope, detail: see.via, level: level(see.level, copy))
                }
            }
            heading(copy(.canDo))
            GrantList {
                ForEach(Array(grants.canDo.enumerated()), id: \.offset) { _, item in
                    GrantRow(icon: .bolt, title: item.skill, detail: nil, level: level(item.level, copy))
                }
            }
            heading(copy(.never))
            GrantList {
                ForEach(Array(grants.never.enumerated()), id: \.offset) { _, scope in
                    GrantRow(icon: .ban, title: scope, detail: nil, level: nil, muted: true)
                }
            }
            KeptLine(text: grants.egressNote.isEmpty ? keptDefault(copy) : grants.egressNote)
            Button(copy(.revokeGrant)) {}
                .disabled(true)
                .help(copy(.notAvailableYet))
                .padding(.top, 8)
                .accessibilityLabel(copy(.revokeGrant)).accessibilityIdentifier("agent-profile-revoke-grant")
            Text(copy(.notAvailableYet)).font(.meta).foregroundStyle(palette.muted.color)
        case .loading:
            heading(copy(.canSee))
            paragraph(copy(.loading))
        case .failed:
            heading(copy(.canSee))
            paragraph(copy(.loadFailed))
        case .unavailable:
            heading(copy(.canSee))
            paragraph(copy(.grantsUnavailable))
            KeptLine(text: keptDefault(copy))
        }
    }

    private func keptDefault(_ copy: Copy) -> String {
        member.role == .chief ? copy(.keptChief) : copy(.hintAgentNoBrain)
    }

    private func level(_ raw: String, _ copy: Copy) -> String {
        switch raw {
        case "read": return copy(.lvRead)
        case "ask": return copy(.lvAsksEveryTime)
        case "auto": return copy(.lvAuto)
        case "off": return copy(.lvOff)
        default: return raw
        }
    }

    @ViewBuilder private func memorySection(_ copy: Copy) -> some View {
        heading(copy(.memory))
        switch shell.memory[member.id] ?? .loading {
        case .loaded(let items) where items.isEmpty:
            paragraph(copy.f(.memoryEmpty, member.name))
        case .loaded(let items):
            VStack(spacing: 0) {
                ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                    if index > 0 { Hairline() }
                    HStack(alignment: .top, spacing: 10) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(item.text).foregroundStyle(palette.ink.color)
                            if let at = item.at {
                                Text(at).font(.meta).foregroundStyle(palette.muted.color)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        ForgetButton(title: copy(.forget), identifier: "agent-memory-forget-\(member.id)-\(item.id)") { shell.forget(item, agent: member.id) }
                    }
                    .font(.ui)
                    .lineSpacing(2)
                    .padding(.vertical, 8)
                }
            }
        case .unavailable:
            paragraph(copy.f(.memoryEmpty, member.name))
        case .failed:
            paragraph(copy(.loadFailed))
        case .loading:
            paragraph(copy(.loading))
        }
    }

    private func skillsLine(_ copy: Copy) -> String {
        if case .loaded(let grants)? = shell.grants[member.id], !grants.canDo.isEmpty {
            return grants.canDo.map(\.skill).joined(separator: " · ")
        }
        if case .loaded(let skills) = shell.skills, !skills.isEmpty {
            return skills.map(\.name).joined(separator: " · ")
        }
        return copy(.skillsEmpty)
    }

    @ViewBuilder private func pauseRow(_ copy: Copy) -> some View {
        HStack(spacing: 10) {
            Text(copy.f(.pauseAgent, member.name))
                .font(.ui)
                .foregroundStyle(palette.ink.color)
            Spacer()
            Toggle(copy.f(.pauseAgent, member.name), isOn: Binding(
                get: { shell.isPaused(member.id) },
                set: { shell.setPaused(member.id, $0) }
            ))
            .toggleStyle(.switch)
            .tint(palette.blue.color)
            .labelsHidden()
            .controlSize(.small)
            .accessibilityLabel(copy.f(.pauseAgent, member.name))
            .accessibilityIdentifier("agent-pause-toggle-\(member.id)")
        }
        .padding(.top, 18)
        if shell.pauseFailures.contains(member.id) {
            Text(copy.f(.pauseChangeFailed, member.name))
                .font(.meta)
                .foregroundStyle(palette.red.color)
                .padding(.top, 6)
                .accessibilityAddTraits(.updatesFrequently)
        }
    }

    private func heading(_ text: String) -> some View {
        Text(text)
            .font(.hk(Theme.Text.ui, Theme.Weight.strong))
            .foregroundStyle(palette.ink.color)
            .padding(.top, 18)
            .padding(.bottom, 6)
    }

    private func paragraph(_ text: String) -> some View {
        Text(text)
            .font(.ui)
            .foregroundStyle(palette.ink2.color)
            .lineSpacing(4)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.bottom, 8)
    }
}

struct NotificationsRulesDetail: View {
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text(copy(.notificationsQuietHours))
                    .font(.hk(Theme.Text.title, Theme.Weight.bold))
                    .foregroundStyle(palette.ink.color)
                Text(copy(.notificationsUnavailable))
                    .font(.ui).foregroundStyle(palette.ink2.color).padding(.top, 6)
                section(copy(.interruptRules))
                value(copy(.interruptDecisionWaiting), copy(.todayUnavailable))
                value(copy(.interruptFailure), copy(.todayUnavailable))
                value(copy(.interruptUnknownOutcome), copy(.todayUnavailable))
                section(copy(.quietHours))
                value(copy(.schedule), copy(.todayUnavailable))
                Button(copy(.changeQuietHours)) {}
                    .disabled(true).help(copy(.notAvailableYet)).padding(.vertical, 8)
                    .accessibilityLabel(copy(.changeQuietHours)).accessibilityIdentifier("agent-change-quiet-hours")
                Text(copy(.notAvailableYet)).font(.meta).foregroundStyle(palette.muted.color)
                section(copy(.channels))
                value(copy(.configuredChannels), copy(.todayUnavailable))
                section(copy(.recentNotices))
                value(copy(.deliveryState), copy(.todayUnavailable))
            }
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(palette.work.color)
    }

    private func section(_ title: String) -> some View {
        Text(title).font(.hk(Theme.Text.ui, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
            .padding(.top, 24).padding(.bottom, 6)
    }

    private func value(_ title: String, _ value: String) -> some View {
        HStack { Text(title).foregroundStyle(palette.ink2.color); Spacer(); Text(value).foregroundStyle(palette.muted.color) }
            .font(.ui).padding(.vertical, 8).overlay(alignment: .top) { Hairline() }
    }
}

private struct GrantList<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(spacing: 0) { content() }
    }
}

private struct GrantRow: View {
    let icon: Icon
    let title: String
    let detail: String?
    let level: String?
    var muted = false
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            IconView(icon: icon, size: 15)
                .foregroundStyle(muted ? palette.faint.color : palette.muted.color)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).foregroundStyle(muted ? palette.muted.color : palette.ink.color)
                if let detail {
                    Text(detail).font(.meta).foregroundStyle(palette.muted.color)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if let level {
                Text(level).font(.meta).foregroundStyle(palette.muted.color).fixedSize()
            }
        }
        .font(.ui)
        .lineSpacing(2)
        .padding(.vertical, 8)
        .overlay(alignment: .top) { Hairline() }
    }
}

/// `.kept`: the green line — what stays on this Mac.
struct KeptLine: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            IconView(icon: .shield).foregroundStyle(palette.ink3.color).padding(.top, 2)
            Text(text)
                .font(.ui)
                .foregroundStyle(palette.ink2.color)
                .lineSpacing(4)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(palette.blueSoft.color))
        .padding(.top, 4)
    }
}

struct ForgetButton: View {
    let title: String
    let identifier: String
    let action: () -> Void
    @Environment(\.palette) private var palette
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.meta)
                .foregroundStyle(hovering ? palette.red.color : palette.muted.color)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: 5).fill(hovering ? palette.redSoft.color : .clear))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel(title).accessibilityIdentifier(identifier)
    }
}
