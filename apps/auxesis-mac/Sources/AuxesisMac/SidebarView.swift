// The v3 Queue navigation. NavigationSplitView supplies native selection,
// resizing and sidebar collapse behaviour.
import AuxesisKit
import SwiftUI

struct SidebarView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.language) private var language
    @Environment(\.palette) private var palette
    @State private var query = ""
    @FocusState private var searchFocused: Bool
    /// MASCOT-2: the agent whose mascot sheet is open.
    @State private var mascotFor: TeamMember?

    var body: some View {
        let copy = Copy(language: language)
        let entries = SidebarSearch.filter(shell.sidebarEntries(), query: query)
        let conversations = ConversationList.rows(shell.store.conversations)
        List(selection: Binding(get: { shell.route }, set: { if let value = $0 { shell.go(value) } })) {
            // Aux pinned, then the Team; each row says what is going on.
            if let aux = entries.first(where: { $0.row.member.role == .chief }) {
                Section { agentRow(aux) }
            }
            let team = entries.filter { $0.row.member.role != .chief }
            if !team.isEmpty {
                Section {
                    ForEach(team, id: \.row.member.id) { agentRow($0) }
                } header: {
                    Text(copy(.sidebarTeam)).textCase(.uppercase)
                }
            } else if !query.isEmpty && entries.isEmpty {
                Text(copy(.sidebarNoMatch)).font(.meta).foregroundStyle(palette.ink3.color)
                    .accessibilityIdentifier("sidebar-no-match")
            }
            Section {
                Button { shell.newConversation() } label: {
                    Label(copy(.newConversation), systemImage: "plus")
                        .font(.hk(Theme.Text.ui, Theme.Weight.medium))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(copy(.newConversation))
                .accessibilityIdentifier("sidebar-new-conversation")
                .listRowSeparator(.hidden)
                ForEach(conversations) { conversationRow($0, now: Date()) }
            } header: {
                Text(copy(.sidebarConversations)).textCase(.uppercase)
            }
            // No page list here; the former "More" pages are in the
            // header's Records menu and the Go menu.
        }
        .environment(\.defaultMinListRowHeight, 24)
        .listStyle(.sidebar)
        .tint(palette.blue.color)
        .scrollContentBackground(.hidden)
        .background(palette.list.color)
        .safeAreaInset(edge: .top, spacing: 0) { searchField(copy) }
        .task(id: shell.searchFocusRequest) { if shell.consumeSearchFocus() { searchFocused = true } }
        .sheet(item: $mascotFor) { member in
            MascotPickerSheet(member: member, team: TeamMap.members(agents: shell.store.agents),
                              status: shell.sidebarEntries().first { $0.row.member.id == member.id }?.status.text)
                .environment(\.language, shell.language)
                .themed()
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            // The day can turn while the app is open: the timeline gives the
            // footer a fresh clock, so the numbers are the new day's.
            TimelineView(.periodic(from: Date(), by: 60)) { context in
                let footer = SidebarText.footer(
                    read: shell.store.privacyRecordRead, receipts: shell.store.receiptLog.receipts,
                    delegations: shell.delegations, now: context.date, language: language
                )
                // Nothing true to say: no band, no rule.
                if footer.requests != nil || footer.stayed != nil {
                VStack(alignment: .leading, spacing: 3) {
                    if let requests = footer.requests {
                        footerRow(requests, icon: privacyCountIcon(at: context.date), id: "sidebar-privacy-record-count")
                    }
                    if let stayed = footer.stayed {
                        footerRow(stayed, icon: "lock.shield", id: "sidebar-privacy-stayed")
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(palette.list.color)
                .overlay(alignment: .top) { Rectangle().fill(palette.line.color).frame(height: 1) }
                }
            }
        }
    }

    /// One footer line: icon and words in neutral ink (SOBER-1); the meaning
    /// never rests on colour.
    private func footerRow(_ text: String, icon: String, id: String) -> some View {
        Button { shell.go(.privacyRecord) } label: {
            Label(text, systemImage: icon)
                .labelStyle(TwoToneLabelStyle(titleColor: palette.ink2.color, iconColor: palette.ink3.color))
                .font(.meta)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(text).accessibilityIdentifier(id)
    }

    private func agentRow(_ entry: SidebarEntry) -> some View {
        let route = ShellModel.Route.agent(entry.row.member.id)
        return MessengerRow(entry: entry, selected: shell.route == route, stopped: shell.stopped)
            .tag(route)
            .listRowBackground(RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(shell.route == route && !shell.conversationPresented ? palette.selection.color : .clear)
                .padding(.horizontal, 6))
            .listRowSeparator(.hidden)
            .contextMenu {
                Button(L10n.ui(.mascotMenu, language)) { mascotFor = entry.row.member }
                    .accessibilityLabel(L10n.ui(.mascotMenu, language)).accessibilityIdentifier("sidebar-mascot-\(entry.row.member.id)")
            }
    }

    private func conversationRow(_ conversation: ConversationSummary, now: Date) -> some View {
        let selected = shell.conversationPresented && shell.store.selectedConversationId == conversation.id
        let title = ConversationList.title(conversation, language: language)
        let time = ConversationList.timeLabel(conversation, now: now, language: language)
        return Button { shell.openConversation(session: conversation.id) } label: {
            HStack(spacing: 8) {
                Text(title)
                    .font(.hk(Theme.Text.ui, selected ? Theme.Weight.semibold : Theme.Weight.regular))
                    .foregroundStyle(palette.ink.color)
                    .lineLimit(1)
                Spacer(minLength: 4)
                if let time {
                    Text(time).font(.caption.monospacedDigit()).foregroundStyle(palette.ink3.color)
                }
            }
            .padding(.vertical, 3)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel([title, time].compactMap { $0 }.joined(separator: ", "))
        .listRowBackground(RoundedRectangle(cornerRadius: 8, style: .continuous)
            .fill(selected ? palette.selection.color : .clear)
            .padding(.horizontal, 6))
        .accessibilityIdentifier("sidebar-conversation-\(conversation.id)")
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }

    /// Local filter on name and last line (⌘F focuses it, Esc clears it).
    private func searchField(_ copy: Copy) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").font(.meta).foregroundStyle(palette.ink3.color).accessibilityHidden(true)
            TextField(copy(.sidebarSearch), text: $query)
                .textFieldStyle(.plain)
                .font(.hk(Theme.Text.ui, Theme.Weight.regular))
                .focused($searchFocused)
                .onExitCommand { query = ""; searchFocused = false; shell.endSearch() }
                .accessibilityLabel(copy(.sidebarSearch)).accessibilityIdentifier("sidebar-search")
            if query.isEmpty {
                Text("⌘F").font(.meta).foregroundStyle(palette.ink3.color).accessibilityHidden(true)
            } else {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(palette.ink3.color) }
                    .buttonStyle(.plain)
                    .accessibilityLabel(copy(.sidebarSearchClear)).accessibilityIdentifier("sidebar-search-clear")
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(palette.raise.color))
        .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).stroke(palette.line2.color, lineWidth: 1))
        .padding(.horizontal, 12).padding(.top, 6).padding(.bottom, 8)
        .background(palette.list.color)
    }

    /// The footer counts the requests that left the Mac today, counted from
    /// the run receipts the privacy record page shows. Three states: the
    /// record is still being read (a neutral line, no number), it could not
    /// be read (the count is unavailable), or the number is known.
    private func privacyCount(at now: Date) -> PrivacyRecordCount {
        PrivacyRecordCounter.state(
            read: shell.store.privacyRecordRead,
            receipts: shell.store.receiptLog.receipts,
            now: now
        )
    }

    private func privacyCountLabel(at now: Date) -> String {
        PrivacyRecordCounter.label(privacyCount(at: now), language)
    }

    /// Indigo when something left this Mac, green when nothing did, plain
    /// when there is nothing to say yet. The colour never carries the meaning
    /// alone: the line says it in words.
    private func privacyCountIcon(at now: Date) -> String {
        switch privacyCount(at: now) {
        case .count(0): return "lock.shield"
        case .count: return "arrow.up.right"
        case .loading: return "lock.shield"
        case .unavailable: return "questionmark.circle"
        }
    }
}

struct AgentSelectionList: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.language) private var language
    @Environment(\.palette) private var palette
    @Binding var selected: String
    var workingOnly = false
    var onSelect: ((String) -> Void)?

    var body: some View {
        let copy = Copy(language: language)
        Group {
            if workingOnly && shell.workingAgents.isEmpty {
                EmptyRouteView(copyKey: .runningEmpty)
            } else {
                List(selection: $selected) {
                    ForEach(TeamMember.all.filter { !workingOnly || shell.workingAgents.contains($0.id) }) { member in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Label(member.name, systemImage: "person")
                                Spacer(minLength: 4)
                                Text(agentState(member)).font(.meta).foregroundStyle(palette.muted.color)
                            }
                            Text(shell.brainLabel(of: member.id) ?? copy(.brainUnavailable))
                                .font(.meta).foregroundStyle(palette.muted.color)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel([member.name, shell.brainLabel(of: member.id) ?? copy(.brainUnavailable), agentState(member)].joined(separator: " · ")).accessibilityIdentifier("agent-selection-row-\(member.id)")
                        .accessibilityAddTraits(selected == member.id ? [.isSelected] : [])
                        .tag(member.id)
                        .listRowBackground(selected == member.id ? palette.selection.color : palette.list.color)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            selected = member.id
                            onSelect?(member.id)
                        }
                    }
                    if !workingOnly {
                        Section {
                            Label([copy(.interruptRules), copy(.quietHours), copy(.channels)].joined(separator: " · "), systemImage: "bell")
                                .accessibilityLabel([copy(.interruptRules), copy(.quietHours), copy(.channels)].joined(separator: " · ")).accessibilityIdentifier("agent-selection-notifications-row")
                                .accessibilityAddTraits(selected == "notifications" ? [.isSelected] : [])
                                .tag("notifications")
                                .listRowBackground(selected == "notifications" ? palette.selection.color : palette.list.color)
                        } header: {
                            Text(copy(.notificationsQuietHours)).foregroundStyle(palette.ink2.color)
                        }
                    }
                }
                .listStyle(.sidebar)
                .tint(palette.blue.color)
                .scrollContentBackground(.hidden)
                .background(palette.work.color)
            }
        }
        .background(palette.work.color)
        .accessibilityLabel(copy(.agentsRules))
        .onAppear { shell.loadProviders() }
    }

    private func agentState(_ member: TeamMember) -> String {
        if shell.stopped { return L10n.ui(.pausedByStop, language) }
        if shell.workingAgents.contains(member.id) { return L10n.ui(.agentWorking, language) }
        if let paused = shell.pauseOverrides[member.id] {
            return L10n.ui(paused ? .agentPaused : .agentIdle, language)
        }
        guard let agent = shell.store.agents.first(where: { $0.name == member.id }) else { return L10n.ui(.agentStateUnavailable, language) }
        switch agent.state {
        case .idle: return L10n.ui(.agentIdle, language)
        case .thinking: return L10n.ui(.agentThinking, language)
        case .working: return L10n.ui(.agentWorking, language)
        case .needsYou: return L10n.ui(.agentNeedsYou, language)
        case .paused: return L10n.ui(.agentPaused, language)
        case .killed: return L10n.ui(.agentStopped, language)
        }
    }
}

/// One conversation row: neutral round avatar, name and time, the last
/// result, and the amber "needs you" badge (hourglass + words, never a dot).
struct MessengerRow: View {
    let entry: SidebarEntry
    let selected: Bool
    let stopped: Bool
    @Environment(\.palette) private var palette

    var body: some View {
        let row = entry.row
        HStack(alignment: .center, spacing: 10) {
            AgentMascot(agentId: row.member.id, size: 28, working: row.working, stopped: stopped || entry.status.kind == .stopped)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(row.member.name)
                        .font(.hk(Theme.Text.ui, row.unread ? Theme.Weight.semibold : Theme.Weight.medium))
                        .foregroundStyle(palette.ink.color)
                        .layoutPriority(1)
                    if let role = entry.role {
                        Text(role).font(.hk(Theme.Text.caption, Theme.Weight.regular)).foregroundStyle(palette.ink3.color).lineLimit(1)
                    }
                }
                HStack(spacing: 6) {
                    switch entry.status.kind {
                    case .stopped: Image(systemName: "stop.fill").font(.system(size: 8)).foregroundStyle(palette.red.color)
                    case .working: Image(systemName: "circle.dotted").font(.system(size: 9)).foregroundStyle(palette.ink2.color)
                    default: EmptyView()
                    }
                    Text(entry.status.text)
                        .font(.hk(Theme.Text.secondary, Theme.Weight.regular))
                        .foregroundStyle(entry.status.kind == .stopped ? palette.red.color : palette.ink2.color)
                        .lineLimit(entry.status.kind == .waiting ? 2 : 1)
                        .truncationMode(.tail)
                }
            }
            Spacer(minLength: 0)
            // Time on top, the needs-you badge (hourglass and words) under it.
            VStack(alignment: .trailing, spacing: 4) {
                if let time = row.time {
                    Text(time).font(.caption.monospacedDigit()).foregroundStyle(palette.ink3.color)
                }
                if let badge = entry.badge {
                    Label(badge, systemImage: "hourglass")
                        .font(.hk(Theme.Text.caption, Theme.Weight.semibold))
                        .foregroundStyle(palette.amber.color)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(palette.amberSoft.color))
                        .fixedSize()
                }
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel([row.member.name, entry.role, entry.badge, entry.status.text, row.time].compactMap { $0 }.joined(separator: ", "))
        .accessibilityIdentifier("team-agent-row-\(row.member.id)")
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

/// Actions waiting for the owner: blue, the same number everywhere.
struct CountBadge: View {
    let count: Int
    @Environment(\.palette) private var palette

    var body: some View {
        Text("\(count)")
            .font(.hk(11, Theme.Weight.bold))
            .foregroundStyle(palette.onBlue.color)
            .padding(.horizontal, 5)
            .frame(minWidth: 18, minHeight: 18)
            .background(Capsule().fill(palette.blue.color))
    }
}

struct FooterRow: View {
    let icon: Icon
    let title: String
    var count = 0
    var selected = false
    /// Stable accessibility identifier, for a UI driver that reads the
    /// accessibility tree.
    var identifier = "sidebar-footer-row"
    let action: () -> Void
    @Environment(\.palette) private var palette
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                IconView(icon: icon).foregroundStyle(palette.muted.color)
                Text(title)
                    .font(.hk(Theme.Text.ui, selected ? Theme.Weight.semibold : Theme.Weight.regular))
                    .foregroundStyle(selected ? palette.ink.color : palette.ink2.color)
                Spacer()
                if count > 0 {
                    Text("\(count)").font(.meta).foregroundStyle(palette.muted.color)
                }
            }
            .padding(.horizontal, 8)
            .frame(height: 30)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(selected ? palette.selection.color : hovering ? palette.hover.color : .clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel(title).accessibilityIdentifier(identifier)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

/// "Running · 2 working · Private mode" with a dot: green = running on this
/// Mac; red = stopped; grey = not running.
struct StateLine: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let (text, dot) = state(copy)
        HStack(spacing: 7) {
            Circle().fill(dot).frame(width: 7, height: 7)
            Text(text).font(.meta).foregroundStyle(palette.muted.color).lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 8)
        .padding(.top, 8)
        .padding(.bottom, 2)
    }

    private func state(_ copy: Copy) -> (String, Color) {
        switch shell.store.connection {
        case .connecting:
            return (copy(.stateConnecting), palette.faint.color)
        case .offline, .unauthorized:
            return (copy(.stateOffline), palette.faint.color)
        case .online:
            if shell.stopped { return (copy(.stateStopped), palette.red.color) }
            let working = shell.workingAgents.count
            var parts = [copy(.stateRunning)]
            if working > 0 { parts.append(copy.f(.stateWorking, working)) }
            parts.append(copy(.statePrivate))
            return (parts.joined(separator: " · "), palette.ink2.color)
        }
    }
}
