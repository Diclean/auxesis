// The window: the team sidebar (288), the main area, and the right
// panel (360, ⌥⌘I) beside a conversation. A conversation is one centred
// 640-pt column; a record page (Records menu) draws its list and detail.
import AuxesisKit
import SwiftUI

struct ShellView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @State private var selectedAgent = TeamMember.aux.id
    @State private var todaySelection = TodaySelection.brief
    @State private var selectedPrivacyRecord: String?
    @State private var selectedLedgerEntryID: String?

    var body: some View {
        NavigationSplitView(columnVisibility: Binding(
            get: { shell.sidebarVisible ? .all : .detailOnly },
            set: { shell.sidebarVisible = ($0 != .detailOnly) }
        )) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 260, ideal: Theme.sidebarWidth, max: 340)
        } detail: {
            VStack(spacing: 0) {
                HeaderBar()
                Hairline()
                if shell.stopped { StopBanner() }
                mainArea.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .background(palette.work.color)
            .inspector(isPresented: Binding(get: { shell.inspectorOpen && panelMember != nil },
                                             set: { shell.setRightPanel($0) })) {
                if let member = panelMember {
                    RightPanel(member: member)
                        .inspectorColumnWidth(min: 300, ideal: Theme.inspectorWidth, max: 440)
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
        .background(palette.work.color)
        .background(NoInitialFocus())
        .tint(palette.blue.color)
        .frame(minWidth: 1100, minHeight: 700)
        .sheet(isPresented: $shell.setupOpen) {
            SetupSheet(publish: { [store = shell.store] in try await store.publishAppleEventKit($0) })
                .environmentObject(shell)
                .environment(\.language, shell.language)
                .themed()
        }
        .onAppear {
            if AppEnvironment.fixture == nil && SetupModel.shouldShow() { shell.setupOpen = true }
            // v4: the window opens on Aux's conversation, not on a pane.
            if shell.route == .today { shell.go(.agent(TeamMember.aux.id)) }
        }
        .onChange(of: shell.route) { _, route in
            if case .agent(let id) = route { selectedAgent = id; shell.inspectorOpen = shell.rightPanelPreferred }
        }
        .sheet(isPresented: Binding(
            get: { shell.settingsTab != nil },
            set: { if !$0 { shell.settingsTab = nil } }
        )) {
            SettingsSheet()
                .environmentObject(shell)
                .themed()
        }
        .sheet(isPresented: $shell.shortcutHelpOpen) {
            KeyboardShortcutsSheet(language: shell.language)
                .themed()
                .frame(minWidth: 480, minHeight: 420)
        }
    }

    private var area: ShellModel.SplitLayout.MainArea {
        ShellModel.SplitLayout.mainArea(for: shell.route, conversationPresented: shell.conversationPresented,
                                        conversationAgent: shell.conversationAgent)
    }

    private var offline: Bool {
        switch shell.store.connection {
        case .offline, .unauthorized: return true
        case .connecting, .online: return false
        }
    }

    /// The right panel shows the open conversation's agent; record pages have none.
    private var panelMember: TeamMember? {
        guard case .conversation(let id) = area else { return nil }
        return TeamMember.member(id) ?? .custom(id)
    }

    @ViewBuilder private var mainArea: some View {
        switch area {
        case .conversation(let id):
            VStack(spacing: 0) {
                if offline { OfflineBar() }
                ConversationView(agent: id).id(id)
                    .disabled(shell.stopped)
            }
        case .page(let detail):
            HStack(spacing: 0) {
                MainColumn(selectedAgent: $selectedAgent, todaySelection: $todaySelection,
                           selectedLedgerEntryID: $selectedLedgerEntryID, privacySelection: $selectedPrivacyRecord)
                    .frame(width: detail ? 380 : nil)
                    .frame(maxWidth: detail ? 380 : .infinity)
                if detail {
                    Rectangle().fill(palette.line.color).frame(width: 1)
                    DetailColumn(selectedAgent: selectedAgent, todaySelection: todaySelection,
                                 selectedLedgerEntryID: selectedLedgerEntryID, privacySelection: selectedPrivacyRecord)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .disabled(shell.stopped)
                        .help(StopActionState.disabledReason(stopped: shell.stopped, language: shell.language) ?? "")
                }
            }
        }
    }
}

struct DetailColumn: View {
    @EnvironmentObject private var shell: ShellModel
    let selectedAgent: String
    let todaySelection: TodaySelection
    let selectedLedgerEntryID: String?
    let privacySelection: String?

    var body: some View {
        if shell.route == .privacyRecord {
            RequestInspectorView(receipt: shell.store.receipts.first { $0.runId == privacySelection })
        } else if shell.route == .today {
            if case .waiting(let id) = todaySelection,
               let approval = shell.waitingApprovals.first(where: { $0.id == id }) {
                ApprovalProposalView(approval: approval)
            } else {
                TodayView(selection: todaySelection)
            }
        } else if shell.route == .clients {
            if shell.selectedClient != nil { ClientCardView() }
            else { EmptyRouteView(copyKey: .clientsPick) }
        } else if shell.route == .documents, let model = shell.documents {
            if let row = model.selected { DocumentDetailView(row: row) }
            else { EmptyRouteView(copyKey: .selectItemDetail) }
        } else if shell.route == .waiting {
            if let approval = shell.store.approvals.first(where: { $0.id == shell.store.focusedApprovalId }) {
                ApprovalProposalView(approval: approval)
            } else {
                EmptyRouteView(copyKey: .selectItemDetail)
            }
        } else if shell.route == .calendar, let model = shell.calendar {
            CalendarView(model: model)
        } else if shell.route == .sinceYouLeft {
            let entry = (shell.ledger.value ?? []).first { $0.id == selectedLedgerEntryID }
            if let entry {
                SinceYouLeftDetailView(entry: entry)
            } else {
                EmptyRouteView(copyKey: ledgerSelectionCopyKey)
            }
        } else if shell.route == .running && shell.workingAgents.isEmpty {
            EmptyRouteView(copyKey: .selectItemDetail)
        } else if shell.route == .agentsAndRules && selectedAgent == "notifications" {
            NotificationsRulesDetail()
        } else if shell.route == .agentsAndRules, let member = TeamMember.member(selectedAgent) {
            // Agents and rules: the agent's rules, brain and grants; its chat is in the sidebar.
            ProfileInspector(member: member, embedded: true)
        } else {
            EmptyRouteView(copyKey: .selectItemDetail)
        }
    }

    private var ledgerSelectionCopyKey: UIKey {
        switch shell.ledger {
        case .loaded(let rows): return rows.isEmpty ? .ledgerEmpty : .selectItemDetail
        case .loading: return .loading
        case .failed: return .loadFailed
        case .unavailable: return .unavailable
        }
    }
}

struct EmptyRouteView: View {
    @Environment(\.language) private var language
    @Environment(\.palette) private var palette
    let copyKey: UIKey

    var body: some View {
        Text(Copy(language: language)(copyKey))
            .font(.ui)
            .foregroundStyle(palette.ink2.color)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .multilineTextAlignment(.center)
            .padding(36)
    }
}

/// A record page's list: the existing route view or its contract empty state.
struct MainColumn: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Binding var selectedAgent: String
    @Binding var todaySelection: TodaySelection
    @Binding var selectedLedgerEntryID: String?
    @Binding var privacySelection: String?

    var body: some View {
        VStack(spacing: 0) {
            if isOffline { OfflineBar() }
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
                .disabled(shell.stopped)
                .help(StopActionState.disabledReason(stopped: shell.stopped, language: shell.language) ?? "")
        }
        .background(palette.work.color)
    }

    @ViewBuilder private var content: some View {
        switch shell.route {
        case .agent(let id):
            ConversationView(agent: id).id(id)
        case .today: TodayQueueList(selection: $todaySelection)
        case .calendar: TodayQueueList(selection: $todaySelection)
        case .waiting: WaitingView()
        case .ledger: LedgerView()
        case .sinceYouLeft: SinceYouLeftList(selection: $selectedLedgerEntryID)
        case .clients: ClientsView()
        case .documents:
            if let model = shell.documents { DocumentsView(model: model) } else { DomainPlaceholderView(member: .documents) }
        case .running: AgentSelectionList(selected: $selectedAgent, workingOnly: true) { shell.go(.agent($0)) }
        case .money: EmptyRouteView(copyKey: .moneyEmpty)
        case .memory:
            if let model = shell.memoryPage { MemoryView(model: model) } else { EmptyRouteView(copyKey: .memoryUnavailable) }
        case .privacyRecord: PrivacyRecordListView(selection: $privacySelection)
        case .agentsAndRules:
            AgentSelectionList(selected: $selectedAgent)
        }
    }

    private var isOffline: Bool {
        switch shell.store.connection {
        case .offline, .unauthorized: return true
        case .connecting, .online: return false
        }
    }
}

private struct TodayQueueList: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.language) private var language
    @Environment(\.palette) private var palette
    @Binding var selection: TodaySelection

    var body: some View {
        let copy = Copy(language: language)
        let approvals = shell.waitingApprovals
        let entries = SinceYouLeftPresentation.previewEntries(shell.ledger.value ?? [])
        let running = TeamMember.all.filter { shell.workingAgents.contains($0.id) }
        let groups = TodayQueueModel.groups(waiting: approvals.count, dueToday: 0,
                                             sinceYouLeft: nil, runningNow: running.count)
        List {
            ForEach(groups, id: \.kind) { group in
                Section {
                    switch group.kind {
                    case .waiting:
                        if approvals.isEmpty { Text(copy(.waitingEmpty)).font(.meta).foregroundStyle(palette.muted.color) }
                        ForEach(approvals) { approval in
                            Button { selection = .waiting(approval.id) } label: {
                                queueRow(shell.rowHeadline(for: approval), icon: "tray", tone: palette.amber.color)
                            }
                            .buttonStyle(.plain).listRowBackground(selected(.waiting(approval.id)) ? palette.blueSoft.color : .clear)
                            .accessibilityLabel(shell.rowHeadline(for: approval)).accessibilityIdentifier("today-waiting-row-\(approval.id)")
                            .accessibilityAddTraits(selected(.waiting(approval.id)) ? [.isSelected] : [])
                        }
                    case .dueToday:
                        Text(copy(.todayDueEmpty)).font(.meta).foregroundStyle(palette.muted.color)
                    case .sinceYouLeft:
                        if entries.isEmpty { Text(copy(.ledgerEmpty)).font(.meta).foregroundStyle(palette.muted.color) }
                        ForEach(entries.prefix(1)) { entry in
                            Button { selection = .ledger(entry.id) } label: {
                                queueRow(LedgerText.what(entry, language: language), icon: "clock.arrow.circlepath", tone: palette.ink2.color)
                            }
                            .buttonStyle(.plain).listRowBackground(selected(.ledger(entry.id)) ? palette.blueSoft.color : .clear)
                            .accessibilityLabel(LedgerText.what(entry, language: language)).accessibilityIdentifier("today-ledger-row-\(entry.id)")
                            .accessibilityAddTraits(selected(.ledger(entry.id)) ? [.isSelected] : [])
                        }
                    case .runningNow:
                        if running.isEmpty { Text(copy(.idleLine)).font(.meta).foregroundStyle(palette.muted.color) }
                        ForEach(running) { member in
                            Button { selection = .agent(member.id) } label: {
                                queueRow(member.name, icon: "arrow.triangle.2.circlepath", tone: palette.ink2.color)
                            }
                            .buttonStyle(.plain).listRowBackground(selected(.agent(member.id)) ? palette.blueSoft.color : .clear)
                            .accessibilityLabel(member.name).accessibilityIdentifier("today-running-row-\(member.id)")
                            .accessibilityAddTraits(selected(.agent(member.id)) ? [.isSelected] : [])
                        }
                    }
                } header: {
                    Button { selection = .group(group.kind) } label: {
                        HStack {
                            Text(group.kind.title(copy)).font(.meta)
                            Spacer()
                            if group.kind == .dueToday {
                                Text("?").font(.meta.monospacedDigit())
                            } else if let count = group.count {
                                Text(String(count)).font(.meta.monospacedDigit())
                            }
                        }.foregroundStyle(palette.ink2.color)
                    }
                    .buttonStyle(.plain).listRowBackground(selected(.group(group.kind)) ? palette.blueSoft.color : .clear)
                    .accessibilityLabel(group.kind.title(copy)).accessibilityIdentifier("today-group-\(groupIdentifier(group))")
                    .accessibilityAddTraits(selected(.group(group.kind)) ? [.isSelected] : [])
                }
            }
        }
        .buttonStyle(.plain)
        .listStyle(.inset)
        .scrollContentBackground(.hidden)
        .background(palette.work.color)
    }

    private func selected(_ candidate: TodaySelection) -> Bool { selection == candidate }
    private func groupIdentifier(_ group: TodayQueueGroup) -> String {
        switch group.kind {
        case .waiting: return "waiting"
        case .dueToday: return "due-today"
        case .sinceYouLeft: return "since-you-left"
        case .runningNow: return "running-now"
        }
    }
    private func queueRow(_ title: String, icon: String, tone: Color) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(tone)
            Text(title).font(.ui).foregroundStyle(palette.ink.color).lineLimit(2)
        }
    }
}

// MARK: - Header

struct HeaderBar: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    /// v5 header: who you talk to, the brain chip, then Records, the panel
    /// toggle and Stop all. Back (⌘[) and Ask Aux (⌘K) live in the menus.
    var body: some View {
        let copy = Copy(language: language)
        HStack(spacing: 10) {
            title
            if let agent = conversationAgent { BrainButton(agent: agent) }
            Spacer(minLength: 8)
            RecordsMenu()
            if conversationAgent != nil {
                ToolbarIconButton(icon: .insp, help: copy(.panelToggle), identifier: "toolbar-inspector-toggle", pressed: shell.inspectorOpen) {
                    withAnimation(.easeOut(duration: 0.24)) { shell.toggleRightPanel() }
                }
            }
            StopButton()
        }
        .padding(.leading, 20)
        .padding(.trailing, 12)
        .frame(height: Theme.barHeight)
    }

    /// The agent whose conversation fills the main area, if one does.
    private var conversationAgent: String? {
        if shell.conversationPresented { return shell.conversationAgent }
        return shell.selectedAgent
    }

    @ViewBuilder private var title: some View {
        let copy = Copy(language: language)
        if shell.conversationPresented, let member = TeamMember.member(shell.conversationAgent) {
            HeaderTitle(
                tile: AnyView(AgentTile(member: member, size: .header)),
                title: member.name,
                subtitle: headerLine(member: member, row: shell.row(for: member)),
                tone: .muted
            )
        } else { switch shell.route {
        case .agent(let id):
            let member = TeamMember.member(id) ?? .custom(id)
            let row = shell.row(for: member)
            HeaderTitle(
                tile: AnyView(AgentTile(member: member, size: .header, working: row.working, stopped: shell.stopped)),
                title: member.name,
                subtitle: headerLine(member: member, row: row),
                tone: shell.stopped ? .halt : (row.tone == .live || row.working ? .live : .muted)
            )
        case .today:
            HeaderTitle(tile: AnyView(IconTile(icon: .sun)), title: copy(.today), subtitle: copy(.todaySubtitle), tone: .muted)
        case .calendar:
            HeaderTitle(tile: AnyView(IconTile(icon: .cal)), title: copy(.calPage), subtitle: copy(.calSubtitle), tone: .muted)
        case .waiting:
            HeaderTitle(tile: AnyView(IconTile(icon: .inbox)), title: copy(.waitingForYou), subtitle: copy(.waitingSubtitle), tone: .muted)
        case .sinceYouLeft:
            HeaderTitle(tile: nil, title: copy(.sinceYouLeft), subtitle: copy(.ledgerSubtitle), tone: .muted)
        case .running:
            HeaderTitle(tile: nil, title: copy(.running), subtitle: copy(.idleLine), tone: .muted)
        case .ledger:
            HeaderTitle(tile: nil, title: copy(.ledger), subtitle: copy(.ledgerSubtitle), tone: .muted)
        case .money:
            HeaderTitle(tile: nil, title: copy(.money), subtitle: copy(.moneyEmpty), tone: .muted)
        case .memory:
            HeaderTitle(tile: nil, title: copy(.whatAuxKnows), subtitle: copy(.memoryLede), tone: .muted)
        case .privacyRecord:
            HeaderTitle(tile: nil, title: copy(.privacyRecord), subtitle: copy(.privacyRecordLede), tone: .muted)
        case .agentsAndRules:
            HeaderTitle(tile: nil, title: copy(.agentsRules), subtitle: copy(.team), tone: .muted)
        case .clients:
            HeaderTitle(tile: AnyView(IconTile(icon: .people)), title: copy(.clients), subtitle: copy(.clientsSubtitle), tone: .muted)
        case .documents:
            HeaderTitle(tile: AnyView(IconTile(icon: .doc)), title: copy(.documents), subtitle: copy(.documentsSubtitle), tone: .muted)
        }
        }
    }

    private func headerLine(member: TeamMember, row: TeamRowModel) -> String {
        let copy = Copy(language: language)
        if shell.stopped {
            return member.role == .chief ? copy(.stateStopped) : copy(.pausedByStop)
        }
        if member.role == .chief {
            let working = shell.workingAgents.subtracting([member.id]).count
            if working > 0 {
                return working == 1 ? copy(.chiefWorkingOne) : copy.f(.chiefWorkingMany, working)
            }
            return copy(member.roleKey)
        }
        return row.working ? row.line : copy(member.roleKey)
    }
}

/// The pages that left the sidebar, in one native menu in the header.
/// The Go menu lists the same pages, without shortcuts.
struct RecordsMenu: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.language) private var language
    @Environment(\.palette) private var palette

    var body: some View {
        let copy = Copy(language: language)
        Menu {
            ForEach(Array(ShellModel.recordsMenu.enumerated()), id: \.offset) { index, routes in
                if index > 0 { Divider() }
                ForEach(routes, id: \.self) { route in
                    let title = RouteText.title(route, copy, waiting: shell.waitingCount())
                    Button { shell.go(route) } label: { Label(title, systemImage: RouteText.symbol(route)) }
                        .accessibilityLabel(title).accessibilityIdentifier("records-\(RouteText.identifier(route))")
                }
            }
        } label: {
            Label(copy(.recordsMenu), systemImage: "square.grid.2x2").font(.ui)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .tint(palette.ink2.color)
        .help(copy(.recordsMenu))
        .accessibilityLabel(copy(.recordsMenu)).accessibilityIdentifier("toolbar-records-menu")
    }
}

/// Title, symbol and stable id of a page route (Records menu, VoiceOver, UI drivers).
enum RouteText {
    static func title(_ route: ShellModel.Route, _ copy: Copy, waiting: Int = 0) -> String {
        switch route {
        case .today: return copy(.today)
        case .waiting: return waiting > 0 ? "\(copy(.waitingForYou)) · \(waiting)" : copy(.waitingForYou)
        case .sinceYouLeft: return copy(.sinceYouLeft)
        case .running: return copy(.running)
        case .clients: return copy(.clients)
        case .documents: return copy(.documents)
        case .money: return copy(.money)
        case .memory: return copy(.whatAuxKnows)
        case .privacyRecord: return copy(.privacyRecord)
        case .agentsAndRules: return copy(.agentsRules)
        case .calendar: return copy(.calPage)
        case .ledger: return copy(.ledger)
        case .agent(let id): return TeamMember.displayName(id)
        }
    }

    static func symbol(_ route: ShellModel.Route) -> String {
        switch route {
        case .today: return "sun.max"
        case .waiting: return "hourglass"
        case .sinceYouLeft: return "clock.arrow.circlepath"
        case .running: return "arrow.triangle.2.circlepath"
        case .clients: return "person.2"
        case .documents: return "doc.text"
        case .money: return "eurosign.circle"
        case .memory: return "text.book.closed"
        case .privacyRecord: return "lock.shield"
        case .agentsAndRules: return "slider.horizontal.3"
        case .calendar: return "calendar"
        case .ledger: return "list.bullet"
        case .agent: return "person"
        }
    }

    static func identifier(_ route: ShellModel.Route) -> String {
        GoMenu.identifier(for: route)
    }
}

struct HeaderTitle: View {
    let tile: AnyView?
    let title: String
    let subtitle: String
    let tone: LineTone
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: 10) {
            if let tile { tile }
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.hk(Theme.Text.ui, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(tone.color(palette))
                    .lineLimit(1)
            }
        }
    }
}

/// An outlined squircle around a view icon (Waiting for you, Clients, …).
struct IconTile: View {
    let icon: Icon
    var side: CGFloat = 30
    @Environment(\.palette) private var palette

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: side * 0.3, style: .continuous)
        ZStack {
            shape.fill(palette.work.color)
            shape.strokeBorder(palette.line2.color, lineWidth: 1)
            IconView(icon: icon, size: side * 0.53).foregroundStyle(palette.ink2.color)
        }
        .frame(width: side, height: side)
    }
}

extension LineTone {
    func color(_ palette: Palette) -> Color {
        switch self {
        case .muted: return palette.muted.color
        case .live: return palette.ink2.color
        case .halt: return palette.red.color
        }
    }
}

/// The brain button: model name, the daemon's real mode for this agent, and a
/// chevron. The chip never guesses: a daemon that does not report a mode shows
/// "Mode unknown", never "Private". Opens the profile, where the brain is
/// changed.
struct BrainButton: View {
    let agent: String
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var hovering = false

    var body: some View {
        let copy = Copy(language: language)
        let mode = shell.privacyMode(of: agent)
        Button {
            withAnimation(.easeOut(duration: 0.24)) { shell.rightPanelTab = .work; shell.setRightPanel(true) }
        } label: {
            HStack(spacing: 6) {
                Text(shell.brainLabel(of: agent) ?? copy(.brainDefault))
                    .foregroundStyle(palette.ink2.color)
                HStack(spacing: 4) {
                    IconView(icon: .shield, size: 14)
                    Text(copy(mode.chipKey)).font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                }
                .foregroundStyle(palette.ink2.color)
                IconView(icon: .down, size: 14).foregroundStyle(palette.ink2.color)
            }
            .font(.ui)
            .padding(.leading, 9)
            .padding(.trailing, 8)
            .frame(height: 28)
            .background(RoundedRectangle(cornerRadius: 6).fill(hovering ? palette.hover.color : .clear))
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(palette.line2.color, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(copy(.profile))
        .accessibilityLabel(copy(.profile)).accessibilityIdentifier("toolbar-brain-menu")
    }
}

/// Stop all in the toolbar; turns into a filled red Resume while stopped.
struct StopButton: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        if shell.stopped {
            Button { shell.resumeAll() } label: {
                HStack(spacing: 6) {
                    IconView(icon: .play)
                    Text(copy(.resume))
                }
            }
            .buttonStyle(AuxButtonStyle(kind: .stopFilled))
            .disabled(shell.stopInFlight)
            .help("⌘.")
            .accessibilityLabel(copy(.resume)).accessibilityIdentifier("toolbar-resume")
        } else {
            Button { shell.stopAll() } label: {
                HStack(spacing: 6) {
                    IconView(icon: .stop)
                    Text(copy(.stopAll))
                }
            }
            .buttonStyle(AuxButtonStyle(kind: .stop))
            .disabled(shell.stopInFlight || shell.client == nil)
            .help("⌘.")
            .accessibilityLabel(copy(.stopAll)).accessibilityIdentifier("toolbar-stop-all")
        }
    }
}

// MARK: - Bars

struct OfflineBar: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        HStack(spacing: 10) {
            IconView(icon: .alert).foregroundStyle(palette.muted.color)
            Text(copy(.offlineTitle)).font(.ui).foregroundStyle(palette.ink.color)
            Spacer(minLength: 8)
            Button(copy(.offlineStart)) { shell.store.restart() }
                .buttonStyle(AuxButtonStyle())
                .accessibilityLabel(copy(.offlineStart)).accessibilityIdentifier("offline-start")
            Button(copy(.offlineRetry)) { shell.store.restart() }
                .buttonStyle(AuxButtonStyle(kind: .plain))
                .accessibilityLabel(copy(.offlineRetry)).accessibilityIdentifier("offline-retry")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(palette.raise.color)
        .overlay(alignment: .bottom) { Hairline() }
    }
}

private struct KeyboardShortcutsSheet: View {
    let language: Language
    @State private var query = ""

    private var entries: [(String, String)] {
        // TODO: Move the complete menu and help shortcut catalog into AuxesisKit so both stay in sync.
        let values: [(String, String)] = [
            (L10n.ui(.newConversation, language), "⌘N"),
            ("Settings", "⌘,"), ("Quit Auxesis (agents keep running)", "⌘Q"),
            ("Today", "⌘1"), ("Waiting", "⌘2"), ("Since you left", "⌘3"),
            ("Money", "⌘4"), ("Privacy record", "⌘5"), ("Agents and rules", "⌘6"),
            ("Clients", "⌘7"), ("Documents", "⌘8"), ("What Aux knows", "⌘9"),
            ("Ask Aux…", "⌘K"), ("Find", "⌘F"), ("Edit proposal", "E"),
            ("Not now", "⌘D"), ("Show or hide sidebar", "⌃⌘S"), ("Send proposal", "⌘↩"),
            ("Move through waiting items", "↑ / ↓ · J / K"), ("Open selected row", "↩"),
            ("Leave editing", "Esc"),
        ]
        return values.filter { query.isEmpty || $0.0.localizedCaseInsensitiveContains(query) || $0.1.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(language == .fr ? "Raccourcis clavier" : "Keyboard Shortcuts")
                .font(.title2.weight(.semibold))
            TextField(language == .fr ? "Rechercher les raccourcis" : "Search shortcuts", text: $query)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(language == .fr ? "Rechercher les raccourcis" : "Search shortcuts").accessibilityIdentifier("keyboard-shortcuts-search")
            List {
                ForEach(entries, id: \.0) { entry in
                    HStack { Text(entry.0); Spacer(); Text(entry.1).foregroundStyle(.secondary).monospaced() }
                }
            }
            .listStyle(.plain)
        }
        .padding(20)
    }
}
