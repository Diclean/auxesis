// ShellModel — the E2 shell's state on top of `Store`. The Store keeps the
// live daemon session (snapshot, socket, messages, approvals); this model adds
// what the team UI needs: where the owner is, delegations, the approval
// object's local phases (10-second Undo, Not now), Stop all, and the reads of
// Waiting for you, the Ledger, Settings and the agent profile.
//
// One approval, one id: phases are keyed by approval id and every view reads
// `card(for:)`, so answering in Waiting for you, in Mail's thread or in Aux's
// mirror changes the same object.
import Combine
import Foundation

public enum Loadable<Value: Equatable>: Equatable {
    case loading
    case loaded(Value)
    case failed
    /// The route is not on this daemon yet (NEW in E1).
    case unavailable

    public var value: Value? {
        if case .loaded(let value) = self { return value }
        return nil
    }
}

/// Which side of the Mac a brain runs on, from the provider that serves it.
public enum BrainPlace {
    /// A loopback base URL is the only proof the app has that the brain is on
    /// this Mac. An unknown, unmatched or ambiguous provider proves nothing.
    public static func isOnThisMac(_ brain: String?, providers: [ProviderSummary]) -> Bool {
        guard let brain, !brain.isEmpty else { return false }
        let matches = providers.filter { $0.model == brain || $0.name == brain }
        guard matches.count == 1, let provider = matches.first else { return false }
        return PrivacyRecordCounter.isLoopback(provider.baseURL)
    }
}

/// A brain's name for the owner: "deepseek-flash" → "DeepSeek Flash".
/// Only a lower-case `word-word` model id is reworded; a name already written
/// for people ("DeepSeek V3.2") or any other shape is shown as it is.
public enum BrainName {
    private static let words = [
        "deepseek": "DeepSeek", "gpt": "GPT", "glm": "GLM", "minimax": "MiniMax", "qwen": "Qwen",
        "mistral": "Mistral", "claude": "Claude", "llama": "Llama", "gemma": "Gemma", "kimi": "Kimi",
    ]

    public static func display(_ id: String) -> String {
        let parts = id.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count > 1, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy { ($0.isLowercase && $0.isASCII) || $0.isNumber || $0 == "." } }) else {
            return id
        }
        return parts.map { part in
            let word = String(part)
            if let known = words[word] { return known }
            return word.contains(where: \.isNumber) ? word : word.prefix(1).uppercased() + word.dropFirst()
        }.joined(separator: " ")
    }
}

@MainActor
public final class ShellModel: ObservableObject {
    public enum Route: Hashable {
        case agent(String)
        case today
        case calendar
        case waiting
        case sinceYouLeft
        case running
        case clients
        case documents
        case ledger
        case money
        case memory
        case privacyRecord
        case agentsAndRules
    }

    /// Column policy for the v5 shell: sidebar · main · right panel.
    public enum SplitLayout {
        /// What the main area draws: a conversation fills it alone; a
        /// record page draws its list, and its detail beside it when it has one.
        public enum MainArea: Equatable {
            case conversation(String)
            case page(detail: Bool)
        }

        public static func mainArea(for route: Route, conversationPresented: Bool, conversationAgent: String) -> MainArea {
            if conversationPresented { return .conversation(conversationAgent) }
            if case .agent(let id) = route { return .conversation(id) }
            return .page(detail: !collapsesDetail(for: route))
        }

        /// The right panel (Work · Team · Privacy) belongs to a conversation.
        public static func showsRightPanel(_ area: MainArea) -> Bool {
            if case .conversation = area { return true }
            return false
        }

        public static func collapsesDetail(for route: Route) -> Bool {
            if case .agent = route { return true }
            return route == .running || route == .memory
        }

        public static func showsAgentProfileInInspector(
            for route: Route, selectedAgent: String, conversationPresented: Bool
        ) -> Bool {
            conversationPresented || route == .running || (route == .agent(selectedAgent))
                || (route == .agentsAndRules && selectedAgent != "notifications")
        }
    }

    public enum SidebarSection: String, CaseIterable, Identifiable {
        case queue, records, agents
        public var id: String { rawValue }
        public var destinations: [Route] {
            switch self {
            case .queue: return [.today, .waiting, .sinceYouLeft]
            case .records: return [.clients, .documents, .money, .memory, .privacyRecord]
            case .agents: return [.agentsAndRules]
            }
        }
    }

    nonisolated public static let sidebarSections = SidebarSection.allCases

    /// The pages that left the sidebar, reached from the header's
    /// Records menu (one section per group) and the Go menu.
    nonisolated public static var recordsMenu: [[Route]] { sidebarSections.map(\.destinations) }

    public enum SettingsTab: String, CaseIterable, Identifiable {
        case general, providers, skills, plugins, privacy, budgets
        public var id: String { rawValue }
        public var titleKey: UIKey {
            switch self {
            case .general: return .tabGeneral
            case .providers: return .tabProviders
            case .skills: return .tabSkills
            case .plugins: return .tabPlugins
            case .privacy: return .tabPrivacy
            case .budgets: return .tabBudgets
            }
        }
        public var icon: Icon {
            switch self {
            case .general: return .sliders
            case .providers: return .cpu
            case .skills: return .bolt
            case .plugins: return .tool
            case .privacy: return .shield
            case .budgets: return .gauge
            }
        }
    }

    /// How long a yes waits before it leaves (contract: 10-second Undo).
    public static let undoSeconds = 10

    public let store: Store
    public let client: TeamClient?
    /// Private answers to the owner's texts: in memory, never persisted (see PrivateAnswers.swift).
    public let privateAnswers: PrivateAnswersModel
    /// The Calendar page and its refresh loop; set by the app.
    public var calendar: CalendarPageModel?
    /// The Documents page; set by the app, nil in fixture runs.
    public var documents: DocumentsPageModel?
    /// "What Aux knows": the memory page; set by the app.
    public var memoryPage: MemoryPageModel?

    @Published public private(set) var route: Route = .today
    @Published public var settingsTab: SettingsTab?
    @Published public var shortcutHelpOpen = false
    @Published public private(set) var askFocusRequest = 0
    /// ⌘F: the sidebar search takes the keyboard.
    @Published public private(set) var searchFocusRequest = 0
    /// A click on the conversation: the composer takes the keyboard, nothing does earlier.
    @Published public private(set) var composerFocusRequest = 0
    @Published public var askDraft = ""
    @Published public private(set) var conversationPresented = false
    @Published public private(set) var conversationAgent = TeamMember.aux.id
    @Published public private(set) var agentSelectionClearRequest = 0
    private var conversationReturnRoute: Route?
    /// The permissions setup sheet (SETUP-SCREEN): once at first launch, then from Settings.
    @Published public var setupOpen = false
    @Published public var inspectorOpen = false
    /// The right panel's tab and whether the owner wants it open: remembered
    /// across routes and launches (UserDefaults, nil in tests).
    @Published public var rightPanelTab: RightPanelTab {
        didSet { defaults?.set(rightPanelTab.rawValue, forKey: Self.rightPanelTabKey) }
    }
    private let defaults: UserDefaults?
    static let rightPanelTabKey = "auxesis.rightPanel.tab"
    static let rightPanelOpenKey = "auxesis.rightPanel.open"
    private var rightPanelWanted = false
    public var rightPanelPreferred: Bool { defaults?.bool(forKey: Self.rightPanelOpenKey) ?? rightPanelWanted }

    /// The owner opens or closes the panel; the choice outlives route changes.
    public func setRightPanel(_ open: Bool) {
        inspectorOpen = open
        rightPanelWanted = open
        defaults?.set(open, forKey: Self.rightPanelOpenKey)
    }

    public func toggleRightPanel() { setRightPanel(!inspectorOpen) }
    @Published public var sidebarVisible = true {
        // Closing it by hand ends the "⌘F opened it" state.
        didSet { if !sidebarVisible { sidebarOpenedBySearch = false } }
    }
    /// True while the sidebar is open only because ⌘F opened it: Esc closes it again.
    public private(set) var sidebarOpenedBySearch = false
    private var searchFocusPending = false
    private var askFocusPending = false
    /// Set when an agent thread was opened from one of Aux's delegation rows.
    @Published public private(set) var returnDelegation: String?
    @Published public private(set) var flashDelegation: String?
    @Published public private(set) var delegations: [Delegation] = []
    @Published public private(set) var delegationsAvailable = true
    @Published public var expanded: Set<String> = []
    /// The drafts the owner has unfolded (a mirror in Aux's thread).
    @Published public private(set) var unfoldedDrafts: Set<String> = []
    @Published public private(set) var snoozed: Set<String> = []
    @Published public private(set) var countdowns: [String: Int] = [:]
    @Published public private(set) var answering: Set<String> = []
    @Published public private(set) var cancelledByStop: Set<String> = []
    @Published public private(set) var failedApprovals: Set<String> = []
    @Published public var editing: String?
    @Published public var editDrafts: [String: String] = [:]
    @Published public var swapped: Set<String> = []
    @Published public private(set) var stopped = false
    @Published public private(set) var cancelledSends = 0
    @Published public private(set) var stopInFlight = false
    @Published public private(set) var coverage: Loadable<[CoverageRow]> = .loading
    @Published public private(set) var ledger: Loadable<[LedgerEntry]> = .loading
    @Published public private(set) var planned: Loadable<[PlannedJob]> = .loading
    /// Today: the brief of the day, and the answer of the last run.
    @Published public private(set) var today: Loadable<TodayPresentation> = .loading
    @Published public private(set) var briefRunning = false
    @Published public private(set) var briefRunNote: UIKey?
    /// Possible-new-client rows with a call in flight, and the one row whose
    /// last call failed (one inline line, never a modal).
    @Published public private(set) var prospectsBusy: Set<String> = []
    @Published public private(set) var prospectFailed: String?
    @Published public private(set) var providers: Loadable<[ProviderSummary]> = .loading
    @Published public private(set) var providerTests: [String: ProviderTest] = [:]
    @Published public private(set) var providerError: String?
    @Published public private(set) var skills: Loadable<[LocalSkill]> = .loading
    @Published public private(set) var usage: Loadable<UsageDay> = .loading
    @Published public private(set) var grants: [String: Loadable<AgentGrants>] = [:]
    @Published public private(set) var memory: [String: Loadable<[MemoryItem]>] = [:]
    @Published public private(set) var pauseOverrides: [String: Bool] = [:]
    @Published public private(set) var pauseFailures: Set<String> = []
    /// Clients (E3): the list, the open card, and the editor's state.
    @Published public private(set) var clients: Loadable<[ClientSummary]> = .loading
    @Published public private(set) var selectedClient: Int64?
    @Published public private(set) var clientCard: Loadable<ClientCard> = .loading
    /// The open card's party is no longer on this Mac (404 on a live route).
    @Published public private(set) var clientGone = false
    @Published public var clientEditing = false
    /// The open editor's text; nil when the card is not being edited. It is
    /// locked while a save is in flight: `setClientDraft` refuses changes.
    @Published public private(set) var clientDraft: ClientDraft?
    /// Unsaved edits of other clients, by party id: moving away keeps the
    /// draft, coming back reopens the editor with it.
    @Published public private(set) var clientDrafts: [Int64: ClientDraft] = [:]
    @Published public var clientTab: ClientTab = .overview
    @Published public private(set) var clientSaving = false
    @Published public private(set) var clientError: UIKey?
    @Published public private(set) var clientSaved = false
    private var clientLoad = 0
    /// The edit each yes carries, by approval id: the text and the version it
    /// was made on. Only a yes on the open editor puts one here.
    @Published private var pendingEdits: [String: EditVersion] = [:]
    /// The editable text each open editor started from, by approval id.
    private var editBases: [String: String] = [:]
    private var countdownTask: Task<Void, Never>?
    private var pollTask: Task<Void, Never>?
    private var subscriptions: Set<AnyCancellable> = []
    private let clock: () -> Date

    public init(store: Store, client: TeamClient?, defaults: UserDefaults? = nil, clock: @escaping () -> Date = Date.init) {
        self.store = store
        self.defaults = defaults
        rightPanelTab = defaults?.string(forKey: Self.rightPanelTabKey).flatMap(RightPanelTab.init(rawValue:)) ?? .work
        self.client = client
        self.clock = clock
        let source = client
        privateAnswers = PrivateAnswersModel(
            fetch: { try await source?.privateAnswers() ?? [] },
            remove: { id in try await source?.dismissPrivateAnswer(id: id) })
        store.$stopEngaged
            .removeDuplicates()
            .sink { [weak self] engaged in
                guard let self, !self.stopInFlight else { return }
                self.applyStop(engaged)
            }
            .store(in: &subscriptions)
        // Re-render whenever the Store changes: views read both.
        store.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &subscriptions)
        // The ledger is a read, not the socket: loaded once on appear it went
        // stale while the day's runs streamed in as receipts. Refresh it when
        // the daemon (re)connects and whenever a run finishes, so "Since you
        // left" shows the work that happened while the page stayed open.
        store.$connection
            .removeDuplicates()
            .sink { [weak self] connection in
                guard case .online = connection else { return }
                self?.loadLedger()
            }
            .store(in: &subscriptions)
        store.receiptLog.$receipts
            .removeDuplicates()
            .dropFirst()
            .sink { [weak self] _ in self?.loadLedger() }
            .store(in: &subscriptions)
    }

    public var language: Language { store.language }

    // MARK: Lifecycle

    public func start() {
        if store.selectedAgentName == nil {
            store.selectAgent(TeamMember.aux.id)
        }
        store.start()
        refreshDelegations()
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                guard let self, self.delegationsAvailable else { continue }
                self.refreshDelegations()
            }
        }
    }

    // MARK: Navigation

    public var selectedAgent: String? {
        if case .agent(let id) = route { return id }
        return nil
    }

    /// ⌘F: show the sidebar if it was collapsed, then focus its search.
    public func requestSearchFocus() {
        if !sidebarVisible {
            sidebarVisible = true
            sidebarOpenedBySearch = true
        }
        searchFocusPending = true
        searchFocusRequest &+= 1
    }

    /// The search view takes the pending focus once, even when it mounted
    /// after the request (the sidebar was collapsed), never on a plain reopen.
    public func consumeSearchFocus() -> Bool {
        defer { searchFocusPending = false }
        return searchFocusPending
    }

    /// Esc in the search: back to the previous state, only if ⌘F opened the sidebar.
    public func endSearch() {
        if sidebarOpenedBySearch { sidebarVisible = false }
        sidebarOpenedBySearch = false
    }

    public func requestAskFocus() {
        askFocusRequest &+= 1
    }

    /// ⌘K "Ask Aux…": Aux's conversation, its composer focused,
    /// even when that composer appears only after the move.
    public func askAux() { steer(TeamMember.aux.id) }

    /// Work tab "Steer": that agent's conversation, its composer focused, to
    /// tell it more while its task runs. Nothing is sent by the click.
    public func steer(_ agent: String) {
        if conversationPresented || selectedAgent != agent { go(.agent(agent)) }
        askFocusPending = true
        askFocusRequest &+= 1
    }

    /// The composer takes a pending ⌘K once.
    public func consumeAskFocus() -> Bool {
        defer { askFocusPending = false }
        return askFocusPending
    }

    public func requestComposerFocus() {
        composerFocusRequest &+= 1
    }

    public func submitAsk(_ raw: String) {
        let message = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        openConversation(agent: TeamMember.aux.id)
        // A send during a run is dropped by the store: keep the draft then.
        guard !message.isEmpty, !store.isSendingMessage else {
            if message.isEmpty { askDraft = "" }
            return
        }
        askDraft = ""
        store.sendMessage(message)
    }

    /// The one ⌘[ action: leave an open conversation, else return to the chief.
    public func goBack() {
        if conversationPresented { closeConversation() } else { returnToChief() }
    }

    public func escapeAskField() { askDraft = "" }

    public func openConversationFromAgents(_ agent: String) {
        guard route == .agentsAndRules, agent != "notifications" else { return }
        openConversation(agent: agent)
    }

    @discardableResult
    public func openSelectedAgentConversationIfNeeded(_ agent: String) -> Bool {
        guard TeamMember.member(agent) != nil else { return false }
        switch route {
        case .agentsAndRules:
            openConversationFromAgents(agent)
        case .running where workingAgents.contains(agent):
            openConversation(agent: agent)
        default:
            return false
        }
        return conversationPresented && conversationAgent == agent
    }

    public func openConversation(agent: String) {
        present(agent: agent)
        store.selectAgent(agent)
    }

    /// Open a past Aux chat; the Store makes it the current one.
    public func openConversation(session id: Int64) {
        present(agent: TeamMember.aux.id)
        store.selectConversation(id)
    }

    public func newConversation() {
        if !conversationPresented || conversationAgent != TeamMember.aux.id {
            openConversation(agent: TeamMember.aux.id)
        }
        store.startNewChat()
    }

    private func present(agent: String) {
        if !conversationPresented {
            conversationReturnRoute = route
            if case .agent = route { route = .today }
        }
        conversationAgent = agent
        conversationPresented = true
        inspectorOpen = true
    }

    public func closeConversation() {
        let clearAgentSelection = conversationPresented && (route == .agentsAndRules || route == .running)
        conversationPresented = false
        if let route = conversationReturnRoute {
            self.route = route
            if case .agent(let id) = route { store.selectAgent(id) }
        }
        conversationReturnRoute = nil
        if clearAgentSelection { agentSelectionClearRequest += 1 }
    }

    public func go(_ route: Route) {
        conversationPresented = false
        conversationReturnRoute = nil
        if case .agent(let id) = route {
            store.selectAgent(id)
        }
        if route != self.route { returnDelegation = nil }
        self.route = route
    }

    /// "Open in Mail" from a delegation row: the agent's thread at that task.
    public func open(agent: String, fromDelegation delegation: String) {
        go(.agent(agent))
        returnDelegation = delegation
        flash(delegation)
    }

    /// "‹ Aux" or ⌘[: back to the same row in Aux's thread.
    public func returnToChief() {
        let row = returnDelegation
        go(.agent(TeamMember.aux.id))
        if let row {
            expanded.insert(row)
            flash(row)
        }
    }

    private func flash(_ delegation: String) {
        flashDelegation = delegation
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_400_000_000)
            if self?.flashDelegation == delegation { self?.flashDelegation = nil }
        }
    }

    // MARK: Counts (one function, every view)

    public var waitingApprovals: [Approval] {
        TeamPresenter.waiting(store.approvals, snoozed: snoozed)
            .filter { countdowns[$0.id] == nil && !answering.contains($0.id) }
    }

    /// Waiting for you lists every card the daemon holds open (Not now, counting down and Stop-cancelled
    /// ones too); an answered card leaves it. The page header counts exactly these rows.
    public var waitingListApprovals: [Approval] {
        store.approvals.filter { $0.state.isPending }
    }

    /// A row names its card's own phase, never a fixed "waits".
    public func rowStatus(for approval: Approval) -> String {
        let copy = { (key: UIKey) in L10n.ui(key, self.language) }
        switch phase(for: approval) {
        case .open, .editing: return copy(.apWaits)
        case .notNow: return copy(.apNotNow)
        case .sending(let left): return String(format: copy(.apSendingIn), left)
        case .answering, .sent: return language == .fr ? "Réponse envoyée" : "Answer given"
        case .failed: return copy(.apError)
        case .cancelledByStop: return copy(.apCancelledByStop)
        case .declined: return copy(.apDeclined)
        case .expired: return copy(.apExpired)
        }
    }

    public func waitingCount(agent: String? = nil) -> Int {
        guard !stopped else { return agent == nil ? waitingApprovals.count : 0 }
        return waitingApprovals.filter { agent == nil || $0.agent == agent }.count
    }

    public var workingAgents: Set<String> {
        TeamPresenter.workingAgents(agents: store.agents, delegations: delegations, stopped: stopped)
    }

    public func row(for member: TeamMember, now: Date = Date()) -> TeamRowModel {
        let agent = store.agents.first { $0.name == member.id }
        // Activity rows that carry a raw payload are not a line for the owner.
        // The row says the real last line of the conversation; an agent with
        // no message yet keeps its last activity.
        let preview = (store.selectedAgentName == member.id ? ConversationPreview.latest(in: store.conversation) : nil)
            ?? store.previews[member.id]
        let last: (String, Date?)? = preview.map { ($0.line(language), $0.date) } ?? agent.map { agent in
            let readable = LedgerText.what(agent.status, agent: agent.name, language: language)
            return (readable, agent.lastActive.map { Date(timeIntervalSince1970: TimeInterval($0) / 1000) })
        }
        let teamWaiting = TeamMember.domain.reduce(0) { $0 + waitingCount(agent: $1.id) }
        return TeamPresenter.row(
            member: member,
            agent: agent,
            delegations: delegations,
            working: workingAgents,
            waitingCount: waitingCount(agent: member.id),
            teamWaitingCount: teamWaiting,
            stopped: stopped,
            lastActivity: last.map { (text: $0.0, at: $0.1) },
            unread: false,
            now: now,
            language: language
        )
    }

    // MARK: Approval object

    public func card(for approval: Approval) -> ApprovalCard {
        ApprovalCard.make(approval, phase: phase(for: approval))
    }

    /// The v5 draft card's buttons: they call the answers the app already has.
    public func answer(_ action: DraftCard.Action, for approval: Approval) {
        switch action {
        case .send, .sendEdited: sendProposal(approval)
        case .edit: beginEdit(approval)
        case .notNow: notNow(approval)
        case .cancel: cancelEdit(approval)
        case .showDraft: break
        }
    }

    /// A mirror keeps its draft folded; this opens it (or folds it again).
    public func toggleDraft(_ id: String) {
        if unfoldedDrafts.contains(id) {
            unfoldedDrafts.remove(id)
        } else {
            unfoldedDrafts.insert(id)
        }
    }

    /// A next-step link acts inside the app only: it opens a draft, opens a
    /// steps card, or fills the composer. The id it returns is what the thread
    /// scrolls to, if anything.
    public func act(on link: NextStepItem) -> String? {
        switch link.action {
        case .openApproval(let id):
            unfoldedDrafts.insert(id)
            return NextStepItem.draftTarget(id)
        case .openSteps(let id):
            expanded.insert(id)
            return NextStepItem.stepsTarget(id)
        case .fillComposer(let text):
            // The owner's own words stay: a link never overwrites them.
            guard store.composerText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            store.composerText = text
            requestComposerFocus()
            return nil
        }
    }

    /// True when the owner has opened this draft.
    public func isDraftUnfolded(_ id: String) -> Bool { unfoldedDrafts.contains(id) }

    /// Exact proposal text currently shown and, when queued, sent for this approval.
    public func proposal(for approval: Approval) -> ProposalViewModel {
        ProposalViewModel(approval: approval, language: language)
    }

    /// The approval selected in Waiting for you, if it is still actionable.
    public var selectedWaitingApproval: Approval? {
        // ⌘Return sends only what is on screen: the Waiting for you page shows
        // each pending body whole; from any other page the focused item is
        // unseen, so the shortcut does nothing.
        guard !stopped,
              route == .waiting,
              let id = store.focusedApprovalId,
              let approval = store.approvals.first(where: { $0.id == id }),
              approval.state.isPending,
              waitingApprovals.contains(where: { $0.id == id }),
              countdowns[id] == nil,
              !answering.contains(id),
              !failedApprovals.contains(id)
        else { return nil }
        return approval
    }

    public func canSendProposal(_ approval: Approval) -> Bool {
        guard !stopped, store.canAct(approval), countdowns[approval.id] == nil else { return false }
        switch phase(for: approval) {
        // A send Stop cancelled waits for a new Send once Stop is lifted.
        case .open, .editing, .notNow, .cancelledByStop: break
        default: return false
        }
        // Only the open editor's text can block Send: it is the one that goes.
        if editing == approval.id, let body = editDrafts[approval.id],
           body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        return true
    }

    /// Shared action path for the proposal button and the Agents menu.
    public func sendProposal(_ approval: Approval) {
        guard canSendProposal(approval) else { return }
        // The card shows the editor's text only while it is open; any other
        // Send is a yes on the daemon's own text.
        if editing == approval.id {
            sendEdited(approval)
        } else {
            discardEdit(approval.id)
            approve(approval)
        }
    }

    public func phase(for approval: Approval) -> ApprovalPhase {
        if cancelledByStop.contains(approval.id) { return .cancelledByStop }
        if let left = countdowns[approval.id] { return .sending(secondsLeft: left) }
        // The daemon's answer wins over the local "answering" flag.
        switch approval.state {
        case .allowed: return .sent
        case .denied: return .declined
        case .expired, .unknown: return .expired
        case .pending:
            if answering.contains(approval.id) { return .answering }
            if failedApprovals.contains(approval.id) { return .failed }
            if editing == approval.id { return .editing }
            if snoozed.contains(approval.id) { return .notNow }
            return .open
        }
    }

    /// Every approval a thread shows: its own, and for Aux the team's mirror.
    public func approvals(inThreadOf agent: String) -> [Approval] {
        if agent == TeamMember.aux.id {
            return store.approvals
        }
        return store.approvals.filter { $0.agent == agent }
    }

    /// Send: the yes waits `undoSeconds`, then it is given to the daemon.
    public func approve(_ approval: Approval, editedText: String? = nil) {
        guard !stopped, !stopInFlight, approval.state.isPending, countdowns[approval.id] == nil else { return }
        failedApprovals.remove(approval.id)
        cancelledByStop.remove(approval.id)
        snoozed.remove(approval.id)
        // A yes carries exactly one version: this edit, or none.
        let base = editBases[approval.id] ?? card(for: approval).editableText
        pendingEdits[approval.id] = editedText.map { EditVersion(text: $0, base: base) }
        editing = nil
        countdowns[approval.id] = Self.undoSeconds
        runCountdown()
    }

    /// Undo takes the yes back with its edit: the card is the daemon's text
    /// again, and so is what the next Send posts.
    public func undo(_ approval: Approval) {
        countdowns[approval.id] = nil
        discardEdit(approval.id)
    }

    public func notNow(_ approval: Approval) {
        snoozed.insert(approval.id)
        if editing == approval.id {
            editing = nil
            discardEdit(approval.id)
        }
    }

    public func reopen(_ approval: Approval) {
        discardEdit(approval.id)
        snoozed.remove(approval.id)
        cancelledByStop.remove(approval.id)
        failedApprovals.remove(approval.id)
    }

    public func beginEdit(_ approval: Approval) {
        if editDrafts[approval.id] == nil {
            let card = card(for: approval)
            editDrafts[approval.id] = card.editorText
            editBases[approval.id] = card.editableText
        }
        editing = approval.id
    }

    /// Cancel drops the edit: the card and the next Send are the daemon's text.
    public func cancelEdit(_ approval: Approval? = nil) {
        if let id = approval?.id ?? editing { discardEdit(id) }
        editing = nil
    }

    /// The edited body sent back in the same shape as the preview. An edit
    /// made on another version of the draft is refused: nothing is sent.
    public func sendEdited(_ approval: Approval) {
        let card = card(for: approval)
        // The version check is app-side only: the daemon has no compare-and-swap
        // because a pending ask never changes under its id (it is built once in
        // crates/auxd/src/api/approval.rs:962-977 and only resolved after).
        if let base = editBases[approval.id], base != card.editableText {
            refuseStaleEdit(approval)
            return
        }
        let text = editDrafts[approval.id] ?? card.editorText
        approve(approval, editedText: text)
    }

    /// The text a queued or sent yes carries when it is an edit; nil means
    /// the daemon's own text goes.
    public func queuedEdit(for id: String) -> String? { pendingEdits[id]?.text }

    /// What a card shows outside the editor: exactly what a yes posts. A
    /// queued edit is its own text with no daemon fields (the edit carries
    /// them); otherwise the daemon's text and fields. Every surface reads this.
    public func shownDraft(for approval: Approval) -> ShownDraft {
        if let edit = queuedEdit(for: approval.id) { return ShownDraft(text: edit, edited: true) }
        return ShownDraft(text: card(for: approval).displayText, edited: false)
    }

    /// The one line a summary row shows for an approval: the daemon's
    /// headline, or — while a yes waits with an edit — the edited version's
    /// recipient and subject. The row reads the same helper every other
    /// surface reads, so a row can never name the version a card replaced.
    public func rowHeadline(for approval: Approval) -> String {
        let shown = shownDraft(for: approval)
        guard shown.edited else { return daemonHeadline(for: approval) }
        // An edit that names no recipient and no subject changed nothing the
        // headline names: the daemon's own title is still the truth.
        return EditedHeadline.line(shown.text, language: language) ?? daemonHeadline(for: approval)
    }

    /// The daemon's own title for an approval.
    private func daemonHeadline(for approval: Approval) -> String {
        PlainLabel.headline(approval.headline.isEmpty ? approval.action : approval.headline, tool: approval.scopeTool)
    }

    private func discardEdit(_ id: String) {
        editDrafts[id] = nil
        editBases[id] = nil
        pendingEdits[id] = nil
    }

    private func refuseStaleEdit(_ approval: Approval) {
        countdowns[approval.id] = nil
        discardEdit(approval.id)
        if editing == approval.id { editing = nil }
        store.noteApprovalError(approval.id, L10n.t(.draftEditStale, language))
        failedApprovals.insert(approval.id)
    }

    private func runCountdown() {
        guard countdownTask == nil else { return }
        countdownTask = Task { [weak self] in
            while let self, !self.countdowns.isEmpty, !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                self.tick()
            }
            self?.countdownTask = nil
        }
    }

    /// One second of every running countdown; at zero the yes is given.
    public func tick() {
        for (id, left) in countdowns {
            if left <= 1 {
                countdowns[id] = nil
                guard let approval = store.approvals.first(where: { $0.id == id }) else { continue }
                answer(approval)
            } else {
                countdowns[id] = left - 1
            }
        }
    }

    private func answer(_ approval: Approval) {
        // A Stop in flight or in force wins over a countdown that just ended.
        if stopInFlight || stopped {
            discardEdit(approval.id)
            cancelledByStop.insert(approval.id)
            return
        }
        let edit = pendingEdits[approval.id]
        // The yes goes only on the version it was given on.
        if let edit, edit.base != card(for: approval).editableText {
            refuseStaleEdit(approval)
            return
        }
        answering.insert(approval.id)
        if let edit {
            // A skill run's edit goes back as its run, rebuilt from the
            // version the owner edited; the card only ever showed the text.
            store.resolve(approval, decision: .edit, text: RunEdit.posted(edit.text, base: edit.base))
        } else {
            store.resolve(approval, decision: .allowOnce)
        }
        Task { [weak self] in
            // The Store owns the answer and its errors; follow it by id.
            for _ in 0..<40 {
                try? await Task.sleep(nanoseconds: 250_000_000)
                guard let self else { return }
                let current = self.store.approvals.first { $0.id == approval.id }
                if current?.state.isPending == false { break }
                if self.store.approvalErrors[approval.id] != nil {
                    if self.store.refusedEdits.contains(approval.id) {
                        // The daemon refused the edited card: it never took the
                        // ask, so the card stays open and editable with the
                        // owner's text. Nothing was sent.
                        self.reopenRefusedEdit(approval)
                    } else {
                        self.failedApprovals.insert(approval.id)
                    }
                    break
                }
            }
            self?.answering.remove(approval.id)
        }
    }

    /// A refused edited card leaves the card open: the owner's text stays in
    /// the editor, the refused version is not queued any more, and the card
    /// can be answered again. The reason stays on the card.
    private func reopenRefusedEdit(_ approval: Approval) {
        pendingEdits[approval.id] = nil
        failedApprovals.remove(approval.id)
        if editDrafts[approval.id] == nil {
            let card = card(for: approval)
            editDrafts[approval.id] = card.editorText
            editBases[approval.id] = card.editableText
        }
        editing = approval.id
    }

    // MARK: Stop

    public func stopAll() {
        guard let client, !stopInFlight else { return }
        stopInFlight = true
        // Pending sends are cancelled before the daemon is asked: no tick can
        // post while the stop is on its way. A failed stop leaves them
        // cancelled; Reopen brings them back.
        let pending = Array(countdowns.keys)
        for id in pending {
            countdowns[id] = nil
            discardEdit(id)
            cancelledByStop.insert(id)
        }
        // Messages typed while a turn ran are never sent either; they say so.
        store.cancelQueuedSends()
        Task { [weak self] in
            do {
                try await client.stopAll()
                guard let self else { return }
                self.cancelledSends = pending.count
                self.applyStop(true)
            } catch {
                self?.applyStop(self?.store.stopEngaged ?? false)
            }
            self?.stopInFlight = false
        }
    }

    public func resumeAll() {
        guard let client, !stopInFlight else { return }
        stopInFlight = true
        Task { [weak self] in
            do {
                try await client.resumeAll()
                self?.applyStop(false)
            } catch {}
            self?.stopInFlight = false
            self?.refreshDelegations()
        }
    }

    private func applyStop(_ engaged: Bool) {
        stopped = engaged
        if !engaged {
            cancelledSends = 0
        } else {
            for id in countdowns.keys { cancelledByStop.insert(id) }
            countdowns.removeAll()
            store.cancelQueuedSends()
        }
    }

    // MARK: Delegations

    public func delegations(forChief: Bool = true) -> [Delegation] { delegations }

    public func delegations(for agent: String) -> [Delegation] {
        delegations.filter { $0.agent == agent }
    }

    public func refreshDelegations() {
        guard let client else { return }
        Task { [weak self] in
            do {
                let list = try await client.delegations(thread: TeamMember.aux.id)
                self?.delegations = list
                self?.delegationsAvailable = true
            } catch let error as AuxdError where error.isUnavailableRoute {
                self?.delegationsAvailable = false
            } catch {}
        }
    }

    public func stopDelegation(_ delegation: Delegation) {
        guard let client else { return }
        if let index = delegations.firstIndex(where: { $0.id == delegation.id }) {
            delegations[index].state = .stopped
        }
        Task { [weak self] in
            try? await client.stopDelegation(id: delegation.id)
            self?.refreshDelegations()
        }
    }

    public func resumeDelegation(_ delegation: Delegation) {
        guard let client else { return }
        if let index = delegations.firstIndex(where: { $0.id == delegation.id }) {
            delegations[index].state = .working
        }
        Task { [weak self] in
            try? await client.resumeDelegation(id: delegation.id)
            self?.refreshDelegations()
        }
    }

    // MARK: What the model saw

    /// The record behind "What X sent to its brain" for one agent group.
    public func modelSaw(agent: String, group: ThreadGroup) -> ModelSawRecord? {
        // A folded preamble is the same turn's words: the model saw them too.
        let ids = group.entries.flatMap { entry -> [String] in
            if case .message(let message) = entry { return message.preamble.map(\.id) + [message.id] }
            return []
        }
        if let provider = client as? ModelSawProviding {
            return provider.modelSaw(agent: agent, messageIds: ids)
        }
        return ModelSawRecord.from(receipts: store.receiptLog.receipts, agent: agent, at: group.last)
    }

    public func brain(of agent: String) -> String? {
        if let brain = store.agents.first(where: { $0.name == agent })?.brain, !brain.isEmpty { return brain }
        guard case .loaded(let providers) = providers, providers.count == 1 else { return nil }
        let provider = providers[0]
        return provider.model.isEmpty ? provider.name : provider.model
    }

    /// The agent's brain as the owner reads it; `brain(of:)` keeps the raw id.
    public func brainLabel(of agent: String) -> String? {
        brain(of: agent).map(BrainName.display)
    }

    /// The mode the daemon last reported for this agent (MODE-CHIP-TRUTH).
    /// Unknown until the snapshot names one: the chip and footer never guess
    /// Private from absence.
    public func privacyMode(of agent: String) -> PrivacyMode {
        store.agents.first { $0.name == agent }?.privacyMode ?? .unknown
    }

    /// True only when the provider that serves this agent's brain is on this
    /// Mac. The provider list is the only evidence the app has; an unknown,
    /// unmatched or ambiguous provider proves nothing.
    public func brainIsOnThisMac(_ agent: String) -> Bool {
        BrainPlace.isOnThisMac(brain(of: agent), providers: providers.value ?? [])
    }

    // MARK: Reads

    private func load<T: Equatable>(_ work: @escaping () async throws -> T, into keyPath: ReferenceWritableKeyPath<ShellModel, Loadable<T>>) {
        guard client != nil else {
            self[keyPath: keyPath] = .unavailable
            return
        }
        if self[keyPath: keyPath].value == nil { self[keyPath: keyPath] = .loading }
        Task { [weak self] in
            do {
                let value = try await work()
                self?[keyPath: keyPath] = .loaded(value)
            } catch let error as AuxdError where error.isUnavailableRoute {
                self?[keyPath: keyPath] = .unavailable
            } catch {
                self?[keyPath: keyPath] = .failed
            }
        }
    }

    public func loadCoverage() {
        guard let client else { return coverage = .unavailable }
        load({ try await client.coverage().paths }, into: \.coverage)
    }

    /// The Work tab's "Up next": the planned runs only.
    public func loadPlanned() {
        guard let client else { return planned = .unavailable }
        load({ try await client.plannedJobs() }, into: \.planned)
    }

    public func loadLedger() {
        guard let client else { return ledger = .unavailable }
        load({ try await client.ledger(limit: 200) }, into: \.ledger)
        load({ try await client.plannedJobs() }, into: \.planned)
    }

    public func loadToday() {
        guard let client else { return today = .unavailable }
        let day = TodayPresentation.day(clock())
        Task { [weak self] in
            let jobs = (try? await client.plannedJobs()) ?? []
            do {
                let brief = try await client.todayBrief()
                self?.today = .loaded(.make(brief: brief, today: day, jobs: jobs))
            } catch let error as AuxdError where error.isUnavailableRoute {
                // No read route on this auxd yet: the empty state still offers the run.
                self?.today = .loaded(.make(brief: nil, today: day, jobs: jobs))
            } catch {
                self?.today = .failed
            }
        }
    }

    /// "Add as prospect" / "Ignore": on success or a 404 (handled elsewhere)
    /// the row leaves Today; any other error keeps it with one line under it.
    public func resolveProspect(_ prospect: BriefProspect, add: Bool) {
        guard let client, !prospectsBusy.contains(prospect.id) else { return }
        prospectsBusy.insert(prospect.id)
        if prospectFailed == prospect.id { prospectFailed = nil }
        Task { [weak self] in
            let done: Bool
            do {
                _ = try await client.resolveProspect(account: prospect.account, email: prospect.email, add: add)
                done = true
            } catch {
                done = false
            }
            guard let self else { return }
            self.prospectsBusy.remove(prospect.id)
            guard done else { return self.prospectFailed = prospect.id }
            if case .loaded(.brief(var brief)) = self.today {
                brief.prospects.removeAll { $0.id == prospect.id }
                self.today = .loaded(.brief(brief))
            }
        }
    }

    /// "Run the brief now": `POST /v1/brief/run`, then read Today again.
    public func runBriefNow() {
        guard let client, !briefRunning else { return }
        briefRunning = true
        briefRunNote = nil
        Task { [weak self] in
            let note: UIKey
            do {
                note = Self.briefNote(try await client.runBrief().status)
            } catch let error as AuxdError {
                if case .http(409, _) = error { note = .briefRunStopped } else { note = .briefRunFailed }
            } catch {
                note = .briefRunFailed
            }
            self?.briefRunning = false
            self?.briefRunNote = note
            self?.loadToday()
        }
    }

    /// "No brief yet today" is hidden once a run wrote or found today's brief:
    /// the re-read can still answer empty (no `GET` route on an older auxd), and
    /// "No brief yet" under "written" contradicts itself.
    public var showsTodayEmptySentence: Bool { Self.showsEmptySentence(afterRun: briefRunNote) }

    static func showsEmptySentence(afterRun note: UIKey?) -> Bool {
        note != .briefRunWritten && note != .briefRunAlready
    }

    static func briefNote(_ status: String) -> UIKey {
        switch status {
        case "written": return .briefRunWritten
        case "already_today": return .briefRunAlready
        case "skipped_quiet_hours": return .briefRunQuiet
        case "source_unavailable": return .briefRunNoSource
        default: return .briefRunFailed
        }
    }

    public func loadProviders() {
        guard let client else { return providers = .unavailable }
        load({ try await client.providerList() }, into: \.providers)
    }

    public func loadSkills() {
        guard let client else { return skills = .unavailable }
        load({ try await client.skillList() }, into: \.skills)
    }

    public func loadUsage() {
        guard let client else { return usage = .unavailable }
        if usage.value == nil { usage = .loading }
        Task { [weak self] in
            do {
                let day = try await client.usageToday()
                self?.usage = .loaded(day)
                self?.store.applyUsage(day)
            } catch let error as AuxdError where error.isUnavailableRoute {
                self?.usage = .unavailable
            } catch {
                self?.usage = .failed
            }
        }
    }

    public func loadProfile(_ agent: String) {
        guard let client else { return }
        loadProviders()
        if grants[agent]?.value == nil { grants[agent] = .loading }
        if memory[agent]?.value == nil { memory[agent] = .loading }
        Task { [weak self] in
            do {
                self?.grants[agent] = .loaded(try await client.grants(agent: agent))
            } catch let error as AuxdError where error.isUnavailableRoute {
                self?.grants[agent] = .unavailable
            } catch {
                self?.grants[agent] = .failed
            }
            do {
                self?.memory[agent] = .loaded(try await client.memory(agent: agent))
            } catch let error as AuxdError where error.isUnavailableRoute {
                self?.memory[agent] = .unavailable
            } catch {
                self?.memory[agent] = .failed
            }
        }
        loadSkills()
    }

    public func forget(_ item: MemoryItem, agent: String) {
        guard let client else { return }
        if case .loaded(var items) = memory[agent] {
            items.removeAll { $0.id == item.id }
            memory[agent] = .loaded(items)
        }
        Task { [weak self] in
            do { try await client.forget(agent: agent, item: item.id) } catch { self?.loadProfile(agent) }
        }
    }

    public func setPaused(_ agent: String, _ paused: Bool) {
        guard let client else { return }
        let previousState = isPaused(agent)
        pauseFailures.remove(agent)
        pauseOverrides[agent] = paused
        Task { [weak self] in
            do {
                try await client.setAgentPaused(agent, paused: paused)
            } catch {
                guard let self else { return }
                self.pauseOverrides[agent] = previousState
                self.pauseFailures.insert(agent)
            }
        }
    }

    public func isPaused(_ agent: String) -> Bool {
        if let override = pauseOverrides[agent] { return override }
        return store.agents.first { $0.id == agent }?.state == .paused
    }

    // MARK: Clients (E3)

    /// Read the list; the first client opens when none is open yet.
    public func loadClients() {
        guard let client else { return clients = .unavailable }
        if clients.value == nil { clients = .loading }
        Task { [weak self] in
            do {
                let list = try await client.clients()
                guard let self else { return }
                self.clients = .loaded(list)
                if let open = self.selectedClient, list.contains(where: { $0.id == open }) { return }
                if let first = list.first {
                    self.selectClient(first.id)
                } else {
                    self.selectedClient = nil
                }
            } catch let error as AuxdError where error.isUnavailableRoute {
                self?.clients = .unavailable
            } catch {
                self?.clients = .failed
            }
        }
    }

    /// One import sheet for one file. The importer is nil when the
    /// daemon has no contacts route, and the sheet says so.
    public func clientImport(path: String, language: Language) -> ClientImportModel {
        ClientImportModel(path: path, importer: client as? ContactsImportClient, language: language) { [weak self] in
            self?.loadClients()
        }
    }

    public func selectClient(_ id: Int64) {
        if selectedClient != id {
            if let open = selectedClient, clientEditing, let draft = clientDraft,
               clientCard.value.map({ ClientDraft($0.party) != draft }) ?? true {
                clientDrafts[open] = draft
            }
            clientDraft = clientDrafts.removeValue(forKey: id)
            clientEditing = clientDraft != nil
            clientTab = .overview
            clientError = nil
            clientSaved = false
            clientCard = .loading
        }
        selectedClient = id
        loadClientCard()
    }

    public func loadClientCard() {
        guard let client, let id = selectedClient else { return }
        clientLoad += 1
        let ticket = clientLoad
        clientGone = false
        Task { [weak self] in
            do {
                let card = try await client.client(id: id)
                guard let self, self.clientLoad == ticket else { return }
                self.clientCard = .loaded(card)
            } catch {
                guard let self, self.clientLoad == ticket else { return }
                if case .http(404, _) = error as? AuxdError, self.clients.value != nil {
                    self.clientGone = true
                }
                self.clientCard = .failed
            }
        }
    }

    public func beginClientEdit() {
        guard let party = clientCard.value?.party else { return }
        clientError = nil
        clientSaved = false
        clientDraft = ClientDraft(party)
        clientEditing = true
    }

    /// One editor field changed. Ignored while the save is in flight, so
    /// nothing typed then is dropped when the save closes the editor.
    public func setClientDraft(_ keyPath: WritableKeyPath<ClientDraft, String>, _ value: String) {
        guard !clientSaving, clientDraft != nil else { return }
        clientDraft?[keyPath: keyPath] = value
    }

    public func cancelClientEdit() {
        clientEditing = false
        clientDraft = nil
        clientError = nil
    }

    /// Save the open editor (the header's Save, ⌘S).
    @discardableResult
    public func saveClientDraft() async -> Bool {
        guard let draft = clientDraft else { return false }
        return await saveClient(draft.edit)
    }

    /// Save the editor. The daemon writes the party and refreshes the names
    /// the next brain call replaces; the answer is the new card.
    @discardableResult
    public func saveClient(_ edit: ClientEdit) async -> Bool {
        guard let client, let id = selectedClient, !clientSaving else { return false }
        guard edit.isValid else {
            clientError = .clientInvalidName
            return false
        }
        clientSaving = true
        clientError = nil
        clientSaved = false
        defer { clientSaving = false }
        do {
            let card = try await client.updateClient(id: id, edit)
            loadClients()
            // The owner moved to another client mid-save: the kept draft is
            // the text just written, and the open card is someone else's.
            guard selectedClient == id else {
                clientDrafts[id] = nil
                return true
            }
            clientCard = .loaded(card)
            clientEditing = false
            clientDraft = nil
            clientSaved = true
            return true
        } catch {
            guard selectedClient == id else { return false }
            clientError = ClientText.saveError(error)
            if clientError == .clientGone { clientGone = true }
            return false
        }
    }

    public func forgetClientMemory(_ item: ClientMemory) {
        guard let client, let id = selectedClient, case .loaded(var card) = clientCard else { return }
        let before = card
        card.memory.removeAll { $0.id == item.id }
        clientCard = .loaded(card)
        clientError = nil
        Task { [weak self] in
            do {
                try await client.forgetClientMemory(client: id, item: item.id)
            } catch {
                guard let self, self.selectedClient == id else { return }
                self.clientCard = .loaded(before)
                self.clientError = .clientForgetFailed
            }
        }
    }

    /// `/client` from the card: the Clients thread, asked for a brief. When
    /// the thread cannot send yet, the command waits in its composer.
    public func briefClient() {
        guard let party = clientCard.value?.party else { return }
        let command = ClientText.briefCommand(party)
        go(.agent(TeamMember.clients.id))
        if store.selectedAgent != nil, !stopped {
            store.sendMessage(command)
        } else {
            store.composerText = command
        }
    }

    // MARK: Providers

    /// Add a provider from Settings. The key travels only in this request
    /// and is never kept by the model.
    public func addProvider(kind: String, name: String, address: String, model: String, key: String?) async -> Bool {
        guard let client else { return false }
        providerError = nil
        let trimmedKey = key?.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            try await client.addProvider(CreateProviderRequest(
                name: name, kind: kind, baseURL: address, model: model,
                apiKey: trimmedKey?.isEmpty == false ? trimmedKey : nil
            ))
            loadProviders()
            return true
        } catch {
            providerError = L10n.ui(.providerSaveFailed, language)
            return false
        }
    }

    public func testProvider(_ id: String) {
        guard let client else { return }
        Task { [weak self] in
            if let result = try? await client.testProvider(id: id) {
                self?.providerTests[id] = result
            }
        }
    }

    /// True once at least one provider exists (the composer's "no brain" note).
    public var hasBrain: Bool {
        if case .loaded(let list) = providers { return !list.isEmpty }
        return !store.setup.firstRun
    }
}

/// The Clients import sheet's state: a dry run first, then the
/// owner's yes. It holds the file's path only for its two calls and never shows
/// it, nor any contact value; the answer carries counts and column names.
@MainActor
public final class ClientImportModel: ObservableObject, Identifiable {
    public enum Phase: Equatable {
        /// The dry run is in flight.
        case reading
        /// The dry run answered: the owner decides.
        case previewed(ContactsImportAnswer)
        /// The real import is in flight.
        case importing(ContactsImportAnswer)
        /// The import went through; the client list has been reloaded.
        case imported(ContactsImportAnswer)
        /// The dry run was refused or could not be sent; `message` says why.
        case failed
    }

    public let id = UUID()
    @Published public private(set) var phase: Phase = .reading
    /// The daemon's sentence for the last refusal, or the plain copy. Nil when none.
    @Published public private(set) var message: String?
    /// The party kind every row becomes. Clients by default.
    @Published public var tag: ContactsImportTag = .client
    /// The country the owner types for national-format phone numbers.
    @Published public var country = ""

    private let path: String
    private let importer: ContactsImportClient?
    private let language: Language
    private let reload: @MainActor () -> Void

    public init(path: String, importer: ContactsImportClient?, language: Language, reload: @escaping @MainActor () -> Void) {
        self.path = path
        self.importer = importer
        self.language = language
        self.reload = reload
    }

    /// The country code the import will use, when one is typed and valid.
    public var countryCode: String? { ContactsImportText.countryCode(country) }

    /// The import button: a preview with contacts in it, and a country when phone
    /// numbers in the file need one.
    public var canImport: Bool {
        guard case .previewed(let answer) = phase, answer.contacts > 0 else { return false }
        return answer.skipped.phoneNeedsCountry == 0 || countryCode != nil
    }

    /// The dry run. Starts on open; nothing is written.
    public func preview() {
        guard let importer else { return unavailable() }
        phase = .reading
        message = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                let answer = try await importer.importContacts(path: self.path, dryRun: true, tag: self.tag.wire, country: nil)
                self.phase = .previewed(answer)
            } catch {
                self.phase = .failed
                self.message = ContactsImportText.failure(error, self.language)
            }
        }
    }

    /// The owner's yes: the real import with the chosen tag and country. On
    /// success the client list reloads; on a refusal the preview stays, with the sentence.
    public func confirm() {
        guard case .previewed(let answer) = phase, canImport, let importer else { return }
        phase = .importing(answer)
        message = nil
        let code = countryCode
        Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await importer.importContacts(path: self.path, dryRun: false, tag: self.tag.wire, country: code)
                self.phase = .imported(result)
                self.reload()
            } catch {
                self.phase = .previewed(answer)
                self.message = ContactsImportText.failure(error, self.language)
            }
        }
    }

    private func unavailable() {
        phase = .failed
        message = L10n.t(.importUnavailable, language)
    }
}

/// The right panel's tabs (v5): what is running, who is on the team, what left.
public enum RightPanelTab: String, CaseIterable, Equatable {
    case work, team, privacy
}

/// The text a card shows outside the editor: what a yes posts.
public struct ShownDraft: Equatable {
    public let text: String
    /// True when the text is the owner's queued edit.
    public let edited: Bool
}

/// One edit as a yes carries it: the owner's text and the editable text it
/// was made on.
struct EditVersion: Equatable {
    let text: String
    let base: String
}

/// The line a summary row shows for an edited version: the recipient and the
/// subject of the text a yes will post.
///
/// The owner's own text is the tool arguments as JSON — the daemon refuses
/// anything else (`crates/auxd/src/api/routes.rs:1632`) — so the fields are
/// read from there. A plain mail is asked with its arguments flat; a skill's
/// run keeps its mail inside its calls, under `real` — the shape the daemon
/// sends (`crates/auxd/src/api/approval_preview.rs:492`). A mail draft's own
/// header lines are read too.
enum EditedHeadline {
    /// The row's line, or nil when the edit names no recipient and no subject.
    static func line(_ text: String, language: Language) -> String? {
        let fields = fields(in: text)
        var parts: [String] = []
        if let to = fields.to { parts.append(L10n.ui(.apRowTo, language) + to) }
        if let subject = fields.subject { parts.append(L10n.ui(.apRowSubject, language) + subject) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private static func fields(in text: String) -> (to: String?, subject: String?) {
        if let data = text.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data),
           let arguments = object as? [String: Any] {
            let found = mailFields(in: arguments)
            if found.to != nil || found.subject != nil { return found }
        }
        // A mail draft: "To: …" and "Subject: …" header lines.
        guard let draft = MailDraft.parse(text) else { return (nil, nil) }
        return (clean(draft.to), clean(draft.subject))
    }

    /// The mail fields of one set of arguments, or of the mail inside a
    /// skill's calls.
    private static func mailFields(in arguments: [String: Any]) -> (to: String?, subject: String?) {
        // A skill's run (`calls`) is read only through its calls: the daemon's card for a
        // `skill__` tool ignores top-level fields, so a top-level `to` there never leaves.
        guard let calls = arguments["calls"] as? [Any] else {
            let to = recipient(arguments["to"])
            let subject = clean(arguments["subject"] as? String)
            return (to, subject)
        }
        for call in calls {
            guard let call = call as? [String: Any] else { continue }
            // A skill's run sends each call's arguments under `real`, and the
            // daemon reads only that one: the card it builds, and the one it
            // will send, come from it (`crates/auxd/src/api/approval_preview.rs:492`).
            // A call may also carry an `arguments` the daemon ignores, so the
            // row must not read it: it would name a recipient that never
            // leaves the Mac. A call without `real` names nothing the row can
            // be sure of: the row keeps the daemon's headline.
            guard let real = call["real"] as? [String: Any] else { continue }
            let found = mailFields(in: real)
            if found.to != nil || found.subject != nil { return found }
        }
        return (nil, nil)
    }

    /// One recipient or a list of them.
    private static func recipient(_ value: Any?) -> String? {
        if let text = value as? String { return clean(text) }
        guard let list = value as? [Any] else { return nil }
        let names = list.compactMap { item -> String? in
            if let text = item as? String { return clean(text) }
            guard let fields = item as? [String: Any] else { return nil }
            for key in ["email", "address"] {
                if let text = fields[key] as? String, let value = clean(text) { return value }
            }
            return nil
        }
        return names.isEmpty ? nil : names.joined(separator: ", ")
    }

    private static func clean(_ text: String?) -> String? {
        guard let text else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
