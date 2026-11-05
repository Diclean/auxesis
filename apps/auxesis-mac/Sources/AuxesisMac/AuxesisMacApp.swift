// Auxesis for macOS — the E2 shell over the auxd local API.
// SwiftPM executable (no Xcode): a bare binary that becomes a regular app.
import AppKit
import AuxesisKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // Before any window exists, so the first window is a real app window.
        // An offscreen snapshot run (sandbox only) stays out of the Dock.
        NSApp.setActivationPolicy(AppEnvironment.snapshotDirectory == nil ? .regular : .accessory)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // A background instance (a test run, `open -g -j` from a deploy) opens
        // its window without taking the focus away from the owner.
        let background = LaunchPolicy.launchedInBackground(
            isHidden: NSApp.isHidden, isActive: NSApp.isActive, inBundle: Bundle.main.bundleURL.pathExtension == "app")
        if LaunchPolicy.shouldActivateAtLaunch(inBackground: background) {
            NSApp.activate(ignoringOtherApps: true)
        }
        print("AUXESIS_MAC_READY")
        if let directory = AppEnvironment.snapshotDirectory {
            if ProcessInfo.processInfo.environment["AUXESIS_MAC_MASCOTS"] == "1" {
                SnapshotRunner.runMascots(into: directory)
            } else if ProcessInfo.processInfo.environment["AUXESIS_MAC_HERO"] == "1" {
                SnapshotRunner.runHero(into: directory)
            } else if ProcessInfo.processInfo.environment["AUXESIS_MAC_LIVE"] == "docs" {
                SnapshotRunner.runDocsLive(into: directory)
            } else if ProcessInfo.processInfo.environment["AUXESIS_MAC_LIVE"] == "clients" {
                SnapshotRunner.runClientsLive(into: directory)
            } else {
                SnapshotRunner.run(into: directory)
            }
        }
        // H4: the opt-in daily update check. Default OFF, and never in a
        // sandbox or snapshot run.
        if !AppEnvironment.sandbox, UpdatePreferences().shouldCheckDaily() {
            CheckForUpdates.run(silent: true)
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            if let main = sender.windows.first(where: { $0.canBecomeMain }) {
                AppActivation.bringToFront(main)
            } else {
                MainWindowOpener.open?()
            }
        } else if LaunchPolicy.shouldActivate() {
            NSApp.activate(ignoringOtherApps: true)
        }
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Closing the window is not quitting: Auxesis stays in the menu bar.
        AppLifecycle.shouldTerminateAfterLastWindowClosed()
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Quit stops only the service the app started itself.
        ServiceSupervisor.stopCurrent()
    }
}

/// Only the SwiftUI scene can recreate a closed window; it publishes how.
enum MainWindowOpener {
    static var open: (() -> Void)?
}

/// Whether a main window exists. Menu commands and the menu-bar extra outlive
/// the window (closing it keeps the app running), so the Go menu disables
/// itself rather than pretending it can switch a window that is not there.
final class MainWindowPresence: ObservableObject {
    @Published private(set) var hasMainWindow = false
    /// What covers the window, for the greyed proposal items; their actions
    /// read AppKit again when they run.
    @Published private(set) var cover = MainWindowCover(noWindowOnScreen: true)
    private let center: NotificationCenter
    private var observers: [NSObjectProtocol] = []

    init(center: NotificationCenter = .default) {
        self.center = center
        for name in [
            NSWindow.didBecomeMainNotification,
            NSWindow.didBecomeKeyNotification,
            NSWindow.didResignMainNotification,
            NSWindow.willCloseNotification,
            NSWindow.didMiniaturizeNotification,
            NSWindow.didDeminiaturizeNotification,
            // A sheet, an alert or a dialog opens or closes over a window.
            NSWindow.willBeginSheetNotification,
            NSWindow.didEndSheetNotification,
        ] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                // willClose arrives while the window still exists; one main
                // turn later the window list tells the truth either way.
                DispatchQueue.main.async { self?.refresh() }
            })
        }
        refresh()
    }

    deinit {
        for observer in observers { center.removeObserver(observer) }
    }

    func refresh() {
        // The same predicate `applicationShouldHandleReopen` and the menu-bar
        // "Open" use: a minimized window still exists and still counts.
        hasMainWindow = (NSApp?.windows ?? []).contains { $0.canBecomeMain }
        cover = .current
    }
}

extension MainWindowCover {
    /// What AppKit shows over the main window now: the `ProposalMenuGate` input.
    static var current: MainWindowCover {
        guard let app = NSApp else { return MainWindowCover(noWindowOnScreen: true) }
        let windows = app.windows
        return MainWindowCover(
            // The window `MainWindowPresence` counts, on screen.
            noWindowOnScreen: !windows.contains { $0.canBecomeMain && $0.isVisible && !$0.isMiniaturized },
            // Every window, not only `mainWindow`: an app that is not frontmost
            // has no main window, yet its sheet is still up.
            sheetAttached: app.mainWindow?.attachedSheet != nil || windows.contains { $0.attachedSheet != nil },
            keyWindowIsSheet: app.keyWindow?.sheetParent != nil,
            modalSession: app.modalWindow != nil
        )
    }
}

/// Launch environment. Fixture data and offscreen snapshots are honoured only
/// in a sandbox run (`AUXESIS_SANDBOX=1`), never against a real home.
enum AppEnvironment {
    static var sandbox: Bool { ProcessInfo.processInfo.environment["AUXESIS_SANDBOX"] == "1" }
    /// The real EventKit only outside a sandbox run (`AUXESIS_SANDBOX=1` or a
    /// HOME that is not the OS user's home): the resolver's shared predicate.
    @MainActor static func eventKit() -> AppleEventKitProviding {
        EndpointResolver.isSandboxed() ? SandboxedAppleEventKit() : SystemAppleEventKit()
    }

    static var fixture: FixtureDaemon.Scenario? {
        guard sandbox, let raw = ProcessInfo.processInfo.environment["AUXESIS_MAC_FIXTURE"] else { return nil }
        return FixtureDaemon.Scenario(rawValue: raw)
    }

    static var snapshotDirectory: URL? {
        guard sandbox, let raw = ProcessInfo.processInfo.environment["AUXESIS_MAC_SNAPSHOT"], !raw.isEmpty else { return nil }
        return URL(fileURLWithPath: raw, isDirectory: true)
    }

    @MainActor
    static func makeShell(fixture: FixtureDaemon.Scenario? = AppEnvironment.fixture) -> ShellModel {
        makeShellAndWorker(fixture: fixture).shell
    }

    /// The E2 shell plus the Mac extraction bridge (C2c), built from the same
    /// client so the worker is created once at app start. Fixture runs get no
    /// worker: they never touch a real daemon.
    @MainActor
    static func makeShellAndWorker(fixture: FixtureDaemon.Scenario? = AppEnvironment.fixture)
        -> (shell: ShellModel, docsWorker: ExtractionWorker?)
    {
        if let fixture {
            let daemon = FixtureDaemon(scenario: fixture)
            let store = Store(transport: daemon, language: .en)
            let shell = ShellModel(store: store, client: daemon)
            shell.calendar = calendarPage(store: store, kit: FixtureEventKit(granted: fixture != .empty), status: daemon, login: SandboxedLoginItem())
            shell.memoryPage = MemoryPageModel(client: daemon)
            return (shell, nil)
        }
        let endpoint = EndpointResolver.resolve(
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            realHomeDirectory: EndpointResolver.osHomeDirectory()
        )
        let client = AuxdClient(endpoint: endpoint)
        let userHome = EndpointResolver.osHomeDirectory() ?? FileManager.default.homeDirectoryForCurrentUser
        let service = ServiceSupervisor(bundleURL: Bundle.main.bundleURL, home: endpoint.home, userHome: userHome)
        // English only for now; French slots fall back.
        let store = Store(transport: client, language: .en, defaults: .standard, endpoint: endpoint, service: service)
        // On by default (no settings flag exists yet). `start()` itself refuses
        // a non-loopback endpoint, so a hostile resolver can never point the
        // worker off-box.
        let docsWorker = ExtractionWorker(client: client, baseURL: endpoint.baseURL)
        let shell = ShellModel(store: store, client: client, defaults: .standard)
        // A sandbox run never registers a login item on this Mac.
        let login: LoginItemControlling = EndpointResolver.isSandboxed() ? SandboxedLoginItem() : SystemLoginItem()
        shell.calendar = calendarPage(store: store, kit: eventKit(), status: client, login: login)
        shell.documents = DocumentsPageModel(client: client)
        shell.memoryPage = MemoryPageModel(client: client)
        return (shell, docsWorker)
    }

    /// Keeps the calendar snapshot fresh. Reads only when Calendar access is
    /// already granted; the permission prompt stays in Settings.
    @MainActor
    private static func calendarPage(
        store: Store, kit: AppleEventKitProviding, status: CalendarStatusClient, login: LoginItemControlling
    ) -> CalendarPageModel {
        let refresher = CalendarAutoRefresher(
            kit: kit,
            isReady: { store.connection.isOnline },
            publish: { try await store.publishAppleEventKit($0) })
        return CalendarPageModel(refresher: refresher, status: { try await status.calendarStatus() }, login: login)
    }
}

@main
struct AuxesisMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var shell: ShellModel
    /// Drives the Go menu's disabled state when the main window is closed.
    @StateObject private var windowPresence = MainWindowPresence()
    /// The Mac extraction bridge (C2c): claims queued documents over the
    /// loopback API and posts their text back. Created once at app start.
    @State private var docsWorker: ExtractionWorker?
    @Environment(\.openWindow) private var openWindow

    static let mainWindowID = "main"

    init() {
        let (shellModel, worker) = AppEnvironment.makeShellAndWorker()
        _shell = StateObject(wrappedValue: shellModel)
        _docsWorker = State(initialValue: worker)
        // CLOSURE-4: the extractor runs for the app's life, not the window's.
        // A scanned receipt must be read while Auxesis sits in the menu bar,
        // with no window ever opened; tying the worker to the window's
        // `.task` left every scan `[unread]` until the owner opened it.
        worker?.start()
    }

    var body: some Scene {
        Window(L10n.ui(.appName, .en), id: Self.mainWindowID) {
            ShellView()
                .environmentObject(shell)
                .environment(\.language, shell.language)
                .themed()
                .onAppear {
                    MainWindowOpener.open = { openMainWindow() }
                    windowPresence.refresh()
                    shell.start()
                    startCalendarLoop()
                }
                .onDisappear { windowPresence.refresh() }
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1440, height: 900)
        .commands {
            TeamCommands(shell: shell, windows: windowPresence)
            UpdateCommands(shell: shell)
        }

        MenuBarExtra {
            MenuBarPanel(onOpen: openMainWindow)
                .environmentObject(shell)
                .environment(\.language, shell.language)
                .themed()
        } label: {
            // The menu bar lives with no window too (login item), so the
            // calendar loop starts from here as well.
            MenuBarLabel(shell: shell)
                .onAppear { startCalendarLoop() }
        }
        .menuBarExtraStyle(.window)
    }

    /// The calendar refresh loop runs for the app's life, window or not.
    private func startCalendarLoop() {
        guard AppEnvironment.fixture == nil else { return }
        shell.calendar?.start()
    }

    private func openMainWindow() {
        if LaunchPolicy.shouldActivate() {
            NSApp.activate(ignoringOtherApps: true)
        }
        if let main = NSApp.windows.first(where: { $0.canBecomeMain }) {
            AppActivation.bringToFront(main)
        } else {
            openWindow(id: Self.mainWindowID)
        }
    }
}

/// The app's own commands. Availability comes from the same tested policy as AuxesisKit.
struct TeamCommands: Commands {
    @ObservedObject var shell: ShellModel
    @ObservedObject var windows: MainWindowPresence

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button(L10n.ui(.newConversation, shell.language)) { shell.newConversation() }
                .menuShortcut(.newConversation)
                .accessibilityLabel(L10n.ui(.newConversation, shell.language))
                .accessibilityIdentifier("menu-new-conversation")
        }
        CommandGroup(replacing: .appSettings) {
            Button(L10n.ui(.settings, shell.language) + "…") { shell.go(.agentsAndRules) }
                .menuShortcut(.settings)
                .accessibilityLabel(L10n.ui(.settings, shell.language) + "…").accessibilityIdentifier("menu-settings")
        }
        CommandGroup(replacing: .appTermination) {
            Button(shell.language == .fr ? "Quitter Auxesis (les agents continuent)" : "Quit Auxesis (agents keep running)") {
                NSApp.terminate(nil)
            }
            .menuShortcut(.quit)
            .accessibilityLabel(shell.language == .fr ? "Quitter Auxesis (les agents continuent)" : "Quit Auxesis (agents keep running)").accessibilityIdentifier("menu-quit")
        }
        CommandMenu(L10n.ui(.go, shell.language)) {
            // Rebuilt whenever the store's agents change (the shell republishes them).
            let agents = shell.store.agents
            let loading = GoMenu.loading(agents: agents)
            ForEach(GoMenu.entries(agents: agents)) { entry in
                switch entry {
                case .item(let item):
                    goButton(item, loading: loading)
                case .addAgent:
                    Button(L10n.ui(.addAgentMenu, shell.language)) { shell.beginAddAgent() }
                        .disabled(loading || !windows.hasMainWindow || !shell.canAddAgents || shell.addingAgent != nil)
                        .accessibilityLabel(L10n.ui(.addAgentMenu, shell.language))
                        .accessibilityIdentifier("menu-go-add-agent")
                case .separator:
                    Divider()
                }
            }
        }
        CommandGroup(replacing: .sidebar) {
            Button(shell.sidebarVisible ? (shell.language == .fr ? "Masquer la barre latérale" : "Hide Sidebar") : (shell.language == .fr ? "Afficher la barre latérale" : "Show Sidebar")) {
                shell.sidebarVisible.toggle()
            }
            .menuShortcut(.toggleSidebar)
            .accessibilityLabel(shell.sidebarVisible ? (shell.language == .fr ? "Masquer la barre latérale" : "Hide Sidebar") : (shell.language == .fr ? "Afficher la barre latérale" : "Show Sidebar")).accessibilityIdentifier("menu-toggle-sidebar")
        }
        CommandMenu(L10n.ui(.agents, shell.language)) {
            Button(shell.language == .fr ? "Demander à Aux…" : "Ask Aux…") { shell.askAux() }
                .menuShortcut(.askAux)
                .accessibilityLabel(shell.language == .fr ? "Demander à Aux…" : "Ask Aux…").accessibilityIdentifier("menu-ask-aux")
            // Send, Edit and Not now pass the one gate: greyed while the window
            // is covered, and asked again when they run.
            let cover = windows.cover
            let textFocused = AppTextFocus.isFocused
            Button(shell.language == .fr ? "Envoyer la proposition" : "Send proposal") { runProposal(.send) }
                .menuShortcut(.sendProposal)
                .disabled(!proposalEnabled(.send, cover: cover, textFocused: textFocused))
                .accessibilityLabel(shell.language == .fr ? "Envoyer la proposition" : "Send proposal").accessibilityIdentifier("menu-send-proposal")
            Button(shell.language == .fr ? "Modifier la proposition" : "Edit proposal") { runProposal(.edit) }
                .disabled(!proposalEnabled(.edit, cover: cover, textFocused: textFocused))
                .accessibilityLabel(shell.language == .fr ? "Modifier la proposition" : "Edit proposal").accessibilityIdentifier("menu-edit-proposal")
            Button(Copy(language: shell.language)(.apNotNow)) { runProposal(.notNow) }
                .menuShortcut(.notNow)
                .disabled(!proposalEnabled(.notNow, cover: cover, textFocused: textFocused))
                .accessibilityLabel(Copy(language: shell.language)(.apNotNow)).accessibilityIdentifier("menu-not-now")
            Divider()
            Button(L10n.ui(.panelToggle, shell.language)) { shell.toggleRightPanel() }
                .menuShortcut(.togglePanel)
                .accessibilityLabel(L10n.ui(.panelToggle, shell.language)).accessibilityIdentifier("menu-profile")
            Button(L10n.ui(.back, shell.language)) { shell.goBack() }
                .menuShortcut(.back)
                .disabled(!shell.conversationPresented && shell.returnDelegation == nil)
                .accessibilityLabel(L10n.ui(.back, shell.language)).accessibilityIdentifier("menu-back")
            Divider()
            if shell.stopped {
                Button(L10n.ui(.resume, shell.language)) { shell.resumeAll() }
                    .menuShortcut(.stopAll)
                    .accessibilityLabel(L10n.ui(.resume, shell.language)).accessibilityIdentifier("menu-resume")
            } else {
                Button(L10n.ui(.stopAll, shell.language)) { shell.stopAll() }
                    .menuShortcut(.stopAll)
                    .accessibilityLabel(L10n.ui(.stopAll, shell.language)).accessibilityIdentifier("menu-stop-all")
            }
        }
        CommandGroup(after: .textEditing) {
            Button(shell.language == .fr ? "Rechercher" : "Find") { shell.requestSearchFocus() }
                .menuShortcut(.find)
                .accessibilityLabel(shell.language == .fr ? "Rechercher" : "Find").accessibilityIdentifier("menu-find")
        }
        CommandGroup(after: .help) {
            Button(shell.language == .fr ? "Raccourcis clavier" : "Keyboard Shortcuts…") {
                shell.shortcutHelpOpen = true
            }
            .accessibilityLabel(shell.language == .fr ? "Raccourcis clavier" : "Keyboard Shortcuts…").accessibilityIdentifier("menu-keyboard-shortcuts")
        }
    }

    /// A proposal item is on when the gate, as the window looked when the menu
    /// drew, hands out an approval.
    @MainActor
    private func proposalEnabled(_ action: ProposalMenuGate.Action, cover: MainWindowCover, textFocused: Bool) -> Bool {
        ProposalMenuGate.target(for: action, in: shell, cover: cover, textFieldFocused: textFocused) != nil
    }

    /// Every proposal item's action: the gate again, on AppKit as it is now,
    /// so a sheet that opened after the menu drew leaves the item inert.
    @MainActor
    private func runProposal(_ action: ProposalMenuGate.Action) {
        ProposalMenuGate.perform(action, in: shell, cover: .current, textFieldFocused: AppTextFocus.isFocused)
    }

    /// One Go item: the agents that exist get ⌘1…; a Records page has none.
    /// Every item is disabled while the main window is closed, and an agent
    /// item while the agents load.
    @ViewBuilder
    private func goButton(_ item: GoMenuItem, loading: Bool) -> some View {
        let title = GoMenu.title(for: item, language: shell.language)
        let isAgent: Bool = { if case .agent = item.route { return true } else { return false } }()
        let button = Button(title) {
            GoMenu.select(item, hasMainWindow: windows.hasMainWindow, in: shell)
        }
        .disabled(!windows.hasMainWindow || (isAgent && loading))
        .accessibilityLabel(title)
        .accessibilityIdentifier("menu-go-\(item.id)")
        if let binding = item.binding {
            button.menuShortcut(binding)
        } else {
            button
        }
    }
}

/// The app's only bridge from the shortcut tables to SwiftUI: the menu bar
/// reads `MenuShortcutTable`, views read `ViewShortcutTable`. Every
/// `.keyboardShortcut` call lives here, so a chord cannot miss the collision
/// tests.
private extension MenuShortcutModifiers {
    var eventModifiers: EventModifiers {
        var modifiers: EventModifiers = []
        if contains(.control) { modifiers.formUnion(.control) }
        if contains(.option) { modifiers.formUnion(.option) }
        if contains(.shift) { modifiers.formUnion(.shift) }
        if contains(.command) { modifiers.formUnion(.command) }
        return modifiers
    }
}

extension View {
    /// Bind the chord the one table gives this action.
    func menuShortcut(_ action: MenuAction) -> some View {
        menuShortcut(MenuShortcutTable.binding(for: action))
    }

    /// Bind one table row (the Go menu picks its agent digits at runtime).
    func menuShortcut(_ binding: MenuShortcutBinding) -> some View {
        keyboardShortcut(KeyEquivalent(binding.key), modifiers: binding.modifiers.eventModifiers)
    }

    /// Bind one in-view table row. Return and Escape keep SwiftUI's symbolic
    /// sheet cases so the sheet behaves the standard macOS way.
    @ViewBuilder
    func viewShortcut(_ action: ViewAction) -> some View {
        switch ViewShortcutTable.binding(for: action).key {
        case .some(.character(let key, let modifiers)):
            keyboardShortcut(KeyEquivalent(key), modifiers: modifiers.eventModifiers)
        case .some(.cancel):
            keyboardShortcut(.cancelAction)
        case .some(.defaultAction):
            keyboardShortcut(.defaultAction)
        case .none:
            self
        }
    }
}

enum AppTextFocus {
    static var isFocused: Bool {
        guard let responder = NSApp.keyWindow?.firstResponder else { return false }
        return responder is NSTextField || responder is NSTextView
    }
}

/// H4 — the update menu: a manual check, plus the opt-in daily check
/// (default OFF). System controls only; no custom UI in this slice.
struct UpdateCommands: Commands {
    @ObservedObject var shell: ShellModel
    @AppStorage(UpdatePreferences.dailyCheckEnabledKey) private var dailyCheck = false

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button(L10n.ui(.checkForUpdates, shell.language)) { CheckForUpdates.run() }
                .accessibilityLabel(L10n.ui(.checkForUpdates, shell.language)).accessibilityIdentifier("menu-check-for-updates")
            Toggle("Check for Updates Automatically", isOn: $dailyCheck)
                .accessibilityLabel(L10n.ui(.checkForUpdatesAutomatically, shell.language)).accessibilityIdentifier("menu-check-for-updates-automatically")
        }
    }
}
