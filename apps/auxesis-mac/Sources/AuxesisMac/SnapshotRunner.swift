// Offscreen screenshots for visual review, sandbox only:
//   AUXESIS_SANDBOX=1 AUXESIS_MAC_FIXTURE=team AUXESIS_MAC_SNAPSHOT=<dir>
//   [AUXESIS_MAC_PROTO_SHOTS=<dir with the prototype shots, optional>]
// Each screen is rendered from fixture data into <dir>/<name>.png at
// 1440×900, and, when the prototype shot exists, <dir>/<name>-side.png puts
// the prototype (left) next to the SwiftUI render (right). Then the app quits.
// No screen capture: nothing outside this process is read.
import AppKit
import AuxesisKit
import SwiftUI

@MainActor
enum SnapshotRunner {
    struct Shot {
        let name: String
        let prototype: String?
        var scenario: FixtureDaemon.Scenario = .team
        var dark = false
        var size = CGSize(width: 1440, height: 900)
        var view: Kind = .shell
        var top = false
        var french = false
        let setup: (ShellModel) -> Void
    }

    enum Kind { case shell, settings, menu, pluginPreview }

    static let shots: [Shot] = [
        // Neutral where-labels and footer, the new agent marks.
        Shot(name: "sober-1-steps-open-light", prototype: nil, top: true) { $0.expanded.formUnion(["dl-1", "dl-3", "dl-5"]) },
        Shot(name: "sober-1-steps-open-fr-dark", prototype: nil, dark: true, top: true, french: true) { $0.expanded.formUnion(["dl-1", "dl-3", "dl-5"]) },
        Shot(name: "sober-1-team-light", prototype: nil, top: true) { $0.rightPanelTab = .team; $0.setRightPanel(true) },
        Shot(name: "sober-1-mail-dark", prototype: nil, dark: true, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        Shot(name: "sober-1-privacy-light", prototype: nil, top: true) { $0.rightPanelTab = .privacy; $0.setRightPanel(true) },
        // The Open Alpha marks in the sidebar and in the team map.
        Shot(name: "brand-1-sidebar-light", prototype: nil, top: true) { _ in },
        Shot(name: "brand-1-sidebar-dark", prototype: nil, dark: true, top: true) { _ in },
        Shot(name: "brand-1-team-light", prototype: nil, top: true) { $0.rightPanelTab = .team; $0.setRightPanel(true) },
        Shot(name: "brand-1-team-dark", prototype: nil, dark: true, top: true) { $0.rightPanelTab = .team; $0.setRightPanel(true) },
        // The v5 frame — sidebar, one 640-pt column, the right panel.
        Shot(name: "ui-v5-finish-1-panel-dark", prototype: nil, dark: true, top: true) { $0.rightPanelTab = .team; $0.setRightPanel(true) },
        Shot(name: "ui-v5-finish-1-agents-light", prototype: nil) { $0.go(.agentsAndRules) },
        Shot(name: "ui-v5-finish-1-fr-dark", prototype: nil, dark: true, top: true, french: true) { $0.go(.agent(TeamMember.mail.id)) },
        // The Privacy tab (today's record) and the v5 composer hint.
        Shot(name: "ui-v5-finish-4-privacy-dark", prototype: nil, dark: true, top: true) { $0.rightPanelTab = .privacy; $0.setRightPanel(true) },
        Shot(name: "ui-v5-finish-4-privacy-mail-light", prototype: nil, top: true) { $0.go(.agent(TeamMember.mail.id)); $0.rightPanelTab = .privacy; $0.setRightPanel(true) },
        // Sidebar v5 rows, search and privacy footer, next to the v5 prototype.
        Shot(name: "ui-v5-3-light", prototype: nil, top: true) { _ in },
        Shot(name: "ui-v5-3-dark", prototype: "v5-prototype-dark.png", dark: true, top: true) { _ in },
        // The draft card with its amber badge, and the next-step
        // links under an answer (the mirror in Aux's thread, the open draft in
        // the agent's thread).
        Shot(name: "ui-v5-5-draft-light", prototype: nil, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        Shot(name: "ui-v5-5-draft-dark", prototype: nil, dark: true, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        Shot(name: "ui-v5-5-links-light", prototype: nil, top: true) { _ in },
        Shot(name: "ui-v5-5-links-dark", prototype: nil, dark: true, top: true) { _ in },
        // A rich reply: a table, a list, code and hidden values in Aux's thread.
        Shot(name: "ui-v5-rich-1-light", prototype: nil, scenario: .rich, top: true) { _ in },
        Shot(name: "ui-v5-rich-1-dark", prototype: nil, scenario: .rich, dark: true, top: true) { _ in },
        // A Calendar answer with its calendar card.
        Shot(name: "ui-v5-rich-2a-light", prototype: nil, scenario: .calendarCard, top: true) { $0.go(.agent(TeamMember.calendar.id)) },
        Shot(name: "ui-v5-rich-2a-dark", prototype: nil, scenario: .calendarCard, dark: true, top: true) { $0.go(.agent(TeamMember.calendar.id)) },
        Shot(name: "ui-v5-rich-2a-fr-light", prototype: nil, scenario: .calendarCard, top: true, french: true) { $0.go(.agent(TeamMember.calendar.id)) },
        // The v5 Steps card (collapsed, then open) and the handoff line.
        Shot(name: "ui-v5-finish-2-steps-light", prototype: nil, top: true) { _ in },
        Shot(name: "ui-v5-finish-2-steps-open-dark", prototype: nil, dark: true, top: true) { $0.expanded.formUnion(["dl-1", "dl-3", "dl-5"]) },
        Shot(name: "ui-v5-finish-2-handoff-dark", prototype: nil, dark: true, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        // The Work tab (Active, Up next), Aux's mirror with its text and Send.
        Shot(name: "ui-v5-finish-3-work-dark", prototype: nil, dark: true, top: true) { $0.rightPanelTab = .work; $0.setRightPanel(true) },
        Shot(name: "ui-v5-finish-3-work-light", prototype: nil, top: true) { $0.rightPanelTab = .work; $0.setRightPanel(true) },
        Shot(name: "ui-v5-finish-3-mirror-light", prototype: nil) { _ in },
        // v4 messenger frame, next to the v4 prototype states.
        Shot(name: "v4-home-light", prototype: "v4-home-light-en.png", top: true) { _ in },
        Shot(name: "v4-home-dark", prototype: "v4-home-dark-en.png", dark: true, top: true) { _ in },
        Shot(name: "v4-mail-light", prototype: "v4-mail-light-en.png", top: true) { $0.go(.agent(TeamMember.mail.id)) },
        Shot(name: "v4-mail-dark", prototype: "v4-mail-dark-en.png", dark: true, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        // The right panel's Team tab, next to the v5 mock.
        Shot(name: "ui-v4-3-team-light", prototype: nil, top: true) { $0.rightPanelTab = .team; $0.setRightPanel(true) },
        Shot(name: "ui-v4-3-team-dark", prototype: nil, dark: true, top: true) { $0.rightPanelTab = .team; $0.setRightPanel(true) },
        // Neutral ink accent (selected row, send button, links).
        Shot(name: "ui-v4-3-mail-light", prototype: nil, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        Shot(name: "ui-v4-3-mail-dark", prototype: nil, dark: true, top: true) { $0.go(.agent(TeamMember.mail.id)) },
        Shot(name: "ui3-8-agents-light", prototype: nil) { shell in
            shell.go(.agentsAndRules)
            shell.inspectorOpen = true
        },
        Shot(name: "ui3-8-agents-dark", prototype: nil, dark: true) { shell in
            shell.go(.agentsAndRules)
            shell.inspectorOpen = true
        },
        Shot(name: "ui3-2-three-pane-shell-light", prototype: nil) { $0.go(.today) },
        Shot(name: "ui3-2-three-pane-shell-dark", prototype: nil, dark: true) { $0.go(.today) },
        Shot(name: "ui3-3-today-light", prototype: nil) { $0.go(.today) },
        Shot(name: "ui3-3-today-dark", prototype: nil, dark: true) { $0.go(.today) },
        Shot(name: "ui3-5-privacy-light", prototype: nil) { $0.go(.privacyRecord) },
        Shot(name: "ui3-5-privacy-dark", prototype: nil, dark: true) { $0.go(.privacyRecord) },
        Shot(name: "ui3-6-since-light", prototype: nil) { $0.go(.sinceYouLeft) },
        Shot(name: "ui3-6-since-dark", prototype: nil, dark: true) { $0.go(.sinceYouLeft) },
        Shot(name: "01-chief-team-at-work", prototype: "32-chief-team-at-work.png", top: true) { _ in },
        Shot(name: "02-delegation-expanded", prototype: "33-delegation-expanded.png", top: true) { shell in
            shell.expanded.formUnion(["dl-1", "dl-3"])
        },
        Shot(name: "03-subagent-thread", prototype: "34-subagent-thread.png") { shell in
            shell.open(agent: TeamMember.mail.id, fromDelegation: "dl-5")
        },
        Shot(name: "04-approval-undo", prototype: "05-undo-10s.png") { shell in
            shell.go(.agent(TeamMember.mail.id))
            if let approval = shell.store.approvals.first(where: { $0.id == "ap-camille" }) {
                shell.approve(approval)
            }
        },
        Shot(name: "05-approval-edit", prototype: "04-edit-in-place.png") { shell in
            shell.go(.agent(TeamMember.mail.id))
            if let approval = shell.store.approvals.first(where: { $0.id == "ap-camille" }) {
                shell.beginEdit(approval)
            }
        },
        Shot(name: "06-waiting-for-you", prototype: "36-waiting-for-you.png") { shell in
            shell.go(.waiting)
        },
        Shot(name: "ui3-4a-approval-light", prototype: nil) { shell in
            shell.go(.waiting)
            if let approval = shell.store.pendingApprovals.first { shell.store.focus(approval.id) }
        },
        Shot(name: "ui3-4a-approval-dark", prototype: nil, dark: true) { shell in
            shell.go(.waiting)
            if let approval = shell.store.pendingApprovals.first { shell.store.focus(approval.id) }
        },
        Shot(name: "ui3-4a-approval-edited-countdown", prototype: nil) { shell in
            shell.go(.waiting)
            if let approval = shell.store.pendingApprovals.first(where: { $0.id == "ap-camille" }) {
                shell.store.focus(approval.id)
                shell.beginEdit(approval)
                shell.editDrafts[approval.id] = "Hi Camille, the edited proposal remains visible while this send waits."
                shell.sendProposal(approval)
            }
        },
        Shot(name: "07-agent-profile", prototype: "37-agent-profile-grants.png") { shell in
            shell.go(.agent(TeamMember.mail.id))
            shell.inspectorOpen = true
        },
        Shot(name: "08-swap-model-saw", prototype: "40-swap-per-agent.png", top: true) { shell in
            swapFirstAgentGroup(shell, agent: TeamMember.aux.id)
        },
        Shot(name: "09-stop-all", prototype: "39-stop-all.png", scenario: .stopped) { _ in },
        Shot(name: "ui3-7a-stop-light", prototype: nil, scenario: .stopped) { _ in },
        Shot(name: "ui3-7a-stop-dark", prototype: nil, scenario: .stopped, dark: true) { _ in },
        Shot(name: "10-ledger", prototype: "25-ledger.png") { shell in
            shell.go(.ledger)
        },
        Shot(name: "11-settings-providers", prototype: "26-settings-skills.png", size: CGSize(width: 760, height: 640), view: .settings) { shell in
            shell.settingsTab = .providers
        },
        Shot(name: "12-settings-coverage", prototype: nil, size: CGSize(width: 760, height: 640), view: .settings) { shell in
            shell.settingsTab = .privacy
        },
        Shot(name: "13-settings-budgets", prototype: nil, size: CGSize(width: 760, height: 640), view: .settings) { shell in
            shell.settingsTab = .budgets
        },
        Shot(name: "m6-4-plugins-light", prototype: nil, size: CGSize(width: 760, height: 640), view: .settings) { $0.settingsTab = .plugins },
        // The install preview names the agent that gets the tools.
        Shot(name: "m6-4-plugins-preview-light", prototype: nil, size: CGSize(width: 560, height: 360), view: .pluginPreview) { shell in
            Task { await shell.store.loadPlugins(); if let entry = shell.store.mcpCatalog.first { await shell.store.installPlugin(entry) } }
        },
        Shot(name: "m6-4-plugins-dark", prototype: nil, dark: true, size: CGSize(width: 760, height: 640), view: .settings) { $0.settingsTab = .plugins },
        Shot(name: "14-menu-bar", prototype: "15-menu-bar.png", size: CGSize(width: 270, height: 200), view: .menu) { _ in },
        Shot(name: "15-clients-empty", prototype: nil, scenario: .empty) { shell in
            shell.go(.clients)
        },
        Shot(name: "16-empty-chief", prototype: "21-empty-new.png", scenario: .empty) { _ in },
        Shot(name: "17-dark-chief", prototype: "41-dark-chief.png", dark: true, top: true) { _ in },
        Shot(name: "18-dark-approval", prototype: "29-dark-approval.png", dark: true) { shell in
            shell.go(.agent(TeamMember.mail.id))
        },
        // Clients. Fixture people only (Camille Exemple, Jonas Weber).
        Shot(name: "e3-01-clients-card", prototype: "22-client-inspector.png") { shell in
            openClient(shell)
        },
        Shot(name: "e3-02-clients-card-dark", prototype: nil, dark: true) { shell in
            openClient(shell)
        },
        Shot(name: "e3-03-clients-timeline", prototype: nil) { shell in
            openClient(shell) { $0.clientTab = .timeline }
        },
        Shot(name: "e3-04-clients-memory-dark", prototype: "31-dark-memory.png", dark: true) { shell in
            openClient(shell) { $0.clientTab = .memory }
        },
        Shot(name: "e3-05-clients-edit", prototype: nil) { shell in
            openClient(shell) { $0.beginClientEdit() }
        },
        Shot(name: "e3-06-clients-edit-dark", prototype: nil, dark: true) { shell in
            openClient(shell) { $0.beginClientEdit() }
        },
        Shot(name: "e3-07-clients-empty-dark", prototype: nil, scenario: .empty, dark: true) { shell in
            shell.go(.clients)
        },
        Shot(name: "e3-08-clients-error", prototype: nil, scenario: .clientsDown) { shell in
            shell.go(.clients)
        },
        Shot(name: "e3-09-clients-error-dark", prototype: nil, scenario: .clientsDown, dark: true) { shell in
            shell.go(.clients)
        },
        // Today, the brief of the day. Fixture events and mail only.
        Shot(name: "m2-01-today", prototype: nil) { $0.go(.today) },
        Shot(name: "m2-02-today-dark", prototype: nil, dark: true) { $0.go(.today) },
        Shot(name: "m2-03-today-fr", prototype: nil, french: true) { $0.go(.today) },
        Shot(name: "m2-04-today-degraded", prototype: nil, scenario: .briefDegraded) { $0.go(.today) },
        Shot(name: "m2-05-today-empty", prototype: nil, scenario: .empty) { $0.go(.today) },
        Shot(name: "m2-06-today-empty-dark-fr", prototype: nil, scenario: .empty, dark: true, french: true) { $0.go(.today) },
        // TODAY-SHAPE-1: one shot per focus state (the team one is m2-01).
        Shot(name: "m2-07-today-job", prototype: nil, scenario: .todayJob) { $0.go(.today) },
        Shot(name: "m2-08-today-event-dark", prototype: nil, scenario: .todayEvent, dark: true) { $0.go(.today) },
        Shot(name: "m2-09-today-mail-fr", prototype: nil, scenario: .todayMail, french: true) { $0.go(.today) },
        Shot(name: "m2-10-today-calm", prototype: nil, scenario: .todayCalm) { $0.go(.today) },
        // The Calendar page. Invented events only (FixtureEventKit).
        Shot(name: "cal-01-fresh", prototype: nil) { $0.go(.calendar) },
        Shot(name: "cal-02-stale", prototype: nil, scenario: .calendarStale) { $0.go(.calendar) },
        Shot(name: "cal-03-stale-dark-fr", prototype: nil, scenario: .calendarStale, dark: true, french: true) { $0.go(.calendar) },
        Shot(name: "cal-04-not-shared", prototype: nil, scenario: .empty) { $0.go(.calendar) },
        // "What Aux knows", light, English and French.
        Shot(name: "mem-01-what-aux-knows", prototype: nil) { $0.go(.memory) },
        Shot(name: "mem-02-what-aux-knows-fr", prototype: nil, french: true) { $0.go(.memory) },
        // The same page with nothing saved: one empty line
        // per section, light and dark, English and French.
        Shot(name: "mem-03-what-aux-knows-empty-light", prototype: nil, scenario: .memoryEmpty) { $0.go(.memory) },
        Shot(name: "mem-04-what-aux-knows-empty-dark", prototype: nil, scenario: .memoryEmpty, dark: true) { $0.go(.memory) },
        Shot(name: "mem-05-what-aux-knows-empty-fr", prototype: nil, scenario: .memoryEmpty, french: true) { $0.go(.memory) },
        Shot(name: "mem-06-what-aux-knows-empty-dark-fr", prototype: nil, scenario: .memoryEmpty, dark: true, french: true) { $0.go(.memory) },
    ]

    /// Clients, with the first card open, then `then` once the card is in.
    private static func openClient(_ shell: ShellModel, then: ((ShellModel) -> Void)? = nil) {
        shell.go(.clients)
        shell.loadClients()
        guard let then else { return }
        Task { @MainActor in
            _ = await until(5) { shell.clientCard.value != nil }
            then(shell)
        }
    }

    static func run(into directory: URL) {
        // The live window is not part of the review.
        for window in NSApp.windows { window.orderOut(nil) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let prototypes = ProcessInfo.processInfo.environment["AUXESIS_MAC_PROTO_SHOTS"].map { URL(fileURLWithPath: $0, isDirectory: true) }
        let only = ProcessInfo.processInfo.environment["AUXESIS_MAC_SNAPSHOT_ONLY"]
        Task { @MainActor in
            for shot in shots where only == nil || shot.name.hasPrefix(only!) {
                await render(shot, into: directory, prototypes: prototypes)
            }
            print("AUXESIS_MAC_SNAPSHOT_DONE")
            NSApp.terminate(nil)
        }
    }

    /// With `AUXESIS_MAC_MASCOTS=1`: the ten mascots at 64/28/20/16 pt
    /// and the five tints, light and dark, rendered offscreen with
    /// ImageRenderer into <dir>/mascots-{light,dark}.png at 2×.
    static func runMascots(into directory: URL) {
        for window in NSApp.windows { window.orderOut(nil) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for dark in [false, true] {
            let sheet = MascotSheet()
                .themed()
                .environment(\.colorScheme, dark ? .dark : .light)
            let renderer = ImageRenderer(content: sheet)
            renderer.scale = 2
            let url = directory.appendingPathComponent("mascots-\(dark ? "dark" : "light").png")
            if let image = renderer.cgImage,
               let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) {
                try? png.write(to: url)
                print("AUXESIS_MAC_SNAPSHOT \(url.lastPathComponent)")
            }
        }
        // The mascot sheet, as in the design board — light: Mail with
        // its tint changed; dark: an agent the owner made, looking like Documents.
        let travel = TeamMember.custom("Travel")
        for dark in [false, true] {
            let sheet = (dark
                ? MascotPickerSheet(member: travel, team: TeamMember.all + [travel], status: "Idle · last: Train times to Lyon",
                                    looks: AgentLooks(defaults: UserDefaults(suiteName: "auxesis.snapshot.mascots")!), start: MascotLook(.specs))
                : MascotPickerSheet(member: .mail, status: "Waiting on you: 1 reply",
                                    looks: AgentLooks(defaults: UserDefaults(suiteName: "auxesis.snapshot.mascots")!), start: MascotLook(.glance, .slate)))
                .themed()
                .environment(\.colorScheme, dark ? .dark : .light)
            let renderer = ImageRenderer(content: sheet)
            renderer.scale = 2
            let url = directory.appendingPathComponent("picker-\(dark ? "dark" : "light").png")
            if let image = renderer.cgImage,
               let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) {
                try? png.write(to: url)
                print("AUXESIS_MAC_SNAPSHOT \(url.lastPathComponent)")
            }
        }
        print("AUXESIS_MAC_SNAPSHOT_DONE")
        NSApp.terminate(nil)
    }

    /// The hero path against a real sandboxed auxd (`AUXESIS_MAC_HERO=1`):
    /// add the sandbox test provider in Settings, send a message to Aux, see
    /// the reply. Each step calls the ShellModel action the button calls and
    /// is rendered to <dir>/hero-*.png. Prints `HERO <step> ok|fail`.
    static func runHero(into directory: URL) {
        for window in NSApp.windows { window.orderOut(nil) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        Task { @MainActor in
            let shell = AppEnvironment.makeShell(fixture: nil)
            shell.start()
            let online = await until(20) { shell.store.connection.isOnline }
            print("HERO connect \(online ? "ok" : "fail")")
            shell.loadProviders()
            _ = await until(5) { shell.providers != .loading }
            await snap(shell, "hero-1-start", view: .shell, into: directory)
            shell.settingsTab = .providers
            let added = await shell.addProvider(kind: "fake", name: "test", address: "http://127.0.0.1:9/v1", model: "echo", key: nil)
            _ = await until(5) { (shell.providers.value?.count ?? 0) > 0 }
            print("HERO add-provider \(added && (shell.providers.value?.count ?? 0) > 0 ? "ok" : "fail")")
            await snap(shell, "hero-2-provider", view: .settings, into: directory)
            shell.settingsTab = nil
            shell.go(.agent(TeamMember.aux.id))
            _ = await until(3) { true }
            shell.store.sendMessage("Hello Aux, this is the hero path.")
            let replied = await until(30) {
                !shell.store.isSendingMessage
                    && shell.store.messages.contains { if case .agent = $0.author { return !$0.text.isEmpty } else { return false } }
            }
            print("HERO reply \(replied ? "ok" : "fail")\(shell.store.lastMessageError.map { " (\($0))" } ?? "")")
            await snap(shell, "hero-3-reply", view: .shell, into: directory)
            for message in shell.store.messages {
                print("HERO message id=\(message.id) author=\(message.author) ts=\(message.ts)")
            }
            print("HERO approvals-pending \(shell.store.approvals.count)")
            shell.loadCoverage()
            let covered = await until(10) { shell.coverage.value != nil }
            print("HERO coverage \(covered ? "ok" : "fail") paths=\(shell.coverage.value?.count ?? 0)")
            shell.settingsTab = .privacy
            await snap(shell, "hero-4-coverage", view: .settings, into: directory)
            shell.settingsTab = nil
            shell.go(.ledger)
            shell.loadLedger()
            let ledger = await until(10) { shell.ledger.value != nil }
            print("HERO ledger \(ledger ? "ok" : "fail") rows=\(shell.ledger.value?.count ?? 0)")
            await snap(shell, "hero-5-ledger", view: .shell, into: directory)
            print("AUXESIS_MAC_HERO_DONE")
            NSApp.terminate(nil)
        }
    }

    /// A proof against a real sandboxed auxd (`AUXESIS_MAC_LIVE=clients`,
    /// run through `scripts/run-auxesis-mac.sh`): the empty Clients view, then,
    /// once the parties seeded from outside appear, the first card and its
    /// editor, light and dark, then the editor locked by a held save.
    /// Prints `LIVE <step> ok|fail`.
    static func runClientsLive(into directory: URL) {
        for window in NSApp.windows { window.orderOut(nil) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        Task { @MainActor in
            let shell = AppEnvironment.makeShell(fixture: nil)
            shell.start()
            let online = await until(20) { shell.store.connection.isOnline }
            print("LIVE connect \(online ? "ok" : "fail")")
            shell.go(.clients)
            shell.loadClients()
            let empty = await until(10) { shell.clients == .loaded([]) }
            print("LIVE empty \(empty ? "ok" : "fail")")
            await snap(shell, "e3-00-clients-empty", view: .shell, into: directory)
            await snap(shell, "e3-07-clients-empty-dark", view: .shell, into: directory, dark: true)
            print("LIVE empty-done")
            // The parties are written from outside (aux crm, then PUT).
            var seeded = false
            for _ in 0..<120 where !seeded {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                shell.loadClients()
                _ = await until(2) { shell.clients != .loading }
                seeded = (shell.clients.value?.count ?? 0) >= 2
                    && shell.clients.value?.contains { !$0.phones.isEmpty } == true
            }
            print("LIVE seeded \(seeded ? "ok" : "fail")")
            if let first = shell.clients.value?.first { shell.selectClient(first.id) }
            let card = await until(10) { shell.clientCard.value != nil }
            print("LIVE card \(card ? "ok" : "fail")")
            await snap(shell, "e3-01-clients-card", view: .shell, into: directory)
            await snap(shell, "e3-02-clients-card-dark", view: .shell, into: directory, dark: true)
            shell.beginClientEdit()
            await snap(shell, "e3-05-clients-edit", view: .shell, into: directory)
            await snap(shell, "e3-06-clients-edit-dark", view: .shell, into: directory, dark: true)
            // The locked editor while a save is in flight: the harness pauses
            // auxd on `hold-daemon` and resumes it on `saving-done`.
            print("LIVE hold-daemon")
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            Task { await shell.saveClientDraft() }
            let saving = await until(2) { shell.clientSaving }
            print("LIVE saving \(saving ? "ok" : "fail")")
            await snap(shell, "e3-10-clients-saving", view: .shell, into: directory)
            print("LIVE saving-done")
            let saved = await until(30) { shell.clientSaved }
            print("LIVE saved \(saved ? "ok" : "fail")")
            print("AUXESIS_MAC_LIVE_DONE")
            NSApp.terminate(nil)
        }
    }

    /// A proof against a real sandboxed auxd (`AUXESIS_MAC_LIVE=docs`) whose
    /// home was seeded with fictional receipts: the Documents page light, dark
    /// and French, then the No client filter. Prints `LIVE <step> ok|fail`.
    static func runDocsLive(into directory: URL) {
        for window in NSApp.windows { window.orderOut(nil) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        Task { @MainActor in
            let shell = AppEnvironment.makeShell(fixture: nil)
            shell.start()
            print("LIVE connect \(await until(20) { shell.store.connection.isOnline } ? "ok" : "fail")")
            guard let page = shell.documents else { return }
            shell.go(.documents)
            await page.reload()
            print("LIVE docs \(page.load) clients=\(page.clients.count)")
            await snap(shell, "m5-4-docs", view: .shell, into: directory)
            await snap(shell, "m5-4-docs-dark", view: .shell, into: directory, dark: true)
            await snap(shell, "m5-4-docs-fr", view: .shell, into: directory, french: true)
            page.filter = .unlinked
            _ = await until(5) { if case .loaded(let rows) = page.load { return rows.allSatisfy { $0.client == nil } } else { return false } }
            await snap(shell, "m5-4-docs-unlinked", view: .shell, into: directory)
            print("AUXESIS_MAC_LIVE_DONE")
            NSApp.terminate(nil)
        }
    }

    private static func until(_ seconds: Double, _ condition: @escaping () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition(), Date() < deadline {
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        return condition()
    }

    private static func snap(_ shell: ShellModel, _ name: String, view: Kind, into directory: URL, dark: Bool = false, french: Bool = false) async {
        let size = view == .settings ? CGSize(width: 760, height: 640) : CGSize(width: 1440, height: 900)
        let content: AnyView = view == .settings
            ? AnyView(SettingsSheet().environmentObject(shell))
            : AnyView(ShellView().environmentObject(shell))
        let host = NSHostingView(rootView: content.environment(\.language, french ? .fr : shell.language).themed().environment(\.colorScheme, dark ? .dark : .light).frame(width: size.width, height: size.height))
        host.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: CGRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        window.contentView = host
        window.orderBack(nil)
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        host.layoutSubtreeIfNeeded()
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        window.orderOut(nil)
        let image = NSImage(size: size)
        image.addRepresentation(rep)
        write(image, size: size, to: directory.appendingPathComponent("\(name).png"))
    }

    private static func swapFirstAgentGroup(_ shell: ShellModel, agent: String) {
        let items = ThreadTimeline.build(
            agent: agent,
            messages: shell.store.messages,
            delegations: shell.delegations,
            approvals: shell.approvals(inThreadOf: agent)
        )
        for case .group(let group) in items {
            guard case .agent = group.voice else { continue }
            let hasMessage = group.entries.contains { if case .message = $0 { return true } else { return false } }
            if hasMessage {
                shell.swapped.insert(group.id)
                return
            }
        }
    }

    private static func render(_ shot: Shot, into directory: URL, prototypes: URL?) async {
        let shell = AppEnvironment.makeShell(fixture: shot.scenario)
        shell.start()
        try? await Task.sleep(nanoseconds: 700_000_000)
        shot.setup(shell)
        try? await Task.sleep(nanoseconds: 300_000_000)

        let scheme: ColorScheme = shot.dark ? .dark : .light
        let content: AnyView
        switch shot.view {
        case .shell:
            content = AnyView(ShellView().environmentObject(shell))
        case .settings:
            content = AnyView(SettingsSheet().environmentObject(shell))
        case .menu:
            content = AnyView(MenuBarPanel(onOpen: {}).environmentObject(shell).fixedSize())
        case .pluginPreview:
            content = AnyView(shell.store.pluginPreview.map { PreviewSheet(store: shell.store, preview: $0, name: shell.store.mcpCatalog.first?.name ?? $0.id) })
        }
        let root = content
            .environment(\.language, shot.french ? .fr : shell.language)
            .themed()
            .environment(\.colorScheme, scheme)
            .environment(\.threadStartsAtTop, shot.top)
            .frame(width: shot.size.width, height: shot.size.height, alignment: .topLeading)

        let host = NSHostingView(rootView: root)
        host.frame = CGRect(origin: .zero, size: shot.size)
        let window = NSWindow(
            contentRect: CGRect(origin: CGPoint(x: -20_000, y: -20_000), size: shot.size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.appearance = NSAppearance(named: shot.dark ? .darkAqua : .aqua)
        window.contentView = host
        window.orderBack(nil)
        // Let onAppear loads land and animations settle.
        try? await Task.sleep(nanoseconds: 1_600_000_000)
        host.layoutSubtreeIfNeeded()

        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        window.orderOut(nil)
        let render = NSImage(size: shot.size)
        render.addRepresentation(rep)
        write(render, size: shot.size, to: directory.appendingPathComponent("\(shot.name).png"))

        if let prototypes, let name = shot.prototype,
           let proto = NSImage(contentsOf: prototypes.appendingPathComponent(name)) {
            let side = sideBySide(proto: proto, render: render, size: shot.size, dark: shot.dark)
            write(side.image, size: side.size, to: directory.appendingPathComponent("\(shot.name)-side.png"))
        }
        print("AUXESIS_MAC_SNAPSHOT \(shot.name)")
    }

    /// Prototype left, SwiftUI right, one caption line each. The prototype
    /// keeps its own frame (1440×900); small renders are centred on a panel.
    private static func sideBySide(proto: NSImage, render: NSImage, size: CGSize, dark: Bool) -> (image: NSImage, size: CGSize) {
        let panel = CGSize(width: 1440, height: 900)
        let caption: CGFloat = 44
        let gap: CGFloat = 32
        let total = CGSize(width: panel.width * 2 + gap, height: panel.height + caption)
        let image = NSImage(size: total, flipped: true) { _ in
            let background = dark ? NSColor(red: 0.08, green: 0.08, blue: 0.09, alpha: 1) : NSColor(red: 0.95, green: 0.95, blue: 0.945, alpha: 1)
            background.setFill()
            CGRect(origin: .zero, size: total).fill()
            let ink = dark ? NSColor(white: 0.85, alpha: 1) : NSColor(white: 0.25, alpha: 1)
            let attributes: [NSAttributedString.Key: Any] = [.font: Fonts.nsFont(15, 650), .foregroundColor: ink]
            NSAttributedString(string: "Prototype", attributes: attributes).draw(at: CGPoint(x: 16, y: 13))
            NSAttributedString(string: "SwiftUI (apps/auxesis-mac)", attributes: attributes).draw(at: CGPoint(x: panel.width + gap + 16, y: 13))
            proto.draw(in: fit(proto.size, into: CGRect(x: 0, y: caption, width: panel.width, height: panel.height)),
                       from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
            let target = size.width < panel.width
                ? CGRect(x: panel.width + gap + (panel.width - size.width) / 2, y: caption + (panel.height - size.height) / 2, width: size.width, height: size.height)
                : CGRect(x: panel.width + gap, y: caption, width: panel.width, height: panel.height)
            render.draw(in: target, from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
            return true
        }
        return (image, total)
    }

    private static func fit(_ size: CGSize, into rect: CGRect) -> CGRect {
        guard size.width > 0, size.height > 0 else { return rect }
        let scale = min(rect.width / size.width, rect.height / size.height)
        let fitted = CGSize(width: size.width * scale, height: size.height * scale)
        return CGRect(x: rect.minX + (rect.width - fitted.width) / 2, y: rect.minY + (rect.height - fitted.height) / 2, width: fitted.width, height: fitted.height)
    }

    /// Writes at 1 point = 1 pixel so files stay comparable and small.
    private static func write(_ image: NSImage, size: CGSize, to url: URL) {
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: Int(size.width), pixelsHigh: Int(size.height),
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
        ) else { return }
        bitmap.size = size
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        image.draw(in: CGRect(origin: .zero, size: size))
        NSGraphicsContext.restoreGraphicsState()
        try? bitmap.representation(using: .png, properties: [:])?.write(to: url)
    }
}

/// The mascot board: one column per mascot (64, 28, 20, 16 pt, then its
/// name and the agent it is the default for), then each tint at 28/20/16.
private struct MascotSheet: View {
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: 28) {
            HStack(alignment: .top, spacing: 24) {
                ForEach(MascotVariant.allCases, id: \.self) { variant in
                    VStack(spacing: 10) {
                        MascotView(look: MascotLook(variant), size: 64)
                        HStack(alignment: .bottom, spacing: 8) {
                            ForEach([CGFloat(28), 20, 16], id: \.self) { MascotView(look: MascotLook(variant), size: $0) }
                        }
                        Text(variant.name).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                        Text(defaultFor(variant)).font(.caption).foregroundStyle(palette.ink3.color)
                    }
                    .frame(width: 96)
                }
            }
            HStack(spacing: 28) {
                ForEach(MascotTint.allCases, id: \.self) { tint in
                    HStack(alignment: .bottom, spacing: 8) {
                        ForEach([CGFloat(28), 20, 16], id: \.self) { MascotView(look: MascotLook(.loop, tint), size: $0) }
                        Text(tint.name).font(.caption).foregroundStyle(palette.ink2.color)
                    }
                }
                HStack(alignment: .bottom, spacing: 8) {
                    MascotView(look: MascotLook(.specs), size: 28, stopped: true)
                    ForEach([CGFloat(20), 16], id: \.self) { MascotView(look: MascotLook(.glance), size: $0, mono: true) }
                    Text("stopped · handoff").font(.caption).foregroundStyle(palette.ink2.color)
                }
            }
        }
        .padding(32)
        .background(palette.work.color)
    }

    private func defaultFor(_ variant: MascotVariant) -> String {
        let agents = TeamMember.all.filter { MascotLook.default(for: $0.id).variant == variant }.map(\.name)
        return variant == .sprout ? "New agents" : agents.isEmpty ? "—" : agents.joined(separator: ", ")
    }
}
