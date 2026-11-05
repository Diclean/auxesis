// Settings, a sheet with tabs (prototype `.set`, 760 wide): General,
// Providers, Skills, Plugins, Privacy & Coverage, Budgets & Stop. Usable while stopped.
import AuxesisKit
import SwiftUI

struct SettingsSheet: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let copy = Copy(language: shell.language)
        let tab = shell.settingsTab ?? .providers
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                Text(copy(.settings))
                    .font(.hk(Theme.Text.ui, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                HStack(spacing: 2) {
                    ForEach(ShellModel.SettingsTab.allCases) { item in
                        TabButton(tab: item, selected: item == tab) { shell.settingsTab = item }
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.top, 12)
            .padding(.bottom, 6)
            .frame(maxWidth: .infinity)
            .background(palette.list.color)
            .overlay(alignment: .topTrailing) {
                ToolbarIconButton(icon: .x, help: copy(.close), identifier: "settings-close") { dismiss() }
                    .viewShortcut(.dismissSheet)
                    .padding(10)
            }
            Hairline()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Text(copy(tab.titleKey))
                        .font(.hk(Theme.Text.title, Theme.Weight.bold))
                        .foregroundStyle(palette.ink.color)
                        .padding(.bottom, 4)
                    switch tab {
                    case .general: GeneralTab()
                    case .providers: ProvidersTab()
                    case .skills: SkillsTab()
                    case .plugins: PluginsTab(store: shell.store)
                    case .privacy: PrivacyTab()
                    case .budgets: BudgetsTab()
                    }
                }
                .padding(.horizontal, 28)
                .padding(.top, 20)
                .padding(.bottom, 26)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(width: 760, height: 640)
        .background(palette.work.color)
        .environment(\.language, shell.language)
    }
}

private struct TabButton: View {
    let tab: ShellModel.SettingsTab
    let selected: Bool
    let action: () -> Void
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var hovering = false

    var body: some View {
        let copy = Copy(language: language)
        Button(action: action) {
            VStack(spacing: 3) {
                IconView(icon: tab.icon, size: 20)
                Text(copy(tab.titleKey)).font(.meta).lineLimit(1)
            }
            .foregroundStyle(selected ? palette.ink.color : palette.muted.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .frame(minWidth: 84)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(selected ? palette.selection.color : hovering ? palette.hover.color : .clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel(copy(tab.titleKey)).accessibilityIdentifier("settings-tab-\(String(describing: tab).lowercased())")
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

// MARK: - Building blocks

/// `.lede`
struct Lede: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        Text(text)
            .font(.ui)
            .foregroundStyle(palette.muted.color)
            .lineSpacing(4)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.bottom, 16)
    }
}

/// `.form`: rows separated by hairlines inside one hairline box.
struct FormBox<Content: View>: View {
    @ViewBuilder let content: () -> Content
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(spacing: 0) { content() }
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(palette.line.color, lineWidth: 1))
            .padding(.bottom, 18)
    }
}

/// `.fr`: one form row; every row after the first has a top hairline.
struct FormRow<Trailing: View>: View {
    var first = false
    let title: String
    var detail: String?
    var leading: AnyView?
    @ViewBuilder let trailing: () -> Trailing
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: 12) {
            if let leading { leading }
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.ui).foregroundStyle(palette.ink.color)
                if let detail {
                    Text(detail)
                        .font(.meta)
                        .foregroundStyle(palette.muted.color)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            trailing()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .overlay(alignment: .top) { if !first { Hairline() } }
    }
}

private struct SectionTitle: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        Text(text)
            .font(.hk(Theme.Text.ui, Theme.Weight.strong))
            .foregroundStyle(palette.ink.color)
            .padding(.bottom, 8)
    }
}

// MARK: - General

private struct GeneralTab: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var calendarNote: UIKey?
    @State private var reading = false

    var body: some View {
        let copy = Copy(language: language)
        Lede(text: copy(.generalLede))
        FormBox {
            FormRow(first: true, title: copy(.language)) {
                Text(copy(.languageValue)).font(.ui).foregroundStyle(palette.ink2.color)
            }
            FormRow(title: copy(.calendarAccess), detail: calendarNote.map { copy($0) } ?? copy(.calendarAccessHint)) {
                Button(calendarNote == .calendarSaved ? copy(.calendarRead) : copy(.calendarAllow)) { readCalendar() }
                    .buttonStyle(AuxButtonStyle())
                    .disabled(reading || AppEnvironment.fixture != nil)
                    .accessibilityLabel(calendarNote == .calendarSaved ? copy(.calendarRead) : copy(.calendarAllow)).accessibilityIdentifier("settings-calendar-access")
            }
            FormRow(title: copy(.notifications), detail: copy(.notificationsHint)) { EmptyView() }
            FormRow(title: copy(.setupRow), detail: copy(.setupRowHint)) {
                Button(copy(.setupRowOpen)) {
                    shell.settingsTab = nil
                    // Let the Settings sheet close before the setup sheet opens.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { shell.setupOpen = true }
                }
                    .buttonStyle(AuxButtonStyle())
                    .accessibilityLabel(copy(.setupRowOpen)).accessibilityIdentifier("settings-setup-open")
            }
        }
    }

    /// EventKit access is asked only when the owner presses the button.
    private func readCalendar() {
        reading = true
        Task { @MainActor in
            defer { reading = false }
            let kit = AppEnvironment.eventKit()
            do {
                let snapshot = try await kit.requestAccessAndRead()
                guard snapshot.authorized else {
                    calendarNote = .calendarDenied
                    return
                }
                try await shell.store.publishAppleEventKit(snapshot.boundedAndCleaned())
                calendarNote = .calendarSaved
            } catch {
                calendarNote = kit.access == .denied ? .calendarDenied : .calendarError
            }
        }
    }
}

// MARK: - Providers

private struct ProvidersTab: View {
    enum Kind: String, CaseIterable { case openai = "openai_compat", fake }

    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var kind: Kind = .openai
    @State private var name = ""
    @State private var address = ""
    @State private var model = ""
    @State private var key = ""
    @State private var saving = false

    var body: some View {
        let copy = Copy(language: language)
        Lede(text: copy(.providersLede))
        switch shell.providers {
        case .loading:
            Lede(text: copy(.loading))
        case .failed:
            Lede(text: copy(.loadFailed))
        case .unavailable:
            Lede(text: copy(.unavailable))
        case .loaded(let list) where list.isEmpty:
            Text(copy(.providersEmpty))
                .font(.ui)
                .foregroundStyle(palette.ink.color)
                .padding(.bottom, 18)
        case .loaded(let list):
            FormBox {
                ForEach(Array(list.enumerated()), id: \.element.id) { index, provider in
                    providerRow(provider, first: index == 0, copy: copy)
                }
            }
        }
        SectionTitle(text: copy(.providerAdd))
        addForm(copy)
            .onAppear { shell.loadProviders() }
    }

    private func providerRow(_ provider: ProviderSummary, first: Bool, copy: Copy) -> some View {
        let test = shell.providerTests[provider.id]
        let status: (String, Color) = {
            if let test {
                if test.ok { return (copy(.providerConnected), palette.ink2.color) }
                if test.keyPresent == true, test.reachable == true { return (copy.f(.providerKeyRefused, provider.name), palette.red.color) }
                return (copy(.providerNotResponding), palette.red.color)
            }
            if provider.lastTest == "ok" { return (copy(.providerConnected), palette.ink2.color) }
            return (copy(.providerNotTested), palette.muted.color)
        }()
        return FormRow(
            first: first,
            title: provider.name,
            detail: provider.model + " · " + provider.baseURL,
            leading: AnyView(ProviderMark(name: provider.name))
        ) {
            HStack(spacing: 10) {
                Text(status.0).font(.meta).foregroundStyle(status.1).lineLimit(2).frame(maxWidth: 200, alignment: .trailing)
                Button(copy(.providerTest)) { shell.testProvider(provider.id) }
                    .buttonStyle(AuxButtonStyle())
                    .accessibilityLabel(copy(.providerTest)).accessibilityIdentifier("provider-test-\(provider.id)")
            }
        }
    }

    private func addForm(_ copy: Copy) -> some View {
        let kinds: [Kind] = AppEnvironment.sandbox ? [.openai, .fake] : [.openai]
        let ready = !name.trimmingCharacters(in: .whitespaces).isEmpty
            && !model.trimmingCharacters(in: .whitespaces).isEmpty
            && !address.trimmingCharacters(in: .whitespaces).isEmpty
        return VStack(alignment: .leading, spacing: 0) {
            FormBox {
                FormRow(first: true, title: copy(.providerKind)) {
                    Picker(copy(.providerKind), selection: $kind) {
                        ForEach(kinds, id: \.self) { item in
                            Text(item == .openai ? copy(.providerKindOpenAI) : copy(.providerKindFake)).tag(item)
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityLabel(copy(.providerKind))
                    .accessibilityIdentifier("provider-kind-picker")
                    .onChange(of: kind) { _, value in prefill(value) }
                }
                field(copy(.providerName), identifier: "provider-name", text: $name, prompt: "deepseek")
                field(copy(.providerAddress), identifier: "provider-address", text: $address, prompt: "https://api.example.test/v1")
                field(copy(.providerModel), identifier: "provider-model", text: $model, prompt: "deepseek-chat")
                if kind == .openai {
                    FormRow(title: copy(.providerKey), detail: copy(.providerKeyHint)) {
                        SecureField(copy(.providerKey), text: $key)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 260)
                            .accessibilityLabel(copy(.providerKey))
                            .accessibilityIdentifier("provider-key")
                    }
                }
            }
            HStack(spacing: 10) {
                Button(saving ? copy(.saving) : copy(.providerSave)) { save() }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .disabled(!ready || saving)
                    .accessibilityLabel(saving ? copy(.saving) : copy(.providerSave)).accessibilityIdentifier("provider-save")
                if let error = shell.providerError {
                    Text(error).font(.meta).foregroundStyle(palette.red.color)
                }
            }
        }
    }

    private func field(_ title: String, identifier: String, text: Binding<String>, prompt: String) -> some View {
        FormRow(title: title) {
            TextField(title, text: text, prompt: Text(prompt))
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .accessibilityLabel(title)
                .accessibilityIdentifier(identifier)
        }
    }

    /// The sandbox test provider answers on this Mac; it needs no key.
    private func prefill(_ value: Kind) {
        guard value == .fake else { return }
        if name.isEmpty { name = "test" }
        if address.isEmpty { address = "http://127.0.0.1:9/v1" }
        if model.isEmpty { model = "echo" }
        key = ""
    }

    private func save() {
        saving = true
        let secret = kind == .fake ? nil : key
        Task { @MainActor in
            let ok = await shell.addProvider(kind: kind.rawValue, name: name, address: address, model: model, key: secret)
            key = ""
            if ok {
                name = ""
                address = ""
                model = ""
            }
            saving = false
        }
    }
}

private struct ProviderMark: View {
    let name: String
    @Environment(\.palette) private var palette

    var body: some View {
        Text(String(name.prefix(1)).uppercased())
            .font(.hk(12, Theme.Weight.bold))
            .foregroundStyle(palette.ink2.color)
            .frame(width: 28, height: 28)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(palette.selection.color))
    }
}

// MARK: - Skills

private struct SkillsTab: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        Lede(text: copy(.skillsLede))
        Group {
            switch shell.skills {
            case .loading: Lede(text: copy(.loading))
            case .failed: Lede(text: copy(.loadFailed))
            case .unavailable: Lede(text: copy(.unavailable))
            case .loaded(let list) where list.isEmpty: Lede(text: copy(.skillsEmpty))
            case .loaded(let list):
                FormBox {
                    ForEach(Array(list.enumerated()), id: \.element.id) { index, skill in
                        FormRow(first: index == 0, title: skill.name, detail: skill.description) {
                            switch skill.status {
                            case .valid:
                                Text(copy(.skillReady)).font(.meta).foregroundStyle(palette.ink2.color)
                            case .ignored(let reason):
                                Text(copy.f(.skillIgnored, reason)).font(.meta).foregroundStyle(palette.ink3.color)
                            }
                        }
                    }
                }
            }
        }
        .onAppear { shell.loadSkills() }
    }
}

// MARK: - Privacy & Coverage

private struct PrivacyTab: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        Lede(text: copy(.privacyLede))
        FormBox {
            FormRow(first: true, title: copy(.privateMode), detail: copy(.privateModeHint), leading: AnyView(IconView(icon: .shield).foregroundStyle(palette.ink2.color))) {
                // `PUT /v1/mode` is not implemented yet: Private mode is on, always.
                HStack(spacing: 5) {
                    IconView(icon: .lock, size: 13)
                    Text(copy(.privateModeOn)).font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                }
                .foregroundStyle(palette.ink.color)
                .accessibilityElement(children: .combine)
            }
        }
        SectionTitle(text: copy(.coverageTitle))
        Lede(text: copy(.acpReadsAsk))
        Group {
            switch shell.coverage {
            case .loading: Lede(text: copy(.loading))
            case .failed: Lede(text: copy(.loadFailed))
            case .unavailable: Lede(text: copy(.unavailable))
            case .loaded(let rows):
                let covered = rows.filter { $0.state == .covered }.count
                let missed = rows.filter { $0.state == .missed }.count
                Text(copy.f(.coverageSummary, covered, rows.count, missed))
                    .font(.ui)
                    .foregroundStyle(palette.ink2.color)
                    .padding(.bottom, 10)
                FormBox {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                        CoverageLine(row: row, first: index == 0)
                    }
                }
            }
        }
        .onAppear { shell.loadCoverage() }
    }
}

private struct CoverageLine: View {
    let row: CoverageRow
    let first: Bool
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let (state, color): (String, Color) = {
            switch row.state {
            case .covered: return (copy(.covCovered), palette.ink2.color)
            case .partial: return (copy(.covPartial), palette.ink3.color)
            case .missed: return (copy(.covMissed), palette.red.color)
            }
        }()
        let behaviour: String = {
            switch row.privateMode {
            case "allow": return copy(.covRunsPrivate)
            case "ask": return copy(.covAsksPrivate)
            default: return copy(.covOffPrivate)
            }
        }()
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(row.id)
                .font(.meta)
                .foregroundStyle(palette.muted.color)
                .frame(width: 30, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.label).font(.ui).foregroundStyle(row.state == .missed ? palette.red.color : palette.ink.color)
                Text(behaviour).font(.meta).foregroundStyle(palette.muted.color)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 5) {
                if row.state == .covered { IconView(icon: .check, size: 13) }
                Text(state)
            }
            .font(.meta)
            .foregroundStyle(color)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .overlay(alignment: .top) { if !first { Hairline() } }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Budgets & Stop

private struct BudgetsTab: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        Lede(text: copy(.budgetsLede))
        FormBox {
            FormRow(first: true, title: copy(.spentToday), detail: spent(copy)) { EmptyView() }
            ForEach(budgetRows) { agent in
                FormRow(title: TeamMember.displayName(agent.name), detail: budgetDetail(agent, copy)) {
                    BudgetMeter(used: agent.budgetUsed, hit: agent.budgetHit)
                }
                .accessibilityIdentifier("settings-budget-\(agent.name)")
            }
            FormRow(title: copy(.capsTitle), detail: copy(.capsHint)) { EmptyView() }
        }
        FormBox {
            FormRow(first: true, title: copy(.stopRowTitle), detail: copy(.stopRowHint), leading: AnyView(IconView(icon: .stop).foregroundStyle(palette.red.color))) {
                if shell.stopped {
                    Button(copy(.resume)) { shell.resumeAll() }
                        .buttonStyle(AuxButtonStyle(kind: .stopFilled))
                        .disabled(shell.stopInFlight)
                        .accessibilityLabel(copy(.resume)).accessibilityIdentifier("settings-stop-resume")
                } else {
                    Button(copy(.stopNow)) { shell.stopAll() }
                        .buttonStyle(AuxButtonStyle(kind: .stop))
                        .disabled(shell.stopInFlight)
                        .accessibilityLabel(copy(.stopNow)).accessibilityIdentifier("settings-stop-all")
                }
            }
        }
        .onAppear { shell.loadUsage() }
    }

    /// One row per capped agent; `Store.applyUsage` has already set the ratio.
    private var budgetRows: [Agent] {
        guard case .loaded(let day) = shell.usage else { return [] }
        let capped = Set(day.agents.filter { $0.caps?.isUnset == false }.map(\.agent))
        return shell.store.agents.filter { capped.contains($0.name) }
    }

    private func budgetDetail(_ agent: Agent, _ copy: Copy) -> String {
        let percent = copy.f(.budgetUsedPercent, Self.percent(agent.budgetUsed))
        return agent.budgetHit ? percent + " · " + copy(.budgetCapHit) : percent
    }

    static func percent(_ ratio: Double) -> Int {
        min(100, max(0, Int((ratio * 100).rounded())))
    }

    private func spent(_ copy: Copy) -> String {
        switch shell.usage {
        case .loaded(let day):
            let dollars = String(format: "$%.2f", Double(day.total.usdCents) / 100)
            return copy.f(.spentTodayValue, dollars, Self.count(day.total.tokensIn), Self.count(day.total.tokensOut))
        case .loading: return copy(.loading)
        case .failed: return copy(.loadFailed)
        case .unavailable: return copy(.unavailable)
        }
    }

    static func count(_ value: UInt64) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.locale = Locale(identifier: "en_US")
        return formatter.string(from: NSNumber(value: value)) ?? "\(value)"
    }
}

/// A 64×4 daily-cap bar: ink while there is room, amber only on attention
/// (the daemon's 80 % line or a reached cap). The row's words carry the meaning.
private struct BudgetMeter: View {
    let used: Double
    let hit: Bool
    @Environment(\.palette) private var palette

    var body: some View {
        Capsule().fill(palette.line.color)
            .overlay(alignment: .leading) {
                Capsule().fill(hit || used >= 0.8 ? palette.amber.color : palette.ink3.color)
                    .frame(width: 64 * min(1, max(0.03, used)))
            }
            .frame(width: 64, height: 4)
            .accessibilityHidden(true)
    }
}
