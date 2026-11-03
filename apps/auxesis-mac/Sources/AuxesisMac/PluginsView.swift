// Settings › Plugins (M6-4): see what a plugin may read, write and reach before any
// Install, then one preview and one yes. Browsing only reads lists: nothing starts.
import AuxesisKit
import SwiftUI

struct PluginsTab: View {
    @ObservedObject var store: Store
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    /// The open row: "s:<server id>" or "c:<catalog id>".
    @State private var open: String?
    /// The short list: recommended entries not installed yet.
    private var shortList: [McpCatalogEntry] {
        let installed = Set(store.mcpServers.map(\.id))
        return store.mcpCatalog.filter { $0.tier == "recommended" && !installed.contains($0.id) }
    }
    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 0) {
            Lede(text: copy(.pluginsLede))
            if store.mcpFailed { Lede(text: copy(.loadFailed)) }
            heading(copy(.pluginsInstalled))
            FormBox {
                if store.mcpServers.isEmpty { FormRow(first: true, title: copy(.pluginsEmpty)) { EmptyView() } }
                ForEach(Array(store.mcpServers.enumerated()), id: \.element.id) { installedRow($1, first: $0 == 0, copy) }
            }
            heading(copy(.pluginsAvailable))
            FormBox {
                ForEach(Array(shortList.enumerated()), id: \.element.id) { catalogRow($1, first: $0 == 0, copy) }
            }
        }
        .task {
            await store.loadPlugins()
            if open == nil { open = shortList.first.map { "c:" + $0.id } }
        }
        .sheet(item: Binding(get: { store.pluginPreview }, set: { if $0 == nil { store.cancelPluginPreview() } })) { preview in
            PreviewSheet(store: store, preview: preview, name: store.mcpCatalog.first { $0.id == preview.id }?.name ?? preview.id)
                .environment(\.language, language)
        }
    }
    private func heading(_ text: String) -> some View {
        Text(text).font(.hk(Theme.Text.ui, Theme.Weight.strong)).foregroundStyle(palette.ink.color).padding(.bottom, 8)
    }
    /// On / Off in ink; Needs you in amber; Error in red. Always words and a glyph.
    private func stateLabel(_ state: PluginState) -> some View {
        glyph(state.icon, L10n.ui(state.key, language), tint: state.isAmber ? palette.amber.color : state == .error ? palette.red.color : nil)
            .padding(.horizontal, 7).padding(.vertical, 2).background(Capsule().fill(state.isAmber ? palette.amberSoft.color : .clear))
    }
    /// A monochrome glyph and its words.
    private func glyph(_ icon: Icon, _ text: String, tint: Color? = nil) -> some View {
        HStack(spacing: 4) {
            IconView(icon: icon, size: 12).foregroundStyle(tint ?? palette.ink3.color)
            Text(text).font(.meta).foregroundStyle(tint ?? palette.ink2.color).lineLimit(1)
        }
    }
    private func action(_ title: String, _ id: String, primary: Bool = false, _ perform: @escaping () -> Void) -> some View {
        Button(title, action: perform).buttonStyle(AuxButtonStyle(kind: primary ? .primary : .normal))
            .accessibilityLabel(title).accessibilityIdentifier(id)
    }
    private func catalogRow(_ entry: McpCatalogEntry, first: Bool, _ copy: Copy) -> some View {
        let access = PluginAccess(entry.access), connects = PluginText.connects(entry, language)
        return DisclosureRow(first: first, open: $open, key: "c:" + entry.id, title: entry.name, detail: PluginText.purpose(entry)) {
            HStack(spacing: 10) {
                glyph(access.icon, copy(access.key)).padding(.horizontal, 7).padding(.vertical, 2)
                    .overlay(Capsule().strokeBorder(palette.line2.color, lineWidth: 1))
                glyph(entry.transport == "stdio" ? .cpu : .link, connects)
            }
        } details: {
            Fact(copy(.pluginAccess), copy(access.key))
            Fact(copy(.pluginConnects), connects)
            Fact(copy(.pluginAuth), PluginText.auth(entry.auth, language))
            Fact(copy(.pluginData), PluginText.dataClass(entry.dataClass, language))
            Fact(copy(.pluginTools), copy(.pluginToolsLater))
            HStack { Spacer(); action(copy(.pluginInstall), "plugin-install-\(entry.id)", primary: true) { Task { await store.installPlugin(entry) } } }
        }
    }
    private func installedRow(_ server: McpServerView, first: Bool, _ copy: Copy) -> some View {
        let state = PluginState(server)
        let entry = store.mcpCatalog.first { $0.id == server.id }
        let tools = server.tools.map { (name: $0.name, access: $0.risk == "low" ? PluginAccess.read : .readWrite) }
        return DisclosureRow(first: first, open: $open, key: "s:" + server.id, title: entry?.name ?? server.id, detail: entry.map(PluginText.purpose)) {
            if state.isAmber { // "Needs you" opens the preview and its one yes.
                Button { Task { await store.reviewPlugin(server) } } label: { stateLabel(state) }
                    .buttonStyle(.plain).accessibilityLabel(copy(.pluginReview)).accessibilityIdentifier("plugin-needs-you-\(server.id)")
            } else { stateLabel(state) }
        } details: {
            if let entry { Fact(copy(.pluginConnects), PluginText.connects(entry, language)) }
            Fact(copy(.pluginAuth), PluginText.auth(server.auth, language))
            Fact(copy(.pluginData), PluginText.dataClass(server.dataClass, language))
            Fact(copy(.pluginTools), tools.isEmpty ? copy(.pluginToolsLater) : PluginText.tools(tools, language))
            HStack(spacing: 8) {
                Spacer()
                action(copy(.pluginRemove), "plugin-remove-\(server.id)") { store.deletePlugin(server) }
                if state == .on {
                    action(copy(.pluginTurnOff), "plugin-off-\(server.id)") { Task { await store.setPlugin(server, enabled: false) } }
                } else { // Turning on always goes through the preview and the one yes.
                    action(copy(.pluginReview), "plugin-review-\(server.id)", primary: true) { Task { await store.reviewPlugin(server) } }
                }
            }
        }
    }
}

/// The install preview: everything the one yes approves, then the yes.
struct PreviewSheet: View {
    @ObservedObject var store: Store
    let preview: McpApprovalPreview, name: String
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 0) {
            Text(copy.f(.pluginPreviewTitle, name)).font(.hk(Theme.Text.title, Theme.Weight.bold)).foregroundStyle(palette.ink.color).padding(.bottom, 6)
            Lede(text: copy(.pluginPreviewLede))
            target(copy).padding(.bottom, 10)
            VStack(alignment: .leading, spacing: 8) {
                Fact(copy(.pluginConnects), PluginText.runs(preview))
                Fact(copy(.pluginNetwork), PluginText.network(preview, language))
                Fact(copy(.pluginEnv), preview.env.isEmpty ? copy(.pluginNone) : preview.env.joined(separator: ", "))
                Fact(copy(.pluginData), PluginText.dataClass(preview.dataClass, language))
                Fact(copy(.pluginTools), PluginText.tools(preview.tools.map { ($0.name, PluginAccess($0.access)) }, language))
            }
            .padding(14)
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(palette.line.color, lineWidth: 1))
            HStack(spacing: 8) {
                if store.mcpFailureCode != nil { Text(copy(.pluginError)).font(.meta).foregroundStyle(palette.red.color) }
                Spacer()
                Button(copy(.apNotNow)) { store.cancelPluginPreview() }
                    .buttonStyle(AuxButtonStyle()).keyboardShortcut(.cancelAction)
                    .accessibilityLabel(copy(.apNotNow)).accessibilityIdentifier("plugin-preview-cancel")
                Button(copy(.pluginApprove)) { Task { await store.approvePluginPreview() } }
                    .buttonStyle(AuxButtonStyle(kind: .primary)).keyboardShortcut(.defaultAction)
                    .disabled(store.pluginPreviewAgent != store.pluginAgent)
                    .accessibilityLabel(copy(.pluginApprove)).accessibilityIdentifier("plugin-preview-approve")
            }
            .padding(.top, 18)
        }
        .padding(24)
        .frame(width: 520)
        .background(palette.work.color)
    }
    /// r1 (#532 P2): the agent that gets the tools, in words, with the team list to change it.
    /// The sentence keeps its order in each language: the picker stands where %@ is.
    private func target(_ copy: Copy) -> some View {
        let parts = copy(.pluginGivesTo).components(separatedBy: "%@").map { $0.trimmingCharacters(in: .whitespaces) }
        let sentence = copy.f(.pluginGivesTo, TeamMember.displayName(store.pluginAgent))
        return HStack(spacing: 6) {
            Text(parts.first ?? "").font(.ui).foregroundStyle(palette.ink.color)
            Picker(sentence, selection: Binding(get: { store.pluginAgent }, set: { agent in Task { await store.choosePluginAgent(agent) } })) {
                ForEach(TeamMember.all) { Text($0.name).tag($0.id) }
            }
            .labelsHidden().pickerStyle(.menu).fixedSize()
            .disabled(store.pluginPreviewCatalogID == nil || store.pluginPreviewAgent == nil)
            .accessibilityLabel(sentence).accessibilityIdentifier("plugin-preview-agent")
            if parts.count > 1, !parts[1].isEmpty { Text(parts[1]).font(.ui).foregroundStyle(palette.ink.color) }
        }
    }
}

/// One hairline row that opens in place to show its facts.
private struct DisclosureRow<Trailing: View, Details: View>: View {
    let first: Bool
    @Binding var open: String?
    let key: String, title: String, detail: String?
    @ViewBuilder let trailing: () -> Trailing
    @ViewBuilder let details: () -> Details
    @Environment(\.palette) private var palette
    var body: some View {
        let isOpen = open == key
        VStack(alignment: .leading, spacing: 8) {
            Button { open = isOpen ? nil : key } label: {
                HStack(spacing: 10) {
                    IconView(icon: isOpen ? .down : .fwd, size: 12).foregroundStyle(palette.ink3.color)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(title).font(.ui).foregroundStyle(palette.ink.color)
                        if let detail { Text(detail).font(.meta).foregroundStyle(palette.muted.color).lineLimit(1) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    trailing()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(title).accessibilityIdentifier("plugin-row-\(key)")
            .accessibilityAddTraits(isOpen ? [.isSelected] : [])
            if isOpen { VStack(alignment: .leading, spacing: 8) { details() }.padding(.leading, 22) }
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
        .overlay(alignment: .top) { if !first { Hairline() } }
    }
}

private struct Fact: View {
    let label: String, value: String
    init(_ label: String, _ value: String) { self.label = label; self.value = value }
    @Environment(\.palette) private var palette
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label).font(.meta).foregroundStyle(palette.ink3.color).frame(width: 140, alignment: .leading)
            Text(value).font(.ui).foregroundStyle(palette.ink.color).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
