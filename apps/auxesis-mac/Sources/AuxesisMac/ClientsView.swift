// Clients: the list on the left, the open card on the right.
// The card is identity, then Overview (follow-ups, notes), Timeline and
// Memory, with "Ask Clients" (`/client` in the Clients thread) and Edit; in
// edit mode Save and Cancel take their place in the same header row. The
// editor writes the party on this Mac; the next brain call replaces every
// name, address and number on it (the green line says so). Keyboard: ⌘F
// filters, ↑/↓ move through the list, Return opens the first match. Moving
// away from an open editor keeps its draft for that client. Import… (above the
// list, and on the empty state) reads a vCard or CSV file on this Mac through a
// preview first; see ClientImportSheet.
import AuxesisKit
import SwiftUI

struct ClientsView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    /// The import sheet, open while a file is being previewed or imported.
    @State private var importing: ClientImportModel?

    var body: some View {
        let copy = Copy(language: language)
        Group {
            switch shell.clients {
            case .loading:
                LoadNote(text: copy(.loading))
            case .unavailable:
                LoadNote(text: copy(.unavailable))
            case .failed:
                RetryNote(text: copy(.clientsLoadFailed)) { shell.loadClients() }
            case .loaded(let list):
                VStack(spacing: 0) {
                    importBar
                    if list.isEmpty {
                        DomainPlaceholderView(member: .clients)
                    } else {
                        ClientList(clients: list)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .onAppear { shell.loadClients() }
        .sheet(item: $importing) { model in
            ClientImportSheet(model: model)
        }
    }

    /// Import… sits above both the list and the empty state: an empty Clients fills up from here.
    private var importBar: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Button(L10n.t(.importOpen, language)) { startImport() }
                    .buttonStyle(AuxButtonStyle())
                    .accessibilityLabel(L10n.t(.importOpen, language)).accessibilityIdentifier("clients-import")
            }
            .padding(.horizontal, 12)
            .frame(height: 40)
            Hairline()
        }
    }

    /// The picker first; a cancelled picker opens nothing. The preview starts at once.
    private func startImport() {
        guard let path = ContactsFilePicker.pick(language: language) else { return }
        let model = shell.clientImport(path: path, language: language)
        importing = model
        model.preview()
    }
}

/// A quiet line with a Retry button (no spinners in content).
private struct RetryNote: View {
    let text: String
    let retry: () -> Void
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        VStack(spacing: 12) {
            HStack(alignment: .top, spacing: 8) {
                IconView(icon: .alert).foregroundStyle(palette.red.color).padding(.top, 1)
                Text(text)
                    .font(.ui)
                    .foregroundStyle(palette.ink2.color)
                    .lineSpacing(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button(Copy(language: language)(.retry), action: retry)
                .buttonStyle(AuxButtonStyle())
                .accessibilityLabel(Copy(language: language)(.retry)).accessibilityIdentifier("clients-retry")
        }
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }
}

// MARK: - List

private struct ClientList: View {
    let clients: [ClientSummary]
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var filter = ""
    @FocusState private var filterFocused: Bool

    var body: some View {
        let copy = Copy(language: language)
        let shown = ClientText.filter(clients, filter)
        VStack(spacing: 0) {
            HStack(spacing: 7) {
                IconView(icon: .search, size: 14).foregroundStyle(palette.muted.color)
                TextField(copy(.clientsFilter), text: $filter)
                    .textFieldStyle(.plain)
                    .font(.ui)
                    .foregroundStyle(palette.ink.color)
                    .focused($filterFocused)
                    .onSubmit { if let first = shown.first { shell.selectClient(first.id) } }
                    .onKeyPress(.downArrow) { move(1, in: shown) }
                    .onKeyPress(.upArrow) { move(-1, in: shown) }
                    .accessibilityLabel(copy(.clientsFilter))
                    .accessibilityIdentifier("clients-filter")
            }
            .padding(.horizontal, 10)
            .frame(height: 30)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(palette.hover.color))
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            Hairline()
            ScrollView {
                LazyVStack(spacing: 1) {
                    ForEach(shown) { client in
                        ClientRowView(client: client, selected: shell.selectedClient == client.id,
                                      unsaved: shell.clientDrafts[client.id] != nil) {
                            shell.selectClient(client.id)
                        }
                    }
                    if shown.isEmpty {
                        Text(copy(.clientsNoMatch))
                            .font(.ui)
                            .foregroundStyle(palette.muted.color)
                            .padding(.top, 24)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 8)
            }
            .focusable()
            .focusEffectDisabled()
            .onMoveCommand { direction in
                switch direction {
                case .down: _ = move(1, in: shown)
                case .up: _ = move(-1, in: shown)
                default: break
                }
            }
        }
    }

    private func move(_ step: Int, in shown: [ClientSummary]) -> KeyPress.Result {
        guard let next = ClientText.move(from: shell.selectedClient, by: step, in: shown) else { return .ignored }
        if next != shell.selectedClient { shell.selectClient(next) }
        return .handled
    }
}

private struct ClientRowView: View {
    let client: ClientSummary
    let selected: Bool
    /// An edit kept for this client, not saved yet (opening it reopens the editor).
    let unsaved: Bool
    let action: () -> Void
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var hovering = false

    var body: some View {
        let copy = Copy(language: language)
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Initials(name: client.displayName, company: client.kind == "company", side: 32)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(client.displayName)
                            .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                            .foregroundStyle(palette.ink.color)
                            .lineLimit(1)
                        Spacer(minLength: 4)
                        Text(ClientText.day(client.lastInteractionAt, now: Date(), language: language))
                            .font(.meta)
                            .monospacedDigit()
                            .foregroundStyle(palette.muted.color)
                    }
                    if unsaved {
                        Text(copy(.clientUnsaved))
                            .font(.meta)
                            .foregroundStyle(palette.ink2.color)
                            .lineLimit(1)
                    } else if let next = client.nextFollowup {
                        Text(ClientText.due(next.due, now: Date(), language: language) + " · " + next.reason)
                            .font(.meta)
                            .foregroundStyle(palette.ink2.color)
                            .lineLimit(1)
                    } else {
                        Text(ClientText.contactLine(client))
                            .font(.meta)
                            .foregroundStyle(palette.muted.color)
                            .lineLimit(1)
                    }
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(selected ? palette.selection.color : hovering ? palette.hover.color : .clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel(client.displayName).accessibilityIdentifier("client-row-\(client.id)")
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

/// The round mark of a client: two initials, hairline outline. A company
/// gets a rounded square, a person a circle.
private struct Initials: View {
    let name: String
    let company: Bool
    var side: CGFloat = 32
    @Environment(\.palette) private var palette

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: company ? side * 0.28 : side / 2, style: .continuous)
        Text(ClientText.initials(name))
            .font(.hk(side * 0.36, Theme.Weight.semibold))
            .foregroundStyle(palette.ink2.color)
            .frame(width: side, height: side)
            .background(shape.fill(palette.raise.color))
            .overlay(shape.strokeBorder(palette.line2.color, lineWidth: 1))
            .accessibilityHidden(true)
    }
}

// MARK: - Card

struct ClientCardView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        Group {
            if shell.selectedClient == nil {
                LoadNote(text: copy(.clientsPick))
            } else {
                switch shell.clientCard {
                case .loading: LoadNote(text: copy(.loading))
                case .unavailable: LoadNote(text: copy(.unavailable))
                case .failed:
                    if shell.clientGone {
                        LoadNote(text: copy(.clientGone))
                    } else {
                        RetryNote(text: copy(.loadFailed)) { shell.loadClientCard() }
                    }
                case .loaded(let card):
                    ScrollView {
                        content(card, copy)
                            .frame(maxWidth: 640, alignment: .leading)
                            .padding(.horizontal, 32)
                            .padding(.top, 24)
                            .padding(.bottom, 40)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .id(card.party.id)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    @ViewBuilder private func content(_ card: ClientCard, _ copy: Copy) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            identity(card.party, copy)
            if shell.clientEditing {
                if let error = shell.clientError {
                    ErrorLine(text: copy(error)).padding(.top, 14)
                }
                ClientEditor()
                    .padding(.top, 20)
                    // Locked while the save is in flight: the header's Save
                    // reads "Saving" and the fields dim; nothing typed is lost.
                    .disabled(shell.clientSaving)
                    .opacity(shell.clientSaving ? 0.55 : 1)
                    .animation(.easeOut(duration: 0.15), value: shell.clientSaving)
            } else {
                if shell.clientSaved {
                    HStack(spacing: 6) {
                        IconView(icon: .check, size: 14)
                        Text(copy(.clientSaved))
                    }
                    .font(.ui)
                    .foregroundStyle(palette.ink.color)
                    .padding(.top, 14)
                }
                if let error = shell.clientError {
                    ErrorLine(text: copy(error)).padding(.top, 14)
                }
                facts(card.party, copy)
                    .padding(.top, 18)
                KeptLine(text: copy(.clientKept))
                    .padding(.top, 14)
                Segmented(options: [
                    (ClientTab.overview, copy(.clientOverview), "client-tab-overview"),
                    (ClientTab.timeline, copy(.clientTimeline), "client-tab-timeline"),
                    (ClientTab.memory, copy(.memory), "client-tab-memory"),
                ], selection: $shell.clientTab)
                .padding(.top, 22)
                .padding(.bottom, 6)
                switch shell.clientTab {
                case .overview: overview(card, copy)
                case .timeline: timeline(card, copy)
                case .memory: memory(card, copy)
                }
            }
        }
    }

    private func identity(_ party: ClientParty, _ copy: Copy) -> some View {
        HStack(alignment: .center, spacing: 14) {
            Initials(name: party.displayName, company: party.kind == "company", side: 52)
            Text(party.displayName)
                .font(.hk(Theme.Text.heading, Theme.Weight.strong))
                .foregroundStyle(palette.ink.color)
                .lineLimit(2)
                .textSelection(.enabled)
            Spacer(minLength: 12)
            if shell.clientEditing {
                Button(copy(.clientCancel)) { shell.cancelClientEdit() }
                    .buttonStyle(AuxButtonStyle())
                    .keyboardShortcut(.cancelAction)
                    .disabled(shell.clientSaving)
                    .accessibilityLabel(copy(.clientCancel)).accessibilityIdentifier("client-edit-cancel")
                Button(shell.clientSaving ? copy(.saving) : copy(.clientSave)) {
                    Task { await shell.saveClientDraft() }
                }
                .buttonStyle(AuxButtonStyle(kind: .primary))
                .keyboardShortcut("s", modifiers: .command)
                .disabled(shell.clientSaving || !(shell.clientDraft?.edit.isValid ?? false))
                .accessibilityLabel(shell.clientSaving ? copy(.saving) : copy(.clientSave)).accessibilityIdentifier("client-edit-save")
            } else {
                Button(copy(.clientEdit)) { shell.beginClientEdit() }
                    .buttonStyle(AuxButtonStyle())
                    .keyboardShortcut("e", modifiers: .command)
                    .accessibilityLabel(copy(.clientEdit)).accessibilityIdentifier("client-edit")
                Button { shell.briefClient() } label: {
                    Text(copy(.clientBrief))
                }
                .buttonStyle(AuxButtonStyle(kind: .primary))
                .help(copy(.clientBriefHelp))
                .accessibilityLabel(copy(.clientBrief)).accessibilityIdentifier("client-ask")
            }
        }
    }

    private func facts(_ party: ClientParty, _ copy: Copy) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            FactRow(label: copy(.clientEmails), values: party.emails)
            FactRow(label: copy(.clientPhones), values: party.phones.map(ClientText.phone))
            FactRow(label: copy(.clientAddresses), values: party.addresses)
            FactRow(label: copy(.clientAliases), values: party.nameVariants)
            FactRow(label: copy(.clientTags), values: party.tags.isEmpty ? [] : [party.tags.joined(separator: " · ")])
        }
    }

    @ViewBuilder private func overview(_ card: ClientCard, _ copy: Copy) -> some View {
        // The client's own zone, when the card carries one.
        if let zone = card.party.timeZone, !zone.isEmpty {
            FactRow(label: copy(.clientTimeZone), values: [zone])
                .padding(.top, 14)
        }
        SectionTitle(text: copy(.clientNext))
        if card.followups.isEmpty {
            Muted(text: copy(.clientNoFollowups))
        } else {
            VStack(spacing: 0) {
                ForEach(card.followups) { followup in
                    DatedRow(day: ClientText.day(followup.due, now: Date(), language: language), text: followup.reason, detail: nil)
                }
            }
        }
        SectionTitle(text: copy(.clientNotes))
        if card.party.notes.isEmpty {
            Muted(text: copy(.clientNoNotes))
        } else {
            Text(card.party.notes)
                .font(.ui)
                .foregroundStyle(palette.ink2.color)
                .lineSpacing(4)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder private func timeline(_ card: ClientCard, _ copy: Copy) -> some View {
        if card.timeline.isEmpty {
            Muted(text: copy(.clientTimelineEmpty)).padding(.top, 10)
        } else {
            VStack(spacing: 0) {
                ForEach(card.timeline) { item in
                    DatedRow(day: ClientText.day(item.at, now: Date(), language: language), text: ClientText.timeline(item, language: language), detail: kindLabel(item.kind, copy))
                }
            }
            .padding(.top, 8)
        }
    }

    @ViewBuilder private func memory(_ card: ClientCard, _ copy: Copy) -> some View {
        Muted(text: copy.f(.clientMemoryLede, ClientText.firstName(card.party)))
            .padding(.top, 10)
            .padding(.bottom, 6)
        if card.memory.isEmpty {
            Muted(text: copy(.clientMemoryEmpty))
        } else {
            VStack(spacing: 0) {
                ForEach(card.memory) { item in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(item.text)
                                .font(.ui)
                                .foregroundStyle(palette.ink.color)
                                .lineSpacing(3)
                                .fixedSize(horizontal: false, vertical: true)
                            if !item.source.isEmpty {
                                Text(item.source).font(.meta).foregroundStyle(palette.muted.color)
                            }
                        }
                        Spacer(minLength: 8)
                        ForgetButton(title: copy(.forget), identifier: "client-memory-forget-\(item.id)") { shell.forgetClientMemory(item) }
                    }
                    .padding(.vertical, 10)
                    .overlay(alignment: .top) { Hairline() }
                }
            }
        }
    }

    private func kindLabel(_ kind: String, _ copy: Copy) -> String {
        switch kind {
        case "mail": return copy(.kindMail)
        case "meeting": return copy(.kindMeeting)
        case "call": return copy(.kindCall)
        case "document": return copy(.kindDocument)
        default: return copy(.kindNote)
        }
    }
}

private struct FactRow: View {
    let label: String
    let values: [String]
    @Environment(\.palette) private var palette

    var body: some View {
        if !values.isEmpty {
            HStack(alignment: .firstTextBaseline, spacing: 0) {
                Text(label)
                    .font(.ui)
                    .foregroundStyle(palette.muted.color)
                    .frame(width: 120, alignment: .leading)
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(values.enumerated()), id: \.offset) { _, value in
                        Text(value)
                            .font(.ui)
                            .monospacedDigit()
                            .foregroundStyle(palette.ink.color)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }
}

private struct SectionTitle: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        Text(text)
            .font(.hk(Theme.Text.ui, Theme.Weight.strong))
            .foregroundStyle(palette.ink.color)
            .padding(.top, 18)
            .padding(.bottom, 6)
    }
}

private struct Muted: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        Text(text)
            .font(.ui)
            .foregroundStyle(palette.muted.color)
            .lineSpacing(3)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A day on the left, tabular; the text, and a muted detail under it.
private struct DatedRow: View {
    let day: String
    let text: String
    let detail: String?
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Text(day)
                .font(.ui)
                .monospacedDigit()
                .foregroundStyle(palette.muted.color)
                .frame(width: 120, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(text)
                    .font(.ui)
                    .foregroundStyle(palette.ink.color)
                    .lineSpacing(3)
                    .fixedSize(horizontal: false, vertical: true)
                if let detail {
                    Text(detail).font(.meta).foregroundStyle(palette.muted.color)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 9)
        .overlay(alignment: .top) { Hairline() }
    }
}

private struct ErrorLine: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            IconView(icon: .alert, size: 15).foregroundStyle(palette.red.color).padding(.top, 1)
            Text(text)
                .font(.ui)
                .foregroundStyle(palette.red.color)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Editor

/// Edit in place: the card's identity as fields. Save and Cancel sit in the
/// card's header row; the text lives in the shell's draft. Lists are one
/// value per line; empty lines are dropped before the save.
private struct ClientEditor: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 14) {
            field(copy(.clientName), hint: nil) {
                TextField(copy(.clientName), text: draft(\.name))
                    .textFieldStyle(.plain)
                    .font(.ui)
                    .padding(.horizontal, 9)
                    .frame(height: 30)
                    .boxed(palette)
                    .accessibilityLabel(copy(.clientName)).accessibilityIdentifier("client-edit-name")
            }
            field(copy(.clientAliases), hint: copy(.clientAliasHint)) { lines(draft(\.aliases), rows: 2, label: copy(.clientAliases), identifier: "client-edit-aliases") }
            field(copy(.clientEmails), hint: copy(.clientOnePerLine)) { lines(draft(\.emails), rows: 2, label: copy(.clientEmails), identifier: "client-edit-emails") }
            field(copy(.clientPhones), hint: copy(.clientPhoneHint)) { lines(draft(\.phones), rows: 2, label: copy(.clientPhones), identifier: "client-edit-phones") }
            field(copy(.clientAddresses), hint: copy(.clientOnePerLine)) { lines(draft(\.addresses), rows: 2, label: copy(.clientAddresses), identifier: "client-edit-addresses") }
            field(copy(.clientTags), hint: copy(.clientOnePerLine)) { lines(draft(\.tags), rows: 2, label: copy(.clientTags), identifier: "client-edit-tags") }
            field(copy(.clientNotes), hint: nil) { lines(draft(\.notes), rows: 4, label: copy(.clientNotes), identifier: "client-edit-notes") }
        }
    }

    private func draft(_ keyPath: WritableKeyPath<ClientDraft, String>) -> Binding<String> {
        Binding(
            get: { shell.clientDraft?[keyPath: keyPath] ?? "" },
            set: { shell.setClientDraft(keyPath, $0) }
        )
    }

    private func field<Content: View>(_ label: String, hint: String?, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                .foregroundStyle(palette.ink.color)
            content()
            if let hint {
                Text(hint)
                    .font(.meta)
                    .foregroundStyle(palette.muted.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func lines(_ text: Binding<String>, rows: Int, label: String, identifier: String) -> some View {
        TextEditor(text: text)
            .font(.ui)
            .scrollContentBackground(.hidden)
            .padding(.horizontal, 5)
            .padding(.vertical, 6)
            .frame(height: CGFloat(rows) * 20 + 14)
            .boxed(palette)
            .accessibilityLabel(label).accessibilityIdentifier(identifier)
    }
}

private extension View {
    func boxed(_ palette: Palette) -> some View {
        let shape = RoundedRectangle(cornerRadius: 7, style: .continuous)
        return self
            .foregroundStyle(palette.ink.color)
            .background(shape.fill(palette.work.color))
            .overlay(shape.strokeBorder(palette.line2.color, lineWidth: 1))
    }
}
