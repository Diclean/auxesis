// The non-thread views in the middle column (prototype `.view`, 900 wide):
// Waiting for you, the Ledger, and the honest empty states for Clients (E3,
// when there is no client yet) and Documents (E4).
import AuxesisKit
import SwiftUI

/// `.view`: title, lede, content, centred at 900.
struct ViewPage<Content: View>: View {
    let title: String
    let lede: String
    @ViewBuilder let content: () -> Content
    @Environment(\.palette) private var palette

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text(title)
                    .font(.hk(Theme.Text.heading, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                    .padding(.bottom, 4)
                Text(lede)
                    .font(.ui)
                    .foregroundStyle(palette.muted.color)
                    .lineSpacing(3)
                    .padding(.bottom, 18)
                content()
            }
            .frame(maxWidth: Theme.viewWidth, alignment: .leading)
            .padding(.horizontal, 32)
            .padding(.top, 24)
            .padding(.bottom, 40)
            .frame(maxWidth: .infinity)
        }
    }
}

/// `.seg`: the small segmented control.
struct Segmented<Value: Hashable>: View {
    let options: [(Value, String, String)]
    @Binding var selection: Value
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Array(options.enumerated()), id: \.offset) { _, option in
                let (value, title, identifier) = option
                let on = value == selection
                Button { selection = value } label: {
                    Text(title)
                        .font(.hk(Theme.Text.ui, on ? Theme.Weight.semibold : Theme.Weight.regular))
                        .foregroundStyle(on ? palette.ink.color : palette.ink2.color)
                        .padding(.horizontal, 10)
                        .frame(height: 24)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(on ? palette.work.color : .clear)
                                .shadow(color: .black.opacity(on ? 0.08 : 0), radius: 1, y: 1)
                        )
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(title).accessibilityIdentifier(identifier)
                .accessibilityAddTraits(on ? [.isSelected] : [])
            }
        }
        .padding(2)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(palette.hover.color))
    }
}

/// Loading / failed / unavailable, in one quiet line (no spinners in content).
struct LoadNote: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        Text(text)
            .font(.ui)
            .foregroundStyle(palette.muted.color)
            .lineSpacing(3)
            .frame(maxWidth: .infinity)
            .multilineTextAlignment(.center)
            .padding(.vertical, 40)
    }
}

// MARK: - Waiting for you

struct WaitingView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        // The rows and the header count the same cards: the ones that still wait.
        let shown = shell.waitingListApprovals
        let open = shown
        let agents = Set(open.map(\.agent))
        ViewPage(
            title: copy(.waitingForYou),
            lede: open.isEmpty ? copy(.waitingEmpty)
                : open.count == 1 ? copy(.waitingLedeOne)
                : agents.count == 1 ? copy.f(.waitingLedeOneAgent, open.count)
                : copy.f(.waitingLede, open.count, agents.count)
        ) {
            ForEach(TeamMember.all.filter { member in shown.contains { $0.agent == member.id } }) { member in
                HStack(spacing: 8) {
                    AgentTile(member: member, size: .sm)
                    Text(member.name).font(.hk(Theme.Text.ui, Theme.Weight.strong))
                        + Text(" · " + (shell.brainLabel(of: member.id) ?? copy(.brainDefault))).font(.ui).foregroundColor(palette.muted.color)
                }
                .foregroundStyle(palette.ink.color)
                .padding(.top, 22)
                .padding(.bottom, 6)
                ForEach(Array(shown.filter { $0.agent == member.id }.enumerated()), id: \.element.id) { index, approval in
                    if index > 0 { Hairline() }
                    Button { shell.store.focus(approval.id) } label: {
                        HStack(alignment: .top, spacing: 8) {
                            let waits = shell.phase(for: approval).isDraft
                            Image(systemName: waits ? "clock.fill" : "clock").foregroundStyle(waits ? palette.amber.color : palette.muted.color)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(TeamMember.displayName(approval.agent) + " · " + shell.rowHeadline(for: approval))
                                    .font(.hk(Theme.Text.ui, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
                                Text(shell.rowStatus(for: approval)).font(.meta).foregroundStyle(palette.muted.color)
                            }
                            Spacer()
                            if shell.store.focusedApprovalId == approval.id { Image(systemName: "chevron.right").foregroundStyle(palette.blue.color) }
                        }
                        .padding(.vertical, 9)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .listRowBackground(shell.store.focusedApprovalId == approval.id ? palette.blueSoft.color : .clear)
                    .accessibilityLabel("\(TeamMember.displayName(approval.agent)) · \(shell.rowHeadline(for: approval))").accessibilityIdentifier("waiting-approval-row-\(approval.id)")
                    .accessibilityAddTraits(shell.store.focusedApprovalId == approval.id ? [.isSelected] : [])
                }
            }
        }
        .onMoveCommand { direction in
            switch direction {
            case .down: shell.store.focusNext()
            case .up: shell.store.focusPrev()
            default: break
            }
        }
        .onKeyPress("j") {
            guard ApprovalKeyboardPolicy.shouldHandle(.nextWaiting, focus: .waitingList, textFieldFocused: AppTextFocus.isFocused) else { return .ignored }
            shell.store.focusNext()
            return .handled
        }
        .onKeyPress("k") {
            guard ApprovalKeyboardPolicy.shouldHandle(.previousWaiting, focus: .waitingList, textFieldFocused: AppTextFocus.isFocused) else { return .ignored }
            shell.store.focusPrev()
            return .handled
        }
    }
}

// MARK: - Ledger

struct LedgerView: View {
    enum Tab: Hashable { case done, planned }

    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var tab: Tab = .done
    @State private var agent = ""

    var body: some View {
        let copy = Copy(language: language)
        ViewPage(title: copy(.ledger), lede: copy(.ledgerLede)) {
            HStack(spacing: 12) {
                Segmented(options: [
                    (Tab.done, copy(.ledgerDone), "ledger-tab-done"),
                    (Tab.planned, copy(.ledgerPlanned), "ledger-tab-planned"),
                ], selection: $tab)
                Spacer()
                Picker(copy(.colAgent), selection: $agent) {
                    Text(copy(.allAgents)).tag("")
                    ForEach(TeamMember.all) { member in
                        Text(member.name).tag(member.id)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .fixedSize()
                .font(.ui)
                .accessibilityLabel(copy(.colAgent))
                .accessibilityIdentifier("ledger-agent-filter")
            }
            .padding(.bottom, 14)
            switch tab {
            case .done: done(copy)
            case .planned: plannedList(copy)
            }
        }
        .onAppear { if shell.ledgerOpensPlanned { tab = .planned; shell.ledgerOpensPlanned = false }; shell.loadLedger() }
    }

    @ViewBuilder private func done(_ copy: Copy) -> some View {
        switch shell.ledger {
        case .loading: LoadNote(text: copy(.loading))
        case .failed: LoadNote(text: copy(.loadFailed))
        case .unavailable: LoadNote(text: copy(.unavailable))
        case .loaded(let all):
            let rows = all.filter { agent.isEmpty || $0.agent == agent }
            if rows.isEmpty {
                LoadNote(text: copy(.ledgerEmpty))
            } else {
                LedgerTable(columns: [copy(.colWhen), copy(.colAgent), copy(.colWhat), copy(.colSkill)]) {
                    ForEach(rows) { entry in
                        LedgerRow(entry: entry)
                    }
                }
            }
        }
    }

    @ViewBuilder private func plannedList(_ copy: Copy) -> some View {
        switch shell.planned {
        case .loading: LoadNote(text: copy(.loading))
        case .failed: LoadNote(text: copy(.loadFailed))
        case .unavailable: LoadNote(text: copy(.unavailable))
        case .loaded(let all):
            let rows = all.filter { agent.isEmpty || $0.agent == agent }
            if rows.isEmpty {
                LoadNote(text: copy(.ledgerPlannedEmpty))
            } else {
                LedgerTable(columns: [copy(.colSchedule), copy(.colAgent), copy(.colWhat), ""]) {
                    ForEach(rows) { job in
                        TableRow(cells: [
                            AnyView(Text(job.schedule).foregroundStyle(palette.muted.color)),
                            AnyView(Text(TeamMember.displayName(job.agent))),
                            AnyView(VStack(alignment: .leading, spacing: 2) {
                                Text(job.name)
                                if let mark = JobHealthMark.make(job, language: language) {
                                    JobHealthLine(mark: mark)
                                }
                            }),
                            AnyView(Text(job.nextRunAt.flatMap(TimeText.parse).map { TimeText.short($0, now: Date(), language: language) } ?? "")
                                .foregroundStyle(palette.muted.color)),
                        ])
                    }
                }
            }
        }
    }
}

/// Column widths: when · agent · what · skill (+ hash).
private let ledgerWidths: [CGFloat?] = [92, 96, nil, 210]

private struct LedgerTable<Rows: View>: View {
    let columns: [String]
    @ViewBuilder let rows: () -> Rows
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                ForEach(Array(columns.enumerated()), id: \.offset) { index, title in
                    cell(Text(title).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.muted.color), index)
                }
            }
            .padding(.vertical, 6)
            .overlay(alignment: .bottom) { Hairline() }
            rows()
        }
    }

    private func cell<V: View>(_ view: V, _ index: Int) -> some View {
        Group {
            if let width = ledgerWidths[index] {
                view.frame(width: width, alignment: .leading)
            } else {
                view.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 10)
    }
}

private struct TableRow: View {
    let cells: [AnyView]
    @Environment(\.palette) private var palette
    @State private var hovering = false

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            ForEach(Array(cells.enumerated()), id: \.offset) { index, view in
                Group {
                    if let width = ledgerWidths[index] {
                        view.frame(width: width, alignment: .leading)
                    } else {
                        view.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.horizontal, 10)
            }
        }
        .font(.ui)
        .foregroundStyle(palette.ink.color)
        .padding(.vertical, 9)
        .background(hovering ? palette.hover.color : .clear)
        .overlay(alignment: .bottom) { Hairline() }
        .onHover { hovering = $0 }
    }
}

private struct LedgerRow: View {
    let entry: LedgerEntry
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let when = TimeText.parse(entry.at).map { TimeText.short($0, now: Date(), language: language) + ($0.isToday ? "" : " " + TimeText.clock($0)) } ?? entry.at
        TableRow(cells: [
            AnyView(Text(when).foregroundStyle(palette.muted.color)),
            AnyView(Text(entry.agent.map(TeamMember.displayName) ?? "—")),
            AnyView(Text(LedgerText.what(entry, language: language)).lineSpacing(2)),
            AnyView(skillCell(copy)),
        ])
    }

    @ViewBuilder private func skillCell(_ copy: Copy) -> some View {
        if entry.skill != nil || entry.skillHash != nil {
            VStack(alignment: .leading, spacing: 2) {
                if let skill = entry.skill {
                    Text(skill).foregroundStyle(palette.ink.color)
                }
                if let hash = entry.skillHash {
                    Text(Self.short(hash))
                        .font(.meta)
                        .foregroundStyle(palette.muted.color)
                        .textSelection(.enabled)
                        .help(hash + "\n" + copy(.ledgerHashHelp))
                        .accessibilityLabel(hash)
                }
            }
        } else {
            Text("")
        }
    }

    /// `sha256:9f2c41ab…` → `sha256 9f2c41ab`.
    static func short(_ hash: String) -> String {
        let parts = hash.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return String(hash.prefix(16)) }
        return parts[0] + " " + String(parts[1].prefix(8))
    }
}

private extension Date {
    var isToday: Bool { Calendar.current.isDateInToday(self) }
}

// MARK: - Clients and Documents (E3, E4)

struct DomainPlaceholderView: View {
    let member: TeamMember
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let isClients = member.id == TeamMember.clients.id
        VStack(spacing: 0) {
            IconTile(icon: isClients ? .people : .doc, side: 46)
                .padding(.bottom, 14)
            Text(isClients ? copy(.clients) : copy(.documents))
                .font(.hk(Theme.Text.heading, Theme.Weight.strong))
                .foregroundStyle(palette.ink.color)
                .padding(.bottom, 6)
            Text(isClients ? copy(.clientsEmpty) : copy(.documentsEmpty))
                .font(.body15)
                .foregroundStyle(palette.muted.color)
                .lineSpacing(4)
                .padding(.bottom, 16)
            Button(isClients ? copy(.clientsAsk) : copy(.documentsAsk)) { shell.go(.agent(member.id)) }
                .buttonStyle(AuxButtonStyle())
                .accessibilityLabel(isClients ? copy(.clientsAsk) : copy(.documentsAsk)).accessibilityIdentifier(isClients ? "clients-ask" : "documents-ask")
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .padding(.top, 110)
    }
}
