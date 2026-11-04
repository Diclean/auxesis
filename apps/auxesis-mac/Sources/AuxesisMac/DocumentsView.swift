// Documents: the receipts Documents collected, newest first, one plain
// table (date · document · amount · client). The client cell is a menu: pick a
// client or remove it. Above, Export a period: dates, an optional client, then
// a folder on this Mac; the result says how many receipts and offers Show in
// Finder. Nothing here shows more than `GET /v1/docs` returns.
import AppKit
import AuxesisKit
import SwiftUI

struct DocumentsView: View {
    @ObservedObject var model: DocumentsPageModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var from = DocumentsView.lastMonth.start
    @State private var to = DocumentsView.lastMonth.end
    @State private var exportClient: Int64?

    /// Date · document · amount · client.
    private static let widths: [CGFloat?] = [95, nil, 85, 105]

    var body: some View {
        let copy = Copy(language: language)
        ViewPage(title: copy(.documents), lede: copy(.docsLede)) {
            exportBand(copy)
            filterRow(copy)
            content(copy)
        }
        .onAppear { Task { await model.reload() } }
    }

    // MARK: Export

    private func exportBand(_ copy: Copy) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(copy(.docsExportTitle)).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                Spacer(minLength: 8)
                Button(copy(.docsExportButton)) { chooseFolderAndExport(copy) }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .disabled(model.exporting)
                    .accessibilityLabel(copy(.docsExportButton)).accessibilityIdentifier("documents-export")
            }
            HStack(spacing: 8) {
                DayField(label: copy(.docsExportTitle), identifier: "documents-export-from-date", day: $from).frame(minWidth: 112)
                Text(copy(.docsExportTo)).font(.ui).foregroundStyle(palette.muted.color)
                DayField(label: copy(.docsExportTo), identifier: "documents-export-to-date", day: $to).frame(minWidth: 112)
                Spacer(minLength: 0)
            }
            HStack(spacing: 8) {
                Picker(copy(.docsColClient), selection: $exportClient) {
                    Text(copy(.docsExportAllClients)).tag(Int64?.none)
                    ForEach(model.clients) { Text($0.displayName).tag(Int64?.some($0.id)) }
                }
                .labelsHidden().pickerStyle(.menu).fixedSize()
                .accessibilityLabel(copy(.docsColClient)).accessibilityIdentifier("documents-export-client-filter")
                Spacer(minLength: 0)
            }
            .font(.ui)
            if let done = model.exportedText(language: language) {
                HStack(spacing: 10) {
                    Text(done).font(.meta).monospacedDigit().foregroundStyle(palette.ink2.color)
                    if case .written(let folder, _, _)? = model.exported {
                        Button(copy(.docsReveal)) {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: folder)])
                        }
                        .buttonStyle(AuxButtonStyle(kind: .link))
                        .accessibilityLabel(copy(.docsReveal)).accessibilityIdentifier("documents-export-show-in-finder")
                    }
                }
            }
            if case .written(_, _, let missing)? = model.exported, missing > 0 {
                Text(copy.f(.docsExportMissing, missing)).font(.meta).foregroundStyle(palette.ink3.color)
            }
            if let problem = model.problem {
                Text(copy(problem.key)).font(.meta).foregroundStyle(palette.red.color)
            }
        }
        .padding(.bottom, 14)
        .overlay(alignment: .bottom) { Hairline() }
        .padding(.bottom, 18)
    }

    private func chooseFolderAndExport(_ copy: Copy) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = copy(.docsExportPrompt)
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        Task { await model.export(from: from, to: to, client: exportClient, into: folder) }
    }

    /// The previous calendar month: what an accountant usually asks for.
    static var lastMonth: (start: Date, end: Date) {
        let calendar = Calendar.current
        let thisMonth = calendar.dateInterval(of: .month, for: Date())?.start ?? Date()
        let start = calendar.date(byAdding: .month, value: -1, to: thisMonth) ?? thisMonth
        return (start, calendar.date(byAdding: .day, value: -1, to: thisMonth) ?? thisMonth)
    }

    // MARK: List

    private func filterRow(_ copy: Copy) -> some View {
        HStack(spacing: 8) {
            Text(copy(.docsShow)).font(.ui).foregroundStyle(palette.muted.color)
            Picker(copy(.docsShow), selection: $model.filter) {
                Text(copy(.docsShowAll)).tag(DocumentsFilter.all)
                Text(copy(.docsShowUnlinked)).tag(DocumentsFilter.unlinked)
                if !model.clients.isEmpty { Divider() }
                ForEach(model.clients) { Text($0.displayName).tag(DocumentsFilter.client($0.id)) }
            }
            .labelsHidden().pickerStyle(.menu).fixedSize().font(.ui)
            .accessibilityLabel(copy(.docsShow)).accessibilityIdentifier("documents-filter")
            Spacer()
        }
        .padding(.bottom, 10)
    }

    @ViewBuilder private func content(_ copy: Copy) -> some View {
        switch model.load {
        case .loading:
            LoadNote(text: copy(.loading))
        case .failed(let problem):
            VStack(spacing: 12) {
                HStack(alignment: .top, spacing: 8) {
                    IconView(icon: .alert).foregroundStyle(palette.red.color).padding(.top, 1)
                    Text(copy(problem.key)).font(.ui).foregroundStyle(palette.ink2.color)
                }
                Button(copy(.retry)) { Task { await model.reload() } }
                    .buttonStyle(AuxButtonStyle())
                    .accessibilityLabel(copy(.retry)).accessibilityIdentifier("documents-retry")
            }
            .frame(maxWidth: .infinity).padding(.vertical, 40)
        case .loaded(let rows) where rows.isEmpty:
            switch model.filter {
            case .all: LoadNote(text: copy(.documentsEmpty))
            case .unlinked: LoadNote(text: copy(.docsEmptyUnlinked))
            case .client: LoadNote(text: copy(.docsEmptyClient))
            }
        case .loaded(let rows):
            VStack(spacing: 0) {
                line([copy(.docsColDate), copy(.docsColDocument), copy(.docsColAmount), copy(.docsColClient)].map { title in
                    AnyView(Text(title).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.muted.color))
                })
                .padding(.vertical, 6)
                .overlay(alignment: .bottom) { Hairline() }
                ForEach(rows) { row(copy, $0) }
            }
        }
    }

    private func row(_ copy: Copy, _ row: DocumentRow) -> some View {
        let read = row.isRead
        return line([
            AnyView(Text(DocumentsPageModel.dateText(row, language: language)).monospacedDigit().foregroundStyle(palette.muted.color)),
            AnyView(Text(DocumentsPageModel.documentText(row, language: language)).foregroundStyle((read && !row.hasNoDetails ? palette.ink : palette.muted).color).lineLimit(1)),
            AnyView(Text(DocumentsPageModel.amountText(row, language: language)).monospacedDigit().foregroundStyle(palette.ink.color).lineLimit(1)),
            AnyView(clientMenu(copy, row).disabled(!read || model.linking != nil).help(read ? "" : copy(.docsLinkAfterRead))),
        ])
        .font(.ui)
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) { Hairline() }
        .contentShape(Rectangle())
        .background(model.selected?.hash == row.hash ? palette.selection.color : .clear)
        .onTapGesture { model.select(row) }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(DocumentsPageModel.documentText(row, language: language)).accessibilityIdentifier("document-row-\(row.hash)")
        .accessibilityAddTraits(model.selected?.hash == row.hash ? [.isSelected] : [])
        .accessibilityAction { model.select(row) }
    }

    private func clientMenu(_ copy: Copy, _ row: DocumentRow) -> some View {
        Menu {
            ForEach(model.clients) { client in
                Button(client.displayName) { Task { await model.link(row, to: client.id) } }
                    .accessibilityLabel(client.displayName).accessibilityIdentifier("document-link-\(row.hash)-\(client.id)")
            }
            if row.client != nil {
                Divider()
                Button(copy(.docsUnlink)) { Task { await model.link(row, to: nil) } }
                    .accessibilityLabel(copy(.docsUnlink)).accessibilityIdentifier("document-unlink-\(row.hash)")
            }
        } label: {
            Text(DocumentsPageModel.clientText(row, language: language))
                .font(.ui)
                .foregroundStyle((row.client == nil || !row.isRead ? palette.muted : palette.ink).color)
                .lineLimit(1)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .accessibilityLabel("\(copy(.docsColClient)): \(DocumentsPageModel.clientText(row, language: language))")
        .accessibilityIdentifier("document-client-menu-\(row.hash)")
    }

    private func line(_ cells: [AnyView]) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            ForEach(Array(cells.enumerated()), id: \.offset) { index, cell in
                // Amounts line up on the right; the rest reads from the left.
                let alignment: Alignment = index == 2 ? .trailing : .leading
                Group {
                    if let width = Self.widths[index] { cell.frame(width: width, alignment: alignment) } else { cell.frame(maxWidth: .infinity, alignment: alignment) }
                }
                .padding(.horizontal, 10)
            }
        }
    }
}

struct DocumentDetailView: View {
    let row: DocumentRow
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 16) {
            Text(DocumentsPageModel.documentText(row, language: language))
                .font(.hk(Theme.Text.title, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
                .fixedSize(horizontal: false, vertical: true)
            detail(copy(.docsColDate), DocumentsPageModel.dateText(row, language: language))
            detail(copy(.docsColAmount), DocumentsPageModel.amountText(row, language: language))
            detail(copy(.docsColClient), DocumentsPageModel.clientText(row, language: language))
            if let number = row.number, !number.isEmpty { detail(copy(.docsColDocument), number) }
            Spacer()
        }
        .frame(maxWidth: 640, alignment: .leading)
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func detail(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.meta).foregroundStyle(palette.muted.color)
            Text(value.isEmpty ? "—" : value).font(.ui).foregroundStyle(palette.ink.color).textSelection(.enabled)
        }
    }
}

/// One export day, written like the table's dates (`Oct 14, 2026` / `14 oct. 2026`)
/// in the app's language; a click opens a calendar in that language.
private struct DayField: View {
    let label: String
    let identifier: String
    @Binding var day: Date
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var open = false

    var body: some View {
        Button { open.toggle() } label: {
            Text(DocumentsPageModel.dayText(day, language: language)).font(.ui).monospacedDigit().foregroundStyle(palette.ink.color)
        }
        .buttonStyle(AuxButtonStyle())
        .accessibilityLabel("\(label) \(DocumentsPageModel.dayText(day, language: language))")
        .accessibilityIdentifier(identifier)
        .popover(isPresented: $open, arrowEdge: .bottom) {
            DatePicker(label, selection: $day, displayedComponents: .date)
                .labelsHidden()
                .datePickerStyle(.graphical)
                .accessibilityLabel(label).accessibilityIdentifier(identifier + "-calendar")
                .environment(\.locale, Locale(identifier: language.localeIdentifier))
                .padding(10)
        }
    }
}
