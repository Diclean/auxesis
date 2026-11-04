// An agent reply as blocks (v5 contract). Display only: a
// link is underlined text with its host on hover, never opened from here; no
// image or HTML is ever loaded. Colours are Palette tokens by name.
import AppKit
import AuxesisKit
import SwiftUI

struct RichMessage: View {
    let text: String
    private let blocks: [MarkdownBlock]
    @Environment(\.palette) private var palette

    init(text: String) {
        self.text = text
        blocks = MarkdownParser.parse(text)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                switch block {
                case .paragraph(let line): RichInline(text: line)
                case .heading(let line): RichInline(text: line, bold: true)
                case .list(let ordered, let items): list(ordered, items)
                case .quote(let line):
                    HStack(alignment: .top, spacing: 10) {
                        Rectangle().fill(palette.line2.color).frame(width: 2)
                        RichInline(text: line, color: palette.ink2.color)
                    }
                case .code(let code): RichCode(code: code)
                case .rule: Rectangle().fill(palette.line.color).frame(height: Theme.hairline).padding(.vertical, 4)
                case .table(let table): RichTable(table: table)
                }
            }
        }
        .environment(\.replyLanguage, RemovalMarker.language(of: text))
        .textSelection(.enabled)
        // Selecting copies the shown words; this keeps the markdown the agent wrote.
        .contextMenu {
            Button("Copy message as text") { Pasteboard.copy(text) }
                .accessibilityLabel("Copy message as text").accessibilityIdentifier("rich-copy-message")
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func list(_ ordered: Bool, _ items: [ListItem]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(items.enumerated()), id: \.offset) { index, item in
                row(ordered ? "\(index + 1)." : "•", item.text)
                ForEach(Array(item.children.enumerated()), id: \.offset) { _, child in
                    row("–", child).padding(.leading, 18)
                }
            }
        }
    }

    private func row(_ marker: String, _ line: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Text(marker).font(.body145).foregroundStyle(palette.ink2.color).monospacedDigit().frame(width: 18, alignment: .leading)
            RichInline(text: line)
        }
    }
}

enum Pasteboard {
    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

extension Font {
    /// Reply body: 14.5 / 1.45 (v5).
    static var body145: Font { .hk(14.5) }
}

/// One line of inline spans. Chips are neutral with a lock; links are ink and underlined.
struct RichInline: View {
    let text: String
    var bold = false
    var color: Color?
    @Environment(\.palette) private var palette
    @Environment(\.replyLanguage) private var replyLanguage

    var body: some View {
        let runs = InlineParser.parse(text, replyLanguage: replyLanguage)
        let hosts = runs.compactMap { $0.link.map(Self.host) }
        Self.compose(runs, bold: bold, palette: palette, color: color ?? palette.ink.color)
            .lineSpacing(3.5)
            .fixedSize(horizontal: false, vertical: true)
            .help(hosts.joined(separator: "\n"))
            .accessibilityLabel(InlineParser.spoken(runs))
    }

    static func host(_ link: String) -> String { URL(string: link)?.host ?? link }

    static func compose(_ runs: [InlineRun], bold: Bool, palette: Palette, color: Color, size: CGFloat = 14.5) -> Text {
        runs.reduce(Text(verbatim: "")) { result, run in
            if run.chip {
                let lock = Text(Image(systemName: "lock.fill")).font(.hk(10)).foregroundColor(palette.ink3.color)
                var label = AttributedString("\u{2009}\(run.text)\u{2009}")
                label.backgroundColor = palette.line.color
                label.foregroundColor = palette.ink2.color
                label.font = .hk(12.5)
                return result + lock + Text(label)
            }
            var piece = AttributedString(run.text)
            piece.foregroundColor = color
            piece.font = run.code ? .system(size: 13, design: .monospaced) : .hk(size, bold || run.bold ? Theme.Weight.semibold : Theme.Weight.regular)
            if run.italic { piece.font = (piece.font ?? .body145).italic() }
            if run.code { piece.backgroundColor = palette.line.color }
            if run.link != nil {
                piece.underlineStyle = .single
                piece.underlineColor = NSColor(palette.ink3.color)
            }
            return result + Text(piece)
        }
    }
}

struct RichCode: View {
    let code: String
    @Environment(\.palette) private var palette

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            Text(verbatim: code.isEmpty ? " " : code)
                .font(.system(size: 12.5, design: .monospaced))
                .foregroundStyle(palette.ink.color)
                .fixedSize()
                .padding(.vertical, 10).padding(.leading, 12).padding(.trailing, 40)
        }
        .background(palette.raise.color, in: RoundedRectangle(cornerRadius: Theme.proposalRadius))
        .overlay(RoundedRectangle(cornerRadius: Theme.proposalRadius).stroke(palette.line.color, lineWidth: Theme.hairline))
        .overlay(alignment: .topTrailing) {
            Button { Pasteboard.copy(code) } label: { Image(systemName: "doc.on.doc").font(.hk(12)) }
                .buttonStyle(.plain).foregroundStyle(palette.ink2.color).padding(8)
                .help("Copy code").accessibilityLabel("Copy code").accessibilityIdentifier("rich-copy-code")
        }
    }
}

struct RichTable: View {
    let table: MarkdownTable
    /// Rows drawn so far: 12 first, then 200 more per tap (a big table never lays out in one go).
    @State private var shown = 12
    @Environment(\.palette) private var palette
    private static let step = 200

    var body: some View {
        let rows = table.rows.prefix(shown)
        let left = table.rows.count - rows.count
        VStack(alignment: .leading, spacing: 6) {
            ScrollView(.horizontal, showsIndicators: false) {
                Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 0) {
                    GridRow { ForEach(table.header.indices, id: \.self) { cell(table.header[$0], $0, header: true) } }
                    ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                        Rectangle().fill(palette.line.color).frame(height: Theme.hairline).gridCellColumns(table.header.count)
                        GridRow { ForEach(row.indices, id: \.self) { cell(row[$0], $0, header: false) } }
                    }
                }
                .padding(.vertical, 2)
            }
            if left > 0 {
                let label = left <= Self.step ? "Show all \(table.rows.count) rows" : "Show \(Self.step) more rows"
                Button(label) { shown += Self.step }
                    .buttonStyle(.plain).font(.meta).foregroundStyle(palette.ink2.color).underline()
                    .accessibilityLabel(label).accessibilityIdentifier("rich-table-show-all")
            } else if table.hiddenRows > 0 {
                Text(verbatim: "\(table.hiddenRows) more rows not shown").font(.meta).foregroundStyle(palette.ink3.color)
            }
        }
    }

    private func cell(_ text: String, _ column: Int, header: Bool) -> some View {
        let align = table.alignment(of: column)
        return RichInline(text: text, bold: header, color: header ? palette.ink2.color : nil)
            .monospacedDigit()
            .padding(.vertical, 6)
            .gridColumnAlignment(align == .trailing ? .trailing : align == .center ? .center : .leading)
            .frame(minWidth: 0, alignment: align == .trailing ? .trailing : .leading)
    }
}
