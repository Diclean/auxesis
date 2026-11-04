// Clients → Import…: the owner picks one vCard or CSV file on
// this Mac, the daemon reads it with a dry run, and the sheet shows what the
// file would do. Only the owner's Import writes. The sheet shows counts, column
// names and reasons, never a contact value. Nothing leaves this Mac: the green
// line says so.
import AppKit
import AuxesisKit
import SwiftUI
import UniformTypeIdentifiers

/// The file picker: one vCard or CSV file. Nil when the owner cancels.
@MainActor
enum ContactsFilePicker {
    static func pick(language: Language) -> String? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.commaSeparatedText, UTType(filenameExtension: "vcf") ?? .data]
        panel.prompt = L10n.t(.importChoose, language)
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return url.path
    }
}

/// The import sheet: a preview with counts, the owner's party kind and, when
/// phone numbers need one, a country. Import writes; Cancel and Done write nothing.
struct ClientImportSheet: View {
    @ObservedObject var model: ClientImportModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(L10n.t(.importTitle, language))
                .font(.hk(Theme.Text.heading, Theme.Weight.strong))
                .foregroundStyle(palette.ink.color)
                .padding(.horizontal, 18)
                .padding(.top, 16)
                .padding(.bottom, 10)
            Hairline()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(L10n.t(.importLede, language))
                        .font(.body15)
                        .foregroundStyle(palette.ink2.color)
                        .lineSpacing(3)
                    Text(L10n.t(.importStaysHere, language))
                        .font(.meta)
                        .foregroundStyle(palette.ink2.color)
                    if let message = model.message {
                        ImportNote(text: message)
                    }
                    content
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Hairline()
            footer
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
        }
        .frame(width: 480, height: 480)
        .background(palette.work.color)
        // Esc must not close the sheet while the write runs: the result would be lost.
        .interactiveDismissDisabled(isImporting)
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .reading:
            Text(L10n.t(.importReading, language))
                .font(.ui)
                .foregroundStyle(palette.muted.color)
        case .failed:
            EmptyView()
        case .previewed(let answer):
            preview(answer, editable: true)
        case .importing(let answer):
            preview(answer, editable: false)
        case .imported(let answer):
            HStack(spacing: 8) {
                IconView(icon: .check).foregroundStyle(palette.ink.color)
                Text(L10n.f(.importDoneLine, language, answer.contacts, answer.partiesCreated, answer.partiesUpdated))
                    .font(.body15)
                    .foregroundStyle(palette.ink.color)
            }
        }
    }

    @ViewBuilder private func preview(_ answer: ContactsImportAnswer, editable: Bool) -> some View {
        if answer.contacts == 0 {
            Text(L10n.t(.importNothingReadable, language))
                .font(.ui)
                .foregroundStyle(palette.muted.color)
        } else {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    if let format = ContactsImportText.format(answer.format) {
                        Text(format).font(.meta).foregroundStyle(palette.muted.color)
                    }
                    Text(L10n.f(.importFound, language, answer.contacts))
                        .font(.body15)
                        .foregroundStyle(palette.ink.color)
                    Text(L10n.f(.importFoundDetail, language, answer.emails, answer.phones))
                        .font(.meta)
                        .foregroundStyle(palette.muted.color)
                    Text(L10n.f(.importParties, language, answer.partiesCreated, answer.partiesUpdated, answer.partiesRefused))
                        .font(.meta)
                        .foregroundStyle(palette.muted.color)
                }
                if !answer.mappedColumns.isEmpty {
                    section(L10n.t(.importColumnsRead, language)) {
                        ForEach(Array(answer.mappedColumns.enumerated()), id: \.offset) { _, column in
                            Text(L10n.f(.importColumnRow, language, column.column, ContactsImportText.role(column.role, language)))
                                .font(.ui)
                                .foregroundStyle(palette.ink2.color)
                        }
                    }
                }
                if !answer.unmappedColumns.isEmpty {
                    Text(L10n.f(.importColumnsIgnored, language, answer.unmappedColumns.joined(separator: ", ")))
                        .font(.meta)
                        .foregroundStyle(palette.muted.color)
                }
                let reasons = ContactsImportText.skippedReasons(answer.skipped)
                if !reasons.isEmpty {
                    section(L10n.t(.importSkippedTitle, language)) {
                        ForEach(Array(reasons.enumerated()), id: \.offset) { _, reason in
                            HStack {
                                Text(L10n.t(reason.0, language))
                                    .font(.ui)
                                    .foregroundStyle(palette.ink2.color)
                                Spacer()
                                Text("\(reason.1)")
                                    .font(.ui)
                                    .foregroundStyle(palette.ink3.color)
                            }
                        }
                    }
                }
                section(L10n.t(.importTagTitle, language)) {
                    Picker(L10n.t(.importTagTitle, language), selection: $model.tag) {
                        ForEach(ContactsImportTag.allCases, id: \.self) { tag in
                            Text(ContactsImportText.tagLabel(tag, language)).tag(tag)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .disabled(!editable)
                    .accessibilityLabel(L10n.t(.importTagTitle, language)).accessibilityIdentifier("client-import-tag")
                }
                if answer.skipped.phoneNeedsCountry > 0 {
                    section(L10n.t(.importCountryLabel, language)) {
                        Text(L10n.f(.importCountryHint, language, answer.skipped.phoneNeedsCountry))
                            .font(.meta)
                            .foregroundStyle(palette.muted.color)
                        TextField(L10n.t(.importCountryLabel, language), text: $model.country)
                            .textFieldStyle(.plain)
                            .font(.ui)
                            .foregroundStyle(palette.ink.color)
                            .padding(.horizontal, 10)
                            .frame(height: 30)
                            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(palette.hover.color))
                            .disabled(!editable)
                            .accessibilityLabel(L10n.t(.importCountryLabel, language)).accessibilityIdentifier("client-import-country")
                    }
                }
            }
        }
    }

    private func section<Body: View>(_ title: String, @ViewBuilder _ body: () -> Body) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.meta)
                .foregroundStyle(palette.muted.color)
            body()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var footer: some View {
        HStack {
            Spacer()
            if case .imported = model.phase {
                Button(L10n.t(.importDone, language)) { dismiss() }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .accessibilityLabel(L10n.t(.importDone, language)).accessibilityIdentifier("client-import-done")
            } else {
                Button(L10n.t(.importCancel, language)) { dismiss() }
                    .buttonStyle(AuxButtonStyle())
                    .disabled(isImporting)
                    .accessibilityLabel(L10n.t(.importCancel, language)).accessibilityIdentifier("client-import-cancel")
                Button(L10n.t(isImporting ? .importRunning : .importRun, language)) { model.confirm() }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .disabled(!model.canImport)
                    .accessibilityLabel(L10n.t(isImporting ? .importRunning : .importRun, language)).accessibilityIdentifier("client-import-run")
            }
        }
    }

    private var isImporting: Bool {
        if case .importing = model.phase { return true }
        return false
    }
}

/// A red line with the daemon's sentence, or the plain copy.
private struct ImportNote: View {
    let text: String
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            IconView(icon: .alert).foregroundStyle(palette.red.color).padding(.top, 1)
            Text(text)
                .font(.ui)
                .foregroundStyle(palette.ink2.color)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
