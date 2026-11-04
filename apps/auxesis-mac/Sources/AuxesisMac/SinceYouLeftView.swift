import AuxesisKit
import SwiftUI
struct SinceYouLeftList: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @Binding var selection: String?
    @State private var filter: SinceYouLeftFilter = .all
    private var entries: [LedgerEntry] { SinceYouLeftPresentation.entries(shell.ledger.value ?? [], filter: filter) }
    var body: some View {
        GeometryReader { geometry in
            VStack(alignment: .leading, spacing: 0) {
                header
                filters
                Text(tr("Showing all returned ledger entries. The last visit boundary is unavailable.",
                        "Toutes les entrées renvoyées sont affichées. La limite de la dernière visite est indisponible."))
                    .font(.meta)
                    .foregroundStyle(palette.ink2.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 10)
                Hairline()
                list
                    .frame(maxHeight: .infinity)
            }
            .frame(width: geometry.size.width, height: geometry.size.height, alignment: .topLeading)
            .background(palette.work.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            shell.loadLedger()
            if selection == nil { selection = entries.first?.id }
        }
        .onChange(of: filter) { _, _ in selection = entries.first?.id }
        .onChange(of: shell.ledger.value) { _, rows in
            if selection == nil { selection = rows?.first?.id }
        }
    }
    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(tr("Since you left", "Depuis votre départ"))
                .font(.hk(Theme.Text.title, Theme.Weight.strong))
                .foregroundStyle(palette.ink.color)
            Text(tr("Activity ledger · written by auxd", "Journal d’activité · écrit par auxd"))
                .font(.meta)
                .foregroundStyle(palette.ink2.color)
        }
        .padding(.horizontal, 18)
        .padding(.top, 18)
        .padding(.bottom, 12)
    }
    private var filters: some View {
        ScrollView(.horizontal) {
            HStack(spacing: 6) {
                ForEach(SinceYouLeftFilter.allCases) { item in
                    let itemID = String(describing: item)
                        .replacingOccurrences(of: "([a-z0-9])([A-Z])", with: "$1-$2", options: .regularExpression)
                        .lowercased()
                    Button {
                        filter = item
                    } label: {
                        Text(title(item))
                            .font(.meta)
                            .fixedSize(horizontal: true, vertical: false)
                            .foregroundStyle(filter == item ? palette.blue.color : palette.ink2.color)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 6)
                            .background(filter == item ? palette.blueSoft.color : palette.hover.color)
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(title(item)).accessibilityIdentifier("ledger-filter-\(itemID)")
                    .accessibilityAddTraits(filter == item ? .isSelected : [])
                }
            }
            .padding(.horizontal, 18)
            .padding(.bottom, 10)
        }
        .scrollIndicators(.hidden)
    }
    @ViewBuilder private var list: some View {
        switch shell.ledger {
        case .loading:
            LoadNote(text: tr("Loading activity…", "Chargement de l’activité…"))
        case .failed:
            LoadNote(text: tr("The activity ledger could not be loaded.", "Le journal d’activité n’a pas pu être chargé."))
        case .unavailable:
            LoadNote(text: tr("The activity ledger is unavailable.", "Le journal d’activité est indisponible."))
        case .loaded:
            if entries.isEmpty {
                LoadNote(text: tr("No entries for this filter.", "Aucune entrée pour ce filtre."))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                    ForEach(entries) { entry in
                        Button {
                            selection = entry.id
                        } label: {
                            LedgerActivityRow(entry: entry, selected: selection == entry.id)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(LedgerText.what(entry, language: language)).accessibilityIdentifier("ledger-row-\(entry.id)")
                        .accessibilityAddTraits(selection == entry.id ? [.isSelected] : [])
                    }
                    }
                }
                .scrollIndicators(.hidden)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
    private func title(_ filter: SinceYouLeftFilter) -> String {
        switch filter {
        case .all: return tr("All", "Tout")
        case .failed: return tr("Failed", "Échecs")
        case .waiting: return tr("Waiting", "En attente")
        case .leftThisMac: return tr("Left this Mac", "Sorti du Mac")
        case .changedHere: return tr("Changed here", "Modifié ici")
        }
    }
    private func tr(_ english: String, _ french: String) -> String {
        language == .fr ? french : english
    }
}
private struct LedgerActivityRow: View {
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    let entry: LedgerEntry
    let selected: Bool
    var body: some View {
        let when = entry.at.isEmpty ? tr("Unavailable", "Indisponible") : LedgerText.localTime(entry.at, locale: Locale(identifier: language.localeIdentifier))
        VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                status
                Text(LedgerText.what(entry, language: language))
                    .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                    .foregroundStyle(palette.ink.color)
                    .lineLimit(2)
            }
            HStack(spacing: 5) {
                Text(when).monospacedDigit()
                Text("·")
                Text(entry.agent.map(TeamMember.displayName) ?? unavailable)
            }
            .font(.meta)
            .foregroundStyle(palette.ink2.color)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? palette.selection.color : .clear)
        .overlay(alignment: .bottom) { Hairline() }
        .accessibilityElement(children: .combine)
    }
    private var status: some View {
        let (label, symbol, color) = statusParts
        return Label(label, systemImage: symbol)
            .font(.meta)
            .foregroundStyle(color)
            .labelStyle(.titleAndIcon)
            .fixedSize()
    }
    private var statusParts: (String, String, Color) {
        if SinceYouLeftDetail(entry: entry).isFinal {
            return (tr("Final", "Final"), "checkmark", palette.ink2.color)
        }
        let filters = SinceYouLeftFilter.allCases.dropFirst().filter {
            $0.selecting(from: [entry]).isEmpty == false
        }
        guard let first = filters.first else {
            return (tr("Recorded", "Consigné"), "checkmark", palette.ink2.color)
        }
        switch first {
        case .failed: return (tr("Failed", "Échec"), "xmark", palette.red.color)
        case .waiting: return (tr("Waiting", "En attente"), "clock", palette.amber.color)
        case .leftThisMac: return (tr("Left this Mac", "Sorti du Mac"), "arrow.up.right", palette.ink2.color)
        case .changedHere: return (tr("Changed here", "Modifié ici"), "checkmark", palette.ink2.color)
        case .all: return (tr("Recorded", "Consigné"), "checkmark", palette.ink2.color)
        }
    }
    private var unavailable: String { tr("Unavailable", "Indisponible") }
    private func tr(_ english: String, _ french: String) -> String {
        language == .fr ? french : english
    }
}
struct SinceYouLeftDetailView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    let entry: LedgerEntry
    private var detail: SinceYouLeftDetail { SinceYouLeftDetail(entry: entry) }
    // The ledger has no stable proposal id yet; a text match would guess, so no link is offered.
    private var matchingApproval: Approval? { nil }
    var body: some View {
        // Scrolls, like the other record details: the wrapped title's height follows the
        // column's width, and unscrolled it fed the window a layout loop.
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text(LedgerText.what(entry, language: language))
                    .font(.hk(Theme.Text.title, Theme.Weight.strong))
                    .foregroundStyle(palette.ink.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 10)
                if detail.isFinal {
                    Label(tr("Final", "Finalisé"), systemImage: "checkmark")
                        .font(.meta)
                        .foregroundStyle(palette.ink2.color)
                        .padding(.bottom, 18)
                }
                section(tr("Entry", "Entrée")) {
                    field(tr("When", "Quand"), detail.when)
                    field(tr("Agent", "Agent"), detail.agent)
                    field(tr("Skill", "Compétence"), detail.skill)
                    field(tr("Skill version", "Version de la compétence"), detail.skillVersion)
                    field(tr("Trigger", "Déclencheur"), detail.trigger)
                    field(tr("Grant used", "Autorisation utilisée"), detail.grantUsed)
                    field(tr("Evidence", "Éléments de preuve"), detail.evidence)
                    field(tr("Outcome per step", "Résultat par étape"), detail.stepOutcomes)
                    field(tr("Affected objects", "Éléments concernés"), detail.affectedObjects)
                }
                section(tr("Actions", "Actions")) {
                    HStack(spacing: 8) {
                        Button(tr("Undo", "Annuler")) {}.disabled(true).help(tr("Not available yet", "Pas encore disponible"))
                            .accessibilityLabel(tr("Undo", "Annuler")).accessibilityIdentifier("ledger-undo")
                        Button(tr("Retry after a check", "Réessayer après vérification")) {}.disabled(true).help(tr("Not available yet", "Pas encore disponible"))
                            .accessibilityLabel(tr("Retry after a check", "Réessayer après vérification")).accessibilityIdentifier("ledger-retry")
                        Button(tr("Open proposal", "Ouvrir la proposition")) {
                            shell.go(.waiting)
                        }
                        .disabled(matchingApproval == nil)
                        .help(matchingApproval == nil
                              ? tr("Not available yet", "Pas encore disponible")
                              : tr("Open the matching waiting approval", "Ouvrir l’approbation en attente correspondante"))
                        .accessibilityLabel(tr("Open proposal", "Ouvrir la proposition")).accessibilityIdentifier("ledger-open-proposal")
                    }
                    .buttonStyle(AuxButtonStyle(kind: .normal))
                    if matchingApproval == nil {
                        Text(tr("Not available yet", "Pas encore disponible"))
                            .font(.meta)
                            .foregroundStyle(palette.ink3.color)
                            .padding(.top, 5)
                    }
                }
            }
            .frame(maxWidth: 680, alignment: .leading)
            .padding(.horizontal, 36)
            .padding(.top, 28)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(palette.work.color)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(.meta)
                .foregroundStyle(palette.ink2.color)
                .padding(.bottom, 7)
            content()
        }
        .padding(.bottom, 22)
    }
    @ViewBuilder private func field(_ label: String, _ value: LedgerDetailValue) -> some View {
        if value != .unavailable {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(label)
                .font(.meta)
                .foregroundStyle(palette.ink2.color)
                .frame(width: 150, alignment: .leading)
            Text(text(value))
                .font(.ui)
                .foregroundStyle(value == .unavailable ? palette.ink3.color : palette.ink.color)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) { Hairline() }
        }
    }
    private func text(_ value: LedgerDetailValue) -> String {
        switch value {
        case .available(let value): return value
        case .unavailable: return tr("Unavailable", "Indisponible")
        }
    }
    private func tr(_ english: String, _ french: String) -> String {
        language == .fr ? french : english
    }
}
