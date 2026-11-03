// The right panel's Privacy tab: today's privacy record for
// the open conversation, in neutral ink (SOBER-1): `ink2` words and an `ink3`
// glyph — arrow for a run that left this Mac, shield only for one with local-host
// evidence, dashed circle for one that recorded no host, "?" when not known.
// The rules live in `PrivacyTabModel`.
import AuxesisKit
import SwiftUI

struct PrivacyTabView: View {
    let member: TeamMember
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(copy(.privacyTabToday)).font(.hk(Theme.Text.meta, Theme.Weight.semibold)).foregroundStyle(palette.ink2.color)
                    .accessibilityAddTraits(.isHeader)
                switch shell.store.privacyRecordRead {
                case .loading: note(copy(.privacyTabLoading))
                case .unavailable: note(copy(.privacyTabUnavailable))
                case .loaded: record(copy)
                }
                Button(copy(.privacyTabOpen)) { shell.go(.privacyRecord) }
                    .buttonStyle(AuxButtonStyle(kind: .link))
                    .font(.meta)
                    .padding(.top, 4)
                    .accessibilityLabel(copy(.privacyTabOpen)).accessibilityIdentifier("privacy-tab-open-record")
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private func record(_ copy: Copy) -> some View {
        let model = PrivacyTabModel(receipts: shell.store.receipts, agent: member.id, day: TodayPresentation.day(Date()))
        let lines = model.summary(language)
        VStack(alignment: .leading, spacing: 4) {
            fact(lines[0], icon: "arrow.up.right")
            fact(lines[1], icon: "circle.dashed")
            if lines.count > 2 { fact(lines[2], icon: "questionmark.circle") }
            if !model.replaced.isEmpty {
                let values = model.replaced.map { "\($0.category.lowercased()) \($0.count)" }.joined(separator: " · ")
                Text(copy.f(.privacyTabReplaced, values)).font(.meta).foregroundStyle(palette.ink2.color).padding(.top, 2)
            }
        }
        if model.rows.isEmpty { note(copy(.privacyTabEmpty)) }
        VStack(alignment: .leading, spacing: 0) {
            ForEach(model.rows) { row in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(row.time).font(.meta.monospacedDigit()).foregroundStyle(palette.ink3.color).frame(width: 40, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.agent).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                        place(row, copy)
                    }
                }
                .padding(.vertical, 7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .overlay(alignment: .top) { Hairline() }
                .accessibilityElement(children: .combine)
            }
        }
    }

    private func place(_ row: PrivacyTabRow, _ copy: Copy) -> some View {
        switch row.place {
        case .left:
            return fact(copy(.whereLeft) + (row.host.map { " · \($0)" } ?? ""), icon: "arrow.up.right")
        case .stayed:
            return fact(copy(.stayedOnMac), icon: "lock.shield")
        case .noOutsideHost:
            return fact(copy(.privacyTabNoOutside), icon: "circle.dashed")
        case .unknown:
            return fact(copy(.whereUnavailable), icon: "questionmark.circle")
        }
    }

    /// Icon and words together: the meaning never rests on the colour.
    private func fact(_ text: String, icon: String) -> some View {
        Label(text, systemImage: icon).font(.meta).lineLimit(2)
            .labelStyle(TwoToneLabelStyle(titleColor: palette.ink2.color, iconColor: palette.ink3.color))
    }

    private func note(_ text: String) -> some View {
        Text(text).font(.meta).foregroundStyle(palette.ink3.color)
    }
}
