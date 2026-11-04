// The calendar card under a Calendar answer. Neutral ink only:
// a free row says "Free" in words, never a hue. Rules live in `CalendarCard`.
import AuxesisKit
import SwiftUI

struct CalendarCardView: View {
    let card: CalendarCardModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                IconView(icon: .cal, size: 14).foregroundStyle(palette.ink2.color).frame(width: 28, height: 28)
                    .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(palette.hover.color))
                Text(card.title(language)).font(.hk(Theme.Text.body, Theme.Weight.semibold))
                    .foregroundStyle(palette.ink.color).accessibilityAddTraits(.isHeader)
                Spacer(minLength: 0)
                if let asOf = card.asOf() {
                    Text(L10n.uf(.calCardAsOf, language, TimeText.clock(asOf))).font(.meta).foregroundStyle(palette.ink3.color)
                }
            }
            .padding(10)
            ForEach(Array(card.rows.enumerated()), id: \.offset) { index, row in
                Hairline()
                CalendarCardRowView(row: row, showDay: index == 0 || !Calendar.current.isDate(row.start, inSameDayAs: card.rows[index - 1].start))
            }
            if card.incomplete {
                Hairline()
                Text(L10n.ui(.calCardIncomplete, language)).font(.meta).foregroundStyle(palette.ink3.color).padding(.horizontal, 12).padding(.vertical, 7)
            }
        }
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(palette.raise.color))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(palette.line.color, lineWidth: 1))
        .frame(maxWidth: 560, alignment: .leading).padding(.top, 4)
        .accessibilityElement(children: .contain).accessibilityLabel(card.title(language)).accessibilityIdentifier("calendar-card")
    }
}

/// One row: the day (only on its first row), the time range, then the title or "Free".
private struct CalendarCardRowView: View {
    let row: CalendarCardRow
    let showDay: Bool
    @FocusState private var focused: Bool
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let (day, time, what) = (CalendarCardModel.day(row.start, language), CalendarCardModel.time(row, language), CalendarCardModel.what(row, language))
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(showDay ? day : "").font(.hk(Theme.Text.meta, Theme.Weight.semibold))
                .foregroundStyle(palette.ink2.color).frame(width: 96, alignment: .leading)
            Text(time).font(.hk(Theme.Text.ui).monospacedDigit()).foregroundStyle(palette.ink2.color).frame(width: 112, alignment: .leading)
            Image(systemName: row.kind == .event || row.kind == .allDay ? "circle.fill" : "circle.dashed")
                .font(.system(size: 7)).foregroundStyle(palette.ink3.color).accessibilityHidden(true)
            Text(what).font(.hk(Theme.Text.ui, row.kind == .free ? Theme.Weight.semibold : Theme.Weight.regular))
                .foregroundStyle(row.kind == .notChecked ? palette.ink3.color : palette.ink.color)
                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
        .background(focused ? palette.hover.color : .clear).focusable().focused($focused)
        .accessibilityElement(children: .ignore).accessibilityLabel("\(day), \(time), \(what)")
    }
}
