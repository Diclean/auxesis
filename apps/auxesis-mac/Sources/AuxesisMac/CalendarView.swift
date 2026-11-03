// Agenda (CAL-PAGE-1): the next 8 days from this Mac's calendars, read-only,
// the same read the app publishes to Aux. On top, how fresh Aux's copy is
// (amber when it may be out of date), Refresh now and, in red, why a refresh
// failed; last, the switch that keeps Auxesis running at login so the menu bar
// refreshes with no window. Named "Agenda" so it never sits as a second
// "Calendar" row next to the Calendar agent.
import AppKit
import AuxesisKit
import SwiftUI

struct CalendarView: View {
    @ObservedObject var model: CalendarPageModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    /// The time column, as on Today.
    private static let leadColumn: CGFloat = 200

    var body: some View {
        let copy = Copy(language: language)
        ViewPage(title: copy(.calPage), lede: copy(.calLede)) {
            syncLine(copy)
            let days = model.days()
            if model.snapshot != nil && days.isEmpty {
                Text(copy(.calNoEvents)).font(.ui).foregroundStyle(palette.muted.color).padding(.bottom, 32)
            }
            ForEach(days) { day in
                section(copy, day)
            }
            loginRow(copy, ruled: !days.isEmpty)
        }
        .onAppear { Task { await model.refreshNow() } }
        // Back from System Settings: show macOS's answer on the login item now.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.reloadLoginItem()
        }
    }

    private func syncLine(_ copy: Copy) -> some View {
        let line = model.line
        return VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 8) {
                // Amber means stale only; the alert icon goes with it.
                if line.isStale { IconView(icon: .alert).foregroundStyle(palette.ink3.color) }
                Text(line.text(language: language))
                    .font(.hk(Theme.Text.ui, line.isStale ? Theme.Weight.semibold : Theme.Weight.regular))
                    .monospacedDigit()
                    .foregroundStyle((line.isStale ? palette.ink3 : palette.ink2).color)
                Spacer(minLength: 12)
                if model.needsCalendarAccess {
                    // Opens the Calendar privacy pane; changes nothing itself.
                    Button(copy(.calOpenSettings)) { SystemOpener.openSettings(for: .calendar) }
                        .buttonStyle(AuxButtonStyle(kind: .normal))
                        .accessibilityLabel(copy(.calOpenSettings)).accessibilityIdentifier("calendar-open-settings")
                } else {
                    Button(model.refreshing ? copy(.calRefreshing) : copy(.calRefresh)) {
                        Task { await model.refreshNow() }
                    }
                    .buttonStyle(AuxButtonStyle(kind: .normal))
                    .disabled(model.refreshing)
                    .accessibilityLabel(model.refreshing ? copy(.calRefreshing) : copy(.calRefresh)).accessibilityIdentifier("calendar-refresh")
                }
            }
            if let problem = model.problemText(language: language) {
                Text(problem).font(.meta).foregroundStyle(palette.red.color)
                    .padding(.leading, line.isStale ? 24 : 0)
            }
            if line.isStale {
                Text(copy(.calStaleHint)).font(.meta).foregroundStyle(palette.muted.color).padding(.leading, 24)
            }
        }
        .padding(.bottom, 14)
        .overlay(alignment: .bottom) { Hairline() }
        .padding(.bottom, 28)
        .accessibilityElement(children: .contain)
    }

    private func section(_ copy: Copy, _ day: CalendarDay) -> some View {
        let count = day.events.count
        return VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(CalendarDay.title(day.day, language: language)).font(.hk(Theme.Text.title, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
                Spacer()
                Text(count == 1 ? copy(.todayEventsOne) : copy.f(.todayEventsMany, count))
                    .font(.meta).monospacedDigit().foregroundStyle(palette.muted.color)
            }
            .padding(.bottom, 8)
            .overlay(alignment: .bottom) { Hairline(strong: true) }
            ForEach(Array(day.events.enumerated()), id: \.offset) { _, event in
                row(event)
            }
        }
        .padding(.bottom, 32)
    }

    private func row(_ event: AppleEventItem) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(event.timeText(language: language))
                .font(.ui).monospacedDigit().foregroundStyle(palette.muted.color)
                .lineLimit(1)
                .frame(width: Self.leadColumn, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(event.title).font(.ui).foregroundStyle(palette.ink.color).lineLimit(2)
                if let location = event.location, !location.isEmpty {
                    Text(location).font(.meta).foregroundStyle(palette.muted.color).lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 11)
        .overlay(alignment: .bottom) { Hairline() }
    }

    /// `ruled`: a hairline above, unless the sync line's is right there.
    private func loginRow(_ copy: Copy, ruled: Bool) -> some View {
        let state = model.loginItem
        let on = state == .enabled || state == .requiresApproval
        let (note, color) = loginNote(copy, state)
        return VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(copy(.calLoginTitle)).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                    Text(copy(.calLoginHint)).font(.meta).foregroundStyle(palette.muted.color)
                }
                Spacer()
                Toggle(copy(.calLoginTitle), isOn: Binding(get: { on }, set: { model.setLoginItem($0) }))
                    .toggleStyle(.switch)
                    .tint(palette.blue.color)
                    .labelsHidden()
                    .controlSize(.small)
                    .disabled(state == .unavailable)
                    .accessibilityLabel(copy(.calLoginTitle))
                    .accessibilityIdentifier("calendar-login-item-toggle")
            }
            Text(note).font(.meta).foregroundStyle(color)
        }
        .padding(.top, ruled ? 14 : 0)
        .overlay(alignment: .top) { if ruled { Hairline() } }
    }

    /// What macOS says, not what the switch says. Waiting for approval is
    /// pending, so neutral grey: amber only means stale.
    private func loginNote(_ copy: Copy, _ state: LoginItemState) -> (String, Color) {
        if model.loginItemFailed { return (copy(.calLoginFailed), palette.red.color) }
        switch state {
        case .enabled: return (copy(.calLoginOn), palette.muted.color)
        case .requiresApproval: return (copy(.calLoginApproval), palette.muted.color)
        case .off: return (copy(.calLoginOff), palette.muted.color)
        case .unavailable: return (copy(.calLoginUnavailable), palette.muted.color)
        }
    }
}
