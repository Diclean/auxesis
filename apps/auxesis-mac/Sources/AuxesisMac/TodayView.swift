// Today (UI3-3): the brief and queue share existing app models. The Today
// selection stays in the detail pane; unavailable sources remain explicit.
import AuxesisKit
import SwiftUI

extension TodayGroup {
    func title(_ copy: Copy) -> String {
        switch self {
        case .waiting: return copy(.waitingForYou)
        case .dueToday: return copy(.dueTodayQueue)
        case .sinceYouLeft: return copy(.sinceYouLeft)
        case .runningNow: return copy(.runningNow)
        }
    }
}

struct TodayView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    /// The queue's selection: a top row's "Open" shows that card here.
    @Binding var selection: TodaySelection
    @State private var showsAllMail = false

    var body: some View {
        let copy = Copy(language: language)
        let selected = TodayQueueModel.resolvedSelection(selection,
            waitingIDs: shell.waitingApprovals.map(\.id), ledgerIDs: shell.ledger.value?.map(\.id) ?? [],
            agentIDs: TeamMember.all.filter { shell.workingAgents.contains($0.id) }.map(\.id))
        ViewPage(title: copy(.today), lede: lede(copy)) {
            selectionDetail(copy, selected: selected)
            switch shell.today {
            case .loading: LoadNote(text: copy(.loading))
            case .failed: LoadNote(text: copy(.loadFailed))
            case .unavailable: LoadNote(text: copy(.unavailable))
            case .loaded(.empty(let nextRun)): empty(copy, nextRun: nextRun)
            case .loaded(.brief(let brief)): content(copy, brief)
            }
        }
        .onAppear { shell.loadToday(); shell.loadLedger() }
    }

    @ViewBuilder private func selectionDetail(_ copy: Copy, selected: TodaySelection) -> some View {
        switch selected {
        case .brief: EmptyView()
        case .group(let group):
            VStack(alignment: .leading, spacing: 8) {
                Text(group.title(copy)).font(.hk(Theme.Text.title, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
                ForEach(Array(groupLines(group, copy).enumerated()), id: \.offset) { _, line in
                    Text(line).font(.ui).foregroundStyle(palette.ink2.color)
                }
            }
        case .waiting(let id):
            if let item = shell.waitingApprovals.first(where: { $0.id == id }) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(shell.rowHeadline(for: item)).font(.hk(Theme.Text.title, Theme.Weight.strong))
                    Text(item.detail.joined(separator: " · ")).font(.ui).foregroundStyle(palette.ink2.color)
                }
            }
        case .ledger(let id):
            if let item = shell.ledger.value?.first(where: { $0.id == id }) {
                Text(LedgerText.what(item, language: language)).font(.hk(Theme.Text.title, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
            }
        case .agent(let id):
            if let member = TeamMember.member(id) {
                let row = shell.row(for: member)
                VStack(alignment: .leading, spacing: 4) {
                    Text(member.name).font(.hk(Theme.Text.title, Theme.Weight.strong))
                    Text(row.line).font(.ui).foregroundStyle(palette.ink2.color)
                }
            }
        }
    }

    private func groupLines(_ group: TodayGroup, _ copy: Copy) -> [String] {
        switch group {
        case .waiting:
            let items = shell.waitingApprovals.map { shell.rowHeadline(for: $0) }
            return items.isEmpty ? [copy(.waitingEmpty)] : items
        case .dueToday:
            return [copy(.todayDueEmpty)]
        case .sinceYouLeft:
            if let line = SinceYouLeftPresentation.emptyLine(shell.ledger, language: language) {
                return [line]
            }
            return SinceYouLeftPresentation.previewLines(shell.ledger.value ?? [], language: language)
        case .runningNow:
            let items = TeamMember.all.filter { shell.workingAgents.contains($0.id) }.map(\.name)
            return items.isEmpty ? [copy(.idleLine)] : items
        }
    }

    private func lede(_ copy: Copy) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language == .fr ? "fr_FR" : "en_GB")
        formatter.setLocalizedDateFormatFromTemplate("EEEEdMMMM")
        let date = formatter.string(from: Date())
        if case .loaded(.brief(let brief)) = shell.today, let written = brief.writtenAt {
            return copy.f(.todayWrittenAt, date, written)
        }
        return date
    }

    private func empty(_ copy: Copy, nextRun: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            if shell.showsTodayEmptySentence {
                Text(copy.f(.todayEmpty, nextRun))
                    .font(.hk(Theme.Text.body, Theme.Weight.regular))
                    .monospacedDigit()
                    .foregroundStyle(palette.ink.color)
            }
            HStack(spacing: 12) {
                Button(shell.briefRunning ? copy(.todayRunning) : copy(.todayRun)) { shell.runBriefNow() }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .disabled(shell.briefRunning || shell.client == nil)
                    .accessibilityLabel(shell.briefRunning ? copy(.todayRunning) : copy(.todayRun)).accessibilityIdentifier("today-run-brief")
                runNote(copy)
            }
        }
        .padding(.top, 8)
    }

    @ViewBuilder private func runNote(_ copy: Copy) -> some View {
        if let note = shell.briefRunNote {
            Text(copy(note))
                .font(.ui)
                .foregroundStyle((note == .briefRunFailed || note == .briefRunStopped ? palette.red : palette.muted).color)
            if note == .briefRunWritten || note == .briefRunAlready {
                Button(copy(.todayOpenAux)) { shell.go(.agent(TeamMember.aux.id)) }
                    .buttonStyle(AuxButtonStyle(kind: .link))
                    .accessibilityLabel(copy(.todayOpenAux)).accessibilityIdentifier("today-open-aux")
            }
        }
    }

    private func content(_ copy: Copy, _ brief: DailyBrief) -> some View {
        let approvals = shell.waitingApprovals.map {
            (id: $0.id, headline: shell.rowHeadline(for: $0), agent: $0.agent,
             at: $0.ts > 0 ? Date(timeIntervalSince1970: TimeInterval($0.ts) / 1000) : nil) as TodayFocusApproval
        }
        let jobs = shell.planned.value ?? []
        let now = shell.now
        let top = TodayFocus.top(approvals: approvals, jobs: jobs, brief: brief, now: now, language: language)
        return VStack(alignment: .leading, spacing: 0) {
            Text(TodayFocus.line(approvals: approvals, jobs: jobs, brief: brief, now: now).text(language))
                .font(.hk(Theme.Text.lead, Theme.Weight.regular)).foregroundStyle(palette.ink.color)
                .accessibilityIdentifier("today-focus").padding(.bottom, 24)
            if !top.isEmpty {
                section(copy(.todayTopTitle), count: nil, loud: true) {
                    ForEach(Array(top.enumerated()), id: \.element.id) { index, item in
                        topRow(copy, item, first: index == 0)
                    }
                }
            }
            Text(copy(.todayYourDay)).font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                .foregroundStyle(palette.ink2.color).padding(.bottom, 12)
            if let events = brief.events {
                section(copy(.todayCalendar), count: events.count == 1 ? copy(.todayEventsOne) : copy.f(.todayEventsMany, events.count)) {
                    if events.isEmpty { emptyRow(copy(.todayNoEvents)) }
                    ForEach(Array(events.enumerated()), id: \.offset) { _, event in
                        row(lead: time(event), text: event.title)
                    }
                }
            } else {
                section(copy(.todayCalendar), count: copy(.unavailable)) { emptyRow(copy(.unavailable)) }
            }
            if let mail = brief.mail {
                let unreadCount = brief.mailTruncated
                    ? copy.f(.todayUnreadAtLeast, mail.count)
                    : (mail.count == 1 ? copy(.todayUnreadOne) : copy.f(.todayUnreadMany, mail.count))
                section(copy(.todayMail), count: unreadCount) {
                    if mail.isEmpty { emptyRow(copy(.todayNoMail)) }
                    ForEach(Array(mail.prefix(showsAllMail ? mail.count : Self.mailPreview).enumerated()), id: \.offset) { _, header in
                        row(lead: header.sender, text: header.subject, strongLead: true)
                    }
                    if !showsAllMail && mail.count > Self.mailPreview {
                        Button(copy(.showAll)) { showsAllMail = true }
                            .buttonStyle(AuxButtonStyle(kind: .link)).padding(.top, 8)
                            .accessibilityLabel(copy(.showAll))
                            .accessibilityIdentifier("today-mail-show-all")
                    }
                }
            } else {
                section(copy(.todayMail), count: copy(.unavailable)) { emptyRow(copy(.unavailable)) }
            }
            let count = brief.prospects.count
            section(copy(.prospectsTitle), count: count == 1 ? copy(.prospectsOne) : copy.f(.prospectsMany, count)) {
                if brief.prospects.isEmpty { emptyRow(copy(.todayNoProspects)) }
                ForEach(brief.prospects) { prospect in
                    prospectRow(copy, prospect).transition(.opacity)
                }
            }
            section(copy(.todayWhatRan), count: nil) {
                if let entries = shell.ledger.value.map(SinceYouLeftPresentation.previewEntries), !entries.isEmpty {
                    ForEach(entries.prefix(5)) { entry in
                        row(lead: LedgerText.localTime(entry.at, locale: Locale(identifier: language.localeIdentifier)),
                            text: LedgerText.what(entry, language: language))
                    }
                } else if let line = SinceYouLeftPresentation.emptyLine(shell.ledger, language: language) {
                    emptyRow(line)
                }
            }
            let checks = TodayBriefChecks.block(for: brief)
            VStack(alignment: .leading, spacing: 6) {
                Text(copy(checks.heading)).font(.meta).foregroundStyle(palette.ink2.color)
                ForEach(Array(checks.checks.enumerated()), id: \.offset) { _, check in
                    HStack(spacing: 8) {
                        IconView(icon: check.state == .available ? .check : .alert).foregroundStyle(palette.muted.color)
                        Text("\(copy(check.source)): \(checkStatus(check.state, copy)); \(copy(.todayFreshnessUnreported))")
                            .font(.ui).foregroundStyle(palette.ink2.color)
                    }
                    if let note = check.note {
                        Text(note).font(.meta).foregroundStyle(palette.muted.color).padding(.leading, 22)
                    }
                }
                if checks.checks.contains(where: { $0.state != .available }) {
                    Button(shell.briefRunning ? copy(.todayRunning) : copy(.todayCheckSources)) { shell.runBriefNow() }
                        .buttonStyle(AuxButtonStyle(kind: .link))
                        .disabled(shell.briefRunning || shell.client == nil)
                        .accessibilityLabel(shell.briefRunning ? copy(.todayRunning) : copy(.todayCheckSources)).accessibilityIdentifier("today-check-sources")
                }
            }.padding(.bottom, 28)
        }
        .animation(.easeOut(duration: 0.22), value: brief.prospects.map(\.id))
    }

    private static let mailPreview = 5  // mail rows before "Show all"

    /// A "What matters first" row: mark, title, evidence, one existing act (the first is the suggested step).
    private func topRow(_ copy: Copy, _ item: TodayTopItem, first: Bool) -> some View {
        var label = copy(.open)
        if case .openJob = item.action { label = copy(.openLedger) }
        return HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    if let mark = item.mark { topMark(copy, mark) }
                    Text(item.title).font(.hk(Theme.Text.body, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                }
                Text(item.evidence).font(.meta).monospacedDigit().foregroundStyle(palette.muted.color)
            }
            .lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 12)
            Button(label) { act(item.action) }
                .buttonStyle(AuxButtonStyle(kind: first ? .primary : .plain, height: 26))
                .accessibilityLabel(label + ", " + item.title)
                .accessibilityIdentifier("today-top-\(item.id)")
        }
        .padding(.vertical, 12)
        .overlay(alignment: .bottom) { Hairline() }
        .accessibilityElement(children: .contain)
    }

    /// Amber only for attention, the error hue only for a failure; always a word too.
    private func topMark(_ copy: Copy, _ mark: TodayTopItem.Mark) -> some View {
        let (word, hue): (String, Color) = switch mark {
        case .waits: (copy(.apNeedsYou), palette.amber.color)
        case .late: (copy(.jobHealthLate), palette.amber.color)
        case .failed: (copy(.jobHealthFailing), palette.red.color)
        }
        return HStack(spacing: 5) {
            Circle().fill(hue).frame(width: 6, height: 6).accessibilityHidden(true)
            Text(word).font(.meta).foregroundStyle(mark == .failed ? palette.red.color : palette.ink2.color)
        }
    }

    private func act(_ action: TodayTopItem.Action) {
        switch action {
        case .openApproval(let id): selection = .waiting(id)
        case .openJob: shell.ledgerOpensPlanned = true; shell.go(.ledger)
        case .openCalendar: shell.go(.calendar)
        case .openMail: shell.go(.agent(TeamMember.mail.id))
        }
    }

    private func checkStatus(_ state: TodayBriefCheckState, _ copy: Copy) -> String {
        switch state {
        case .available: return copy(.todayAvailable)
        case .unavailable: return copy(.todayUnavailable)
        case .notChecked: return copy(.todayNotChecked)
        }
    }

    /// One lead column for every section, so Calendar, Mail and Possible new
    /// clients share a single grid.
    private static let leadColumn: CGFloat = 200

    private func prospectRow(_ copy: Copy, _ prospect: BriefProspect) -> some View {
        let busy = shell.prospectsBusy.contains(prospect.id)
        let hasName = prospect.title != prospect.email
        let date = prospect.shortDate(language)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(prospect.title)
                        .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                        .foregroundStyle(palette.ink.color)
                    if hasName {
                        Text(prospect.email).font(.meta).foregroundStyle(palette.muted.color)
                    }
                }
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: Self.leadColumn, alignment: .leading)
                VStack(alignment: .leading, spacing: 2) {
                    Text(copy(prospect.reasonKey)).font(.ui).foregroundStyle(palette.ink.color)
                    if !date.isEmpty {
                        Text(date).font(.meta).monospacedDigit().foregroundStyle(palette.muted.color)
                    }
                }
                .lineLimit(1)
                Spacer(minLength: 12)
                Button(copy(.prospectIgnore)) { shell.resolveProspect(prospect, add: false) }
                    .buttonStyle(AuxButtonStyle(kind: .plain, height: 26))
                    .accessibilityLabel(copy.f(.prospectIgnoreLabel, prospect.title))
                    .accessibilityIdentifier("today-prospect-ignore-\(prospect.id)")
                Button(copy(.prospectAdd)) { shell.resolveProspect(prospect, add: true) }
                    .buttonStyle(AuxButtonStyle(kind: .primary, height: 26))
                    .accessibilityLabel(copy.f(.prospectAddLabel, prospect.title))
                    .accessibilityIdentifier("today-prospect-add-\(prospect.id)")
            }
            .disabled(busy || shell.client == nil)
            if shell.prospectFailed == prospect.id {
                Text(copy(.prospectFailed)).font(.meta).foregroundStyle(palette.red.color)
            }
        }
        .padding(.vertical, 10)
        .overlay(alignment: .bottom) { Hairline() }
        .accessibilityElement(children: .contain)
        .accessibilityLabel([prospect.title, hasName ? prospect.email : nil, copy(prospect.reasonKey), date]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", "))
    }

    private func time(_ event: BriefEvent) -> String {
        CalendarEventPresentation.timeText(for: event, language: language)
    }

    /// Only "What matters first" is `loud`; the rest of the day sits below it, quieter.
    private func section<Rows: View>(_ title: String, count: String?, loud: Bool = false, @ViewBuilder rows: () -> Rows) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.hk(loud ? Theme.Text.title : Theme.Text.body, Theme.Weight.strong)).foregroundStyle(palette.ink.color)
                Spacer()
                if let count { Text(count).font(.meta).monospacedDigit().foregroundStyle(palette.muted.color) }
            }
            .padding(.bottom, 8)
            .overlay(alignment: .bottom) { Hairline(strong: true) }
            rows()
        }
        .padding(.bottom, 32)
    }

    private func row(lead: String, text: String, strongLead: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(lead)
                .font(.hk(Theme.Text.ui, strongLead ? Theme.Weight.semibold : Theme.Weight.regular))
                .monospacedDigit()
                .foregroundStyle((strongLead ? palette.ink : palette.muted).color)
                .lineLimit(1)
                .frame(width: Self.leadColumn, alignment: .leading)
            Text(text).font(.ui).foregroundStyle(palette.ink.color).lineLimit(2)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 11)
        .overlay(alignment: .bottom) { Hairline() }
    }

    private func emptyRow(_ text: String) -> some View {
        Text(text).font(.ui).foregroundStyle(palette.muted.color).padding(.vertical, 11)
    }
}
