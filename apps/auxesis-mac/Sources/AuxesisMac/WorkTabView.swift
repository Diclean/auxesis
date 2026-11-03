// The right panel's Work tab: "Active" (a waiting draft with
// the amber hourglass; a running task with its thin ink bar and "Steer · Stop")
// and "Up next". Under them, the agent's profile, where its brain is changed.
// The rules live in `WorkTab`; no animation.
import AuxesisKit
import SwiftUI

struct WorkTabView: View {
    let member: TeamMember
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        let active = WorkTab.active(approvals: shell.waitingApprovals, delegations: shell.delegations,
                                    stopped: shell.stopped, language: language)
        let next = WorkTab.upNext(shell.planned.value ?? [], now: Date(), language: language)
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                heading(copy(.workActive))
                if active.isEmpty { empty(copy(.workNothingActive)) }
                ForEach(active.prefix(WorkTab.limit)) { WorkRow(item: $0) }
                more(active.count, copy)
                heading(copy(.workUpNext)).padding(.top, 10)
                if next.isEmpty { empty(copy(.workNothingNext)) }
                ForEach(next.prefix(3)) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.title).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color).lineLimit(1)
                        Text(item.line).font(.meta).foregroundStyle(palette.ink3.color).lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 8)
                    .overlay(alignment: .top) { Hairline() }
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 14)
            Hairline()
            ProfileInspector(member: member, embedded: true)
        }
        .onAppear { shell.loadPlanned() }
    }

    private func heading(_ text: String) -> some View {
        Text(text).font(.hk(Theme.Text.meta, Theme.Weight.semibold)).foregroundStyle(palette.ink2.color)
            .padding(.bottom, 4)
            .accessibilityAddTraits(.isHeader)
    }

    private func empty(_ text: String) -> some View {
        Text(text).font(.meta).foregroundStyle(palette.ink3.color).padding(.vertical, 6)
    }

    @ViewBuilder private func more(_ count: Int, _ copy: Copy) -> some View {
        if count > WorkTab.limit {
            Text(copy.f(.workMore, count - WorkTab.limit)).font(.meta).foregroundStyle(palette.ink3.color).padding(.top, 4)
        }
    }
}

/// One "Active" row. A click opens the agent's conversation.
private struct WorkRow: View {
    let item: WorkItem
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        HStack(alignment: .center, spacing: 10) {
            Button { shell.go(.agent(item.agent)) } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color).lineLimit(1)
                    Text(item.line).font(.meta)
                        .foregroundStyle(item.kind == .halted ? palette.red.color : palette.ink3.color).lineLimit(1)
                    if let progress = item.progress {
                        // Thin ink bar: a fact drawn, not a hue.
                        ZStack(alignment: .leading) {
                            Capsule().fill(palette.line.color)
                            Capsule().fill(palette.ink2.color).frame(width: 150 * progress)
                        }
                        .frame(width: 150, height: 3)
                        .padding(.top, 4)
                        .accessibilityHidden(true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(item.title + ". " + item.line).accessibilityIdentifier("work-item-\(item.id)")
            switch item.kind {
            case .waiting:
                Label(copy(.apNeedsYou), systemImage: "hourglass").labelStyle(.iconOnly)
                    .font(.hk(Theme.Text.caption, Theme.Weight.semibold)).foregroundStyle(palette.amber.color)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(palette.amberSoft.color))
                    .accessibilityHidden(true)   // the row's line already says "Needs you"
            case .running:
                HStack(spacing: 4) {
                    Button(copy(.workSteer)) { shell.steer(item.agent) }
                        .buttonStyle(.plain).foregroundStyle(palette.ink2.color)
                        .accessibilityLabel(copy(.workSteer) + " " + item.title).accessibilityIdentifier("work-steer-\(item.id)")
                    Text("·").foregroundStyle(palette.ink3.color).accessibilityHidden(true)
                    Button(copy(.workStop)) { if let task = delegation { shell.stopDelegation(task) } }
                        .buttonStyle(.plain).foregroundStyle(palette.ink2.color)
                        .disabled(delegation == nil)
                        .accessibilityLabel(copy(.workStop) + " " + item.title).accessibilityIdentifier("work-stop-\(item.id)")
                }
                .font(.meta)
                .fixedSize()
            case .halted:
                EmptyView()
            }
        }
        .padding(.vertical, 8)
        .overlay(alignment: .top) { Hairline() }
    }

    private var delegation: Delegation? { shell.delegations.first { $0.id == item.id } }
}
