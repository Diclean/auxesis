// The right panel (v5): Work / Team / Privacy tabs, and the Team tab's map.
// Aux on top, the agents in a row below joined by hairlines (wrapping at four
// a row); a request Aux has open with an agent is drawn solid ink and labelled
// with its task. No animation: the map is the same with Reduce Motion on.
import AuxesisKit
import SwiftUI

struct RightPanel: View {
    let member: TeamMember
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        let copy = Copy(language: language)
        VStack(spacing: 0) {
            HStack(spacing: 4) {
                ForEach(RightPanelTab.allCases, id: \.self) { tab in
                    Button { shell.rightPanelTab = tab } label: {
                        Text(copy(title(tab)))
                            .font(.hk(Theme.Text.meta, shell.rightPanelTab == tab ? Theme.Weight.semibold : Theme.Weight.regular))
                            .foregroundStyle(shell.rightPanelTab == tab ? palette.ink.color : palette.ink2.color)
                            .frame(maxWidth: .infinity, minHeight: 26)
                            .background(RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .fill(shell.rightPanelTab == tab ? palette.selection.color : .clear))
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(copy(title(tab)))
                    .accessibilityAddTraits(shell.rightPanelTab == tab ? [.isSelected] : [])
                    .accessibilityIdentifier("right-panel-tab-\(tab.rawValue)")
                }
            }
            .padding(3)
            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(palette.raise.color))
            .padding(.horizontal, 16)
            .frame(height: Theme.barHeight)
            Hairline()
            switch shell.rightPanelTab {
            case .work: WorkTabView(member: member)
            case .team: TeamMapView()
            case .privacy: PrivacyTabView(member: member)
            }
        }
        .background(palette.list.color)
    }

    private func title(_ tab: RightPanelTab) -> UIKey {
        switch tab {
        case .work: return .workTab
        case .team: return .teamTab
        case .privacy: return .privacyTab
        }
    }
}

struct TeamMapView: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    private let columns = 4

    var body: some View {
        let nodes = shell.teamNodes()
        let flows = TeamMap.inFlight(delegations: shell.delegations, stopped: shell.stopped)
        let rows = stride(from: 1, to: nodes.count, by: columns).map { Array(nodes[$0..<min($0 + columns, nodes.count)]) }
        ScrollView {
            VStack(spacing: 0) {
                if let aux = nodes.first { TeamNodeView(node: aux) }
                ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                    Connector(ids: row.map(\.id), columns: columns, solid: Set(flows.map(\.agent)))
                        .frame(height: 22)
                    GeometryReader { geo in
                        HStack(alignment: .top, spacing: 0) {
                            ForEach(row) { TeamNodeView(node: $0).frame(width: geo.size.width / CGFloat(columns)) }
                        }
                        .frame(width: geo.size.width, alignment: .center)
                    }
                    .frame(height: 96)
                }
                ForEach(flows, id: \.agent) { flow in
                    Text(L10n.uf(.teamAsked, language, TeamMember.displayName(flow.agent) + ": " + flow.task))
                        .font(.hk(Theme.Text.caption, Theme.Weight.regular)).foregroundStyle(palette.ink2.color)
                        .lineLimit(1).truncationMode(.tail).frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
                }
                Hairline().padding(.vertical, 14)
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(nodes) { node in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(node.member.name).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                                if let brain = node.brain { Text(BrainName.display(brain)).foregroundStyle(palette.ink2.color) }
                            }
                            Text(node.stateText(language)).foregroundStyle(palette.ink.color).lineLimit(1)
                            Text(node.today.line(language)).foregroundStyle(palette.ink3.color)
                        }
                        .font(.hk(Theme.Text.meta, Theme.Weight.regular))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityHidden(true)   // each node above already reads all of this
            }
            .padding(16)
        }
    }
}

/// Hairlines from Aux to a row of nodes: a drop from the trunk to a bus, a drop to each node.
/// Solid ink where Aux has an open request to that agent.
private struct Connector: View {
    let ids: [String]
    let columns: Int
    let solid: Set<String>
    @Environment(\.palette) private var palette

    var body: some View {
        Canvas { context, size in
            let hair = palette.ink3.color.opacity(0.5), cell = size.width / CGFloat(columns), mid = size.height / 2
            let xs = ids.indices.map { size.width / 2 + (CGFloat($0) - CGFloat(ids.count - 1) / 2) * cell }
            func stroke(_ from: CGPoint, _ to: CGPoint, _ heavy: Bool) {
                var path = Path(); path.move(to: from); path.addLine(to: to)
                context.stroke(path, with: .color(heavy ? palette.ink.color : hair), lineWidth: heavy ? 2 : 1)
            }
            stroke(CGPoint(x: size.width / 2, y: 0), CGPoint(x: size.width / 2, y: mid), false)
            stroke(CGPoint(x: xs.first ?? 0, y: mid), CGPoint(x: xs.last ?? 0, y: mid), false)
            for (id, x) in zip(ids, xs) {
                let heavy = solid.contains(id)
                if heavy { stroke(CGPoint(x: size.width / 2, y: 0), CGPoint(x: size.width / 2, y: mid), true)
                           stroke(CGPoint(x: size.width / 2, y: mid), CGPoint(x: x, y: mid), true) }
                stroke(CGPoint(x: x, y: mid), CGPoint(x: x, y: size.height), heavy)
            }
        }
    }
}

/// One node: disc, name, and its state under it. Click opens the conversation.
struct TeamNodeView: View {
    let node: TeamNode
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    var body: some View {
        Button { shell.openTeamNode(node) } label: {
            VStack(spacing: 4) {
                AgentMascot(agentId: node.member.id, size: 32)
                Text(node.member.name).font(.hk(Theme.Text.meta, Theme.Weight.semibold)).foregroundStyle(palette.ink.color).lineLimit(1)
                stateLabel
            }
            .padding(6)
            .frame(minWidth: 68)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(node.spoken(language))
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("team-node-\(node.id)")
    }

    /// Label plus icon, never colour alone.
    @ViewBuilder private var stateLabel: some View {
        let text = node.shortText(language)
        switch node.state {
        case .working:
            HStack(spacing: 4) {
                Circle().trim(from: 0, to: 0.8).stroke(palette.ink2.color, lineWidth: 1.5).frame(width: 9, height: 9).rotationEffect(.degrees(-90))
                Text(text)
            }.font(.hk(Theme.Text.caption, Theme.Weight.regular)).foregroundStyle(palette.ink.color)
        case .needsYou:
            Label(text, systemImage: "hourglass")
                .font(.hk(Theme.Text.caption, Theme.Weight.semibold)).foregroundStyle(palette.amber.color)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(palette.amberSoft.color))
        case .stopped:
            Label(text, systemImage: "stop.fill").font(.hk(Theme.Text.caption, Theme.Weight.semibold)).foregroundStyle(palette.red.color)
        case .idle, .offline:
            Text(text).font(.hk(Theme.Text.caption, Theme.Weight.regular)).foregroundStyle(palette.ink3.color)
        }
    }
}
