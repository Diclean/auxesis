// The "<Agent>'s mascot" sheet: a live preview, the ten mascots in
// a 5 × 2 grid, the five tints. Nothing is saved until Done (↩); Cancel (esc)
// drops the pick. Done saves through `AgentLooks.set`, so every mascot on
// screen changes at once. App-only presentation: nothing goes to the daemon.
import AuxesisKit
import SwiftUI

struct MascotPickerSheet: View {
    let member: TeamMember
    /// Every agent on the team, to say when another one already looks the same.
    let team: [TeamMember]
    /// The agent's sidebar status line, when the shell has one.
    let status: String?
    let looks: AgentLooks
    @State private var picker: MascotPicker
    @FocusState private var gridFocused: Bool
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @Environment(\.colorScheme) private var scheme

    /// `start` opens on a pick that is not saved yet (offscreen renders).
    init(member: TeamMember, team: [TeamMember] = TeamMember.all, status: String? = nil,
         looks: AgentLooks = AgentLooks(), start: MascotLook? = nil) {
        self.member = member
        self.team = team
        self.status = status
        self.looks = looks
        var picker = MascotPicker(agentId: member.id, looks: looks)
        if let start { picker.look = start }
        _picker = State(initialValue: picker)
    }

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(copy.f(.mascotTitle, member.name))
                    .font(.hk(Theme.Text.title, Theme.Weight.bold)).foregroundStyle(palette.ink.color)
                Text(copy.f(.mascotLede, member.name))
                    .font(.ui).foregroundStyle(palette.ink2.color).fixedSize(horizontal: false, vertical: true)
            }
            preview
            section(copy(.mascotHeading), value: picker.look.variant.name) { grid(copy) }
            section(copy(.mascotTint), value: picker.look.tint.name) { tints }
            if let twin = picker.twin(among: team.map(\.id), looks: looks) {
                Text(copy.f(.mascotSame, team.first { $0.id == twin }?.name ?? TeamMember.displayName(twin)))
                    .font(.ui).foregroundStyle(palette.ink2.color)
                    .accessibilityIdentifier("mascot-same-look")
            }
            Hairline()
            HStack(spacing: 10) {
                Button(copy(.mascotReset)) { picker.reset() }
                    .buttonStyle(AuxButtonStyle(kind: .link))
                    .disabled(picker.isDefault)
                    .accessibilityLabel(copy(.mascotReset)).accessibilityIdentifier("mascot-reset")
                Spacer()
                Button { picker.cancel(looks); dismiss() } label: { keyLabel(copy(.mascotCancel), key: "esc") }
                    .buttonStyle(AuxButtonStyle())
                    .viewShortcut(.dismissSheet)
                    .accessibilityLabel(copy(.mascotCancel)).accessibilityIdentifier("mascot-cancel")
                Button {
                    picker.save(to: looks)
                    dismiss()
                } label: { keyLabel(copy(.mascotDone), key: "↩") }
                    .buttonStyle(AuxButtonStyle(kind: .primary))
                    .viewShortcut(.confirmSheet)
                    .accessibilityLabel(copy(.mascotDone)).accessibilityIdentifier("mascot-done")
            }
        }
        .padding(28)
        .frame(width: 560)
        .background(palette.work.color)
        .onAppear { gridFocused = true }
    }

    /// The look in the places it lives: big, the sidebar row (28 pt), the chat
    /// author line (20 pt) and a handoff line (16 pt, ink3). Decorative: the
    /// choices below are what VoiceOver reads.
    private var preview: some View {
        let now = Date()
        // Aux's own handoff line names the agent it asks; show it asking Mail.
        let asked = member.role == .chief ? TeamMember.mail.id : member.id
        return HStack(spacing: 28) {
            MascotView(look: picker.look, size: 104)
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    MascotView(look: picker.look, size: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            Text(member.name).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                            if let role = SidebarText.role(member, language) {
                                Text(role).font(.hk(Theme.Text.caption, Theme.Weight.regular)).foregroundStyle(palette.ink3.color)
                            }
                        }
                        if let status {
                            Text(status).font(.hk(Theme.Text.secondary, Theme.Weight.regular))
                                .foregroundStyle(palette.ink2.color).lineLimit(1)
                        }
                    }
                }
                HStack(spacing: 8) {
                    MascotView(look: picker.look, size: 20)
                    Text(member.name).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                    Text(TimeText.clock(now)).font(.meta).foregroundStyle(palette.ink3.color)
                }
                EventLine(text: HandoffLine.text(agents: [asked], at: now, language: language),
                          agents: [TeamMember.aux.id, asked], preview: (member.id, picker.look))
                    .fixedSize()
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(palette.raise.color))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(palette.line.color, lineWidth: 1))
        .accessibilityHidden(true)
    }

    /// The ten mascots, drawn in the picked tint. One focus stop: the arrow
    /// keys move the pick; VoiceOver reads each name, "default" and selected.
    private func grid(_ copy: Copy) -> some View {
        // A plain Grid, not a lazy one: ImageRenderer draws it too.
        let rows = stride(from: 0, to: MascotVariant.allCases.count, by: MascotPicker.columns).map {
            Array(MascotVariant.allCases[$0..<min($0 + MascotPicker.columns, MascotVariant.allCases.count)])
        }
        return Grid(horizontalSpacing: 6, verticalSpacing: 6) {
            ForEach(rows, id: \.self) { row in
                GridRow { ForEach(row, id: \.self) { cell($0, copy) } }
            }
        }
        .focusable()
        .focused($gridFocused)
        .onKeyPress(.leftArrow) { move(dx: -1, dy: 0) }
        .onKeyPress(.rightArrow) { move(dx: 1, dy: 0) }
        .onKeyPress(.upArrow) { move(dx: 0, dy: -1) }
        .onKeyPress(.downArrow) { move(dx: 0, dy: 1) }
    }

    private func cell(_ variant: MascotVariant, _ copy: Copy) -> some View {
        let selected = picker.look.variant == variant
        let isDefault = picker.defaultLook.variant == variant
        return VStack(spacing: 4) {
            MascotView(look: MascotLook(variant, picker.look.tint), size: 28)
            Text(variant.name)
                .font(.hk(Theme.Text.meta, selected ? Theme.Weight.semibold : Theme.Weight.regular))
                .foregroundStyle((selected ? palette.ink : palette.ink2).color)
            Text(copy(.mascotDefault)).font(.hk(Theme.Text.caption, Theme.Weight.regular))
                .foregroundStyle(palette.ink3.color).opacity(isDefault ? 1 : 0)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(selected ? palette.ink.color : .clear, lineWidth: 1.5))
        .contentShape(Rectangle())
        .onTapGesture {
            picker.look.variant = variant
            gridFocused = true
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(isDefault ? "\(variant.name), \(copy(.mascotDefault))" : variant.name)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { picker.look.variant = variant }
        .accessibilityIdentifier("mascot-\(variant.rawValue)")
    }

    private func move(dx: Int, dy: Int) -> KeyPress.Result {
        picker.look.variant = MascotPicker.move(picker.look.variant, dx: dx, dy: dy)
        return .handled
    }

    /// The five tints with their names: the next focus stop (Tab); ← → move.
    private var tints: some View {
        HStack(spacing: 14) {
            ForEach(MascotTint.allCases, id: \.self) { tint in
                let selected = picker.look.tint == tint
                VStack(spacing: 5) {
                    Circle().fill(tint.value(dark: scheme == .dark).color)
                        .frame(width: 22, height: 22)
                        .padding(3)
                        .overlay(Circle().strokeBorder(selected ? palette.ink.color : .clear, lineWidth: 1.5))
                    Text(tint.name)
                        .font(.hk(Theme.Text.meta, selected ? Theme.Weight.semibold : Theme.Weight.regular))
                        .foregroundStyle((selected ? palette.ink : palette.ink2).color)
                }
                .contentShape(Rectangle())
                .onTapGesture { picker.look.tint = tint }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(tint.name)
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
                .accessibilityAction { picker.look.tint = tint }
                .accessibilityIdentifier("mascot-tint-\(tint.rawValue)")
            }
        }
        .focusable()
        .onKeyPress(.leftArrow) { stepTint(-1) }
        .onKeyPress(.rightArrow) { stepTint(1) }
    }

    private func stepTint(_ by: Int) -> KeyPress.Result {
        let all = MascotTint.allCases
        // No index, no step: the tint stays where it is.
        guard let current = all.firstIndex(of: picker.look.tint) else { return .handled }
        picker.look.tint = all[min(max(current + by, 0), all.count - 1)]
        return .handled
    }

    private func section<Content: View>(_ title: String, value: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(title).textCase(.uppercase).tracking(0.6)
                    .font(.hk(Theme.Text.caption, Theme.Weight.medium)).foregroundStyle(palette.ink3.color)
                Spacer()
                Text(value).font(.meta).foregroundStyle(palette.ink2.color)
            }
            content()
        }
    }

    private func keyLabel(_ title: String, key: String) -> some View {
        HStack(spacing: 5) {
            Text(title)
            Text(key).font(.hk(Theme.Text.caption, Theme.Weight.regular)).opacity(0.65)
        }
    }
}
