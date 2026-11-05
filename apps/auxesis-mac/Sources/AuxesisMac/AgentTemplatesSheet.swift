// The "Add an agent" sheet: the starter agents, what each does and the
// access it gets. One that exists already is shown but cannot be picked.
// The Add button is the approval: no extra card follows.
import AuxesisKit
import SwiftUI

struct AgentTemplatesSheet: View {
    @ObservedObject var model: AgentTemplatesModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette

    var body: some View {
        let copy = Copy(language: model.language)
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(copy(.addAgent)).font(.hk(Theme.Text.title, Theme.Weight.bold)).foregroundStyle(palette.ink.color)
                Text(copy(.addAgentLede)).font(.ui).foregroundStyle(palette.ink2.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            List(selection: $model.selected) {
                ForEach(model.templates) { template in
                    row(template, copy).tag(template.id).selectionDisabled(template.created)
                }
            }
            .listStyle(.bordered).frame(minHeight: 260)
            .overlay { if !model.loaded { ProgressView() } }
            if let error = model.error {
                Label(error, systemImage: "exclamationmark.triangle").font(.ui).foregroundStyle(palette.red.color)
                    .fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("agent-templates-error")
            }
            HStack(spacing: 10) {
                Spacer()
                Button(L10n.t(.cancel, model.language)) { dismiss() }
                    .buttonStyle(AuxButtonStyle())
                    .viewShortcut(.dismissSheet)
                    .accessibilityLabel(L10n.t(.cancel, model.language)).accessibilityIdentifier("agent-templates-cancel")
                Button(copy(.addAgentConfirm)) {
                    Task { if await model.confirm() { dismiss() } }
                }
                .buttonStyle(AuxButtonStyle(kind: .primary))
                .viewShortcut(.confirmSheet)
                .disabled(!model.canConfirm)
                .accessibilityLabel(copy(.addAgentConfirm)).accessibilityIdentifier("agent-templates-add")
            }
        }
        .padding(24).frame(width: 480).background(palette.work.color)
        .task { await model.load() }
    }

    private func row(_ template: AgentTemplate, _ copy: Copy) -> some View {
        let tone = template.created ? palette.muted.color : palette.ink.color
        return VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(template.name).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(tone)
                Spacer(minLength: 4)
                if template.created {
                    Label(copy(.addAgentAdded), systemImage: "checkmark").font(.meta).foregroundStyle(palette.muted.color)
                }
            }
            Text(AgentTemplatesModel.about(template, model.language)).font(.meta).foregroundStyle(tone)
            ForEach(AgentTemplatesModel.grantLines(template.grants, model.language), id: \.self) { line in
                Text(line).font(.meta).foregroundStyle(palette.muted.color)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("agent-template-\(template.id)")
    }
}
