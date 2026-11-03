// "What Aux knows" (MEM-UI-1): the sections, the suggestions on top, the
// inline editor and the delete confirmation. Contract v3: hairlines between
// rows, no cards, no colour as the only signal.
import AuxesisKit
import SwiftUI

struct MemoryView: View {
    @ObservedObject var model: MemoryPageModel
    @Environment(\.language) private var language
    @Environment(\.palette) private var palette

    var body: some View {
        let copy = Copy(language: language)
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                if model.snapshot != nil {
                    content(copy)
                } else if let problem = model.problem {
                    Text(copy(problem.key)).font(.ui).foregroundStyle(palette.red.color)
                        .accessibilityIdentifier("memory-page-error")
                } else {
                    Text(copy(.loading)).font(.ui).foregroundStyle(palette.ink2.color)
                }
            }
            .padding(.horizontal, Theme.detailSidePadding)
            .padding(.top, Theme.detailTopPadding)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(palette.work.color)
        .onAppear { Task { await model.load() } }
    }

    @ViewBuilder private func content(_ copy: Copy) -> some View {
        // A page-level failure (e.g. the re-read after a save) is never silent.
        if let problem = model.problem, model.problemItem == nil {
            Text(copy(problem.key)).font(.ui).foregroundStyle(palette.red.color)
                .accessibilityIdentifier("memory-page-error")
                .padding(.bottom, 8)
        }
        if !model.suggestions.isEmpty { suggestions(copy) }
        ForEach(model.visibleSections, id: \.self) { section in
            Text(copy(section.titleKey))
                .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                .foregroundStyle(palette.ink.color)
                .padding(.top, Theme.sectionGap)
                .padding(.bottom, 8)
            if section == .rules { fixedRule(copy) }
            ForEach(model.facts(in: section)) { fact in
                factRow(fact, copy)
            }
            if model.showsEmptyLine(in: section) { emptyLine(section, copy) }
        }
    }

    /// The one line an empty section shows (MEM-EMPTY-STATE): where it can be
    /// filled. Muted ink, no colour of its own, the same row as a fact.
    private func emptyLine(_ section: MemorySection, _ copy: Copy) -> some View {
        Text(copy(.memorySectionEmpty))
            .font(.ui)
            .foregroundStyle(palette.ink2.color)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.vertical, 10)
            .overlay(alignment: .top) { Hairline() }
            .accessibilityIdentifier("memory-empty-\(section.rawValue)")
    }

    /// The one rule Aux never breaks, and never offers to break.
    private func fixedRule(_ copy: Copy) -> some View {
        HStack(alignment: .top, spacing: 10) {
            IconView(icon: .lock, size: 14).foregroundStyle(palette.ink2.color).padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                Text(copy(.memoryRuleAlways)).font(.ui).foregroundStyle(palette.ink.color)
                Text(copy(.memoryRuleFixed)).font(.meta).foregroundStyle(palette.muted.color)
            }
        }
        .padding(.vertical, 10)
        .overlay(alignment: .top) { Hairline() }
    }

    /// One fact: its text, where it came from, and the two actions.
    private func factRow(_ fact: MemoryFact, _ copy: Copy) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if model.editing == fact.id {
                TextField(copy(.memoryEdit), text: $model.draft)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(copy(.memoryEdit)).accessibilityIdentifier("memory-edit-field-\(fact.id)")
                HStack(spacing: 8) {
                    Button(copy(.memorySave)) { Task { await model.saveEdit() } }
                        .buttonStyle(AuxButtonStyle(kind: .primary))
                        .disabled(model.busy == fact.id)
                        .accessibilityLabel(copy(.memorySave)).accessibilityIdentifier("memory-save-\(fact.id)")
                    Button(copy(.memoryCancel)) { model.cancelEdit() }
                        .buttonStyle(AuxButtonStyle())
                        .accessibilityLabel(copy(.memoryCancel)).accessibilityIdentifier("memory-cancel-\(fact.id)")
                }
            } else {
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(fact.text)
                            .font(.ui).foregroundStyle(palette.ink.color)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 6) {
                            Text(MemoryText.source(fact.source, language: language))
                            if let day = MemoryText.day(fact.savedAt, language: language) {
                                Text("·")
                                Text(day)
                            }
                        }
                        .font(.meta).foregroundStyle(palette.muted.color)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    if fact.editable {
                        HStack(spacing: 2) {
                            Button(copy(.memoryEdit)) { model.beginEdit(fact) }
                                .buttonStyle(AuxButtonStyle(kind: .link))
                                .accessibilityLabel(copy(.memoryEdit)).accessibilityIdentifier("memory-edit-\(fact.id)")
                            ForgetButton(title: copy(.memoryForget), identifier: "memory-forget-\(fact.id)") {
                                model.askForget(fact)
                            }
                        }
                    }
                }
            }
            if model.confirming == fact.id {
                HStack(spacing: 8) {
                    Text(copy(.memoryForgetConfirm)).font(.meta).foregroundStyle(palette.ink2.color)
                    Button(copy(.memoryForget)) { Task { await model.forget(fact) } }
                        .buttonStyle(AuxButtonStyle(kind: .stop))
                        .disabled(model.busy == fact.id)
                        .accessibilityLabel(copy(.memoryForget)).accessibilityIdentifier("memory-forget-confirm-\(fact.id)")
                    Button(copy(.memoryCancel)) { model.cancelForget() }
                        .buttonStyle(AuxButtonStyle(kind: .plain))
                        .accessibilityLabel(copy(.memoryCancel)).accessibilityIdentifier("memory-forget-cancel-\(fact.id)")
                }
            }
            if model.problemItem == fact.id, let problem = model.problem {
                Text(copy(problem.key))
                    .font(.meta).foregroundStyle(palette.red.color)
                    .accessibilityIdentifier("memory-error-\(fact.id)")
            }
        }
        .padding(.vertical, 10)
        .overlay(alignment: .top) { Hairline() }
    }

    /// The suggestions Aux may have learned, on top of the sections.
    private func suggestions(_ copy: Copy) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(copy(.memorySuggestions))
                .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                .foregroundStyle(palette.ink.color)
            Text(copy(.memorySuggestionsLede)).font(.meta).foregroundStyle(palette.ink2.color).padding(.top, 2)
            ForEach(model.suggestions) { suggestion in
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(suggestion.text)
                            .font(.ui).foregroundStyle(palette.ink.color)
                            .fixedSize(horizontal: false, vertical: true)
                        Text(MemoryText.source(suggestion.source, language: language))
                            .font(.meta).foregroundStyle(palette.muted.color)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    HStack(spacing: 6) {
                        Button(copy(.memoryRemember)) { Task { await model.decide(suggestion, keep: true) } }
                            .buttonStyle(AuxButtonStyle())
                            .disabled(model.busy == suggestion.id)
                            .accessibilityLabel(copy(.memoryRemember)).accessibilityIdentifier("memory-remember-\(suggestion.id)")
                        Button(copy(.memoryNo)) { Task { await model.decide(suggestion, keep: false) } }
                            .buttonStyle(AuxButtonStyle())
                            .disabled(model.busy == suggestion.id)
                            .accessibilityLabel(copy(.memoryNo)).accessibilityIdentifier("memory-no-\(suggestion.id)")
                    }
                }
                .padding(.vertical, 10)
                .overlay(alignment: .top) { Hairline() }
                if model.problemItem == suggestion.id, let problem = model.problem {
                    Text(copy(problem.key))
                        .font(.meta).foregroundStyle(palette.red.color)
                        .accessibilityIdentifier("memory-error-\(suggestion.id)")
                }
            }
        }
        .padding(.bottom, 8)
    }
}
