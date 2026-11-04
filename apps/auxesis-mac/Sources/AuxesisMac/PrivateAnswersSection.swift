// Private answers: the top section of Today. One row per
// answer, newest first: time, the answer text (selectable, six lines, then
// "Show more"), and Dismiss. Hidden when there are none. Polls while Today is
// on screen and refreshes once when the app becomes active.
import AppKit
import AuxesisKit
import SwiftUI

struct PrivateAnswersSection: View {
    @ObservedObject var model: PrivateAnswersModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var expanded: Set<String> = []

    /// Six lines at the body size; a text past this length gets "Show more".
    private static let collapsedLines = 6
    private static let longText = 360
    private static let timeColumn: CGFloat = 56

    var body: some View {
        let copy = Copy(language: language)
        VStack(alignment: .leading, spacing: 0) {
            if !model.isEmpty {
                HStack(alignment: .firstTextBaseline) {
                    Text(copy(.privateAnswersTitle))
                        .font(.hk(Theme.Text.title, Theme.Weight.strong))
                        .foregroundStyle(palette.ink.color)
                    Spacer()
                    Text(copy(.privateAnswersHint)).font(.meta).foregroundStyle(palette.muted.color)
                }
                .padding(.bottom, 8)
                .overlay(alignment: .bottom) { Hairline(strong: true) }
                ForEach(model.answers) { answer in
                    row(copy, answer)
                }
            }
        }
        .padding(.bottom, model.isEmpty ? 0 : 32)
        .onAppear { model.start() }
        .onDisappear { model.stop() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refresh() }
        }
    }

    private func row(_ copy: Copy, _ answer: PrivateAnswer) -> some View {
        let isOpen = expanded.contains(answer.id)
        let isLong = answer.answer.count > Self.longText || answer.answer.filter(\.isNewline).count >= Self.collapsedLines
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 16) {
                Text(answer.clock())
                    .font(.hk(Theme.Text.ui, Theme.Weight.regular))
                    .monospacedDigit()
                    .foregroundStyle(palette.muted.color)
                    .frame(width: Self.timeColumn, alignment: .leading)
                Text(answer.answer)
                    .font(.hk(Theme.Text.body, Theme.Weight.regular))
                    .foregroundStyle(palette.ink.color)
                    .lineLimit(isOpen || !isLong ? nil : Self.collapsedLines)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 12) {
                if isLong {
                    Button(copy(isOpen ? .privateAnswersShowLess : .privateAnswersShowMore)) { toggle(answer.id) }
                        .accessibilityLabel(copy(isOpen ? .privateAnswersShowLess : .privateAnswersShowMore)).accessibilityIdentifier("private-answer-toggle-\(answer.id)")
                        .buttonStyle(AuxButtonStyle(kind: .link))
                }
                Spacer()
                Button(copy(.privateAnswersDismiss)) { Task { await model.dismiss(answer) } }
                    .accessibilityLabel(copy(.privateAnswersDismiss)).accessibilityIdentifier("private-answer-dismiss-\(answer.id)")
                    .buttonStyle(AuxButtonStyle(kind: .plain, height: 26))
            }
            .padding(.leading, Self.timeColumn + 16)
            if model.dismissFailedID == answer.id {
                Text(copy(.privateAnswersDismissFailed))
                    .font(.meta)
                    .foregroundStyle(palette.red.color)
                    .padding(.leading, Self.timeColumn + 16)
            }
        }
        .padding(.vertical, 10)
        .overlay(alignment: .bottom) { Hairline() }
    }

    private func toggle(_ id: String) {
        if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
    }
}
