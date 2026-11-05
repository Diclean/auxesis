import AuxesisKit
import SwiftUI

/// The stopped strip replaces the old banner while preserving the existing
/// `resumeAll()` call. Missing stop metadata stays explicitly unavailable.
struct StopBanner: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language
    @State private var reportPresented = false

    var body: some View {
        let copy = StopCopy(language: language)
        let facts = StopBannerModel(requestedAt: nil, acknowledgedAt: nil, unknownOutcomeCount: nil, language: language)
        HStack(spacing: 10) {
            IconView(icon: .stop).foregroundStyle(palette.red.color)
            Text(copy.stoppedReadOnly)
                .font(.hk(Theme.Text.ui, Theme.Weight.semibold))
                .foregroundStyle(palette.red.color)
            Text(facts.text)
                .font(.hk(Theme.Text.secondary, Theme.Weight.regular).monospacedDigit())
                .foregroundStyle(palette.ink.color)
                .lineLimit(1)
                .accessibilityLabel(copy.stoppedReadOnly + ". " + facts.text)
            Spacer(minLength: 8)
            Button(copy.report) { reportPresented = true }
                .buttonStyle(AuxButtonStyle(kind: .plain))
                .accessibilityLabel(copy.report).accessibilityIdentifier("stop-report-open")
            Button(copy.resume) { shell.resumeAll() }
                .buttonStyle(AuxButtonStyle())
                .disabled(shell.stopInFlight)
                .help(copy.resumeHelp)
                .accessibilityLabel(copy.resume).accessibilityIdentifier("stop-resume")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(palette.redSoft.color)
        .overlay(alignment: .bottom) { Rectangle().fill(palette.red.color.opacity(0.25)).frame(height: 1) }
        .sheet(isPresented: $reportPresented) {
            StopReportSheet()
                .environmentObject(shell)
                .themed()
        }
    }
}

private struct StopReportSheet: View {
    @EnvironmentObject private var shell: ShellModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @Environment(\.language) private var language

    private var copy: StopCopy { StopCopy(language: language) }

    var body: some View {
        let report = StopReportModel(unknownOutcomeCount: nil, cancelledSends: shell.cancelledSends, language: language)
        VStack(spacing: 0) {
            HStack {
                Text(copy.report).font(.hk(Theme.Text.title, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                Spacer()
                Button(copy.done) { dismiss() }.buttonStyle(AuxButtonStyle(kind: .plain))
                    .accessibilityLabel(copy.done).accessibilityIdentifier("stop-report-dismiss")
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
            Hairline()
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    ForEach(report.groups) { group in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(group.title).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                            HStack(spacing: 10) {
                                Text(group.detail).font(.ui).foregroundStyle(palette.ink2.color)
                                Spacer()
                                if group.title == report.groups[0].title {
                                    Button(copy.checkStatus) {}
                                        .buttonStyle(AuxButtonStyle(kind: .plain))
                                        .disabled(!group.canCheckStatus)
                                        .help(group.checkStatusDisabledReason ?? copy.statusUnavailable)
                                        .accessibilityLabel(copy.checkStatus).accessibilityIdentifier("stop-report-check-status")
                                }
                            }
                        }
                        Hairline()
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Text(copy.grants).font(.hk(Theme.Text.ui, Theme.Weight.semibold)).foregroundStyle(palette.ink.color)
                        Text(copy.grantsRule).font(.ui).foregroundStyle(palette.ink2.color)
                        ForEach(shell.roster) { member in
                            HStack {
                                Text(member.name).font(.ui).foregroundStyle(palette.ink.color)
                            }
                        }
                        Text(copy.routines).font(.ui).foregroundStyle(palette.ink2.color).padding(.top, 2)
                    }
                    Hairline()
                    VStack(alignment: .leading, spacing: 10) {
                        Text(copy.resumeSemantics).font(.ui).foregroundStyle(palette.ink.color)
                        labelValue(copy.left, report.leftSummary)
                        labelValue(copy.stayed, report.stayedSummary)
                    }
                }
                .padding(24)
            }
        }
        .frame(minWidth: 520, minHeight: 560)
    }

    private func labelValue(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).font(.ui).foregroundStyle(palette.ink2.color)
            Spacer()
            Text(value).font(.ui).foregroundStyle(palette.ink.color)
        }
    }
}

private struct StopCopy {
    let language: Language
    private var french: Bool { language == .fr }
    var stoppedReadOnly: String { french ? "Arrêté (lecture seule)" : "Stopped (read-only)" }
    var report: String { french ? "Rapport d’arrêt" : "Stop report" }
    var resume: String { french ? "Reprendre" : "Resume" }
    var resumeHelp: String { french ? "Reprendre débloque l’utilisation, sans envoyer ni rejouer de travail." : "Resume unblocks use; it does not send or replay work." }
    var done: String { french ? "Terminé" : "Done" }
    var checkStatus: String { french ? "Vérifier le statut" : "Check status" }
    var statusUnavailable: String { french ? "Pas encore disponible." : "Not available yet" }
    var grants: String { french ? "Autorisations" : "Grants" }
    var grantsRule: String { french ? "Les autorisations sont conservées ; leur utilisation est bloquée pendant l’arrêt." : "Grants are kept; use is blocked while stopped." }
    var routines: String { french ? "État des routines indisponible." : "Routine status unavailable." }
    var resumeSemantics: String { french ? "Reprendre débloque l’utilisation. Aucun envoi ni rejeu de travail." : "Resume unblocks use. It does not send or replay work." }
    var left: String { french ? "A quitté ce Mac" : "Left this Mac" }
    /// The stop report says who handled the work, not that
    /// the data stayed here. A local brain can be an alias of a cloud model.
    var stayed: String { L10n.ui(.stayedOnMac, language) }
}
