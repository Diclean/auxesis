import Foundation

/// Facts the stopped UI can display without asking auxd for new data.
public struct StopBannerModel: Equatable {
    public let text: String

    public init(requestedAt: Date?, acknowledgedAt: Date?, unknownOutcomeCount: Int?, timeZone: TimeZone = .current, language: Language = .en) {
        let request = requestedAt.map { Self.copy("Stop requested \(Self.time($0, timeZone: timeZone))", "Arrêt demandé à \(Self.time($0, timeZone: timeZone))", language) }
            ?? Self.copy("Stop requested time unavailable", "heure de demande indisponible", language)
        let acknowledgement = acknowledgedAt.map { Self.copy("acknowledged by auxd \(Self.time($0, timeZone: timeZone))", "confirmé par auxd à \(Self.time($0, timeZone: timeZone))", language) }
            ?? Self.copy("acknowledgement time unavailable", "heure de confirmation indisponible", language)
        let outcomes = unknownOutcomeCount.map { Self.copy("\($0) outcomes unknown", "\($0) résultats inconnus", language) }
            ?? Self.copy("unknown outcome count unavailable", "nombre de résultats inconnus indisponible", language)
        text = "\(request) · \(acknowledgement) · \(outcomes)"
    }

    private static func time(_ date: Date, timeZone: TimeZone) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    fileprivate static func copy(_ english: String, _ french: String, _ language: Language) -> String {
        language == .fr ? french : english
    }
}

public struct StopReportGroup: Equatable, Identifiable {
    public let title: String
    public let detail: String
    public let canCheckStatus: Bool
    public let checkStatusDisabledReason: String?

    public var id: String { title }
}

public struct StopReportModel: Equatable {
    public let groups: [StopReportGroup]
    public let resumeSemantics: String
    public let leftSummary: String
    public let stayedSummary: String

    public init(unknownOutcomeCount: Int?, cancelledSends: Int?, language: Language = .en) {
        resumeSemantics = StopBannerModel.copy("Resume unblocks use. It does not send or replay work.", "Reprendre débloque l’utilisation. Aucun envoi ni rejeu de travail.", language)
        leftSummary = StopBannerModel.copy("Unavailable", "Indisponible", language)
        stayedSummary = StopBannerModel.copy("Unavailable", "Indisponible", language)
        groups = [
            StopReportGroup(
                title: StopBannerModel.copy("Outcome unknown", "Résultat inconnu", language),
                detail: unknownOutcomeCount.map { StopBannerModel.copy("\($0) outcomes unknown", "\($0) résultats inconnus", language) }
                    ?? StopBannerModel.copy("Outcome count unavailable", "Nombre de résultats indisponible", language),
                canCheckStatus: false,
                checkStatusDisabledReason: StopBannerModel.copy("Not available yet", "Pas encore disponible.", language)
            ),
            StopReportGroup(
                title: StopBannerModel.copy("Stopped mid-work, partial kept", "Arrêt en cours, résultat partiel conservé", language),
                detail: StopBannerModel.copy("Unavailable", "Indisponible", language), canCheckStatus: false, checkStatusDisabledReason: nil
            ),
            StopReportGroup(
                title: StopBannerModel.copy("Cancelled before leaving", "Annulé avant envoi", language),
                detail: cancelledSends.map { $0 == 1
                    ? StopBannerModel.copy("1 pending send cancelled", "1 envoi en attente annulé", language)
                    : StopBannerModel.copy("\($0) pending sends cancelled", "\($0) envois en attente annulés", language)
                } ?? StopBannerModel.copy("Unavailable", "Indisponible", language),
                canCheckStatus: false,
                checkStatusDisabledReason: nil
            ),
            StopReportGroup(
                title: StopBannerModel.copy("Held, not deleted", "En attente, non supprimé", language),
                detail: StopBannerModel.copy("Unavailable", "Indisponible", language), canCheckStatus: false, checkStatusDisabledReason: nil
            )
        ]
    }
}

public enum StopActionState {
    public static func disabledReason(stopped: Bool, language: Language = .en) -> String? {
        stopped ? StopBannerModel.copy("Stopped (read-only). Resume to use actions.", "Arrêté (lecture seule). Reprenez pour utiliser les actions.", language) : nil
    }
}
