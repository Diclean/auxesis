// Plain-language copy in English and French, following the system language by
// default (a hand-chosen `auxesis.language` wins).
//
// Two rules from the task:
//   * say "agent", never "dot";
//   * say "source not trusted", never "taint".
// `L10nTests` enforces both and checks every key is translated in both
// languages, so a screen can never silently fall back to a raw key.
import Foundation

/// Where the app reads the owner's preferred languages. Injected so the
/// system-language rule is testable without touching the real machine.
public protocol LocaleLanguageProviding: Sendable {
    var preferredLanguages: [String] { get }
}

/// The real system source: `Locale.preferredLanguages`, in the owner's order.
public struct SystemLocaleLanguageProvider: LocaleLanguageProviding {
    public init() {}
    public var preferredLanguages: [String] { Locale.preferredLanguages }
}

public enum Language: String, CaseIterable, Equatable, Identifiable {
    case fr
    case en

    /// The app follows the system: French when the first preferred language
    /// starts with `fr`, English otherwise. A language the owner chose by hand
    /// (`auxesis.language`, see `Store`) always wins over this.
    public static func preferred(
        using provider: LocaleLanguageProviding = SystemLocaleLanguageProvider()
    ) -> Language {
        guard let first = provider.preferredLanguages.first?.lowercased() else { return .en }
        return first.hasPrefix("fr") ? .fr : .en
    }

    /// The default for a fresh install: the system's preferred language.
    public static var `default`: Language { preferred() }

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .fr: return "Français"
        case .en: return "English"
        }
    }

    /// The locale used for date and number formatting (never for copy).
    public var localeIdentifier: String {
        self == .fr ? "fr_FR" : "en_US"
    }

    /// The day/month/year pattern of the receipt popover.
    public var dayMonthYearFormat: String {
        self == .fr ? "d MMM yyyy" : "MMM d, yyyy"
    }
}

public enum StringKey: String, CaseIterable {
    // App / navigation
    case appName
    case navInbox
    case navActivity
    case navSettings
    case sectionAgents
    case sectionRooms

    // Rail (agents list)
    case railSearchPlaceholder
    case railNoMatch
    case railAddAgent
    case railAddAgentSoon
    case onThisMac
    case restoreHidden
    case restoreHiddenSoon

    // Conversation chrome
    case dayToday
    case dayYesterday
    case quotedReply
    case composerPlaceholder
    case composerMenu
    case composerAttach
    case composerEmoji
    case composerVoice
    case composerSend
    case sentTicks
    case notSentYet

    // Workspace shell (planned live computer/browser view — placeholder only)
    case workspaceTitle
    case workspaceSoonBody
    case workspaceTabs
    case workspaceAddress
    case workspaceGive
    case workspaceTake
    case workspaceToggle
    case workspaceCollapse
    case workspaceSoonHint

    // Connection
    case connConnecting
    case connOnline
    case connOffline
    case connUnauthorized
    case connectingTitle
    case offlineTitle
    case offlineHint
    case offlineTokenMissing
    case offlineTokenUnsafe
    case offlineHintTokenMissing
    case offlineHintTokenUnsafe
    case offlineHintKeyRefused
    case offlineTerminalLabel
    case serviceError
    case retry
    case overrideRejectedWithHost
    case overrideRejectedPlain
    case addrOffLoopback
    // Service health (the child the app starts itself)
    case serviceRunning
    case serviceStopped

    // Agent states
    case stateIdle
    case stateThinking
    case stateWorking
    case stateNeedsYou
    case statePaused
    case stateKilled

    // Thread
    case threadPlaceholder
    case threadSend
    case threadEmpty
    case threadYou
    case threadSending
    case threadStreaming
    case threadSendFailed
    case threadToolResult
    case threadSystem
    /// Banner over a reply whose references could not be read locally.
    case threadRehydrationUnavailable
    case threadReturnHint
    case skillsTitle
    case skillsHelp
    case skillsEmpty
    case skillsIgnored
    case skillsExtrasIgnored

    // Empty-conversation starters
    case starterPrepareDay
    case starterDraftMessage
    case starterExplain
    case starterHint

    // Run receipts
    case receiptWhen
    case receiptWhenAt

    // Inbox
    case inboxTitle
    case inboxSubtitle
    case tabApprove
    case tabDecide
    case tabTriage
    case inboxEmpty
    case inboxDecideSoon
    case inboxTriageSoon

    // Approval card
    case approvalWantsTo
    case approvalSummary
    case approvalWhy
    case approvalChecks
    case approvalTrust
    case approvalScope
    case approvalAllowOnce
    case approvalDeny
    case approvalEdit
    case approvalAlways
    case approvalPending
    case approvalSending
    case approvalNotSent
    case approvalAllowedOnce
    case approvalAllowedAlways
    case approvalDenied
    case approvalExpired
    case approvalUnknownState
    case approvalAudit
    case approvalArming
    case approvalNoChecks
    case checksVerifierAgrees
    case checksVerifierDisagrees
    case approvalTaintValue
    case approvalCleanValue
    case approvalAlwaysTainted
    case approvalAlwaysShell
    case approvalAlwaysUnsandboxed
    case approvalAlwaysUnknownTool
    case approvalAlwaysHint
    case approvalAllowUnknownToolTooLong
    case draftEditStale
    case draftEditRefused
    case approvalJkHint
    case approvalEditHint
    case approvalSendEdited
    case cancel
    case approvalEditSoon

    // First run
    case firstRunTitle
    case firstRunIntro
    case firstRunProviderTitle
    case firstRunProviderBody
    case firstRunAgentTitle
    case firstRunAgentBody
    case firstRunRecheck
    case firstRunWaiting
    case firstRunDone

    // Placeholders ("bientôt")
    case soonBadge
    case soonTitle
    case soonBody
    case soonActivityBody
    case soonSettingsBody
    case soonTrayBody

    // Settings (real bits only)
    case settingsTitle
    case settingsLanguage
    case settingsConnection
    case settingsAddress
    case settingsSource
    case settingsToken
    case settingsService
    case settingsRecheck
    case settingsFirstRun
    case appleEventKitTitle
    case appleEventKitStatusUnknown
    case appleEventKitStatusDenied
    case appleEventKitStatusAuthorized
    case appleEventKitStatusRestricted
    case appleEventKitAuthorize
    case appleEventKitRefresh
    case appleEventKitSaved
    case appleEventKitError

    // Agent settings · Personnalité
    case agentSettingsTitle
    case agentSettingsOpen
    case agentSettingsNoAgent
    case personalityTitle
    case personalityIntro
    case personalityHint
    case personalityLoading
    case personalityDefault
    case personalitySave
    case personalitySaving
    case personalitySaved
    case personalityUnsaved
    case personalityCounter
    case personalityOverLimit
    case personalityTooLong
    case personalityReadFailed
    case personalitySaveFailed

    case phoneSettingsTitle
    case phoneNotConfigured
    case phoneWaitingPairing
    case phonePaired
    case phoneSetupHint
    case phoneKeyPlaceholder
    case phoneSaveKey
    case phoneCreateCode
    case phonePairingCode
    case phonePairingHelp
    case phoneSettingsUnavailable
    case phoneEnable

    // Settings · Applications connectées (G4)
    case connectedAppsTitle
    case googleAppName
    case googleConnectedValue
    case googleUpdateNeededValue
    case googleDisconnectedValue
    case googleWaitingValue
    case googleFailedValue
    case googleUnknownValue
    case googleConnect
    case googleUpdatePermissions
    case googleDisconnect
    case googleHint
    case googleWaitingHint

    // Tray
    case trayOpen
    case trayQuit
    case traySoon

    // Accessibility labels
    case a11yAgentRow
    case a11yWaitingSuffix
    case a11yInboxRow
    case a11yMessageFrom
    case a11yApprovalCard
    case a11yAllowButton
    case a11yDenyButton
    case a11yEditButton
    case a11yAlwaysButton
    case a11yComposer

    // Activity screen
    case activitySubtitle
    case activityEmptyTitle
    case activityEmptyBody

    // Notifications (banner titles and bodies)
    case notifDoneTitle
    case notifDoneBody
    case notifNeedsYouTitle
    case notifNeedsYouBody
    case notifApprovalTitle
    case notifApprovalBody

    // Menu bar / quick ask
    case trayAskPlaceholder
    case trayPauseAll
    case trayPauseUnavailable
    case trayPauseFailed
    case quickAskTitle
    case quickAskPlaceholder
    case quickAskNoAgent
    case quickAskReasonNoAgent
    case quickAskReasonOffline
    case quickAskReasonUnknown
    case quickAskReasonPaused

    // Settings · tool sets and notifications
    case settingsToolsTitle
    case settingsNotifications
    case settingsNotificationsToggle
    case settingsNotificationsHint
    case settingsHotkeyFailed
    case settingsTokenPresent
    case pluginsTitle, pluginsCatalog, pluginsInstalled, pluginsAdd, pluginsCommunityWarning, pluginsWriteWarning, pluginsKeyHint, pluginsEnable, pluginsRemove, pluginsOfficial, pluginsCommunity, pluginsEmpty, pluginsFailed

    // New-agent screen
    case newAgentTitle
    case newAgentIntro
    case newAgentNameLabel
    case newAgentNameHint
    case newAgentNameProblem
    case newAgentRoleLabel
    case newAgentRoleHint
    case newAgentRolePlaceholder
    case newAgentModelLabel
    case newAgentModelsLoading
    case newAgentModelsEmpty
    case newAgentCreate
    case newAgentCreating
    case newAgentDoneTitle
    case newAgentDoneBody
    case newAgentOpenThread
    case newAgentCreateAnother
    case newAgentDuplicateTitle
    case newAgentDuplicateDetail
    case newAgentDuplicateNext

    // First run · failure cards
    case firstRunKeyRefusedTitle
    case firstRunKeyRefusedDetail
    case firstRunKeyRefusedNext
    case firstRunAccessDeniedTitle
    case firstRunAccessDeniedDetail
    case firstRunAccessDeniedNext
    case firstRunTooManyTitle
    case firstRunTooManyDetail
    case firstRunTooManyNext
    case firstRunUnreachableTitle
    case firstRunUnreachableDetail
    case firstRunUnreachableNext
    case firstRunLocalServiceTitle
    case firstRunLocalServiceDetail
    case firstRunLocalServiceNext
    case firstRunUnreadableTitle
    case firstRunUnreadableDetail
    case firstRunUnreadableNext
    case firstRunKeyConflictTitle
    case firstRunKeyConflictDetail
    case firstRunKeyConflictNext
    case firstRunMissingKeyTitle
    case firstRunMissingKeyDetail
    case firstRunMissingKeyNext
    case firstRunInvalidConfigTitle
    case firstRunInvalidConfigDetail
    case firstRunInvalidConfigNext
    case firstRunModelNotFoundTitle
    case firstRunModelNotFoundDetail
    case firstRunModelNotFoundNext
    case firstRunUnknownTitle
    case firstRunUnknownDetail
    case firstRunUnknownNext
    case firstRunRefusedTitle
    case firstRunRefusedDetail
    case firstRunRefusedNext
    case firstRunReadyTitle
    case firstRunReadyNext

    // First run · form
    case firstRunSuccessReachable
    case firstRunSuccess
    case firstRunHonestyNote
    case firstRunPickTitle
    case firstRunPickBody
    case firstRunKeyFieldTitle
    case firstRunKeyOnDiskNote
    case firstRunTestButton
    case firstRunLoading
    case firstRunTesting
    case firstRunCreating
    case firstRunDoneTitle
    case firstRunDoneBody
    case firstRunDoneButton
    case firstRunDefaultAgentLabel
    case providerOllamaTitle

    // Store error sentences
    case errorBadURL
    case errorLocalAccessRefused
    case errorLocalAccessRelaunch
    case errorServiceRefused
    case errorThreadBusy
    case errorTimeout
    case errorUnreachable
    case errorUnreadable
    case errorUnexpected
    case errorTokenUnusable
    case packsUnavailable
    case skillsUnavailable
    case appleEventKitUnavailable

    // Roadmap status words
    case roadmapWaiting
    case roadmapPreparing
    case roadmapRunning
    case roadmapNeedsYou
    case roadmapDone
    case roadmapDoneUnverified
    case roadmapFailed
    case roadmapPaused
    case roadmapUnknown
    case roadmapUnknownToken

    // Receipts
    case receiptSectionTitle
    case receiptStatusDone
    case receiptStatusPausedNeedsYou
    case receiptStatusInterrupted
    case receiptStatusFailed
    case receiptStatusUnknown
    case receiptCostKnown
    case receiptCostUnknown
    case receiptCostUnverified
    case receiptCostIncomplete
    case receiptFileReadOne
    case receiptFileReadMany
    case receiptSiteVisitedOne
    case receiptSiteVisitedMany
    case receiptMessageSentOne
    case receiptMessageSentMany
    case receiptFileReadTitleOne
    case receiptFileReadTitleMany
    case receiptSiteVisitedTitleOne
    case receiptSiteVisitedTitleMany
    case receiptMessageSentTitleOne
    case receiptMessageSentTitleMany
    case receiptToolsUsed
    case receiptNoEffect
    case receiptTextUnits
    case receiptPayYourService
    case receiptIncompleteNote
    case receiptToVerify
    case receiptUntrustedSource
    case receiptNoReservation
    case receiptApprovalAsked
    case receiptYourAnswer
    case receiptWaitingAnswer
    case receiptNoApproval
    case receiptEffects
    case receiptCost
    case receiptProof
    case receiptDecisions

    // Tool labels (receipts and approval cards)
    case toolRunCommand
    case toolReadFile
    case toolWriteFile
    case toolWebSearch
    case toolReadPage
    case toolOpenLink
    case toolSendEmail
    case toolCalendar
    case toolMemory
    case toolUnknownWord
    case toolCharacters
    case answerAllowedOnce
    case answerAlwaysAllowed
    case answerDenied
    case answerEdited
    case answerExpired
    case answerRecorded

    // Tool sets (Settings)
    case packsTitle
    case packsForAgent
    case packsReadFailed
    case packsPickAgent
    case packsAvailableCountOne
    case packsAvailableCountMany
    case packsRequiresApp
    case packsSomeUnavailable
    case packsRemove
    case packsCapExceeded
    case packsSaving
    case packsAssign
    case packsAssignedNotRefreshed
    case packsAssignFailed
    case packsRemoveFailed
    case packMailTitle
    case packMailDescription
    case packAgendaTitle
    case packAgendaDescription
    case packWebSearchTitle
    case packWebSearchDescription
    case packToolMailList
    case packToolMailSearch
    case packToolMailRead
    case packToolMailDraft
    case packToolMailSend
    case packToolCalendarList
    case packToolCalendarCreate
    case packToolHttpFetch
    case packToolUnknown
    case packNoChange

    // Clients: import a contacts file (WO-CRMIO-2)
    case importOpen, importTitle, importLede, importStaysHere, importReading, importRunning
    case importFound, importFoundDetail, importParties, importColumnsRead, importColumnRow, importColumnsIgnored
    case importSkippedTitle, importSkippedNoContact, importSkippedRepeated, importSkippedNeedsCountry
    case importSkippedInvalidPhone, importSkippedCharset, importSkippedEncoded, importSkippedCap
    case importTagTitle, importTagClient, importTagPartner, importTagNone
    case importCountryLabel, importCountryHint, importNothingReadable, importDoneLine, importDone
    case importCancel, importRun, importChoose, importFailed, importUnavailable
    case importRoleName, importRoleGiven, importRoleFamily, importRoleNickname, importRoleEmail, importRolePhone
}

public enum L10n {
    /// The service binary inside the installed app bundle. It is only ever
    /// shown inside the copyable Terminal command, never in a sentence.
    public static let embeddedServicePath = "/Applications/Auxesis.app/Contents/Resources/bin/auxd"

    /// The three starter prompts on an empty first conversation, in order. The
    /// views render them as tappable chips that fill the composer (never send).
    public static let starterPrompts: [StringKey] = [
        .starterPrepareDay, .starterDraftMessage, .starterExplain,
    ]

    public static func t(_ key: StringKey, _ language: Language) -> String {
        if let value = table[key]?[language] {
            return value
        }
        assertionFailure("missing \(language.rawValue) copy for \(key.rawValue)")
        return key.rawValue
    }

    public static func f(_ key: StringKey, _ language: Language, _ arguments: CVarArg...) -> String {
        String(format: t(key, language), arguments: arguments)
    }

    /// Every user-visible string, in both languages.
    public static let table: [StringKey: [Language: String]] = [
        // App / navigation
        .appName: [.fr: "Auxesis", .en: "Auxesis"],
        .navInbox: [.fr: "Boîte de réception", .en: "Inbox"],
        .navActivity: [.fr: "Activité", .en: "Activity"],
        .navSettings: [.fr: "Réglages", .en: "Settings"],
        .sectionAgents: [.fr: "TES AGENTS", .en: "YOUR AGENTS"],
        .sectionRooms: [.fr: "SALONS", .en: "ROOMS"],

        // Rail
        .railSearchPlaceholder: [.fr: "Rechercher un agent", .en: "Search agents"],
        .railNoMatch: [.fr: "Aucun agent ne correspond.", .en: "No agent matches."],
        .railAddAgent: [.fr: "Ajouter un agent", .en: "Add an agent"],
        .railAddAgentSoon: [
            .fr: "Ajouter un agent arrive bientôt. En attendant, crée-le avec « aux chat ».",
            .en: "Adding an agent arrives soon. For now, create one with “aux chat”.",
        ],
        .onThisMac: [.fr: "SUR CE MAC", .en: "ON THIS MAC"],
        .restoreHidden: [.fr: "Restaurer les agents masqués", .en: "Restore hidden agents"],
        .restoreHiddenSoon: [
            .fr: "Masquer un agent n'existe pas encore — bientôt.",
            .en: "Hiding an agent doesn't exist yet — soon.",
        ],

        // Conversation chrome
        .dayToday: [.fr: "Aujourd'hui", .en: "Today"],
        .dayYesterday: [.fr: "Hier", .en: "Yesterday"],
        .quotedReply: [.fr: "En réponse à %@", .en: "In reply to %@"],
        .composerPlaceholder: [.fr: "Message", .en: "Message"],
        .composerMenu: [.fr: "Actions du message", .en: "Message actions"],
        .composerAttach: [.fr: "Joindre un fichier", .en: "Attach a file"],
        .composerEmoji: [.fr: "Emoji et symboles", .en: "Emoji & symbols"],
        .composerVoice: [.fr: "Message vocal", .en: "Voice message"],
        .composerSend: [.fr: "Envoyer le message", .en: "Send the message"],
        .sentTicks: [.fr: "envoyé", .en: "sent"],
        .notSentYet: [.fr: "pas encore envoyé", .en: "not sent yet"],

        // Workspace shell
        .workspaceTitle: [
            .fr: "ESPACE DE TRAVAIL · SUR TON MAC",
            .en: "WORKSPACE · ON YOUR MAC",
        ],
        .workspaceSoonBody: [
            .fr: "Le direct sur ton Mac — bureau et navigateur — arrive à une prochaine étape.",
            .en: "The live view of your Mac — desktop and browser — arrives in a later step.",
        ],
        .workspaceTabs: [.fr: "Onglets", .en: "Tabs"],
        .workspaceAddress: [.fr: "Adresse", .en: "Address"],
        .workspaceGive: [.fr: "Donner à l'agent", .en: "Give to agent"],
        .workspaceTake: [.fr: "Prendre la main", .en: "Take control"],
        .workspaceToggle: [
            .fr: "Afficher ou masquer l'espace de travail",
            .en: "Show or hide the workspace",
        ],
        .workspaceCollapse: [
            .fr: "Masquer l'espace de travail",
            .en: "Hide the workspace",
        ],
        .workspaceSoonHint: [.fr: "bientôt, rien n'est simulé ici", .en: "soon, nothing is simulated here"],

        // Connection
        .connConnecting: [.fr: "connexion…", .en: "connecting…"],
        .connOnline: [.fr: "connecté · version %@", .en: "online · version %@"],
        .connOffline: [.fr: "hors ligne — %@", .en: "offline — %@"],
        .connUnauthorized: [.fr: "clé locale refusée", .en: "local key refused"],
        .connectingTitle: [
            .fr: "Connexion au service Auxesis…",
            .en: "Connecting to the Auxesis service…",
        ],
        .offlineTitle: [
            .fr: "Le service Auxesis n'est pas joignable",
            .en: "The Auxesis service is not reachable",
        ],
        .offlineHint: [
            .fr: "Démarre le service avec la commande ci-dessous, puis réessaie.",
            .en: "Start the service with the command below, then try again.",
        ],
        .offlineTokenMissing: [
            .fr: "La clé d'accès de ce Mac est introuvable.",
            .en: "This Mac's access key can't be found.",
        ],
        .offlineTokenUnsafe: [
            .fr: "La clé d'accès de ce Mac a été refusée.",
            .en: "This Mac's access key was refused.",
        ],
        .offlineHintTokenMissing: [
            .fr: "Ouvre le Terminal et lance le service : il crée la clé d'accès de ce Mac au démarrage. Puis clique sur Réessayer.",
            .en: "Open Terminal and start the service: it creates this Mac's access key at startup. Then click Try again.",
        ],
        .offlineHintTokenUnsafe: [
            .fr: "Le fichier de la clé d'accès n'est pas protégé. Corrige-le avec la commande ci-dessous, puis réessaie.",
            .en: "This Mac's access key file isn't protected. Fix it with the command below, then try again.",
        ],
        .offlineHintKeyRefused: [
            .fr: "La clé d'accès de ce Mac ne correspond plus au service. Supprime-la, puis relance le service : une nouvelle clé sera écrite.",
            .en: "This Mac's access key no longer matches the service. Delete it, then restart the service: a new key will be written.",
        ],
        .offlineTerminalLabel: [.fr: "Dans le Terminal :", .en: "In Terminal:"],
        .serviceError: [
            .fr: "Le service n'a pas répondu. Réessaie dans un instant.",
            .en: "The service didn't answer. Try again in a moment.",
        ],
        .retry: [.fr: "Réessayer", .en: "Try again"],
        .overrideRejectedWithHost: [
            .fr: "%@ ignoré : l'hôte %@ n'est pas local. Adresse utilisée : %@.",
            .en: "%@ ignored: host %@ is not local. Using %@.",
        ],
        .overrideRejectedPlain: [
            .fr: "%@ ignoré : l'adresse n'est pas locale. Adresse utilisée : %@.",
            .en: "%@ ignored: the address is not local. Using %@.",
        ],
        .addrOffLoopback: [
            .fr: "adresse non locale refusée",
            .en: "non-local address refused",
        ],
        .serviceRunning: [.fr: "Service en marche", .en: "Service running"],
        .serviceStopped: [.fr: "Service arrêté", .en: "Service stopped"],

        // Agent states
        .stateIdle: [.fr: "au repos", .en: "idle"],
        .stateThinking: [.fr: "réfléchit", .en: "thinking"],
        .stateWorking: [.fr: "au travail", .en: "working"],
        .stateNeedsYou: [.fr: "attend ta réponse", .en: "waiting for you"],
        .statePaused: [.fr: "en pause", .en: "paused"],
        .stateKilled: [.fr: "arrêté à la main", .en: "stopped by hand"],

        // Thread
        .threadPlaceholder: [.fr: "Écris à %@…", .en: "Write to %@…"],
        .threadSend: [.fr: "Envoyer", .en: "Send"],
        .threadEmpty: [
            .fr: "Rien pour l'instant. Écris un message pour commencer.",
            .en: "Nothing yet. Write a message to start.",
        ],
        .threadYou: [.fr: "Toi", .en: "You"],
        .threadSending: [.fr: "envoi…", .en: "sending…"],
        .threadStreaming: [.fr: "écrit…", .en: "writing…"],
        .threadSendFailed: [
            .fr: "Le message n'est pas parti. Vérifie ta connexion, puis appuie sur Réessayer.",
            .en: "The message didn't go through. Check your connection, then press Try again.",
        ],
        .threadToolResult: [.fr: "Résultat d'outil", .en: "Tool result"],
        .threadSystem: [.fr: "Note du système", .en: "System note"],
        .threadRehydrationUnavailable: [.fr: "Coffre indisponible : noms masqués", .en: "Vault unavailable: names hidden"],
        .threadReturnHint: [.fr: "⏎ envoyer", .en: "⏎ send"],
        .skillsTitle: [.fr: "Compétences", .en: "Skills"],
        .skillsHelp: [
            .fr: "Dépose un dossier avec un fichier SKILL.md dans ~/.auxesis/skills.",
            .en: "Drop a folder containing a SKILL.md file into ~/.auxesis/skills.",
        ],
        .skillsEmpty: [.fr: "Aucune compétence disponible pour le moment.", .en: "No skills are available yet."],
        .skillsIgnored: [.fr: "Cette compétence n'est pas disponible.", .en: "This skill is unavailable."],
        .skillsExtrasIgnored: [.fr: "Les autres fichiers du dossier sont ignorés.", .en: "Other files in this folder are ignored."],

        // Empty-conversation starters
        .starterPrepareDay: [.fr: "Aide-moi à préparer ma journée", .en: "Help me plan my day"],
        .starterDraftMessage: [.fr: "Rédige un brouillon de message", .en: "Draft a message"],
        .starterExplain: [.fr: "Explique-moi ce que tu peux faire", .en: "Explain what you can do"],
        .starterHint: [
            .fr: "Remplit le message ; rien ne part tant que tu n'envoies pas.",
            .en: "Fills the message; nothing is sent until you send it.",
        ],

        // Run receipts
        .receiptWhen: [.fr: "Quand", .en: "When"],
        .receiptWhenAt: [.fr: "%@ à %@", .en: "%@ at %@"],

        // Inbox
        .inboxTitle: [.fr: "Boîte de réception", .en: "Inbox"],
        .inboxSubtitle: [.fr: "ce qui a besoin de toi", .en: "things that need you"],
        .tabApprove: [.fr: "Accords", .en: "Approve"],
        .tabDecide: [.fr: "Décisions", .en: "Decide"],
        .tabTriage: [.fr: "Expéditeurs inconnus", .en: "Unknown senders"],
        .inboxEmpty: [.fr: "Rien n'a besoin de toi.", .en: "Nothing needs you."],
        .inboxDecideSoon: [
            .fr: "Les décisions à prendre arrivent bientôt : cette liste est vide pour l'instant.",
            .en: "Decisions to make arrive soon: this list is empty for now.",
        ],
        .inboxTriageSoon: [
            .fr: "Le tri des expéditeurs inconnus arrive bientôt : cette liste est vide pour l'instant.",
            .en: "Unknown-sender triage arrives soon: this list is empty for now.",
        ],

        // Approval card
        .approvalWantsTo: [.fr: "%@ veut", .en: "%@ wants to"],
        .approvalSummary: [
            .fr: "veut %@. Rien ne se fait sans ton accord.",
            .en: "wants to %@. Nothing happens without your OK.",
        ],
        .approvalWhy: [.fr: "Pourquoi", .en: "Why"],
        .approvalChecks: [.fr: "Vérifications", .en: "Checks"],
        .approvalTrust: [.fr: "Provenance", .en: "Source"],
        .approvalScope: [.fr: "Ce qu'il peut toucher", .en: "What it can touch"],
        .approvalAllowOnce: [.fr: "Autoriser une fois", .en: "Allow once"],
        .approvalDeny: [.fr: "Refuser", .en: "Deny"],
        .approvalEdit: [.fr: "Modifier", .en: "Edit"],
        .approvalAlways: [.fr: "Toujours…", .en: "Always…"],
        .approvalPending: [.fr: "en attente · n° %d", .en: "pending · #%d"],
        .approvalSending: [.fr: "envoi…", .en: "sending…"],
        .approvalNotSent: [.fr: "pas envoyé — %@", .en: "not sent — %@"],
        .approvalAllowedOnce: [.fr: "Autorisé une fois", .en: "Allowed once"],
        .approvalAllowedAlways: [
            .fr: "Autorisé pour toujours · règle enregistrée",
            .en: "Always allowed · rule saved",
        ],
        .approvalDenied: [.fr: "Refusé", .en: "Denied"],
        .approvalExpired: [.fr: "Expiré", .en: "Expired"],
        .approvalUnknownState: [.fr: "état inconnu", .en: "unknown state"],
        .approvalAudit: [.fr: "historique n° %d", .en: "history #%d"],
        .approvalArming: [
            .fr: "Armement de sécurité (1 s)…",
            .en: "Safety arming (1 s)…",
        ],
        .approvalNoChecks: [.fr: "aucun contrôle", .en: "no checks"],
        .checksVerifierAgrees: [
            .fr: "seconde vérification (%@) est d'accord",
            .en: "second check (%@) agrees",
        ],
        .checksVerifierDisagrees: [
            .fr: "seconde vérification (%@) n'est pas d'accord — regarde toi-même",
            .en: "second check (%@) disagrees — look yourself",
        ],
        .approvalTaintValue: [
            .fr: "contenu venu d'une source non fiable — %@",
            .en: "content from an untrusted source — %@",
        ],
        .approvalCleanValue: [.fr: "aucune source non fiable", .en: "no untrusted source"],
        .approvalAlwaysTainted: [
            .fr: "« Toujours » est impossible : le contenu vient d'une source non fiable.",
            .en: "“Always” is impossible: the content comes from an untrusted source.",
        ],
        .approvalAlwaysShell: [
            .fr: "Les commandes système ne peuvent pas être autorisées pour toujours.",
            .en: "System commands can't be always allowed.",
        ],
        .approvalAlwaysUnsandboxed: [
            .fr: "Cet appel s'exécuterait sans protection : « Toujours » est impossible.",
            .en: "This call would run without protection: “Always” is impossible.",
        ],
        .approvalAlwaysUnknownTool: [
            .fr: "Outil inconnu : « Toujours » n'est pas disponible. Tu peux autoriser une fois, refuser ou modifier.",
            .en: "Unknown tool: “Always” isn't available. You can allow once, deny or edit.",
        ],
        .draftEditStale: [
            .fr: "Ce brouillon a changé depuis ta modification. Rien n'est parti : modifie-le à nouveau.",
            .en: "This draft changed since you edited it. Nothing was sent: edit it again.",
        ],
        .draftEditRefused: [
            .fr: "Cette modification ne peut pas partir telle quelle : %@. Modifie la carte ou annule.",
            .en: "This change can't be sent as shown: %@. Edit the card or cancel.",
        ],
        .approvalAlwaysHint: [
            .fr: "Enregistre une règle « autoriser » pour cet outil et cet agent",
            .en: "Save an allow rule for this tool and this agent",
        ],
        .approvalAllowUnknownToolTooLong: [
            .fr: "Identifiant d'outil trop long : il serait tronqué, donc impossible à distinguer d'un autre. Tu peux refuser ou modifier.",
            .en: "Tool id too long: it would be truncated, so it can't be told apart from another. You can deny or edit.",
        ],
        .approvalJkHint: [
            .fr: "J / K suivant · A autoriser · D refuser · E modifier",
            .en: "J / K next · A allow · D deny · E edit",
        ],
        .approvalEditHint: [
            .fr: "Corrige le texte avant de l'envoyer",
            .en: "Fix the text before sending",
        ],
        .approvalSendEdited: [.fr: "Envoyer la version modifiée", .en: "Send edited version"],
        .cancel: [.fr: "Annuler", .en: "Cancel"],
        .approvalEditSoon: [
            .fr: "La modification n'est pas encore disponible côté service. Tu peux autoriser une fois ou refuser.",
            .en: "Editing isn't available in the service yet. You can allow once or deny.",
        ],

        // First run
        .firstRunTitle: [.fr: "Bienvenue dans Auxesis", .en: "Welcome to Auxesis"],
        .firstRunIntro: [
            .fr: "Auxesis fait tourner des agents sur ton Mac. Ils lisent, cherchent et préparent le travail ; ils te demandent toujours avant d'agir.",
            .en: "Auxesis runs agents on your Mac. They read, search and prepare work; they always ask you before acting.",
        ],
        .firstRunProviderTitle: [
            .fr: "1. Ajoute une clé de service d'IA",
            .en: "1. Add an AI service key",
        ],
        .firstRunProviderBody: [
            .fr: "Ouvre le Terminal et tape « aux secret set deepseek », puis colle la clé donnée par ton service d'IA. La clé reste sur ton Mac ; l'app ne la lit jamais.",
            .en: "Open Terminal and type “aux secret set deepseek”, then paste the key from your AI service. The key stays on your Mac; this app never reads it.",
        ],
        .firstRunAgentTitle: [
            .fr: "2. Fais naître ton premier agent",
            .en: "2. Create your first agent",
        ],
        .firstRunAgentBody: [
            .fr: "Tape « aux chat \"Bonjour\" » : le premier agent est créé automatiquement. Tu pourras en ajouter d'autres ici plus tard.",
            .en: "Type “aux chat \"Hello\"”: the first agent is created automatically. You'll be able to add more here later.",
        ],
        .firstRunRecheck: [.fr: "Vérifier à nouveau", .en: "Check again"],
        .firstRunWaiting: [
            .fr: "Auxesis n'a pas encore vu de clé ou d'agent. Les deux étapes ci-dessus restent à faire.",
            .en: "Auxesis hasn't seen a key or an agent yet. The two steps above are still to do.",
        ],
        .firstRunDone: [.fr: "Tout est prêt.", .en: "Everything is ready."],

        // Placeholders
        .soonBadge: [.fr: "bientôt", .en: "soon"],
        .soonTitle: [.fr: "Bientôt", .en: "Soon"],
        .soonBody: [
            .fr: "Cet écran arrive dans une prochaine étape — rien n'est simulé ici.",
            .en: "This screen arrives in a later step — nothing is simulated here.",
        ],
        .soonActivityBody: [
            .fr: "L'activité montrera ce que chaque agent a fait, avec l'historique rejouable.",
            .en: "Activity will show what each agent did, with replayable history.",
        ],
        .soonSettingsBody: [
            .fr: "Les réglages permettront d'ajouter des services d'IA, de choisir la seconde vérification et de gérer les permissions.",
            .en: "Settings will let you add AI services, pick the second check and manage permissions.",
        ],
        .soonTrayBody: [
            .fr: "La barre de menus complète arrivera avec le compteur de la boîte de réception.",
            .en: "The full menu-bar item arrives with the inbox counter.",
        ],

        // Settings
        .settingsTitle: [.fr: "Réglages", .en: "Settings"],
        .settingsLanguage: [.fr: "Langue", .en: "Language"],
        .settingsConnection: [.fr: "Connexion", .en: "Connection"],
        .settingsAddress: [.fr: "Adresse", .en: "Address"],
        .settingsSource: [.fr: "Trouvée via", .en: "Found via"],
        .settingsToken: [.fr: "Clé d'accès de ce Mac", .en: "This Mac's access key"],
        .settingsService: [.fr: "Service", .en: "Service"],
        .settingsRecheck: [.fr: "Revérifier l'installation", .en: "Re-check setup"],
        .settingsFirstRun: [.fr: "Première installation", .en: "First-run setup"],
        .appleEventKitTitle: [.fr: "Calendrier et Rappels Apple", .en: "Apple Calendar and Reminders"],
        .appleEventKitStatusUnknown: [.fr: "Accès non accordé", .en: "Access not granted"],
        .appleEventKitStatusDenied: [.fr: "Accès refusé. Tu peux le modifier dans les réglages de macOS.", .en: "Access denied. You can change it in macOS Settings."],
        .appleEventKitStatusAuthorized: [.fr: "Accès autorisé", .en: "Access allowed"],
        .appleEventKitStatusRestricted: [.fr: "Accès indisponible sur ce Mac", .en: "Access is unavailable on this Mac"],
        .appleEventKitAuthorize: [.fr: "Autoriser", .en: "Allow access"],
        .appleEventKitRefresh: [.fr: "Actualiser", .en: "Refresh"],
        .appleEventKitSaved: [.fr: "Tes éléments à venir sont prêts pour tes agents.", .en: "Your upcoming items are ready for your agents."],
        .appleEventKitError: [.fr: "Impossible de lire ton calendrier et tes rappels. Réessaie.", .en: "Could not read your calendar and reminders. Try again."],

        // Agent settings · Personnalité
        .agentSettingsTitle: [.fr: "Réglages de l'agent", .en: "Agent settings"],
        .agentSettingsOpen: [.fr: "Réglages de l'agent", .en: "Agent settings"],
        .agentSettingsNoAgent: [
            .fr: "Choisis un agent pour régler sa personnalité.",
            .en: "Pick an agent to set its personality.",
        ],
        .personalityTitle: [.fr: "Personnalité", .en: "Personality"],
        .personalityIntro: [
            .fr: "Comment cet agent doit se comporter",
            .en: "How this agent should behave",
        ],
        .personalityHint: [
            .fr: "Ce texte est écrit par toi seul : ni l'agent ni ses outils ne peuvent le modifier.",
            .en: "Only you write this text: neither the agent nor its tools can change it.",
        ],
        .personalityLoading: [
            .fr: "Lecture de la personnalité…",
            .en: "Reading the personality…",
        ],
        .personalityDefault: [
            .fr: "Cet agent n'a pas encore de personnalité écrite : voici celle d'origine. Tu peux la remplacer.",
            .en: "This agent has no written personality yet: this is the built-in one. You can replace it.",
        ],
        .personalitySave: [.fr: "Enregistrer", .en: "Save"],
        .personalitySaving: [.fr: "Enregistrement…", .en: "Saving…"],
        .personalitySaved: [.fr: "Enregistré.", .en: "Saved."],
        .personalityUnsaved: [
            .fr: "Modifications non enregistrées.",
            .en: "Unsaved changes.",
        ],
        .personalityCounter: [.fr: "%d sur %d octets", .en: "%d of %d bytes"],
        .personalityOverLimit: [
            .fr: "C'est trop long : la limite est de %d octets.",
            .en: "That is too long: the limit is %d bytes.",
        ],
        .personalityTooLong: [
            .fr: "C'est trop long pour être enregistré. Raccourcis le texte, puis réessaie.",
            .en: "That is too long to save. Shorten the text and try again.",
        ],
        .personalityReadFailed: [
            .fr: "Impossible de lire la personnalité de cet agent. Réessaie.",
            .en: "Could not read this agent's personality. Try again.",
        ],
        .personalitySaveFailed: [
            .fr: "L'enregistrement a échoué. Réessaie.",
            .en: "Saving failed. Try again.",
        ],

        .phoneSettingsTitle: [.fr: "Téléphone", .en: "Phone"],
        .phoneNotConfigured: [.fr: "non configuré", .en: "not configured"],
        .phoneWaitingPairing: [.fr: "en attente d’appairage", .en: "waiting to pair"],
        .phonePaired: [.fr: "appairé", .en: "paired"],
        .phoneSetupHint: [
            .fr: "Crée ton assistant Telegram avec BotFather puis colle la clé ici.",
            .en: "Create your Telegram assistant with BotFather, then paste its key here.",
        ],
        .phoneKeyPlaceholder: [.fr: "Clé Telegram", .en: "Telegram key"],
        .phoneSaveKey: [.fr: "Enregistrer la clé", .en: "Save key"],
        .phoneCreateCode: [.fr: "Créer un code d’appairage", .en: "Create pairing code"],
        .phonePairingCode: [.fr: "Code à envoyer au bot", .en: "Code to send to the bot"],
        .phonePairingHelp: [
            .fr: "Envoie ce code au bot dans Telegram. Il ne sert qu’une fois.",
            .en: "Send this one-time code to your assistant in Telegram.",
        ],
        .phoneSettingsUnavailable: [
            .fr: "Les réglages Telegram ne sont pas accessibles pour le moment.",
            .en: "Telegram settings are unavailable right now.",
        ],
        .phoneEnable: [.fr: "Activer Telegram", .en: "Enable Telegram"],

        // Settings · Applications connectées (G4)
        .connectedAppsTitle: [.fr: "Applications connectées", .en: "Connected apps"],
        .googleAppName: [.fr: "Google", .en: "Google"],
        .googleConnectedValue: [.fr: "connecté", .en: "connected"],
        .googleUpdateNeededValue: [.fr: "autorisations à mettre à jour", .en: "permissions need an update"],
        .googleDisconnectedValue: [.fr: "non connecté", .en: "not connected"],
        .googleWaitingValue: [
            .fr: "en attente de ton accord dans le navigateur",
            .en: "waiting for your OK in the browser",
        ],
        .googleFailedValue: [
            .fr: "la connexion n'a pas abouti",
            .en: "the connection didn't complete",
        ],
        .googleUnknownValue: [.fr: "état inconnu", .en: "state unknown"],
        .googleConnect: [.fr: "Connecter Google", .en: "Connect Google"],
        .googleUpdatePermissions: [.fr: "Mettre à jour les autorisations Google", .en: "Update Google permissions"],
        .googleDisconnect: [.fr: "Déconnecter", .en: "Disconnect"],
        .googleHint: [
            .fr: "Auxesis peut lire tes e-mails et ton agenda Google. Tu peux retirer cet accès quand tu veux.",
            .en: "Auxesis can read your Google mail and calendar. You can remove this access whenever you want.",
        ],
        .googleWaitingHint: [
            .fr: "Une page Google s'est ouverte dans ton navigateur : accepte l'accès, puis reviens ici.",
            .en: "A Google page opened in your browser: accept the access, then come back here.",
        ],

        // Tray
        .trayOpen: [.fr: "Ouvrir Auxesis", .en: "Open Auxesis"],
        .trayQuit: [.fr: "Quitter Auxesis", .en: "Quit Auxesis"],
        .traySoon: [.fr: "Compteur de la boîte de réception : bientôt", .en: "Inbox counter: soon"],

        // Accessibility
        .a11yAgentRow: [.fr: "Agent %@, %@", .en: "Agent %@, %@"],
        .a11yWaitingSuffix: [.fr: " — %d en attente", .en: " — %d waiting"],
        .a11yInboxRow: [.fr: "Boîte de réception, %d en attente", .en: "Inbox, %d waiting"],
        .a11yMessageFrom: [.fr: "%@, %@", .en: "%@, %@"],
        .a11yApprovalCard: [.fr: "Demande de %@ : %@", .en: "Request from %@: %@"],
        .a11yAllowButton: [.fr: "Autoriser une fois", .en: "Allow once"],
        .a11yDenyButton: [.fr: "Refuser", .en: "Deny"],
        .a11yEditButton: [.fr: "Modifier la demande", .en: "Edit the request"],
        .a11yAlwaysButton: [.fr: "Toujours autoriser", .en: "Always allow"],
        .a11yComposer: [.fr: "Message pour %@", .en: "Message to %@"],

        // Activity screen
        .activitySubtitle: [.fr: "Ce qu'Auxesis a fait", .en: "What Auxesis did"],
        .activityEmptyTitle: [.fr: "Rien pour l'instant.", .en: "Nothing yet."],
        .activityEmptyBody: [
            .fr: "Chaque travail terminé laissera ici son reçu : effets, coût, preuve et décisions.",
            .en: "Every finished run will leave its receipt here: effects, cost, proof and decisions.",
        ],

        // Notifications
        .notifDoneTitle: [.fr: "C'est terminé", .en: "It's done"],
        .notifDoneBody: [.fr: "Un travail est prêt à relire.", .en: "Work is ready to review."],
        .notifNeedsYouTitle: [.fr: "Auxesis a besoin de toi", .en: "Auxesis needs you"],
        .notifNeedsYouBody: [
            .fr: "Un travail est bloqué. Ouvre Auxesis pour voir la suite.",
            .en: "Work is blocked. Open Auxesis to see what's next.",
        ],
        .notifApprovalTitle: [
            .fr: "Auxesis a besoin de ton accord",
            .en: "Auxesis needs your OK",
        ],
        .notifApprovalBody: [
            .fr: "Une demande attend ta réponse dans Auxesis.",
            .en: "A request is waiting for your answer in Auxesis.",
        ],

        // Menu bar / quick ask
        .trayAskPlaceholder: [.fr: "Pose ta question…", .en: "Ask your question…"],
        .trayPauseAll: [.fr: "Tout est en pause", .en: "Everything is paused"],
        .trayPauseUnavailable: [
            .fr: "Auxesis ne répond pas.",
            .en: "Auxesis isn't answering.",
        ],
        .trayPauseFailed: [
            .fr: "Le réglage n'a pas été modifié. Réessaie dans un instant.",
            .en: "The setting wasn't changed. Try again in a moment.",
        ],
        .quickAskTitle: [.fr: "Question rapide", .en: "Quick question"],
        .quickAskPlaceholder: [.fr: "Que veux-tu savoir ?", .en: "What do you want to know?"],
        .quickAskNoAgent: [.fr: "Aucun agent prêt", .en: "No agent ready"],
        .quickAskReasonNoAgent: [
            .fr: "Aucun agent n'est disponible pour l'instant.",
            .en: "No agent is available right now.",
        ],
        .quickAskReasonOffline: [
            .fr: "Auxesis est hors ligne. Ta question est conservée.",
            .en: "Auxesis is offline. Your question is kept.",
        ],
        .quickAskReasonUnknown: [
            .fr: "Vérifie la connexion au service avant d'envoyer ta question.",
            .en: "Check the service connection before sending your question.",
        ],
        .quickAskReasonPaused: [
            .fr: "Reprends les agents avant d'envoyer ta question.",
            .en: "Resume the agents before sending your question.",
        ],

        // Settings · tool sets and notifications
        .settingsToolsTitle: [.fr: "Tes ensembles d'outils", .en: "Your tool sets"],
        .settingsNotifications: [.fr: "Notifications", .en: "Notifications"],
        .settingsNotificationsToggle: [
            .fr: "Me prévenir quand c'est fini ou bloqué",
            .en: "Notify me when it's done or blocked",
        ],
        .settingsNotificationsHint: [
            .fr: "Auxesis t'avertit aussi quand une demande attend ton accord. Trois notifications au maximum sur 24 heures, entre 7 h et 22 h.",
            .en: "Auxesis also alerts you when a request needs your OK. Up to three notifications in 24 hours, between 7 a.m. and 10 p.m.",
        ],
        .settingsHotkeyFailed: [
            .fr: "Le raccourci clavier n'a pas pu être activé.",
            .en: "The keyboard shortcut couldn't be turned on.",
        ],
        .settingsTokenPresent: [
            .fr: "La clé d'accès de ce Mac est présente et protégée.",
            .en: "This Mac's access key is present and protected.",
        ],
        .pluginsTitle: [.fr: "Plugins", .en: "Plugins"],
        .pluginsCatalog: [.fr: "Catalogue", .en: "Catalog"],
        .pluginsInstalled: [.fr: "Installés", .en: "Installed"],
        .pluginsAdd: [.fr: "Ajouter", .en: "Add"],
        .pluginsCommunityWarning: [.fr: "Intégration communautaire : vérifie le code avant de l'activer.", .en: "Community integration: review its code before enabling it."],
        .pluginsWriteWarning: [.fr: "Cette intégration peut modifier des données.", .en: "This integration can change data."],
        .pluginsKeyHint: [.fr: "Cette intégration demande une clé : ajoute-la dans Réglages > Clés.", .en: "This integration needs a key: add it in Settings > Keys."],
        .pluginsEnable: [.fr: "Activer le serveur", .en: "Enable server"],
        .pluginsRemove: [.fr: "Supprimer", .en: "Remove"],
        .pluginsOfficial: [.fr: "Officiel", .en: "Official"],
        .pluginsCommunity: [.fr: "Communautaire", .en: "Community"],
        .pluginsEmpty: [.fr: "Aucun serveur ajouté.", .en: "No servers added."],
        .pluginsFailed: [.fr: "Les plugins ne sont pas disponibles.", .en: "Plugins are unavailable."],

        // New-agent screen
        .newAgentTitle: [.fr: "Nouvel agent", .en: "New agent"],
        .newAgentIntro: [
            .fr: "Donne un nom à ton agent, dis en une phrase ce qu'il doit faire, puis choisis le modèle qui va l'animer.",
            .en: "Name your agent, say in one sentence what it should do, then pick the model that will run it.",
        ],
        .newAgentNameLabel: [.fr: "Nom de l'agent", .en: "Agent name"],
        .newAgentNameHint: [
            .fr: "Sans espace ni accent : lettres, chiffres, tirets, points et traits de soulignement.",
            .en: "No spaces or accents: letters, digits, dashes, periods and underscores.",
        ],
        .newAgentNameProblem: [
            .fr: "Ce nom ne peut pas être utilisé. Utilise des lettres sans accent, des chiffres, des tirets, des points ou des traits de soulignement.",
            .en: "This name can't be used. Use letters without accents, digits, dashes, periods or underscores.",
        ],
        .newAgentRoleLabel: [.fr: "Rôle en une phrase", .en: "Role in one sentence"],
        .newAgentRoleHint: [.fr: "Tu pourras le modifier plus tard.", .en: "You can change it later."],
        .newAgentRolePlaceholder: [
            .fr: "Exemple : préparer mes réunions",
            .en: "Example: prepare my meetings",
        ],
        .newAgentModelLabel: [.fr: "Modèle", .en: "Model"],
        .newAgentModelsLoading: [.fr: "Chargement des modèles…", .en: "Loading models…"],
        .newAgentModelsEmpty: [
            .fr: "Aucun modèle disponible pour l'instant. Ajoute d'abord un service d'IA dans les réglages.",
            .en: "No model available yet. Add an AI service in settings first.",
        ],
        .newAgentCreate: [.fr: "Créer l'agent", .en: "Create the agent"],
        .newAgentCreating: [.fr: "Création de l'agent…", .en: "Creating the agent…"],
        .newAgentDoneTitle: [.fr: "L'agent est créé", .en: "The agent is created"],
        .newAgentDoneBody: [
            .fr: "L'agent « %@ » est prêt. Tu peux lui écrire dès maintenant.",
            .en: "The agent “%@” is ready. You can write to it now.",
        ],
        .newAgentOpenThread: [.fr: "Voir la conversation", .en: "Open the conversation"],
        .newAgentCreateAnother: [.fr: "Créer un autre agent", .en: "Create another agent"],
        .newAgentDuplicateTitle: [.fr: "Ce nom est déjà pris", .en: "This name is already taken"],
        .newAgentDuplicateDetail: [
            .fr: "Un agent porte déjà ce nom.",
            .en: "An agent already has this name.",
        ],
        .newAgentDuplicateNext: [
            .fr: "Choisis un autre nom, puis réessaie.",
            .en: "Pick another name, then try again.",
        ],

        // First run · failure cards
        .firstRunKeyRefusedTitle: [.fr: "La clé a été refusée", .en: "The key was refused"],
        .firstRunKeyRefusedDetail: [
            .fr: "Le service d'IA n'a pas accepté cette clé.",
            .en: "The AI service didn't accept this key.",
        ],
        .firstRunKeyRefusedNext: [
            .fr: "Vérifie la clé sur le site de ton service d'IA, puis colle-la à nouveau.",
            .en: "Check the key on your AI service's site, then paste it again.",
        ],
        .firstRunAccessDeniedTitle: [.fr: "L'accès a été refusé", .en: "Access was denied"],
        .firstRunAccessDeniedDetail: [
            .fr: "Ton compte n'a pas le droit d'utiliser ce service.",
            .en: "Your account isn't allowed to use this service.",
        ],
        .firstRunAccessDeniedNext: [
            .fr: "Vérifie les droits de ton compte chez ton service d'IA, puis réessaie.",
            .en: "Check your account permissions with your AI service, then try again.",
        ],
        .firstRunTooManyTitle: [.fr: "Trop de tentatives", .en: "Too many attempts"],
        .firstRunTooManyDetail: [
            .fr: "Le service a reçu trop de demandes en peu de temps.",
            .en: "The service received too many requests in a short time.",
        ],
        .firstRunTooManyNext: [
            .fr: "Attends une minute, puis appuie sur Réessayer.",
            .en: "Wait a minute, then press Try again.",
        ],
        .firstRunUnreachableTitle: [
            .fr: "Le service d'IA n'a pas répondu",
            .en: "The AI service didn't answer",
        ],
        .firstRunUnreachableDetail: [
            .fr: "L'adresse du service est peut-être mauvaise, ou Internet est coupé.",
            .en: "The service address may be wrong, or the Internet is down.",
        ],
        .firstRunUnreachableNext: [
            .fr: "Vérifie ta connexion Internet, puis appuie sur Réessayer.",
            .en: "Check your Internet connection, then press Try again.",
        ],
        .firstRunLocalServiceTitle: [
            .fr: "Auxesis ne répond pas",
            .en: "Auxesis isn't answering",
        ],
        .firstRunLocalServiceDetail: [
            .fr: "L'application n'arrive pas à joindre Auxesis sur cet ordinateur.",
            .en: "The app can't reach Auxesis on this computer.",
        ],
        .firstRunLocalServiceNext: [
            .fr: "Quitte puis relance Auxesis, puis appuie sur Réessayer.",
            .en: "Quit and relaunch Auxesis, then press Try again.",
        ],
        .firstRunUnreadableTitle: [
            .fr: "Auxesis a mal répondu",
            .en: "Auxesis answered badly",
        ],
        .firstRunUnreadableDetail: [
            .fr: "L'application n'a pas reçu une réponse complète d'Auxesis.",
            .en: "The app didn't get a complete answer from Auxesis.",
        ],
        .firstRunUnreadableNext: [.fr: "Appuie sur Réessayer.", .en: "Press Try again."],
        .firstRunKeyConflictTitle: [
            .fr: "Ce service est déjà enregistré",
            .en: "This service is already saved",
        ],
        .firstRunKeyConflictDetail: [
            .fr: "Un autre service au nom très proche utilise déjà cette clé.",
            .en: "Another service with a very similar name already uses this key.",
        ],
        .firstRunKeyConflictNext: [
            .fr: "Choisis un autre service dans la liste, puis réessaie.",
            .en: "Pick another service in the list, then try again.",
        ],
        .firstRunMissingKeyTitle: [.fr: "Il manque la clé", .en: "The key is missing"],
        .firstRunMissingKeyDetail: [
            .fr: "Ce service a besoin d'une clé pour fonctionner.",
            .en: "This service needs a key to work.",
        ],
        .firstRunMissingKeyNext: [
            .fr: "Colle la clé fournie par le service, puis appuie sur Tester.",
            .en: "Paste the key from the service, then press Test.",
        ],
        .firstRunInvalidConfigTitle: [
            .fr: "Ce service est mal configuré",
            .en: "This service is misconfigured",
        ],
        .firstRunInvalidConfigDetail: [
            .fr: "L'adresse du service ou le nom du modèle n'est pas valide.",
            .en: "The service address or the model name isn't valid.",
        ],
        .firstRunInvalidConfigNext: [
            .fr: "Vérifie ces informations chez ton service d'IA, puis réessaie.",
            .en: "Check this information with your AI service, then try again.",
        ],
        .firstRunModelNotFoundTitle: [.fr: "Ce modèle n'existe pas", .en: "This model doesn't exist"],
        .firstRunModelNotFoundDetail: [
            .fr: "Le nom du modèle n'a pas été reconnu par le service.",
            .en: "The service didn't recognize the model name.",
        ],
        .firstRunModelNotFoundNext: [
            .fr: "Vérifie le nom du modèle indiqué par ton service d'IA, puis réessaie.",
            .en: "Check the model name from your AI service, then try again.",
        ],
        .firstRunUnknownTitle: [
            .fr: "La vérification n'a pas abouti",
            .en: "The check didn't complete",
        ],
        .firstRunUnknownDetail: [
            .fr: "Le service a répondu d'une façon inattendue.",
            .en: "The service answered in an unexpected way.",
        ],
        .firstRunUnknownNext: [
            .fr: "Appuie sur Réessayer ; si cela persiste, choisis un autre service.",
            .en: "Press Try again; if it keeps happening, pick another service.",
        ],
        .firstRunRefusedTitle: [
            .fr: "Le service a refusé la demande",
            .en: "The service refused the request",
        ],
        .firstRunRefusedDetail: [.fr: "Réessaie dans un instant.", .en: "Try again in a moment."],
        .firstRunRefusedNext: [
            .fr: "Appuie sur Réessayer ; si cela persiste, choisis un autre service.",
            .en: "Press Try again; if it keeps happening, pick another service.",
        ],
        .firstRunReadyTitle: [.fr: "Le service est prêt", .en: "The service is ready"],
        .firstRunReadyNext: [.fr: "Tu peux continuer.", .en: "You can continue."],

        // First run · form
        .firstRunSuccessReachable: [
            .fr: "La clé est prête et le service répond.",
            .en: "The key is ready and the service answers.",
        ],
        .firstRunSuccess: [.fr: "La clé est prête.", .en: "The key is ready."],
        .firstRunHonestyNote: [
            .fr: "Ce test ne consomme rien : aucune question n'est envoyée au service d'IA.",
            .en: "This check costs nothing: no question is sent to the AI service.",
        ],
        .firstRunPickTitle: [.fr: "Choisis ton service d'IA", .en: "Pick your AI service"],
        .firstRunPickBody: [
            .fr: "L'agent a besoin d'un service d'IA pour répondre. Choisis-en un, puis colle la clé qu'il t'a fournie.",
            .en: "The agent needs an AI service to answer. Pick one, then paste the key it gave you.",
        ],
        .firstRunKeyFieldTitle: [.fr: "Colle ta clé ici", .en: "Paste your key here"],
        .firstRunKeyOnDiskNote: [
            .fr: "La clé reste sur cet ordinateur, dans un fichier privé. Elle n'est jamais affichée.",
            .en: "The key stays on this computer, in a private file. It is never shown.",
        ],
        .firstRunTestButton: [.fr: "Tester", .en: "Test"],
        .firstRunLoading: [.fr: "Chargement…", .en: "Loading…"],
        .firstRunTesting: [.fr: "Vérification en cours…", .en: "Checking…"],
        .firstRunCreating: [.fr: "Création de ton agent…", .en: "Creating your agent…"],
        .firstRunDoneTitle: [.fr: "Tout est prêt", .en: "Everything is ready"],
        .firstRunDoneBody: [
            .fr: "Ton agent « %@ » est créé. Tu peux lui écrire dès maintenant.",
            .en: "Your agent “%@” is created. You can write to it now.",
        ],
        .firstRunDoneButton: [.fr: "Ouvrir la conversation", .en: "Open the conversation"],
        .firstRunDefaultAgentLabel: [.fr: "Mon agent", .en: "My agent"],
        .providerOllamaTitle: [
            .fr: "Ollama (sur cet ordinateur)",
            .en: "Ollama (on this computer)",
        ],

        // Store error sentences
        .errorBadURL: [
            .fr: "L'adresse du service n'est pas valide.",
            .en: "The service address isn't valid.",
        ],
        .errorLocalAccessRefused: [
            .fr: "L'application n'a pas pu vérifier son accès sur ce Mac. Quitte puis relance Auxesis, puis appuie sur Réessayer.",
            .en: "The app couldn't check its access on this Mac. Quit and relaunch Auxesis, then press Try again.",
        ],
        .errorLocalAccessRelaunch: [
            .fr: "L'application n'a pas pu vérifier son accès sur ce Mac. Quitte puis relance Auxesis.",
            .en: "The app couldn't check its access on this Mac. Quit and relaunch Auxesis.",
        ],
        .errorServiceRefused: [
            .fr: "Le service a refusé la demande. Réessaie dans un instant.",
            .en: "The service refused the request. Try again in a moment.",
        ],
        .errorThreadBusy: [
            .fr: "Ton message précédent attend ta réponse à une demande. Réponds-y, puis renvoie ce message.",
            .en: "Your previous message is waiting for your answer to a request. Answer it, then send this again.",
        ],
        .errorTimeout: [
            .fr: "Le service a mis trop de temps à répondre. Réessaie dans un instant.",
            .en: "The service took too long to answer. Try again in a moment.",
        ],
        .errorUnreachable: [
            .fr: "Le service n'est pas joignable. Réessaie dans un instant.",
            .en: "The service can't be reached. Try again in a moment.",
        ],
        .errorUnreadable: [
            .fr: "La réponse du service est illisible. Réessaie dans un instant.",
            .en: "The service's answer can't be read. Try again in a moment.",
        ],
        .errorUnexpected: [
            .fr: "Une erreur inattendue s'est produite. Réessaie dans un instant.",
            .en: "Something unexpected happened. Try again in a moment.",
        ],
        .errorTokenUnusable: [
            .fr: "La clé d'accès de ce Mac n'est pas utilisable.",
            .en: "This Mac's access key can't be used.",
        ],
        .packsUnavailable: [
            .fr: "Cette version d'Auxesis ne propose pas encore les ensembles d'outils.",
            .en: "This version of Auxesis doesn't offer tool sets yet.",
        ],
        .skillsUnavailable: [
            .fr: "Les compétences ne sont pas disponibles.",
            .en: "Skills aren't available.",
        ],
        .appleEventKitUnavailable: [
            .fr: "Le calendrier et les rappels Apple ne sont pas disponibles.",
            .en: "Apple Calendar and Reminders are unavailable.",
        ],

        // Roadmap status words
        .roadmapWaiting: [.fr: "en attente", .en: "waiting"],
        .roadmapPreparing: [.fr: "en préparation", .en: "preparing"],
        .roadmapRunning: [.fr: "en cours", .en: "running"],
        .roadmapNeedsYou: [.fr: "en attente de toi", .en: "waiting for you"],
        .roadmapDone: [.fr: "terminé", .en: "done"],
        .roadmapDoneUnverified: [.fr: "terminé, à vérifier", .en: "done, to check"],
        .roadmapFailed: [.fr: "échoué", .en: "failed"],
        .roadmapPaused: [.fr: "en pause", .en: "paused"],
        .roadmapUnknown: [.fr: "état inconnu", .en: "unknown state"],
        .roadmapUnknownToken: [.fr: "état inconnu (%@)", .en: "unknown state (%@)"],

        // Receipts
        .receiptSectionTitle: [.fr: "REÇUS", .en: "RECEIPTS"],
        .receiptStatusDone: [.fr: "terminé", .en: "done"],
        .receiptStatusPausedNeedsYou: [.fr: "en pause : a besoin de toi", .en: "paused: needs you"],
        .receiptStatusInterrupted: [.fr: "interrompu", .en: "interrupted"],
        .receiptStatusFailed: [.fr: "échoué", .en: "failed"],
        .receiptStatusUnknown: [.fr: "état inconnu", .en: "unknown state"],
        .receiptCostKnown: [.fr: "%@ (ton service d'IA)", .en: "%@ (your AI service)"],
        .receiptCostUnknown: [
            .fr: "Coût inconnu (ton service d'IA)",
            .en: "Cost unknown (your AI service)",
        ],
        .receiptCostUnverified: [
            .fr: "Coût non vérifié (ton service d'IA)",
            .en: "Cost not verified (your AI service)",
        ],
        .receiptCostIncomplete: [.fr: "Reçu incomplet", .en: "Incomplete receipt"],
        .receiptFileReadOne: [.fr: "fichier lu", .en: "file read"],
        .receiptFileReadMany: [.fr: "fichiers lus", .en: "files read"],
        .receiptSiteVisitedOne: [.fr: "site consulté", .en: "site visited"],
        .receiptSiteVisitedMany: [.fr: "sites consultés", .en: "sites visited"],
        .receiptMessageSentOne: [.fr: "message envoyé", .en: "message sent"],
        .receiptMessageSentMany: [.fr: "messages envoyés", .en: "messages sent"],
        .receiptFileReadTitleOne: [.fr: "Fichier lu", .en: "File read"],
        .receiptFileReadTitleMany: [.fr: "Fichiers lus", .en: "Files read"],
        .receiptSiteVisitedTitleOne: [.fr: "Site consulté", .en: "Site visited"],
        .receiptSiteVisitedTitleMany: [.fr: "Sites consultés", .en: "Sites visited"],
        .receiptMessageSentTitleOne: [.fr: "Message envoyé", .en: "Message sent"],
        .receiptMessageSentTitleMany: [.fr: "Messages envoyés", .en: "Messages sent"],
        .receiptToolsUsed: [.fr: "Outils utilisés", .en: "Tools used"],
        .receiptNoEffect: [.fr: "Aucun effet enregistré.", .en: "No effect recorded."],
        .receiptTextUnits: [
            .fr: "Texte lu : %@ · texte écrit : %@ (compté par ton service d'IA)",
            .en: "Text read: %@ · text written: %@ (counted by your AI service)",
        ],
        .receiptPayYourService: [
            .fr: "Tu paies ton service d'IA, jamais nous.",
            .en: "You pay your AI service, never us.",
        ],
        .receiptIncompleteNote: [
            .fr: "Reçu incomplet : le détail de ce travail n'a pas pu être enregistré.",
            .en: "Incomplete receipt: this run's detail could not be saved.",
        ],
        .receiptToVerify: [.fr: "À vérifier : %@", .en: "To verify: %@"],
        .receiptUntrustedSource: [
            .fr: "Le contenu venait d'une source non fiable.",
            .en: "The content came from an untrusted source.",
        ],
        .receiptNoReservation: [.fr: "Rien à signaler.", .en: "Nothing to flag."],
        .receiptApprovalAsked: [.fr: "Demande d'accord : %@", .en: "Asked for your OK: %@"],
        .receiptYourAnswer: [.fr: "Ta réponse : %@", .en: "Your answer: %@"],
        .receiptWaitingAnswer: [
            .fr: "Il attend ta réponse.",
            .en: "It is waiting for your answer.",
        ],
        .receiptNoApproval: [
            .fr: "Aucune demande d'accord pour ce travail.",
            .en: "No request for your OK this run.",
        ],
        .receiptEffects: [.fr: "Ce qui a changé", .en: "What changed"],
        .receiptCost: [.fr: "Coût", .en: "Cost"],
        .receiptProof: [.fr: "Preuve", .en: "Proof"],
        .receiptDecisions: [.fr: "Décisions", .en: "Decisions"],

        // Tool labels
        .toolRunCommand: [.fr: "lancer une commande", .en: "run a command"],
        .toolReadFile: [.fr: "lire un fichier", .en: "read a file"],
        .toolWriteFile: [.fr: "écrire un fichier", .en: "write a file"],
        .toolWebSearch: [.fr: "chercher sur le web", .en: "search the web"],
        .toolReadPage: [.fr: "lire une page web", .en: "read a web page"],
        .toolOpenLink: [.fr: "ouvrir un lien", .en: "open a link"],
        .toolSendEmail: [.fr: "envoyer un email", .en: "send an email"],
        .toolCalendar: [.fr: "modifier l'agenda", .en: "change the calendar"],
        .toolMemory: [.fr: "écrire dans la mémoire", .en: "write to memory"],
        .toolUnknownWord: [.fr: "un outil", .en: "a tool"],
        .toolCharacters: [.fr: "caractères", .en: "characters"],
        .answerAllowedOnce: [.fr: "autorisé une fois", .en: "allowed once"],
        .answerAlwaysAllowed: [.fr: "toujours autorisé", .en: "always allowed"],
        .answerDenied: [.fr: "refusé", .en: "denied"],
        .answerEdited: [.fr: "modifié puis envoyé", .en: "edited then sent"],
        .answerExpired: [.fr: "expiré sans réponse", .en: "expired with no answer"],
        .answerRecorded: [.fr: "réponse enregistrée", .en: "answer recorded"],

        // Tool sets (Settings)
        .packsTitle: [.fr: "Ensembles d'outils", .en: "Tool sets"],
        .packsForAgent: [.fr: "Pour %@", .en: "For %@"],
        .packsReadFailed: [
            .fr: "Impossible de lire les outils disponibles. Réessaie.",
            .en: "Couldn't read the available tools. Try again.",
        ],
        .packsPickAgent: [
            .fr: "Choisis un agent pour voir ses ensembles d'outils.",
            .en: "Pick an agent to see its tool sets.",
        ],
        .packsAvailableCountOne: [.fr: "%d élément disponible", .en: "%d item available"],
        .packsAvailableCountMany: [.fr: "%d éléments disponibles", .en: "%d items available"],
        .packsRequiresApp: [
            .fr: "nécessite l'application connectée %@",
            .en: "needs the connected app %@",
        ],
        .packsSomeUnavailable: [
            .fr: "Certains éléments ne sont pas disponibles sur ce Mac.",
            .en: "Some items aren't available on this Mac.",
        ],
        .packsRemove: [.fr: "Retirer cet ensemble d'outils", .en: "Remove this tool set"],
        .packsCapExceeded: [
            .fr: "Cet ensemble d'outils dépasserait le plafond de %d outils pour cet agent.",
            .en: "This tool set would exceed the cap of %d tools for this agent.",
        ],
        .packsSaving: [.fr: "Enregistrement…", .en: "Saving…"],
        .packsAssign: [
            .fr: "Donner à cet agent",
            .en: "Give to this agent",
        ],
        .packsAssignedNotRefreshed: [
            .fr: "L'ensemble d'outils est donné, mais la liste des outils n'a pas pu être actualisée.",
            .en: "The tool set was given, but the tool list couldn't be refreshed.",
        ],
        .packsAssignFailed: [
            .fr: "L'ensemble d'outils n'a pas pu être donné à cet agent. Réessaie.",
            .en: "The tool set couldn't be given to this agent. Try again.",
        ],
        .packsRemoveFailed: [
            .fr: "L'ensemble d'outils n'a pas pu être retiré. Réessaie.",
            .en: "The tool set couldn't be removed. Try again.",
        ],
        .packMailTitle: [.fr: "Mail", .en: "Mail"],
        .packMailDescription: [
            .fr: "Lire et préparer tes emails.",
            .en: "Read and prepare your emails.",
        ],
        .packAgendaTitle: [.fr: "Agenda", .en: "Calendar"],
        .packAgendaDescription: [
            .fr: "Consulter et organiser ton agenda.",
            .en: "View and organize your calendar.",
        ],
        .packWebSearchTitle: [.fr: "Recherche web", .en: "Web search"],
        .packWebSearchDescription: [
            .fr: "Ouvrir des pages web pour tes recherches.",
            .en: "Open web pages for your searches.",
        ],
        .packToolMailList: [.fr: "consulter tes emails", .en: "check your emails"],
        .packToolMailSearch: [.fr: "chercher dans tes emails", .en: "search your emails"],
        .packToolMailRead: [.fr: "lire tes emails", .en: "read your emails"],
        .packToolMailDraft: [.fr: "préparer un email", .en: "draft an email"],
        .packToolMailSend: [.fr: "envoyer un email", .en: "send an email"],
        .packToolCalendarList: [.fr: "consulter ton agenda", .en: "view your calendar"],
        .packToolCalendarCreate: [.fr: "modifier l'agenda", .en: "change the calendar"],
        .packToolHttpFetch: [.fr: "ouvrir une page web", .en: "open a web page"],
        .packToolUnknown: [.fr: "un outil", .en: "a tool"],
        .packNoChange: [.fr: "Aucun changement.", .en: "No change."],
        .importOpen: [.fr: "Importer…", .en: "Import…"],
        .importTitle: [.fr: "Importer des contacts", .en: "Import contacts"],
        .importLede: [
            .fr: "Lisez un fichier vCard ou CSV. Rien n'est envoyé hors de ce Mac.",
            .en: "Read a vCard or CSV file. Nothing is sent off this Mac.",
        ],
        .importStaysHere: [
            .fr: "Reste sur ce Mac. Le fichier est lu sur place, sans copie.",
            .en: "Stays on this Mac. The file is read where it is, not copied.",
        ],
        .importReading: [.fr: "Lecture du fichier…", .en: "Reading the file…"],
        .importRunning: [.fr: "Import en cours…", .en: "Importing…"],
        .importFound: [.fr: "%d contacts trouvés", .en: "%d contacts found"],
        .importFoundDetail: [
            .fr: "%1$d avec un e-mail, %2$d avec un téléphone",
            .en: "%1$d with an email, %2$d with a phone",
        ],
        .importParties: [
            .fr: "Nouveaux %1$d · Déjà connus %2$d · Refusés %3$d",
            .en: "New %1$d · Already known %2$d · Refused %3$d",
        ],
        .importColumnsRead: [.fr: "Colonnes lues", .en: "Columns read"],
        .importColumnRow: [.fr: "%1$@ → %2$@", .en: "%1$@ → %2$@"],
        .importColumnsIgnored: [.fr: "Colonnes non lues : %@", .en: "Columns not read: %@"],
        .importSkippedTitle: [.fr: "Non importés", .en: "Not imported"],
        .importSkippedNoContact: [
            .fr: "Ni nom, ni e-mail, ni téléphone",
            .en: "No name, email or phone",
        ],
        .importSkippedRepeated: [
            .fr: "Répétés dans le fichier, fusionnés",
            .en: "Repeated in the file, merged",
        ],
        .importSkippedNeedsCountry: [
            .fr: "Téléphone sans indicatif pays",
            .en: "Phone without a country code",
        ],
        .importSkippedInvalidPhone: [
            .fr: "Numéro de téléphone non valide",
            .en: "Phone number not valid",
        ],
        .importSkippedCharset: [
            .fr: "Carte dans un jeu de caractères qu'Auxesis ne lit pas",
            .en: "Card in a character set Auxesis does not read",
        ],
        .importSkippedEncoded: [.fr: "Champ qui ne se décode pas", .en: "Field that does not decode"],
        .importSkippedCap: [.fr: "Au-delà de la limite de taille", .en: "Over the size limit"],
        .importTagTitle: [.fr: "Importer comme", .en: "Import as"],
        .importTagClient: [.fr: "Client", .en: "Client"],
        .importTagPartner: [.fr: "Partenaire", .en: "Partner"],
        .importTagNone: [.fr: "Aucun", .en: "None"],
        .importCountryLabel: [.fr: "Pays", .en: "Country"],
        .importCountryHint: [
            .fr: "%d numéros n'ont pas d'indicatif. Indiquez le pays en deux lettres, comme FR, pour les garder.",
            .en: "%d phone numbers have no country code. Enter the country as two letters, like FR, to keep them.",
        ],
        .importNothingReadable: [
            .fr: "Aucun contact de ce fichier ne peut être lu.",
            .en: "No contact in this file can be read.",
        ],
        .importDoneLine: [
            .fr: "%1$d contacts importés : %2$d nouveaux, %3$d mis à jour.",
            .en: "Imported %1$d contacts: %2$d new, %3$d updated.",
        ],
        .importDone: [.fr: "Terminé", .en: "Done"],
        .importCancel: [.fr: "Annuler", .en: "Cancel"],
        .importRun: [.fr: "Importer", .en: "Import"],
        .importChoose: [.fr: "Choisir", .en: "Choose"],
        .importFailed: [
            .fr: "Impossible d'importer ces contacts. Réessayez.",
            .en: "Couldn't import these contacts. Try again.",
        ],
        .importUnavailable: [
            .fr: "Auxesis est injoignable pour l'instant. Réessayez dans un instant.",
            .en: "Auxesis can't be reached right now. Try again in a moment.",
        ],
        .importRoleName: [.fr: "Nom", .en: "Name"],
        .importRoleGiven: [.fr: "Prénom", .en: "First name"],
        .importRoleFamily: [.fr: "Nom de famille", .en: "Last name"],
        .importRoleNickname: [.fr: "Surnom", .en: "Nickname"],
        .importRoleEmail: [.fr: "E-mail", .en: "Email"],
        .importRolePhone: [.fr: "Téléphone", .en: "Phone"],
    ]
}
