//! Typed UI message catalog shared by the daemon and CLI.

use serde::{Deserialize, Serialize};

/// UI language. Unknown values deliberately fall back to English.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Fr,
}

impl<'de> Deserialize<'de> for Lang {
    /// Config values are lenient: a hand-edited or unknown `[ui].language`
    /// reads as English instead of failing the whole config load.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::parse(&value).unwrap_or_default())
    }
}

impl Lang {
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Fr => "fr",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Fr => "Français",
        }
    }

    /// Parse only the API/config contract values.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "en" => Some(Self::En),
            "fr" => Some(Self::Fr),
            _ => None,
        }
    }

    /// The system language: the explicit Auxesis overrides first, then the
    /// POSIX locale (`LC_ALL`, `LC_MESSAGES`, `LANG`), then the macOS preferred
    /// languages. French when the first usable value says `fr`, English
    /// otherwise, so a missing or unknown locale reads as English.
    ///
    /// The daemon runs under launchd with no `LANG`, so the macOS languages
    /// are what keep a French Mac on French.
    pub fn from_env() -> Self {
        Self::resolve(|key| std::env::var(key).ok(), &system_language_tags())
    }

    fn resolve(lookup: impl Fn(&str) -> Option<String>, preferred: &[String]) -> Self {
        Self::from_locale(lookup)
            .or_else(|| Self::from_language_tags(preferred.iter().map(String::as_str)))
            .unwrap_or_default()
    }

    fn from_locale(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        [
            "AUXESIS_UI_LANG",
            "AUXESIS_LANG",
            "LC_ALL",
            "LC_MESSAGES",
            "LANG",
        ]
        .iter()
        .filter_map(|key| lookup(key))
        .find_map(|value| {
            let value = value.to_ascii_lowercase();
            if value.starts_with("fr") {
                Some(Self::Fr)
            } else if value.starts_with("en") {
                Some(Self::En)
            } else {
                None
            }
        })
    }

    /// The first preferred tag whose primary subtag is `fr` or `en`, in the
    /// owner's order: `de-DE, fr-FR` reads as French. Only the primary subtag
    /// counts, so `fraser` is not French.
    fn from_language_tags<'a>(tags: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        tags.into_iter().find_map(|tag| {
            let primary = tag.split(['-', '_']).next().unwrap_or_default();
            match primary.to_ascii_lowercase().as_str() {
                "fr" => Some(Self::Fr),
                "en" => Some(Self::En),
                _ => None,
            }
        })
    }
}

/// The macOS preferred languages in the owner's order (`fr-FR`, `en-US`, …),
/// read from the global preferences through CoreFoundation. Empty elsewhere.
#[cfg(target_os = "macos")]
fn system_language_tags() -> Vec<String> {
    use core_foundation::array::CFArray;
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;

    // SAFETY: `CFLocaleCopyPreferredLanguages` returns a new array that the
    // caller owns; `wrap_under_create_rule` takes that ownership and releases
    // it exactly once, when `languages` is dropped.
    let languages: CFArray<CFString> = unsafe {
        CFArray::wrap_under_create_rule(
            core_foundation_sys::locale::CFLocaleCopyPreferredLanguages(),
        )
    };
    (0..languages.len())
        .filter_map(|index| languages.get(index).map(|tag| tag.to_string()))
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn system_language_tags() -> Vec<String> {
    Vec::new()
}

/// Stable identifiers for daemon and CLI UI strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    BriefToday,
    BriefAgendaNone,
    BriefAgenda,
    BriefAllDay,
    BriefGoogleReconnect,
    BriefCalendarNotAvailable,
    BriefAgendaUnavailable,
    BriefWeather,
    BriefWeatherUnavailable,
    BriefWeatherNoCity,
    BriefNothingToDecide,
    BriefNoUnreadMail,
    BriefUnreadOne,
    BriefUnreadMany,
    BriefUnreadAtLeast,
    BriefMailNotAvailable,
    BriefMailUnavailable,
    BriefMailPrivate,
    MorningBrief,
    BriefQuotaPaused,
    BriefFailedPrefix,
    BriefSent,
    BriefAlreadySent,
    BriefQuietHours,
    BriefPaused,
    BriefInvalidQuietStart,
    BriefInvalidQuietEnd,
    BriefUnresolvableQuietEnd,
    /// The counts-only brief notification (`{0}` events, `{1}` messages,
    /// `{2}` unread); it never carries a title, sender or subject.
    BriefReady,
    GoogleFlowRunning,
    GoogleFlowHint,
    GoogleDisconnectFailed,
    GoogleReauthRequired,
    GoogleDurableAccessMissing,
    GoogleScopeInsufficient,
    GoogleNotFound,
    GoogleRateLimited,
    GoogleRateLimitedLater,
    GoogleServerError,
    GoogleInvalidResponse,
    GoogleNetwork,
    GoogleBudgetExhausted,
    GoogleMeterUnavailable,
    GoogleAuthorization,
    OAuthSuccess,
    OAuthFailure,
    JobTitle,
    TelegramApprove,
    TelegramDeny,
    McpServersHeader,
    McpNoServers,
    McpToolsHeader,
    McpUnknownServer,
    McpConfigUnusable,
    McpStateReady,
    McpStateDisabled,
    McpStateFailed,
    McpStateNeedsConfirmation,
    McpStateNeedsApproval,
    McpStateQuarantined,
    McpToolCount,
    /// A data path refused in private mode (`{0}` is the path id and label).
    PrivacyDisabled,
}

/// Resolve one typed message. Every catalog entry has both translations.
#[must_use]
pub fn text(msg: Message, lang: Lang) -> &'static str {
    let (en, fr) = match msg {
        Message::BriefToday => ("Today", "Aujourd’hui"),
        Message::BriefAgendaNone => ("Calendar: no events.", "Agenda : aucun événement."),
        Message::BriefAgenda => ("Calendar:", "Agenda :"),
        Message::BriefAllDay => ("(all day)", "(toute la journée)"),
        Message::BriefCalendarNotAvailable => {
            ("Calendar: not available.", "Agenda : indisponible.")
        }
        Message::BriefGoogleReconnect => (
            "Google: reconnect required.",
            "Google : reconnexion demandée.",
        ),
        Message::BriefAgendaUnavailable => (
            "Calendar: source unavailable.",
            "Agenda : source indisponible.",
        ),
        Message::BriefWeather => ("Weather in", "Météo à"),
        Message::BriefWeatherNoCity => (
            "Weather: no city set yet.",
            "Météo : aucune ville réglée pour l’instant.",
        ),
        Message::BriefWeatherUnavailable => (
            "Weather: source unavailable.",
            "Météo : source indisponible.",
        ),
        Message::BriefNothingToDecide => (
            "Nothing to decide based on the available sources.",
            "Rien à décider d’après les sources.",
        ),
        Message::BriefNoUnreadMail => ("No unread mail.", "Aucun mail non lu."),
        Message::BriefUnreadOne => ("1 unread", "1 non lu"),
        Message::BriefUnreadMany => ("{0} unread", "{0} non lus"),
        Message::BriefUnreadAtLeast => ("At least {0} unread", "Au moins {0} non lus"),
        Message::BriefMailNotAvailable => ("Mail: not available.", "Mail : indisponible."),
        Message::BriefMailPrivate => (
            "Mail: not available in private mode.",
            "Mail : indisponible en mode privé.",
        ),
        Message::BriefMailUnavailable => {
            ("Mail: source unavailable.", "Mail : source indisponible.")
        }
        Message::MorningBrief => ("Morning brief", "Brief du matin"),
        Message::BriefQuotaPaused => (
            "Paused (quota): source budget reached.",
            "En pause (quota) : budget de sources atteint.",
        ),
        Message::BriefFailedPrefix => ("Brief failed: ", "Échec du résumé : "),
        Message::BriefSent => ("Brief sent", "Brief envoyé"),
        Message::BriefAlreadySent => ("Brief already sent", "Brief déjà envoyé"),
        Message::BriefQuietHours => (
            "Brief skipped during quiet hours",
            "Brief ignoré pendant les heures calmes",
        ),
        Message::BriefPaused => ("Brief paused (quota)", "Brief en pause (quota)"),
        Message::BriefInvalidQuietStart => (
            "Invalid quiet-hours start time (expected HH:MM)",
            "Heure calme de début invalide dans la configuration (format attendu HH:MM)",
        ),
        Message::BriefInvalidQuietEnd => (
            "Invalid quiet-hours end time (expected HH:MM)",
            "Heure calme de fin invalide dans la configuration (format attendu HH:MM)",
        ),
        Message::BriefUnresolvableQuietEnd => (
            "Quiet-hours end time cannot be resolved in the local timezone",
            "Heure calme de fin non résolvable dans le fuseau local",
        ),
        Message::BriefReady => (
            "Your brief is ready: {0} event(s) today, {1}. Open Auxesis or run `aux brief`.",
            "Ton brief est prêt : {0} événement(s) aujourd’hui, {1}. Ouvre Auxesis ou lance `aux brief`.",
        ),
        Message::GoogleFlowRunning => (
            "A Google connection is already waiting for browser approval.",
            "Une connexion Google attend déjà ton accord dans le navigateur.",
        ),
        Message::GoogleFlowHint => (
            "Finish the open tab, then try again.",
            "Termine l’onglet ouvert, puis réessaie.",
        ),
        Message::GoogleDisconnectFailed => (
            "Google could not be disconnected.",
            "La déconnexion de Google n'a pas abouti.",
        ),
        Message::GoogleReauthRequired => {
            ("Reconnect to Google.", "Il faut te reconnecter à Google.")
        }
        Message::GoogleDurableAccessMissing => (
            "Google did not return durable access; retry and accept the requested access.",
            "Google n'a pas renvoyé d'autorisation durable ; réessaie et accepte l'accès demandé.",
        ),
        Message::GoogleScopeInsufficient => (
            "Google read-only permission is insufficient.",
            "L’autorisation Google en lecture seule est insuffisante.",
        ),
        Message::GoogleNotFound => ("Google item not found.", "Élément Google introuvable."),
        Message::GoogleRateLimited => (
            "Google rate limited the request; retry in {0} seconds.",
            "Google limite les requêtes; réessaie dans {0} s.",
        ),
        Message::GoogleRateLimitedLater => (
            "Google rate limited the request; retry later.",
            "Google limite les requêtes; réessaie plus tard.",
        ),
        Message::GoogleServerError => (
            "Google encountered a server error.",
            "Le service Google a rencontré une erreur.",
        ),
        Message::GoogleInvalidResponse => (
            "Google returned an invalid response.",
            "Google a renvoyé une réponse invalide.",
        ),
        Message::GoogleNetwork => (
            "The connection to Google failed or timed out.",
            "La connexion à Google a échoué ou expiré.",
        ),
        Message::GoogleBudgetExhausted => (
            "The connected-app daily budget is exhausted ({0}/{1} calls).",
            "Le budget quotidien de l’application connectée est épuisé ({0}/{1} appels).",
        ),
        Message::GoogleMeterUnavailable => (
            "The connected-app budget tracker is unavailable; the call was not started.",
            "Le suivi du budget de l’application connectée est indisponible; l’appel n’a pas été lancé.",
        ),
        Message::GoogleAuthorization => (
            "Google access could not be authorized.",
            "L’accès à Google n’a pas pu être autorisé.",
        ),
        Message::OAuthSuccess => (
            "Connection succeeded. You can close this tab.",
            "Connexion réussie, tu peux fermer cet onglet.",
        ),
        Message::OAuthFailure => ("Connection failed.", "La connexion a échoué."),
        Message::JobTitle => ("Job", "Tâche"),
        Message::TelegramApprove => ("Approve", "Approuver"),
        Message::TelegramDeny => ("Deny", "Refuser"),
        Message::McpServersHeader => ("MCP servers:", "Serveurs MCP :"),
        Message::McpNoServers => (
            "No MCP server is configured.",
            "Aucun serveur MCP n’est configuré.",
        ),
        Message::McpToolsHeader => ("MCP tools for {0}:", "Outils MCP de {0} :"),
        Message::McpUnknownServer => (
            "No MCP server with id {0}.",
            "Aucun serveur MCP avec l’identifiant {0}.",
        ),
        Message::McpConfigUnusable => (
            "The MCP configuration is unusable: {0}",
            "La configuration MCP est inutilisable : {0}",
        ),
        Message::McpStateReady => ("ready", "prêt"),
        Message::McpStateDisabled => ("disabled", "désactivé"),
        Message::McpStateFailed => ("failed", "en échec"),
        Message::McpStateNeedsConfirmation => ("needs confirmation", "à confirmer"),
        Message::McpStateNeedsApproval => ("needs approval", "à approuver"),
        Message::McpStateQuarantined => ("quarantined", "mis de côté"),
        Message::McpToolCount => ("{0} tool(s)", "{0} outil(s)"),
        Message::PrivacyDisabled => (
            "Disabled in private mode: {0}.",
            "Désactivé en mode privé : {0}.",
        ),
    };
    match lang {
        Lang::En => en,
        Lang::Fr => fr,
    }
}

/// Resolve a catalog message and interpolate trusted values.
pub fn format(msg: Message, lang: Lang, values: &[&str]) -> String {
    let template = text(msg, lang);
    values
        .iter()
        .enumerate()
        .fold(template.to_string(), |s, (i, v)| {
            s.replace(&format!("{{{i}}}"), v)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_language_codes_and_english_default() {
        assert_eq!(Lang::default(), Lang::En);
        assert_eq!(Lang::parse("fr"), Some(Lang::Fr));
        assert_eq!(Lang::parse("en"), Some(Lang::En));
        assert_eq!(Lang::parse("fr-FR"), None);
        assert_eq!(
            text(Message::GoogleFlowRunning, Lang::En),
            "A Google connection is already waiting for browser approval."
        );
        assert_eq!(
            text(Message::GoogleFlowRunning, Lang::Fr),
            "Une connexion Google attend déjà ton accord dans le navigateur."
        );
    }

    #[test]
    fn format_interpolates_trusted_values_in_both_languages() {
        assert_eq!(
            format(Message::GoogleRateLimited, Lang::En, &["300"]),
            "Google rate limited the request; retry in 300 seconds."
        );
        assert_eq!(
            format(Message::GoogleBudgetExhausted, Lang::Fr, &["4", "10"]),
            "Le budget quotidien de l’application connectée est épuisé (4/10 appels)."
        );
    }

    /// A fake environment: the named variables, nothing else.
    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn system_language_follows_the_locale_and_falls_back_to_english() {
        assert_eq!(
            Lang::resolve(env(&[("LANG", "fr_FR.UTF-8")]), &[]),
            Lang::Fr
        );
        assert_eq!(
            Lang::resolve(env(&[("LANG", "en_US.UTF-8")]), &[]),
            Lang::En
        );
        assert_eq!(Lang::resolve(env(&[("LANG", "de_DE")]), &[]), Lang::En);
        assert_eq!(Lang::resolve(env(&[]), &[]), Lang::En);
        // The C locale names no language, so the next variable decides.
        assert_eq!(
            Lang::resolve(env(&[("LC_ALL", "C"), ("LANG", "fr_FR")]), &[]),
            Lang::Fr
        );
        // LC_ALL outranks LANG, and an Auxesis override outranks both.
        assert_eq!(
            Lang::resolve(env(&[("LC_ALL", "en_US"), ("LANG", "fr_FR")]), &[]),
            Lang::En
        );
        assert_eq!(
            Lang::resolve(env(&[("AUXESIS_UI_LANG", "en"), ("LANG", "fr_FR")]), &[]),
            Lang::En
        );
    }

    #[test]
    fn macos_preferred_languages_decide_when_the_environment_is_silent() {
        // launchd gives the daemon no `LANG`: the owner's Mac order decides.
        let preferred = ["de-DE".to_string(), "fr-FR".to_string()];
        assert_eq!(Lang::resolve(env(&[]), &preferred), Lang::Fr);
        // An explicit locale still outranks the Mac's language list.
        assert_eq!(
            Lang::resolve(env(&[("LANG", "en_US.UTF-8")]), &preferred),
            Lang::En
        );
    }

    #[test]
    fn language_tags_match_the_primary_subtag_in_the_owners_order() {
        let parse = |tags: &[&str]| Lang::from_language_tags(tags.iter().copied());
        assert_eq!(parse(&["fr-FR"]), Some(Lang::Fr));
        assert_eq!(parse(&["fr_CA", "en-US"]), Some(Lang::Fr));
        assert_eq!(parse(&["en-GB"]), Some(Lang::En));
        assert_eq!(parse(&["de-DE", "en-US", "fr-FR"]), Some(Lang::En));
        assert_eq!(parse(&["de-DE", "es-ES"]), None);
        assert_eq!(parse(&["fraser"]), None);
        assert_eq!(parse(&[]), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_language_list_reads_through_corefoundation() {
        // The live call: at least one tag, and every tag is a plain string.
        let tags = system_language_tags();
        assert!(!tags.is_empty(), "CoreFoundation returned no languages");
        assert!(tags.iter().all(|tag| !tag.is_empty()), "{tags:?}");
    }

    #[test]
    fn unknown_config_language_deserializes_to_english() {
        #[derive(Deserialize)]
        struct Probe {
            language: Lang,
        }
        let probe: Probe = toml::from_str("language = \"de\"").unwrap();
        assert_eq!(probe.language, Lang::En);
        let probe: Probe = toml::from_str("language = \"fr\"").unwrap();
        assert_eq!(probe.language, Lang::Fr);
    }
}
