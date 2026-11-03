//! Open and private mode, and how the global, agent and conversation layers
//! combine (`README.md`, "The two modes").

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Whether a turn may use only covered data paths.
///
/// Variants are ordered from least to most restrictive, so `max` picks the
/// most restrictive mode. The default is [`PrivacyMode::Private`]: an absent
/// `[privacy]` section, and any config that failed to load or parse, keeps the
/// owner closed (see [`PrivacyMode::from_config_or_private`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyMode {
    /// The owner opted in: hosted models and sensitive tools run as before.
    #[serde(alias = "public")]
    Open,
    /// Only covered paths run. Every other path is disabled.
    #[default]
    Private,
}

impl PrivacyMode {
    /// The global mode a privacy-config read resolved to, or `Private` when
    /// the read or the parse failed.
    ///
    /// A call site that reads `[privacy]` from a file it cannot open, or that
    /// cannot parse what it read, must not fall back to the permissive mode:
    /// an unreadable or invalid privacy config is a closed one.
    pub fn from_config_or_private<E>(read: Result<PrivacyConfig, E>) -> Self {
        read.map(|privacy| privacy.mode).unwrap_or(Self::Private)
    }
}

/// The live mode of the daemon's home, read again at every call that needs it.
///
/// A choke point never keeps the value it was given: it holds a `ModeFn` and
/// calls it when it admits a call, so a switch to private reaches a turn, a
/// job or a channel that is already running.
pub type ModeFn = Arc<dyn Fn() -> PrivacyMode + Send + Sync>;

/// `[privacy]` in `config.toml`: the global layer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// `"private"` (default) or `"open"`. Any other value is a config error,
    /// so a typo cannot silently leave the owner in open mode; an absent
    /// section resolves to private too.
    pub mode: PrivacyMode,
    /// `mask_first_names = true` (default `false`): mask a bare given name that
    /// stands alone (`Jules`) in e-mail text as well. With it off a lone given
    /// name is left in clear only in a vocative position (`Salut Jules`). Read
    /// by `kernel_privacy::RegistryBuilder::mask_first_names`.
    pub mask_first_names: bool,
}

/// The mode for one turn: the most restrictive of the global, agent and
/// conversation layers. A lower layer can tighten the result but never
/// loosen it.
pub fn resolve(
    global: PrivacyMode,
    agent: Option<PrivacyMode>,
    conversation: Option<PrivacyMode>,
) -> PrivacyMode {
    [agent, conversation]
        .into_iter()
        .flatten()
        .fold(global, PrivacyMode::max)
}

/// Where a privacy change comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The Mac app.
    MacApp,
    /// The `aux` CLI.
    Cli,
    /// WhatsApp or Telegram (`/prive`).
    Channel,
}

/// Which layer a change sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The owner's global setting.
    Global,
    /// One agent.
    Agent,
    /// One conversation.
    Conversation,
}

/// Whether `origin` may set `layer` to `to`.
///
/// A channel may tighten its own conversation and nothing else. Loosening a
/// conversation needs the Mac app. Global and agent layers can be changed in
/// either direction by the Mac app or the CLI.
///
/// The caller must pass the channel's own conversation layer; this function
/// does not check which conversation that is.
pub fn may_set(origin: Origin, layer: Layer, to: PrivacyMode) -> bool {
    match (origin, layer, to) {
        (Origin::MacApp, _, _) => true,
        (Origin::Cli, Layer::Conversation, PrivacyMode::Open) => false,
        (Origin::Cli, _, _) => true,
        (Origin::Channel, Layer::Conversation, PrivacyMode::Private) => true,
        (Origin::Channel, _, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn default_mode_is_private() {
        assert_eq!(PrivacyMode::default(), PrivacyMode::Private);
        assert_eq!(Config::default().privacy.mode, PrivacyMode::Private);
    }

    #[test]
    fn an_unreadable_or_invalid_privacy_config_is_private() {
        // The fail-closed call-site helper: a read that failed (I/O, missing
        // file) and a config that failed to parse both resolve to Private.
        let unreadable: Result<PrivacyConfig, std::io::Error> =
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert_eq!(
            PrivacyMode::from_config_or_private(unreadable),
            PrivacyMode::Private
        );

        let invalid = toml::from_str::<PrivacyConfig>("mode = \"privte\"\n");
        assert!(invalid.is_err(), "a typo must be a parse error");
        assert_eq!(
            PrivacyMode::from_config_or_private(invalid),
            PrivacyMode::Private
        );

        // A valid explicit opt-in still resolves to Open.
        let open = toml::from_str::<PrivacyConfig>("mode = \"open\"\n");
        assert_eq!(PrivacyMode::from_config_or_private(open), PrivacyMode::Open);

        // The same helper over a whole `Config` read: a parse error is Private.
        let whole: Result<Config, toml::de::Error> =
            toml::from_str("[privacy]\nmode = \"privte\"\n");
        assert_eq!(
            PrivacyMode::from_config_or_private(whole.map(|config| config.privacy)),
            PrivacyMode::Private
        );
    }

    #[test]
    fn most_restrictive_layer_wins() {
        use PrivacyMode::{Open, Private};
        assert_eq!(resolve(Open, None, None), Open);
        assert_eq!(resolve(Open, Some(Private), None), Private);
        assert_eq!(resolve(Open, None, Some(Private)), Private);
        assert_eq!(resolve(Open, Some(Open), Some(Private)), Private);
        assert_eq!(resolve(Private, None, None), Private);
    }

    #[test]
    fn a_lower_layer_cannot_loosen_a_private_global() {
        use PrivacyMode::{Open, Private};
        assert_eq!(resolve(Private, Some(Open), Some(Open)), Private);
    }

    #[test]
    fn a_channel_can_tighten_only_its_own_conversation() {
        use PrivacyMode::{Open, Private};
        assert!(may_set(Origin::Channel, Layer::Conversation, Private));
        assert!(!may_set(Origin::Channel, Layer::Conversation, Open));
        assert!(!may_set(Origin::Channel, Layer::Global, Private));
        assert!(!may_set(Origin::Channel, Layer::Agent, Private));
        assert!(!may_set(Origin::Channel, Layer::Global, Open));
    }

    #[test]
    fn a_channel_tightening_resolves_private_even_under_an_open_global() {
        use PrivacyMode::{Open, Private};
        let conversation = Some(Private);
        assert!(may_set(Origin::Channel, Layer::Conversation, Private));
        assert_eq!(resolve(Open, None, conversation), Private);
    }

    #[test]
    fn loosening_a_conversation_needs_the_mac_app() {
        use PrivacyMode::{Open, Private};
        assert!(may_set(Origin::MacApp, Layer::Conversation, Open));
        assert!(!may_set(Origin::Cli, Layer::Conversation, Open));
        assert!(may_set(Origin::Cli, Layer::Global, Open));
        assert!(may_set(Origin::Cli, Layer::Agent, Open));
        assert!(may_set(Origin::Cli, Layer::Conversation, Private));
        assert!(may_set(Origin::MacApp, Layer::Global, Private));
    }

    #[test]
    fn config_section_parses_and_rejects_typos() {
        let private: Config = toml::from_str("[privacy]\nmode = \"private\"\n").unwrap();
        assert_eq!(private.privacy.mode, PrivacyMode::Private);

        let absent: Config = toml::from_str("version = 1\n").unwrap();
        assert_eq!(absent.privacy.mode, PrivacyMode::Private);

        // A config written before the rename still loads: `"public"` is the old
        // spelling of `"open"`.
        let legacy: Config = toml::from_str("[privacy]\nmode = \"public\"\n").unwrap();
        assert_eq!(legacy.privacy.mode, PrivacyMode::Open);

        assert!(toml::from_str::<Config>("[privacy]\nmode = \"Private\"\n").is_err());
        assert!(toml::from_str::<Config>("[privacy]\nmode = \"privte\"\n").is_err());
        assert!(toml::from_str::<Config>("[privacy]\nmode = \"private\"\nextra = 1\n").is_err());
    }

    #[test]
    fn mask_first_names_is_off_by_default_and_parses_on() {
        // (P2) `[privacy] mask_first_names` is off when absent, on when set, and an
        // existing config (the `mode` key alone) still parses with it off.
        let on: Config = toml::from_str("[privacy]\nmask_first_names = true\n").unwrap();
        assert!(on.privacy.mask_first_names);
        assert_eq!(on.privacy.mode, PrivacyMode::Private);

        let absent: Config = toml::from_str("version = 1\n").unwrap();
        assert!(!absent.privacy.mask_first_names);
        assert!(!Config::default().privacy.mask_first_names);

        let existing: Config = toml::from_str("[privacy]\nmode = \"private\"\n").unwrap();
        assert!(!existing.privacy.mask_first_names);
        assert_eq!(existing.privacy.mode, PrivacyMode::Private);

        assert!(toml::from_str::<Config>("[privacy]\nmask_first_name = true\n").is_err());
        assert!(toml::from_str::<Config>("[privacy]\nmask_first_names = \"yes\"\n").is_err());
    }
}
