//! The two calls every choke point makes.
//!
//! * [`admit_call`] guards a call that is about to run. A refusal stops it.
//! * [`may_mount`] guards a registration. A refusal means the feature is not
//!   registered, so the model never sees it.
//!
//! Both go through [`admit`], so the registry stays the only source of truth.

use super::gate::{admit, Context, Decision, Destination, Grant, Reason};
use super::mode::PrivacyMode;
use super::path::PathId;
use crate::i18n::{self, Lang, Message};

/// A choke point refused a path in the current mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The path that was refused.
    pub path: PathId,
    /// Why the gate refused it.
    pub reason: Reason,
}

impl Refused {
    /// The user-facing sentence, in the owner's language.
    pub fn text(&self, lang: Lang) -> String {
        i18n::format(Message::PrivacyDisabled, lang, &[self.path.as_str()])
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "path {} is disabled in private mode", self.path.as_str())
    }
}

impl std::error::Error for Refused {}

/// Admit one call on `path`. `Allow` returns the grant, which the caller holds
/// for the duration of the call. `Deny` and `Ask` both refuse: no registry row
/// asks yet, and the broker approval flow is not wired into this helper, so an
/// `Ask` fails closed until a row needs it.
pub fn admit_call(
    path: PathId,
    mode: PrivacyMode,
    destination: Destination,
) -> Result<Grant, Refused> {
    match admit(path, mode, &Context { destination }) {
        Decision::Allow(grant) => Ok(grant),
        Decision::Ask(_) => Err(Refused {
            path,
            reason: Reason::Disabled,
        }),
        Decision::Deny(reason) => Err(Refused { path, reason }),
    }
}

/// Whether `path` may be registered in `mode`. Only `Allow` mounts: an `Ask`
/// row is not mounted until the approval flow is wired (see [`admit_call`]).
pub fn may_mount(path: PathId, mode: PrivacyMode) -> bool {
    let ctx = Context {
        destination: Destination::LocalDisplay,
    };
    matches!(admit(path, mode, &ctx), Decision::Allow(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_mode_refuses_disabled_paths_and_says_so_in_both_languages() {
        let refused = admit_call(PathId::B8, PrivacyMode::Private, Destination::LocalDisplay)
            .expect_err("Gmail read is disabled in private mode");
        assert_eq!(refused.path, PathId::B8);
        assert_eq!(refused.reason, Reason::Disabled);
        assert_eq!(refused.text(Lang::En), "Disabled in private mode: B8.");
        assert_eq!(refused.text(Lang::Fr), "Désactivé en mode privé : B8.");
    }

    #[test]
    fn open_mode_admits_what_the_registry_allows() {
        assert!(admit_call(PathId::A1, PrivacyMode::Open, Destination::LocalDisplay).is_ok());
        assert!(may_mount(PathId::B5, PrivacyMode::Open));
    }

    #[test]
    fn covered_rows_admit_in_private_mode() {
        assert!(admit_call(PathId::C9, PrivacyMode::Private, Destination::LocalDisplay).is_ok());
        assert!(may_mount(PathId::I1, PrivacyMode::Private));
    }

    #[test]
    fn private_mode_does_not_mount_uncovered_tools() {
        for id in [PathId::B8, PathId::B9] {
            assert!(!may_mount(id, PrivacyMode::Private), "{}", id.as_str());
        }
    }
}
