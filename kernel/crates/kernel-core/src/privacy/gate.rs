//! The gate: one decision per data path, per call.

use super::mode::PrivacyMode;
use super::path::PathId;
use super::policy::{Behaviour, PathPolicy, RecipientRule, Status};
use super::registry::REGISTRY;

/// Where a value would go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// The owner's own chat (WhatsApp or Telegram).
    OwnerSelf,
    /// The owner's Mac screen.
    LocalDisplay,
    /// A third party, by contact alias. The recipient filter applies.
    Recipient(String),
    /// Any other service: a model, a connector, a vendor API.
    Vendor(String),
}

/// The call the gate is asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Where the value would go.
    pub destination: Destination,
}

/// The egress policy a [`Grant`] carries, one per mode.
///
/// The policy is what a `SafeText`/`SafeValue` issuer (kernel-privacy) reads:
/// `Passthrough` runs the detectors but masks nothing, `Tokenised` replaces
/// every detected value with a token. It follows the mode the call was admitted
/// under, never a second switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantPolicy {
    /// Open mode: nothing is masked; the detection report is kept so the
    /// caller can log what private mode would have masked.
    Passthrough,
    /// Private mode: detected values are tokenised, dropped or refused.
    Tokenised,
}

/// Proof that [`admit`] allowed one call on one path.
///
/// Only this module creates a `Grant`. The fields are private, and the type
/// has no `Default`, `Clone`, `Copy`, or serde impls. Executors take `&Grant`,
/// so a path that skips the gate does not compile.
///
/// ```compile_fail,E0451
/// use kernel_core::privacy::{Grant, PathId, PrivacyMode};
/// let _ = Grant { path: PathId::A1, mode: PrivacyMode::Private };
/// ```
///
/// ```compile_fail,E0624
/// use kernel_core::privacy::{Grant, PathId, PrivacyMode};
/// let _ = Grant::new(PathId::A1, PrivacyMode::Private);
/// ```
///
/// ```compile_fail,E0599
/// let _ = kernel_core::privacy::Grant::default();
/// ```
///
/// ```compile_fail,E0599
/// use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
/// let ctx = Context { destination: Destination::OwnerSelf };
/// if let Decision::Allow(grant) = admit(PathId::C9, PrivacyMode::Private, &ctx) {
///     let _copy = grant.clone();
/// }
/// ```
///
/// ```compile_fail,E0382
/// use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
/// let ctx = Context { destination: Destination::OwnerSelf };
/// if let Decision::Allow(grant) = admit(PathId::C9, PrivacyMode::Private, &ctx) {
///     let _first = grant;
///     let _second = grant;
/// }
/// ```
///
/// A `Grant` is never deserializable: no config, file or wire value can mint
/// one.
///
/// ```compile_fail,E0277
/// fn needs_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// needs_deserialize::<kernel_core::privacy::Grant>();
/// ```
#[derive(Debug)]
pub struct Grant {
    path: PathId,
    mode: PrivacyMode,
}

impl Grant {
    fn new(path: PathId, mode: PrivacyMode) -> Self {
        Self { path, mode }
    }

    /// The path this grant covers.
    pub fn path(&self) -> PathId {
        self.path
    }

    /// The mode the call was admitted under.
    pub fn mode(&self) -> PrivacyMode {
        self.mode
    }

    /// The egress policy this grant carries (open → passthrough, private →
    /// tokenised).
    pub fn policy(&self) -> GrantPolicy {
        match self.mode {
            PrivacyMode::Open => GrantPolicy::Passthrough,
            PrivacyMode::Private => GrantPolicy::Tokenised,
        }
    }
}

/// What the owner must approve before the call runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The path the call would use.
    pub path: PathId,
    /// What has to be true before the call may run.
    pub needs: Needs,
}

/// The conditions on an [`Request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Needs {
    /// The owner approves this call, on their own screen or chat.
    OwnerApproval,
    /// The owner approves, and the recipient filter must allow `alias` to
    /// receive this path's values.
    OwnerApprovalAndRecipientFilter {
        /// Contact alias of the third party.
        alias: String,
    },
}

/// Why the gate refused a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No registry row for this path. Unknown means closed in **both** modes.
    Unregistered,
    /// The row is disabled in this mode, or the destination is not allowed.
    Disabled,
    /// The row allows the path, but the path is not covered in private mode.
    NotCovered,
}

/// The gate's answer for one call.
#[derive(Debug)]
pub enum Decision {
    /// The call may run. Keep the grant and pass it to the executor.
    Allow(Grant),
    /// The call may run only after the owner approves the request.
    Ask(Request),
    /// The call must not run.
    Deny(Reason),
}

/// Decides whether `path` may run in `mode` for `ctx`.
///
/// Unknown means closed in both modes: a path with no registry row is
/// refused, never tolerated (soul rule 5). Private mode additionally denies
/// any row that is not covered.
#[must_use]
pub fn admit(path: PathId, mode: PrivacyMode, ctx: &Context) -> Decision {
    decide(REGISTRY, path, mode, ctx)
}

/// [`admit`] against any registry. Tests use this to check the rules with
/// rows that the real registry does not contain.
fn decide(registry: &[PathPolicy], path: PathId, mode: PrivacyMode, ctx: &Context) -> Decision {
    let Some(policy) = registry.iter().find(|row| row.id == path) else {
        return Decision::Deny(Reason::Unregistered);
    };
    let behaviour = match mode {
        PrivacyMode::Open => policy.open,
        PrivacyMode::Private => policy.private,
    };
    match behaviour {
        Behaviour::Disabled => Decision::Deny(Reason::Disabled),
        Behaviour::Allow => match (mode, policy.status) {
            (PrivacyMode::Private, Status::Partial | Status::NotCovered) => {
                Decision::Deny(Reason::NotCovered)
            }
            _ => Decision::Allow(Grant::new(path, mode)),
        },
        Behaviour::AskEachTime(rule) => ask(path, rule, &ctx.destination),
    }
}

/// `AskEachTime`: the owner's own destinations ask for approval. A third party
/// asks only when the rule includes the recipient filter. Vendors never ask.
fn ask(path: PathId, rule: RecipientRule, destination: &Destination) -> Decision {
    let needs = match (rule, destination) {
        (_, Destination::OwnerSelf | Destination::LocalDisplay) => Needs::OwnerApproval,
        (RecipientRule::FilteredRecipients, Destination::Recipient(alias)) => {
            Needs::OwnerApprovalAndRecipientFilter {
                alias: alias.clone(),
            }
        }
        _ => return Decision::Deny(Reason::Disabled),
    };
    Decision::Ask(Request { path, needs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(destination: Destination) -> Context {
        Context { destination }
    }

    fn custom(status: Status, private: Behaviour, open: Behaviour) -> PathPolicy {
        PathPolicy {
            id: PathId::A1,
            label: "test row",
            status,
            private,
            open,
            slice: "test",
        }
    }

    #[test]
    fn unregistered_path_is_denied_in_both_modes() {
        // Soul rule 5: unknown means closed. Open mode no longer tolerates a
        // path the registry does not know.
        let ctx = at(Destination::OwnerSelf);
        let decision = decide(&[], PathId::A1, PrivacyMode::Open, &ctx);
        assert!(matches!(decision, Decision::Deny(Reason::Unregistered)));

        let decision = decide(&[], PathId::A1, PrivacyMode::Private, &ctx);
        assert!(matches!(decision, Decision::Deny(Reason::Unregistered)));

        // A registry with other rows still has no row for this path.
        let partial = [custom(Status::Covered, Behaviour::Allow, Behaviour::Allow)];
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let decision = decide(&partial, PathId::B1, mode, &ctx);
            assert!(
                matches!(decision, Decision::Deny(Reason::Unregistered)),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn a_grant_policy_follows_the_mode() {
        let ctx = at(Destination::OwnerSelf);
        match admit(PathId::C9, PrivacyMode::Open, &ctx) {
            Decision::Allow(grant) => assert_eq!(grant.policy(), GrantPolicy::Passthrough),
            other => panic!("expected Allow, got {other:?}"),
        }
        match admit(PathId::C9, PrivacyMode::Private, &ctx) {
            Decision::Allow(grant) => assert_eq!(grant.policy(), GrantPolicy::Tokenised),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn covered_allow_row_grants_in_private_mode() {
        let decision = admit(
            PathId::C9,
            PrivacyMode::Private,
            &at(Destination::OwnerSelf),
        );
        match decision {
            Decision::Allow(grant) => {
                assert_eq!(grant.path(), PathId::C9);
                assert_eq!(grant.mode(), PrivacyMode::Private);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn disabled_rows_are_denied_in_private_mode() {
        let ctx = at(Destination::OwnerSelf);
        assert!(matches!(
            admit(PathId::B8, PrivacyMode::Private, &ctx),
            Decision::Deny(Reason::Disabled)
        ));
        assert!(matches!(
            admit(PathId::B15, PrivacyMode::Private, &ctx),
            Decision::Deny(Reason::Disabled)
        ));
    }

    #[test]
    fn allow_on_an_uncovered_row_is_denied_in_private_mode_only() {
        let ctx = at(Destination::OwnerSelf);
        for status in [Status::NotCovered, Status::Partial] {
            let rows = [custom(status, Behaviour::Allow, Behaviour::Allow)];
            assert!(matches!(
                decide(&rows, PathId::A1, PrivacyMode::Private, &ctx),
                Decision::Deny(Reason::NotCovered)
            ));
            assert!(matches!(
                decide(&rows, PathId::A1, PrivacyMode::Open, &ctx),
                Decision::Allow(_)
            ));
        }
    }

    #[test]
    fn open_mode_denies_only_rows_disabled_in_open() {
        let ctx = at(Destination::OwnerSelf);
        for row in REGISTRY {
            let decision = decide(REGISTRY, row.id, PrivacyMode::Open, &ctx);
            let disabled = row.open == Behaviour::Disabled;
            assert_eq!(
                matches!(decision, Decision::Deny(Reason::Disabled)),
                disabled,
                "path {}",
                row.id.as_str()
            );
        }
    }

    #[test]
    fn owner_destinations_ask_for_approval() {
        let rows = [custom(
            Status::NotCovered,
            Behaviour::AskEachTime(RecipientRule::OwnerOnly),
            Behaviour::Disabled,
        )];
        for destination in [Destination::OwnerSelf, Destination::LocalDisplay] {
            match decide(&rows, PathId::A1, PrivacyMode::Private, &at(destination)) {
                Decision::Ask(request) => assert_eq!(request.needs, Needs::OwnerApproval),
                other => panic!("expected Ask, got {other:?}"),
            }
        }
    }

    #[test]
    fn owner_only_rule_never_asks_for_a_third_party_or_vendor() {
        let rows = [custom(
            Status::NotCovered,
            Behaviour::AskEachTime(RecipientRule::OwnerOnly),
            Behaviour::Disabled,
        )];
        for destination in [
            Destination::Recipient("Alice".to_string()),
            Destination::Vendor("hosted-model".to_string()),
        ] {
            assert!(matches!(
                decide(&rows, PathId::A1, PrivacyMode::Private, &at(destination)),
                Decision::Deny(Reason::Disabled)
            ));
        }
    }

    #[test]
    fn third_party_ask_requires_the_recipient_filter() {
        let rows = [custom(
            Status::NotCovered,
            Behaviour::AskEachTime(RecipientRule::FilteredRecipients),
            Behaviour::Disabled,
        )];
        match decide(
            &rows,
            PathId::A1,
            PrivacyMode::Private,
            &at(Destination::Recipient("Alice".to_string())),
        ) {
            Decision::Ask(request) => {
                assert_eq!(request.path, PathId::A1);
                assert_eq!(
                    request.needs,
                    Needs::OwnerApprovalAndRecipientFilter {
                        alias: "Alice".to_string()
                    }
                );
            }
            other => panic!("expected Ask, got {other:?}"),
        }
        assert!(matches!(
            decide(
                &rows,
                PathId::A1,
                PrivacyMode::Private,
                &at(Destination::Vendor("hosted-model".to_string())),
            ),
            Decision::Deny(Reason::Disabled)
        ));
    }
}
