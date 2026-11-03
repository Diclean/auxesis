//! The per-session outbound gate (`docs/phase1.md` §2: every byte that reaches
//! a provider passes `admit()` and a `Gate`).
//!
//! Every provider request is built from values this gate issues. Its
//! pseudonym key is an HMAC of the session id under a process-lifetime root,
//! so one session keeps its tokens across turns, two sessions never share a
//! key, and no key is written to disk. A restart mints a new root; the vault
//! (slice 3) replaces this with a stored key.

use std::sync::{Arc, OnceLock};

use kernel_core::privacy::Grant;
use kernel_privacy::safetext::{Gate, GateError};
use kernel_privacy::NameDictionary;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// The process-lifetime root that every session key is derived from.
static ROOT: OnceLock<[u8; 32]> = OnceLock::new();
#[cfg(feature = "ner-gliner")]
static DEEP: OnceLock<Arc<dyn kernel_privacy::safetext::Detector>> = OnceLock::new();

/// Install the process-wide validated model once during daemon startup.
#[cfg(feature = "ner-gliner")]
pub fn install_deep_detector(detector: Arc<dyn kernel_privacy::safetext::Detector>) {
    let _ = DEEP.set(detector);
}

/// The gate for one chat session, keyed from the session id. Every outbound
/// text of the session, the chat engine's and the ACP turn's alike, goes
/// through it.
///
/// `grant` is the admission the outbound call runs under, taken by the caller
/// in the mode in force now. The grant fixes the gate's policy: Open leaves
/// ordinary text clear and removes prohibited spans; Private tokenises them.
///
/// `names` is the owner's known-names dictionary ([`aux_runtime::known_names`]),
/// read by the caller at session start. An empty dictionary leaves a private
/// gate with names unchecked: it still tokenises every pattern value (mail,
/// phone, IBAN, card, ID, health, secret) and issues the text.
pub fn session_gate(
    session_id: i64,
    grant: &Grant,
    names: Arc<NameDictionary>,
) -> Result<Gate, GateError> {
    let root = root_key()?;
    let mut context = b"auxesis.safetext.session.v1".to_vec();
    context.extend_from_slice(&session_id.to_be_bytes());
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &root), &context);
    let mut key = [0u8; 32];
    key.copy_from_slice(tag.as_ref());
    #[cfg(any(test, feature = "test-util"))]
    if let Some(detector) = test_seam::detector() {
        return Ok(Gate::for_tests(grant, key, detector));
    }
    #[cfg(feature = "ner-gliner")]
    if let Some(deep) = DEEP.get() {
        return Ok(Gate::for_grant_with_deep_detector(
            grant,
            key,
            names,
            Arc::clone(deep),
        ));
    }
    Ok(Gate::for_grant_with_dictionary(grant, key, names))
}

/// Test seam: makes the gates this thread builds refuse text on demand. A gate is
/// built synchronously on the caller's thread, so a test that sets the seam and
/// then runs its turn on that thread sees it, and no other test does.
#[cfg(any(test, feature = "test-util"))]
pub mod test_seam {
    use std::cell::RefCell;
    use std::sync::Arc;

    use kernel_privacy::safetext::{DetectError, Detector};
    use kernel_privacy::Span;

    thread_local! {
        static DETECTOR: RefCell<Option<Arc<dyn Detector>>> = const { RefCell::new(None) };
    }

    /// Refuses every text holding `needle`; passes the rest without a value scan.
    struct RefuseContaining(&'static str);

    impl Detector for RefuseContaining {
        fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            if text.contains(self.0) {
                Err(DetectError::Panicked)
            } else {
                Ok(Vec::new())
            }
        }
    }

    /// From now on, the gates this thread builds refuse any text holding `needle`.
    pub fn refuse_text_containing(needle: &'static str) {
        DETECTOR.with(|slot| *slot.borrow_mut() = Some(Arc::new(RefuseContaining(needle))));
    }

    /// From now on, the gates this thread builds use `detector`. A tokenising
    /// gate needs name coverage, so a test that tokenises installs one here.
    pub fn use_detector(detector: Arc<dyn Detector>) {
        DETECTOR.with(|slot| *slot.borrow_mut() = Some(detector));
    }

    /// Put the real detector back for the gates this thread builds.
    pub fn clear() {
        DETECTOR.with(|slot| *slot.borrow_mut() = None);
    }

    pub(crate) fn detector() -> Option<Arc<dyn Detector>> {
        DETECTOR.with(|slot| slot.borrow().clone())
    }
}

fn root_key() -> Result<[u8; 32], GateError> {
    if let Some(root) = ROOT.get() {
        return Ok(*root);
    }
    let mut root = [0u8; 32];
    SystemRandom::new()
        .fill(&mut root)
        .map_err(|_| GateError::Key)?;
    Ok(*ROOT.get_or_init(|| root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_providers::ChatMessage;
    use aux_providers::SafeMessage;
    use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};

    /// A private-mode grant, which tokenises. C9 is the one covered row that
    /// private mode allows, so it is the grant a masking gate can hold.
    fn tokenising_grant() -> Grant {
        admit_call(PathId::C9, PrivacyMode::Private, Destination::LocalDisplay)
            .expect("C9 is covered in private mode")
    }

    /// The token the session's gate gives an e-mail address.
    fn token_for(session_id: i64) -> String {
        test_seam::use_detector(aux_providers::test_gate::names_checked());
        let grant = tokenising_grant();
        let names =
            aux_runtime::known_names::names_for(&aux_runtime::known_names::owner_contacts())
                .unwrap();
        let mut gate = session_gate(session_id, &grant, names).unwrap();
        test_seam::clear();
        let message = ChatMessage::user("écris à elise.vautrin@example.invalid");
        let safe = SafeMessage::issue(&mut gate, &message).unwrap();
        let text = safe.content().as_str().to_string();
        text.split('⟦')
            .nth(1)
            .unwrap()
            .split('⟧')
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn one_session_keeps_its_tokens_across_gates() {
        assert_eq!(token_for(42), token_for(42));
    }

    #[test]
    fn two_sessions_never_share_a_token() {
        assert_ne!(token_for(42), token_for(43));
    }
}
