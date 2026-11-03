//! Setup discovery for `aux mail add` (docs/mail.md §7).
//!
//! The order is fixed: preset by domain, then SRV (`_imaps._tcp`, preferring
//! implicit TLS on 993; `_submission._tcp` 587 or `_submissions._tcp` 465),
//! then `autoconfig.<domain>`, then the whole preset table. Candidates are
//! always returned as a list and shown: nothing is picked silently.
//!
//! The two network steps sit behind [`Discovery`], so tests inject a fake and
//! never open a socket. `aux mail add` still works offline for the seven
//! presets through the same trait.

use crate::error::MailError;
use crate::presets::{all_presets, preset, Endpoint, Preset};

/// One candidate server pair shown by `aux mail add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Where the candidate came from: `preset`, `srv`, `autoconfig` or `table`.
    pub source: &'static str,
    /// A short owner-facing note (preset hint, SRV record name, …).
    pub note: String,
    /// Incoming endpoint.
    pub imap: Endpoint,
    /// Outgoing endpoint, when the probe knows one.
    pub smtp: Option<Endpoint>,
    /// True when the login name is the full address.
    pub username_is_full_address: bool,
}

/// The two network probes discovery uses. A fake covers tests.
pub trait Discovery: Send + Sync {
    /// `_imaps._tcp` / `_submission(s)._tcp` records for `domain`.
    fn srv(&self, domain: &str) -> Result<Vec<Candidate>, MailError>;
    /// `https://autoconfig.<domain>/mail/config-v1.1.xml`, if it answers.
    fn autoconfig(&self, domain: &str) -> Result<Option<Candidate>, MailError>;
}

/// The domain part of an address, lowercased; `None` when there is no `@`.
pub fn address_domain(address: &str) -> Option<String> {
    let (_, domain) = address.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty() && domain.contains('.')).then_some(domain)
}

/// The preset for a mail domain, when one of the seven matches.
pub fn preset_for_domain(domain: &str) -> Option<Preset> {
    let id = match domain {
        "fastmail.com" | "fastmail.fm" => "fastmail",
        "icloud.com" | "me.com" | "mac.com" => "icloud",
        "gandi.net" => "gandi",
        "ovh.net" | "ovh.com" => "ovh",
        "infomaniak.com" | "ik.me" => "infomaniak",
        "gmail.com" | "googlemail.com" => "gmail",
        "outlook.com" | "hotmail.com" | "hotmail.fr" | "live.com" | "live.fr" | "msn.com" => {
            "outlook"
        }
        _ => return None,
    };
    preset(id)
}

/// The full discovery order for `domain`, deduplicated by IMAP `host:port`.
pub fn discover(domain: &str, probes: &dyn Discovery) -> Vec<Candidate> {
    let mut out = Vec::new();
    if let Some(found) = preset_for_domain(domain) {
        out.push(from_preset(&found, "preset"));
    }
    if let Ok(found) = probes.srv(domain) {
        out.extend(found);
    }
    if let Ok(Some(found)) = probes.autoconfig(domain) {
        out.push(found);
    }
    for table in all_presets() {
        out.push(from_preset(table, "table"));
    }
    dedupe(out)
}

fn from_preset(preset: &Preset, source: &'static str) -> Candidate {
    Candidate {
        source,
        note: preset.hint.to_string(),
        imap: preset.imap_endpoint(),
        smtp: Some(preset.smtp_endpoint()),
        username_is_full_address: preset.username_is_full_address,
    }
}

fn dedupe(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for candidate in candidates {
        let key = (candidate.imap.host.clone(), candidate.imap.port);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(candidate);
    }
    out
}

/// The production probes.
///
/// This build keeps discovery offline for own-domain addresses: the preset
/// table and the SRV/autoconfig hooks are wired, but the live resolver and
/// autoconfig HTTP client are not part of MA3 (the CLI says so and shows the
/// preset table instead of inventing a server).
pub struct OfflineDiscovery;

impl Discovery for OfflineDiscovery {
    fn srv(&self, _domain: &str) -> Result<Vec<Candidate>, MailError> {
        Ok(Vec::new())
    }

    fn autoconfig(&self, _domain: &str) -> Result<Option<Candidate>, MailError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Security;

    struct FakeProbes;

    impl Discovery for FakeProbes {
        fn srv(&self, domain: &str) -> Result<Vec<Candidate>, MailError> {
            assert_eq!(domain, "exemple.fr");
            Ok(vec![Candidate {
                source: "srv",
                note: "_imaps._tcp".to_string(),
                imap: Endpoint {
                    host: "imap.exemple.fr".to_string(),
                    port: 993,
                    security: Security::Tls,
                },
                smtp: Some(Endpoint {
                    host: "smtp.exemple.fr".to_string(),
                    port: 587,
                    security: Security::StartTls,
                }),
                username_is_full_address: true,
            }])
        }

        fn autoconfig(&self, _domain: &str) -> Result<Option<Candidate>, MailError> {
            Ok(None)
        }
    }

    #[test]
    fn a_gmail_domain_starts_with_its_preset_and_ends_with_the_table() {
        let candidates = discover("gmail.com", &OfflineDiscovery);
        assert_eq!(candidates[0].source, "preset");
        assert_eq!(candidates[0].imap.host, "imap.gmail.com");
        assert_eq!(candidates.last().unwrap().source, "table");
        // The gmail preset is not repeated by the table.
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| candidate.imap.host == "imap.gmail.com")
                .count(),
            1
        );
    }

    #[test]
    fn an_own_domain_uses_the_injected_network_probes() {
        let candidates = discover("exemple.fr", &FakeProbes);
        let srv = candidates
            .iter()
            .find(|candidate| candidate.source == "srv")
            .expect("the SRV candidate is kept");
        assert_eq!(srv.imap.host, "imap.exemple.fr");
        assert_eq!(srv.smtp.as_ref().unwrap().port, 587);
        // The preset table always follows, so the owner still has choices.
        assert_eq!(candidates.last().unwrap().source, "table");
    }

    #[test]
    fn address_domains_are_lowercased_and_validated() {
        assert_eq!(
            address_domain("Camille@Exemple.FR"),
            Some("exemple.fr".to_string())
        );
        assert_eq!(address_domain("no-at-sign"), None);
        assert_eq!(address_domain("a@localhost"), None);
    }
}
