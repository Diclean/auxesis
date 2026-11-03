//! The seven provider presets, as data.
//!
//! `presets_fixtures.json` is the golden copy of this table: a provider
//! changing a hostname must fail `tests/presets.rs`, with a one-line fix in
//! both places.

use crate::config::Security;

/// A concrete `host:port` endpoint with its transport security.
///
/// The string parameter lets the static [`Preset`] table borrow its host names
/// (`Endpoint<&'static str>`) while runtime code uses the default
/// `Endpoint<String>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint<S = String> {
    /// Server hostname (no scheme, no port).
    pub host: S,
    /// TCP port.
    pub port: u16,
    /// Transport security.
    pub security: Security,
}

/// One provider preset the setup wizard offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    /// Stable slug (`fastmail`, `gmail`, ...).
    pub id: &'static str,
    /// Human label, shown in the wizard.
    pub label: &'static str,
    /// Incoming endpoint.
    pub imap: Endpoint<&'static str>,
    /// Outgoing endpoint.
    pub smtp: Endpoint<&'static str>,
    /// True when the login name is the full address (all seven are).
    pub username_is_full_address: bool,
    /// The plain-words note this provider's users need.
    pub hint: &'static str,
}

impl Preset {
    /// The incoming endpoint as an owned runtime value.
    pub fn imap_endpoint(&self) -> Endpoint {
        owned(self.imap)
    }

    /// The outgoing endpoint as an owned runtime value.
    pub fn smtp_endpoint(&self) -> Endpoint {
        owned(self.smtp)
    }
}

fn owned(source: Endpoint<&'static str>) -> Endpoint {
    Endpoint {
        host: source.host.to_string(),
        port: source.port,
        security: source.security,
    }
}

/// Every preset, in the order the UI shows them.
pub const PRESETS: &[Preset] = &[
    Preset {
        id: "fastmail",
        label: "Fastmail",
        imap: Endpoint {
            host: "imap.fastmail.com",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "smtp.fastmail.com",
            port: 465,
            security: Security::Tls,
        },
        username_is_full_address: true,
        hint: "app password from Fastmail settings",
    },
    Preset {
        id: "icloud",
        label: "iCloud",
        imap: Endpoint {
            host: "imap.mail.me.com",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "smtp.mail.me.com",
            port: 587,
            security: Security::StartTls,
        },
        username_is_full_address: true,
        hint: "Apple-ID app-specific password",
    },
    Preset {
        id: "gandi",
        label: "Gandi",
        imap: Endpoint {
            host: "mail.gandi.net",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "mail.gandi.net",
            port: 465,
            security: Security::Tls,
        },
        username_is_full_address: true,
        hint: "same host for incoming and outgoing",
    },
    Preset {
        id: "ovh",
        label: "OVH",
        imap: Endpoint {
            host: "imap.mail.ovh.net",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "smtp.mail.ovh.net",
            port: 465,
            security: Security::Tls,
        },
        username_is_full_address: true,
        hint:
            "OVH sometimes labels port 587 as SSL/TLS; the explicit security field is what matters",
    },
    Preset {
        id: "infomaniak",
        label: "Infomaniak",
        imap: Endpoint {
            host: "mail.infomaniak.com",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "smtp.mail.infomaniak.com",
            port: 465,
            security: Security::Tls,
        },
        username_is_full_address: true,
        hint: "app password required, created in the Infomaniak settings",
    },
    Preset {
        id: "gmail",
        label: "Gmail",
        imap: Endpoint {
            host: "imap.gmail.com",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "smtp.gmail.com",
            port: 465,
            security: Security::Tls,
        },
        username_is_full_address: true,
        hint: "needs 2FA and an app password",
    },
    Preset {
        id: "outlook",
        label: "Outlook / Microsoft 365",
        imap: Endpoint {
            host: "outlook.office365.com",
            port: 993,
            security: Security::Tls,
        },
        smtp: Endpoint {
            host: "smtp.office365.com",
            port: 587,
            security: Security::StartTls,
        },
        username_is_full_address: true,
        hint: "IMAP may be disabled on the account; an app password may be required",
    },
];

/// Every preset, in UI order.
pub fn all_presets() -> &'static [Preset] {
    PRESETS
}

/// The preset with this id, case-insensitively, if any.
pub fn preset(id: &str) -> Option<Preset> {
    PRESETS
        .iter()
        .copied()
        .find(|preset| preset.id.eq_ignore_ascii_case(id))
}

/// The golden-fixture JSON for `tests/presets.rs`.
///
/// Hand-emitted (the crate has no JSON dependency) but deterministic, so the
/// checked-in `presets_fixtures.json` catches a silent hostname change.
#[doc(hidden)]
pub fn fixture_json() -> String {
    let mut out = String::from("[\n");
    for (index, preset) in PRESETS.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str("  {\n");
        push_string(&mut out, "id", preset.id, false);
        push_string(&mut out, "label", preset.label, false);
        out.push_str("    \"imap\": { ");
        push_endpoint(&mut out, preset.imap);
        out.push_str(" },\n");
        out.push_str("    \"smtp\": { ");
        push_endpoint(&mut out, preset.smtp);
        out.push_str(" },\n");
        out.push_str("    \"username_is_full_address\": ");
        out.push_str(if preset.username_is_full_address {
            "true"
        } else {
            "false"
        });
        out.push_str(",\n");
        push_string(&mut out, "hint", preset.hint, true);
        out.push_str("  }");
    }
    out.push_str("\n]\n");
    out
}

fn push_endpoint(out: &mut String, endpoint: Endpoint<&'static str>) {
    out.push_str("\"host\": \"");
    out.push_str(&json_escape(endpoint.host));
    out.push_str("\", \"port\": ");
    out.push_str(&endpoint.port.to_string());
    out.push_str(", \"security\": \"");
    out.push_str(endpoint.security.as_str());
    out.push('"');
}

fn push_string(out: &mut String, key: &str, value: &str, last: bool) {
    out.push_str("    \"");
    out.push_str(key);
    out.push_str("\": \"");
    out.push_str(&json_escape(value));
    out.push('"');
    if last {
        out.push('\n');
    } else {
        out.push_str(",\n");
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
