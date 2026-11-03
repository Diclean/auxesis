//! M1: the preset table and its golden fixture. Offline, no socket.

use aux_mail::config::{ImapSettings, Security, SmtpSettings};
use aux_mail::presets::{all_presets, fixture_json, preset};

#[test]
fn the_golden_fixture_matches_the_preset_table_byte_for_byte() {
    let golden = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/presets_fixtures.json"
    ));
    assert_eq!(
        fixture_json(),
        golden,
        "a preset host/port changed: update src/presets_fixtures.json"
    );
}

#[test]
fn every_imap_port_is_implicit_tls_or_explicitly_starttls_or_plain() {
    for preset in all_presets() {
        if preset.imap.port == 993 {
            assert_eq!(preset.imap.security, Security::Tls, "{}", preset.id);
        } else {
            assert!(
                matches!(preset.imap.security, Security::StartTls | Security::Plain),
                "{} must be explicit about STARTTLS/plain",
                preset.id
            );
        }
    }
}

#[test]
fn every_preset_uses_the_full_address_for_imap_and_smtp() {
    const ADDRESS: &str = "me@example.org";
    for preset in all_presets() {
        assert!(preset.username_is_full_address, "{}", preset.id);
        // The rule the test name promises, checked on both server blocks: the
        // preset leaves the username unset, so each falls back to the account's
        // full address.
        let imap = ImapSettings {
            host: preset.imap.host.to_string(),
            port: preset.imap.port,
            security: preset.imap.security,
            username: None,
            ca_file: None,
        };
        let smtp = SmtpSettings {
            host: preset.smtp.host.to_string(),
            port: preset.smtp.port,
            security: preset.smtp.security,
            username: None,
            ca_file: None,
        };
        assert_eq!(imap.username(ADDRESS), ADDRESS, "{} imap", preset.id);
        assert_eq!(smtp.username(ADDRESS), ADDRESS, "{} smtp", preset.id);
        assert!(!imap.host.is_empty(), "{}", preset.id);
        assert!(!smtp.host.is_empty(), "{}", preset.id);
    }
}

#[test]
fn presets_are_found_by_id_and_keep_ui_order() {
    assert_eq!(all_presets().len(), 7);
    assert_eq!(all_presets()[0].id, "fastmail");
    assert_eq!(preset("gmail").expect("gmail").imap.host, "imap.gmail.com");
    assert_eq!(preset("GMAIL").expect("case-insensitive").smtp.port, 465);
    assert!(preset("nope").is_none());
}

#[test]
fn owned_endpoints_copy_the_static_table() {
    let gmail = preset("gmail").expect("gmail");
    let imap = gmail.imap_endpoint();
    assert_eq!(imap.host, "imap.gmail.com");
    assert_eq!(imap.port, 993);
    assert_eq!(imap.security, Security::Tls);
}
