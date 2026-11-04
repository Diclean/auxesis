//! Acceptance tests: config round-trip, strict leaf structs, defaults and
//! limit clamping. Offline only — no socket is opened anywhere in this file.

use std::time::Duration;

use aux_mail::{
    FolderMap, ImapSettings, Limits, MailAccount, MailConfig, MailLimits, Security,
    DEFAULT_MAX_ATTACHMENT_BYTES, DEFAULT_MAX_CALL_ATTACHMENT_BYTES, LIST_RESULT_BYTES,
    READ_RESULT_BYTES,
};

/// The per-account table, minus the `[connectors.mail]` wrapper: `MailConfig`
/// *is* the wrapper's contents, so it is parsed directly.
const GOLDEN: &str = r#"
[[accounts]]
id          = "personal"
email       = "me@example.org"
display     = "Personal"
only_folders = ["INBOX", "Newsletters"]

[accounts.imap]
host     = "imap.example.org"
port     = 993
security = "tls"

[accounts.smtp]
host     = "smtp.example.org"
port     = 587
security = "starttls"
username = "me@example.org"

[accounts.folders]
inbox   = "INBOX"
sent    = "Sent"
drafts  = "Drafts"
trash   = "Trash"
archive = "Archive"

[limits]
max_message_bytes    = 1048576
max_call_bytes       = 4194304
max_messages         = 50
max_attachment_bytes = 0
call_timeout_secs    = 10
connect_timeout_secs = 4
max_search_days      = 30
max_inflight_per_agent = 1
"#;

#[test]
fn golden_toml_parses_to_the_struct_and_round_trips() {
    let config = MailConfig::from_toml(GOLDEN).expect("golden config must parse");
    assert_eq!(config.accounts.len(), 1);

    let account = &config.accounts[0];
    assert_eq!(account.id, "personal");
    assert_eq!(account.email, "me@example.org");
    assert_eq!(account.display.as_deref(), Some("Personal"));
    assert_eq!(
        account.only_folders,
        vec!["INBOX".to_string(), "Newsletters".to_string()]
    );
    assert!(account.reads_folder("inbox"));
    assert!(account.reads_folder("NEWSLETTERS"));
    assert!(!account.reads_folder("Trash"));

    assert_eq!(account.imap.host, "imap.example.org");
    assert_eq!(account.imap.port, 993);
    assert_eq!(account.imap.security, Security::Tls);
    assert_eq!(account.imap.username("me@example.org"), "me@example.org");

    let smtp = account.smtp.as_ref().expect("golden smtp block");
    assert_eq!(smtp.host, "smtp.example.org");
    assert_eq!(smtp.port, 587);
    assert_eq!(smtp.security, Security::StartTls);
    assert_eq!(smtp.username("me@example.org"), "me@example.org");

    assert_eq!(
        account.folders,
        FolderMap {
            inbox: "INBOX".to_string(),
            sent: "Sent".to_string(),
            drafts: "Drafts".to_string(),
            trash: "Trash".to_string(),
            archive: "Archive".to_string(),
        }
    );

    assert_eq!(config.limits.max_message_bytes, 1_048_576);
    assert_eq!(config.limits.max_call_bytes, 4_194_304);
    assert_eq!(config.limits.max_messages, 50);
    assert_eq!(config.limits.max_attachment_bytes(), 0);
    assert_eq!(config.limits.call_timeout_secs, 10);
    assert_eq!(config.limits.connect_timeout_secs, 4);
    assert_eq!(config.limits.max_search_days, 30);
    assert_eq!(config.limits.max_inflight_per_agent, 1);

    // Serialize and parse back: the struct survives the round trip unchanged.
    let text = config.to_toml().expect("config must serialize");
    let reparsed = MailConfig::from_toml(&text).expect("serialized config must parse");
    assert_eq!(reparsed, config);
    assert_eq!(reparsed.account("personal"), Some(account));
    assert_eq!(reparsed.account("nope"), None);
}

#[test]
fn the_secret_key_is_aux_mail_and_the_upper_id() {
    // The contract names the `.env` entry `AUX_MAIL_<ACCOUNT_ID_UPPER>`,
    // never the old `AUX_KEY_MAIL_<id>` spelling. `-` folds to `_` so the name
    // is a valid environment key.
    let account = MailAccount {
        id: "personal".to_string(),
        ..MailAccount::default()
    };
    assert_eq!(account.secret_key(), "AUX_MAIL_PERSONAL");

    let mixed = MailAccount {
        id: "Main".to_string(),
        ..MailAccount::default()
    };
    assert_eq!(mixed.secret_key(), "AUX_MAIL_MAIN");

    let hyphen = MailAccount {
        id: "work-mail".to_string(),
        ..MailAccount::default()
    };
    assert_eq!(hyphen.secret_key(), "AUX_MAIL_WORK_MAIL");
}

#[test]
fn account_ids_must_be_canonical_lowercase_slugs() {
    for id in [
        "Personal",
        "PERSONAL",
        "Work-Mail",
        "",
        " lead",
        "trail ",
        "a.b",
        "a b",
    ] {
        let raw = format!("[[accounts]]\nid = {id:?}\n");
        let err =
            MailConfig::from_toml(&raw).expect_err("a non-canonical account id must be refused");
        let message = err.to_string();
        assert!(
            message.contains("slug") && message.contains("identifiant"),
            "the error must state the slug rule in both languages for {id:?}: {message}"
        );
    }

    // Shape boundary: 32 characters is canonical, 33 is not, and the permitted
    // alphabet keeps digits, `_` and `-`.
    let max = "a".repeat(32);
    MailConfig::from_toml(&format!("[[accounts]]\nid = {max:?}\n"))
        .expect("a 32-character slug is canonical");
    let too_long = "a".repeat(33);
    assert!(MailConfig::from_toml(&format!("[[accounts]]\nid = {too_long:?}\n")).is_err());
    MailConfig::from_toml("[[accounts]]\nid = \"a_b-9\"\n")
        .expect("digits, `_` and `-` are part of the slug");
}

#[test]
fn duplicate_account_ids_are_refused() {
    let raw = "[[accounts]]\nid = \"personal\"\nemail = \"a@b.c\"\n\
               [[accounts]]\nid = \"personal\"\nemail = \"c@d.e\"\n";
    let err = MailConfig::from_toml(raw).expect_err("duplicate ids must be refused");
    let message = err.to_string();
    assert!(
        message.contains("personal") && message.contains("duplicate") && message.contains("double"),
        "the error must name the id and be bilingual: {message}"
    );
}

#[test]
fn two_ids_that_fold_to_one_secret_key_are_refused() {
    // `work-mail` and `work_mail` both map to AUX_MAIL_WORK_MAIL, so the two
    // accounts would share one `.env` password.
    let raw = "[[accounts]]\nid = \"work-mail\"\n\
               [[accounts]]\nid = \"work_mail\"\n";
    let err = MailConfig::from_toml(raw).expect_err("one secret key, two accounts");
    let message = err.to_string();
    assert!(
        message.contains("AUX_MAIL_WORK_MAIL")
            && message.contains("work-mail")
            && message.contains("work_mail")
            && message.contains("même clé"),
        "the error must name the colliding key and be bilingual: {message}"
    );
}

#[test]
fn an_unknown_key_inside_the_imap_leaf_is_refused() {
    let err = MailConfig::from_toml(
        r#"
[[accounts]]
id = "a"

[accounts.imap]
host = "imap.example.org"
prot = 993
"#,
    )
    .expect_err("a typo in a server block must be refused");
    let message = err.to_string();
    assert!(
        message.contains("prot") || message.contains("unknown field"),
        "the error must name the offending field: {message}"
    );

    // The same strictness applies to the smtp and folder leaves.
    assert!(MailConfig::from_toml(
        "[[accounts]]\nid = \"a\"\n[accounts.smtp]\nhost = \"h\"\nbogus = 1\n"
    )
    .is_err());
    assert!(MailConfig::from_toml(
        "[[accounts]]\nid = \"a\"\n[accounts.folders]\ninbox = \"INBOX\"\noops = \"X\"\n"
    )
    .is_err());
    assert!(MailConfig::from_toml("[limits]\nmax_messages = 5\ntypo = 1\n").is_err());
}

#[test]
fn missing_sections_default_to_inbox_only() {
    let config = MailConfig::from_toml("[[accounts]]\nid = \"a\"\nemail = \"a@b.c\"\n")
        .expect("a minimal account parses");
    let account = &config.accounts[0];

    assert_eq!(account.only_folders, vec!["INBOX".to_string()]);
    assert_eq!(account.folders, FolderMap::default());
    assert!(account.smtp.is_none(), "no smtp block means no sending");
    assert_eq!(account.imap, ImapSettings::default());
    assert_eq!(account.imap.port, 993);
    assert_eq!(account.imap.security, Security::Tls);
    // A missing username falls back to the account address.
    assert_eq!(account.imap.username("a@b.c"), "a@b.c");

    // Missing `[limits]` means the documented v1 posture.
    assert_eq!(config.limits, MailLimits::default());
    assert_eq!(config.limits.limits(), Limits::default());

    // An empty config is a valid config: no accounts, default bounds.
    let empty = MailConfig::default();
    assert!(empty.accounts.is_empty());
    assert_eq!(empty.limits.limits(), Limits::default());
}

#[test]
fn every_security_spelling_parses_and_serializes() {
    for (text, want) in [
        ("tls", Security::Tls),
        ("starttls", Security::StartTls),
        ("plain", Security::Plain),
    ] {
        let raw = format!("[[accounts]]\nid = \"a\"\n[accounts.imap]\nsecurity = \"{text}\"\n");
        let config = MailConfig::from_toml(&raw).expect("security spelling parses");
        assert_eq!(config.accounts[0].imap.security, want);
        assert_eq!(want.as_str(), text);
        assert_eq!(want.is_encrypted(), want != Security::Plain);

        let out = config.to_toml().expect("serialize");
        assert!(
            out.contains(&format!("security = \"{text}\"")),
            "starttls must serialize with its pinned spelling: {out}"
        );
    }

    assert!(MailConfig::from_toml(
        "[[accounts]]\nid = \"a\"\n[accounts.imap]\nsecurity = \"ssl\"\n"
    )
    .is_err());
}

#[test]
fn a_legacy_send_mode_loads_ignored_with_a_warning() {
    // Phase 1 removed `send_mode`; an old config must still load, and the
    // loader must hand the caller a warning to log.
    for spelling in ["drafts_only", "ask"] {
        let raw = format!("[[accounts]]\nid = \"personal\"\nsend_mode = \"{spelling}\"\n");
        let (config, warnings) =
            MailConfig::load(&raw).expect("a legacy send_mode must not break the load");
        assert_eq!(config.accounts.len(), 1);
        assert_eq!(config.accounts[0].id, "personal");
        assert_eq!(
            warnings.len(),
            1,
            "one warning per ignored key: {warnings:?}"
        );
        assert!(
            warnings[0].contains("send_mode") && warnings[0].contains(spelling),
            "the warning must name the ignored key and value: {warnings:?}"
        );
    }

    // A clean config produces no warning, and `from_toml` still parses.
    let (_clean, warnings) =
        MailConfig::load("[[accounts]]\nid = \"a\"\n").expect("a clean config parses");
    assert!(warnings.is_empty());
    assert_eq!(
        MailConfig::from_toml("[[accounts]]\nid = \"a\"\n")
            .expect("from_toml parses")
            .accounts
            .len(),
        1
    );

    // Serializing a loaded legacy config drops the ignored key.
    let (legacy, _) =
        MailConfig::load("[[accounts]]\nid = \"a\"\nsend_mode = \"ask\"\n").expect("loads");
    let rewritten = legacy.to_toml().expect("serialize");
    assert!(!rewritten.contains("send_mode"), "{rewritten}");
}

#[test]
fn tight_limits_are_smaller_on_every_non_zero_field() {
    let default = Limits::default();
    let tight = Limits::tight();

    assert_eq!(default.max_message_bytes, 2_097_152);
    assert_eq!(default.max_call_bytes, 33_554_432);
    assert_eq!(default.max_messages, 200);
    assert_eq!(default.max_attachment_bytes(), DEFAULT_MAX_ATTACHMENT_BYTES);
    // MA3 downloads attachments: the documented budget is 25 MiB per part.
    const {
        assert!(DEFAULT_MAX_ATTACHMENT_BYTES == 25 * 1024 * 1024);
    }
    assert_eq!(default.call_timeout, Duration::from_secs(20));
    assert_eq!(default.connect_timeout, Duration::from_secs(8));
    assert_eq!(default.max_search_days, 90);
    assert_eq!(default.max_inflight_per_agent, 2);

    assert!(tight.max_message_bytes < default.max_message_bytes);
    assert!(tight.max_call_bytes < default.max_call_bytes);
    assert!(tight.max_messages < default.max_messages);
    // Attachment budgets shrink too, so a fixture can exercise the caps.
    assert!(tight.max_attachment_bytes() < default.max_attachment_bytes());
    assert!(tight.max_call_attachment_bytes() < default.max_call_attachment_bytes());
    assert!(tight.call_timeout < default.call_timeout);
    assert!(tight.connect_timeout < default.connect_timeout);
    assert!(tight.max_search_days < default.max_search_days);
    assert!(tight.max_inflight_per_agent < default.max_inflight_per_agent);
    assert_eq!(tight.call_timeout, Duration::from_millis(300));
}

#[test]
fn every_requested_bound_is_clamped_to_the_hard_one() {
    let limits = Limits::default();

    // Counts: over the cap is clamped, unset falls back to the cap.
    assert_eq!(limits.clamp_messages(20), 20);
    assert_eq!(limits.clamp_messages(1000), 200);
    assert_eq!(limits.clamp_messages(0), 200);
    assert_eq!(limits.clamp_search_days(7), 7);
    assert_eq!(limits.clamp_search_days(3650), 90);
    assert_eq!(limits.clamp_search_days(0), 90);

    // Bytes.
    assert_eq!(limits.clamp_message_bytes(1024), 1024);
    assert_eq!(limits.clamp_message_bytes(usize::MAX), 2_097_152);
    // Attachments: a request is clamped to the ceiling; unset means the ceiling.
    assert_eq!(limits.clamp_attachment_bytes(4096), 4096);
    assert_eq!(
        limits.clamp_attachment_bytes(usize::MAX),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    assert_eq!(
        limits.clamp_attachment_bytes(0),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    assert_eq!(
        limits.clamp_attachment_call_bytes(0),
        DEFAULT_MAX_CALL_ATTACHMENT_BYTES
    );

    // Result caps: never above the tool's own (below the engine's 128 KiB).
    assert_eq!(limits.clamp_result_bytes(1024, LIST_RESULT_BYTES), 1024);
    assert_eq!(
        limits.clamp_result_bytes(usize::MAX, LIST_RESULT_BYTES),
        LIST_RESULT_BYTES
    );
    assert_eq!(
        limits.clamp_result_bytes(0, READ_RESULT_BYTES),
        READ_RESULT_BYTES
    );
    // These two are compile-time facts about the constants themselves.
    const {
        assert!(LIST_RESULT_BYTES < READ_RESULT_BYTES);
        assert!(READ_RESULT_BYTES <= 128 * 1024);
    }

    // A tight ceiling wins over a larger requested value.
    let tight = Limits::tight();
    assert_eq!(tight.clamp_messages(1000), 5);
    assert_eq!(tight.clamp_search_days(3650), 1);
}

#[test]
fn a_zero_in_the_config_falls_back_to_the_default_bound() {
    let config = MailConfig::from_toml(
        "[limits]\n\
         max_message_bytes = 0\n\
         max_call_bytes = 0\n\
         max_messages = 0\n\
         max_attachment_bytes = 0\n\
         call_timeout_secs = 0\n\
         connect_timeout_secs = 0\n\
         max_search_days = 0\n\
         max_inflight_per_agent = 0\n",
    )
    .expect("an all-zero limits table parses");
    let limits = config.limits.limits();

    assert_eq!(limits, Limits::default());
    assert_eq!(limits.call_timeout, Duration::from_secs(20));
    assert_eq!(limits.connect_timeout, Duration::from_secs(8));
    assert_eq!(limits.max_messages, 200);
    assert_eq!(limits.max_inflight_per_agent, 2);
    assert_eq!(limits.max_attachment_bytes(), DEFAULT_MAX_ATTACHMENT_BYTES);
}

#[test]
fn attachments_have_a_documented_budget() {
    // MA3 downloads attachments: the default posture is 25 MiB per part and
    // 50 MiB per call, the tight variant shrinks both, and a request for the
    // largest value still resolves to the ceiling.
    assert_eq!(DEFAULT_MAX_ATTACHMENT_BYTES, 25 * 1024 * 1024);
    assert_eq!(DEFAULT_MAX_CALL_ATTACHMENT_BYTES, 50 * 1024 * 1024);
    assert_eq!(
        Limits::default().max_attachment_bytes(),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    assert!(Limits::tight().max_attachment_bytes() < DEFAULT_MAX_ATTACHMENT_BYTES);
    assert_eq!(
        MailLimits::default().limits().max_attachment_bytes(),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    assert_eq!(
        Limits::default().clamp_attachment_bytes(usize::MAX),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    assert_eq!(
        Limits::default().max_call_attachment_bytes(),
        DEFAULT_MAX_CALL_ATTACHMENT_BYTES
    );
}

#[test]
fn a_configured_attachment_budget_is_accepted_and_capped() {
    // A config may lower the budget; anything above the documented ceiling is
    // capped, and zero (or an absent key) falls back to the default.
    let smaller = MailConfig::from_toml("[limits]\nmax_attachment_bytes = 4096\n")
        .expect("a smaller budget parses");
    assert_eq!(smaller.limits.limits().max_attachment_bytes(), 4096);

    let huge = MailConfig::from_toml("[limits]\nmax_attachment_bytes = 999999999\n")
        .expect("an oversized budget parses and is capped");
    assert_eq!(
        huge.limits.limits().max_attachment_bytes(),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );

    let zero = MailConfig::from_toml("[limits]\nmax_attachment_bytes = 0\n")
        .expect("zero means the default");
    assert_eq!(
        zero.limits.limits().max_attachment_bytes(),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    let absent =
        MailConfig::from_toml("[limits]\nmax_messages = 5\n").expect("an absent key parses");
    assert_eq!(
        absent.limits.limits().max_attachment_bytes(),
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
}

#[test]
fn configured_limits_convert_without_losing_the_values() {
    let config = MailConfig::from_toml(
        "[limits]\n\
         max_message_bytes = 4096\n\
         max_call_bytes = 8192\n\
         max_messages = 3\n\
         max_attachment_bytes = 0\n\
         call_timeout_secs = 2\n\
         connect_timeout_secs = 1\n\
         max_search_days = 5\n\
         max_inflight_per_agent = 2\n",
    )
    .expect("configured limits parse");
    let limits = config.limits.limits();

    assert_eq!(limits.max_message_bytes, 4096);
    assert_eq!(limits.max_call_bytes, 8192);
    assert_eq!(limits.max_messages, 3);
    assert_eq!(limits.call_timeout, Duration::from_secs(2));
    assert_eq!(limits.connect_timeout, Duration::from_secs(1));
    assert_eq!(limits.max_search_days, 5);
    assert_eq!(limits.max_inflight_per_agent, 2);
}

#[test]
fn the_server_leaves_refuse_secret_material() {
    // Configuration names the account only; the secret is resolved at call
    // time. A `password` key in a server block is an unknown field and is
    // refused, so a secret cannot be pasted into `config.toml` by accident.
    let err = MailConfig::from_toml(
        "[[accounts]]\nid = \"a\"\n[accounts.imap]\nhost = \"h\"\npassword = \"hunter2\"\n",
    )
    .expect_err("a password key inside the imap leaf must be refused");
    let message = err.to_string();
    assert!(
        message.contains("password") || message.contains("unknown field"),
        "the error must name the offending key: {message}"
    );
}

#[test]
fn the_account_itself_refuses_secret_material() {
    // The account record is a leaf too: a `password` at the account level (not
    // inside `[accounts.imap]`) must be refused rather than silently ignored,
    // so a secret cannot be pasted next to the account by accident.
    let err = MailConfig::from_toml("[[accounts]]\nid = \"a\"\npassword = \"hunter2\"\n")
        .expect_err("a password key at the account level must be refused");
    let message = err.to_string();
    assert!(
        message.contains("password") || message.contains("unknown field"),
        "the error must name the offending key: {message}"
    );

    // A typo at the account level is refused for the same reason.
    assert!(MailConfig::from_toml("[[accounts]]\nid = \"a\"\nsend_mdoe = \"ask\"\n").is_err());
}

#[test]
fn account_helpers_are_case_insensitive_for_folders() {
    let account = MailAccount {
        only_folders: vec!["INBOX".to_string(), "Newsletters".to_string()],
        ..MailAccount::default()
    };
    assert!(account.reads_folder("inbox"));
    assert!(account.reads_folder("newsletters"));
    assert!(!account.reads_folder("Sent"));
    let default_account = MailAccount::default();
    assert!(default_account.reads_folder("INBOX"));
    assert!(!default_account.reads_folder("Trash"));
}

#[test]
fn a_per_account_limits_table_is_refused() {
    // Bounds are shared, not per-account: a `limits` table inside an account
    // is an unknown field on the strict `MailAccount` leaf and is refused
    // rather than silently ignored.
    let err =
        MailConfig::from_toml("[[accounts]]\nid = \"a\"\n\n[accounts.limits]\nmax_messages = 5\n")
            .expect_err("a per-account limits table must be refused");
    let message = err.to_string();
    assert!(
        message.contains("limits") || message.contains("unknown field"),
        "the error must name the offending key: {message}"
    );
}

#[test]
fn a_negative_attachment_budget_is_a_hard_parse_error() {
    // TOML accepts `-1`, but the field is a `usize`: the type mismatch is a
    // hard parse error, never a silent wrap or clamp.
    let err = MailConfig::from_toml("[limits]\nmax_attachment_bytes = -1\n")
        .expect_err("a negative attachment budget must be a hard parse error");
    let message = err.to_string();
    assert!(
        message.contains("max_attachment_bytes") || message.contains("invalid value"),
        "the error must name the offending key or value: {message}"
    );
}

#[test]
fn an_invalid_integer_is_a_hard_parse_error() {
    // A string or float where an integer bound belongs is a parse error, not a
    // fallback to the default.
    for raw in [
        "[limits]\nmax_messages = \"many\"\n",
        "[limits]\nmax_messages = 1.5\n",
    ] {
        let err =
            MailConfig::from_toml(raw).expect_err("a non-integer bound must be a hard parse error");
        let message = err.to_string();
        assert!(
            message.contains("max_messages")
                || message.contains("invalid type")
                || message.contains("invalid value"),
            "the error must name the offending key or value: {message}"
        );
    }
}
