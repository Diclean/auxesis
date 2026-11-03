//! M1: the error vocabulary — bilingual, non-empty, port-bearing.

use std::time::Duration;

use aux_mail::error::{Lang, MailError};

const HOST: &str = "imap.example.org";
const PORT: u16 = 993;

fn with_hosts() -> Vec<MailError> {
    vec![
        MailError::Dns {
            host: HOST.to_string(),
            port: PORT,
        },
        MailError::Connect {
            host: HOST.to_string(),
            port: PORT,
        },
        MailError::Tls {
            host: HOST.to_string(),
            port: PORT,
        },
        MailError::NoStartTls {
            host: HOST.to_string(),
            port: PORT,
        },
        MailError::InsecurePassword {
            host: HOST.to_string(),
            port: PORT,
        },
        MailError::CertRejected {
            host: HOST.to_string(),
            port: PORT,
        },
    ]
}

fn all_errors() -> Vec<MailError> {
    let mut errors = with_hosts();
    errors.extend([
        MailError::Auth,
        MailError::NoAuthMechanism,
        MailError::FolderUnavailable {
            name: "INBOX.Private".to_string(),
            seen: vec!["INBOX".to_string(), "Sent".to_string()],
        },
        MailError::SmtpAuth,
        MailError::RelayDenied {
            from: "me@example.org".to_string(),
        },
        MailError::RateLimited,
        MailError::TooLarge {
            limit: 1024,
            seen: 4096,
        },
        MailError::Timeout {
            budget: Duration::from_secs(8),
        },
        MailError::Protocol,
    ]);
    errors
}

#[test]
fn every_error_has_a_three_part_message_in_both_languages() {
    for error in all_errors() {
        for lang in [Lang::En, Lang::Fr] {
            let message = error.user_message(lang);
            assert!(!message.title.is_empty(), "{error:?} {lang:?} title");
            assert!(!message.cause.is_empty(), "{error:?} {lang:?} cause");
            assert!(!message.action.is_empty(), "{error:?} {lang:?} action");
        }
    }
}

#[test]
fn every_message_naming_a_host_also_names_its_port() {
    for error in with_hosts() {
        for lang in [Lang::En, Lang::Fr] {
            let message = error.user_message(lang);
            let text = format!("{} {} {}", message.title, message.cause, message.action);
            assert!(
                text.contains(HOST),
                "{error:?} {lang:?} must name the host: {text}"
            );
            assert!(
                text.contains(&PORT.to_string()),
                "{error:?} {lang:?} must name the port: {text}"
            );
        }
    }
}

#[test]
fn messages_are_jargon_free() {
    for error in all_errors() {
        for lang in [Lang::En, Lang::Fr] {
            let message = error.user_message(lang);
            let text = format!("{} {} {}", message.title, message.cause, message.action);
            for token in ["NOAUTH", "A0011", "535", "STARTTLS", "TLS", "SMTP"] {
                assert!(
                    !text.contains(token),
                    "{error:?} {lang:?} leaks {token}: {text}"
                );
            }
        }
    }
}

#[test]
fn french_differs_from_english() {
    for error in all_errors() {
        assert_ne!(
            error.user_message(Lang::En),
            error.user_message(Lang::Fr),
            "{error:?} must be localized"
        );
    }
}

#[test]
fn the_timeout_message_names_its_budget() {
    let message = MailError::Timeout {
        budget: Duration::from_secs(8),
    }
    .user_message(Lang::En);
    assert!(message.cause.contains('8'), "{message:?}");
}

#[test]
fn folder_unavailable_lists_what_was_seen() {
    let message = MailError::FolderUnavailable {
        name: "INBOX.Private".to_string(),
        seen: vec!["INBOX".to_string(), "Sent".to_string()],
    }
    .user_message(Lang::En);
    assert!(message.cause.contains("INBOX"), "{message:?}");
    assert!(message.cause.contains("Sent"), "{message:?}");
}
