//! `aux notify` — send a macOS notification (manual check for Slice N).
//!
//! Delivery is refused while the `STOP` kill-switch marker exists, so the
//! daemon and this manual command share one switch. It is also refused in
//! private mode (C10), as the daemon's job notifications are.

use aux_notify::{system_notifier, Notification, Notifier, StopSwitchNotifier};
use clap::Parser;
use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};
use kernel_core::Lang;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// Send a macOS notification.
#[derive(Debug, Parser)]
pub struct NotifyArgs {
    /// Ask auxd to send one fixed test text on the morning brief's channel,
    /// so macOS can ask for Messages access.
    #[arg(long, conflicts_with_all = ["title", "body"])]
    pub test: bool,
    /// Notification title.
    #[arg(required_unless_present = "test")]
    pub title: Option<String>,
    /// Notification body.
    #[arg(required_unless_present = "test")]
    pub body: Option<String>,
}

/// The extra line when Messages never answered: the Allow pop-up may be open.
const ALLOW_HINT: &str =
    "macOS may be showing an Allow pop-up for auxd: click OK, then run this again.";

/// Deliver `title`/`body` through `osascript`, honoring the `STOP` marker and
/// the privacy mode; or, with `--test`, ask auxd for its test send.
pub fn run(args: NotifyArgs) -> ExitCode {
    let home = kernel_core::auxesis_home();
    if args.test {
        return run_test(&home);
    }
    let notifier = StopSwitchNotifier::new(
        system_notifier(kernel_core::sandbox_guard_active()),
        home.join("STOP"),
    );
    let (title, body) = (
        args.title.unwrap_or_default(),
        args.body.unwrap_or_default(),
    );
    match deliver(&title, &body, &notifier, current_mode(&home)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux notify: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `aux notify --test`: one `POST /v1/notify/test` over loopback, with the
/// same endpoint and token rules as `aux brief`.
fn run_test(home: &Path) -> ExitCode {
    let lang = aux_engine::config::load_or_create(&kernel_core::config_path(home))
        .map(|config| config.ui.language)
        .unwrap_or_default();
    let called = crate::brief::daemon_target(lang).and_then(|(url, token)| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| crate::brief::BriefDaemonError::Protocol(err.to_string()))?;
        runtime.block_on(crate::brief::call_daemon(
            reqwest::Method::POST,
            &url,
            "/v1/notify/test",
            &token,
            lang,
        ))
    });
    let reply = called.map(|body| serde_json::from_str(&body).unwrap_or_default());
    match reply {
        Ok(value) => {
            let (text, delivered) = test_report(lang, &value);
            println!("{text}");
            if delivered {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux notify: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The plain-words line for a `{delivered, cause}` reply, and `delivered`.
fn test_report(lang: Lang, value: &serde_json::Value) -> (String, bool) {
    let fr = lang == Lang::Fr;
    if value["delivered"] == true {
        let text = if fr {
            "Texte de test envoyé par auxd : regardez Messages sur votre téléphone."
        } else {
            "Test text sent from auxd: check Messages on your phone."
        };
        return (text.to_string(), true);
    }
    let cause = value["cause"].as_str().unwrap_or("unknown");
    let why = match (cause, fr) {
        ("timeout" | "not_confirmed", false) => "Messages did not answer in time.",
        ("timeout" | "not_confirmed", true) => "Messages n'a pas répondu à temps.",
        ("not_authorized", false) => "macOS does not allow auxd to control Messages.",
        ("not_authorized", true) => "macOS n'autorise pas auxd à contrôler Messages.",
        ("messages_unavailable", false) => "Messages is off or has no account for you.",
        ("messages_unavailable", true) => "Messages est fermé ou n'a pas de compte pour vous.",
        ("held", false) => "Held: the privacy mode or the channel setup keeps it on this Mac.",
        ("held", true) => "Retenu : le mode privé ou le canal le garde sur ce Mac.",
        (_, false) => "Not delivered.",
        (_, true) => "Non remis.",
    };
    let mut text = format!("{why} ({cause})");
    if matches!(cause, "timeout" | "not_confirmed") {
        text.push('\n');
        text.push_str(ALLOW_HINT);
    }
    (text, false)
}

/// The live privacy mode of `home`. A config that cannot be loaded is private,
/// the same fail-closed rule the daemon applies.
pub(crate) fn current_mode(home: &Path) -> PrivacyMode {
    aux_engine::config::load_or_create(&kernel_core::config_path(home))
        .map_or(PrivacyMode::Private, |config| config.privacy.mode)
}

/// Hand the payload to the transport, once `mode` admits it (C10). Split out so
/// tests can inject a fake and never spawn a real notification.
fn deliver(
    title: &str,
    body: &str,
    notifier: &dyn Notifier,
    mode: PrivacyMode,
) -> Result<(), String> {
    if admit_call(PathId::C10, mode, Destination::LocalDisplay).is_err() {
        return Err(
            "notifications are off in private mode (les notifications sont désactivées en mode privé)"
                .to_string(),
        );
    }
    notifier
        .notify(&Notification::new(title, body))
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_notify::FakeNotifier;
    use kernel_core::privacy::PrivacyMode;

    #[test]
    fn the_payload_reaches_the_transport() {
        let fake = FakeNotifier::new();
        deliver("Title", "Body", &fake, PrivacyMode::Open).unwrap();
        let sent = fake.last().unwrap();
        assert_eq!(sent.title, "Title");
        assert_eq!(sent.body, "Body");
    }

    #[test]
    fn a_transport_failure_is_surfaced() {
        let fake = FakeNotifier::failing("permission denied");
        let err = deliver("Title", "Body", &fake, PrivacyMode::Open).unwrap_err();
        assert!(err.contains("permission denied"), "{err}");
    }

    #[test]
    fn the_test_reply_prints_its_cause_in_plain_words() {
        let reply = serde_json::json!({ "delivered": false, "cause": "timeout" });
        let (text, delivered) = test_report(Lang::En, &reply);
        assert!(!delivered);
        assert!(text.contains("(timeout)"), "{text}");
        assert_eq!(text.lines().last(), Some(ALLOW_HINT));
        let reply = serde_json::json!({ "delivered": false, "cause": "not_authorized" });
        let (text, _) = test_report(Lang::En, &reply);
        assert!(
            text.contains("(not_authorized)") && !text.contains(ALLOW_HINT),
            "{text}"
        );
        let reply = serde_json::json!({ "delivered": true, "cause": null });
        assert!(test_report(Lang::En, &reply).1);
    }

    #[test]
    fn private_mode_sends_no_notification() {
        // C10: a notification leaves the app through the OS, so private mode
        // holds it, as the daemon does for job notifications.
        let fake = FakeNotifier::new();
        let err = deliver("Title", "Body", &fake, PrivacyMode::Private).unwrap_err();
        assert_eq!(fake.count(), 0, "nothing reaches the transport");
        assert!(err.contains("private"), "{err}");
    }
}
